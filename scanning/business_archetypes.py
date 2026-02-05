"""
PHANTOM AI - Business Archetypes

Defines per-domain business rules, state machines, and bypass patterns.
Each archetype encapsulates the security-relevant business logic of a domain:
- E-commerce, SaaS, Fintech, Marketplace, Auth-Centric, Content, API Service

The archetypes are pure data — adding a new domain is just adding a new dict.
No I/O, no network calls, no dependencies beyond dataclasses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


# =============================================================================
# Core Enums
# =============================================================================

class BusinessDomain(Enum):
    """Classification of a target's business domain."""
    ECOMMERCE = "ecommerce"
    SAAS = "saas"
    FINTECH = "fintech"
    MARKETPLACE = "marketplace"
    AUTH_CENTRIC = "auth_centric"
    CONTENT = "content"
    API_SERVICE = "api_service"
    UNKNOWN = "unknown"


class RuleType(Enum):
    """Categories of business rules that can be violated."""
    FIELD_IMMUTABILITY = "field_immutability"    # Client can't set price/role
    STATE_FORWARD_ONLY = "state_forward_only"    # Can't go backwards in workflow
    BOUNDS_ENFORCEMENT = "bounds_enforcement"    # Quantity > 0, amount > 0
    IDEMPOTENCY = "idempotency"                  # Operation can't be replayed
    ISOLATION = "isolation"                      # Can't access other user's data
    AUTHORIZATION = "authorization"              # Must have correct role/permission
    RATE_LIMITING = "rate_limiting"              # Can't repeat too fast


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class BusinessRule:
    """A business rule that should be enforced by the application.

    The scanner will test whether the rule is actually enforced.
    """
    name: str                          # "price_immutability"
    description: str                   # "Client cannot set product price"
    rule_type: RuleType
    target_fields: list[str]           # ["price", "total", "amount", "unit_price"]
    target_endpoints: list[str]        # Endpoint regex patterns to match
    test_values: list[Any]             # Values to try injecting
    severity: str                      # CRITICAL/HIGH/MEDIUM
    confidence_if_violated: float      # 85-95


@dataclass
class WorkflowTemplate:
    """A multi-step business workflow where state skipping is a vulnerability.

    Example: checkout flow where skipping payment is a critical bug.
    """
    name: str                          # "checkout_flow"
    states: list[str]                  # ["cart", "address", "payment", "confirm"]
    transitions: dict[str, list[str]]  # {"cart": ["address"], ...}
    endpoint_patterns: dict[str, list[str]]  # state → endpoint regex patterns
    skip_tests: list[tuple[str, str]]  # (from_state, to_state) invalid jumps


@dataclass
class BypassPattern:
    """A specific bypass technique to test against matching endpoints."""
    name: str                          # "negative_quantity"
    description: str
    method: str                        # POST/PUT/PATCH
    field: str                         # "quantity"
    payloads: list[Any]                # [-1, -100, -999999]
    endpoint_patterns: list[str]       # Regex patterns to match
    success_indicators: list[str]      # Response patterns indicating success
    severity: str                      # CRITICAL/HIGH/MEDIUM
    confidence_if_violated: float = 85.0


@dataclass
class BusinessArchetype:
    """Complete business domain model for security testing."""
    domain: BusinessDomain
    name: str                          # "E-Commerce Application"
    guiding_questions: list[str]       # Pentester's "frases-guia" per domain
    rules: list[BusinessRule]
    workflows: list[WorkflowTemplate]
    bypass_patterns: list[BypassPattern]
    critical_operations: list[str]     # High-value endpoint categories
    race_condition_targets: list[str]  # Endpoints where race conditions matter most


# =============================================================================
# E-Commerce Archetype
# =============================================================================

ECOMMERCE_ARCHETYPE = BusinessArchetype(
    domain=BusinessDomain.ECOMMERCE,
    name="E-Commerce Application",
    guiding_questions=[
        "Can the client set the price of a product?",
        "Can I order with negative quantity and get credited?",
        "Can I skip payment and go directly to order confirmation?",
        "Can I reuse a coupon/discount code?",
        "Can I access another user's cart or orders?",
        "Can I modify the order total in the request?",
    ],
    rules=[
        BusinessRule(
            name="price_immutability",
            description="Client cannot set product price in request body",
            rule_type=RuleType.FIELD_IMMUTABILITY,
            target_fields=["price", "total", "amount", "unit_price", "unitPrice",
                           "subtotal", "totalPrice", "total_price", "item_price"],
            target_endpoints=[
                r"/cart", r"/basket", r"/checkout", r"/order",
                r"/api/.*/items", r"/api/.*/cart",
            ],
            test_values=[0, 0.01, -1, 1],
            severity="CRITICAL",
            confidence_if_violated=90.0,
        ),
        BusinessRule(
            name="quantity_positive",
            description="Quantity must be positive integer",
            rule_type=RuleType.BOUNDS_ENFORCEMENT,
            target_fields=["quantity", "qty", "count", "amount", "num", "numberOfItems"],
            target_endpoints=[
                r"/cart", r"/basket", r"/items", r"/products",
                r"/api/.*/quantity", r"/api/.*/items",
            ],
            test_values=[-1, -100, -999999, 0, 0.5, 99999999],
            severity="CRITICAL",
            confidence_if_violated=90.0,
        ),
        BusinessRule(
            name="coupon_single_use",
            description="Coupon/discount code cannot be applied multiple times",
            rule_type=RuleType.IDEMPOTENCY,
            target_fields=["coupon", "code", "promo", "discount_code", "voucher",
                           "promoCode", "couponCode"],
            target_endpoints=[
                r"/coupon", r"/discount", r"/promo", r"/voucher",
                r"/api/.*/coupon",
            ],
            test_values=["TESTCODE", "DISCOUNT50", "PROMO"],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
        BusinessRule(
            name="role_immutability",
            description="User cannot set own role/admin status",
            rule_type=RuleType.FIELD_IMMUTABILITY,
            target_fields=["role", "admin", "isAdmin", "is_admin", "permissions",
                           "privilege", "level", "tier", "userType"],
            target_endpoints=[
                r"/register", r"/signup", r"/profile", r"/account",
                r"/api/[Uu]sers", r"/api/.*/profile",
            ],
            test_values=["admin", True, 1, "superadmin", "administrator"],
            severity="CRITICAL",
            confidence_if_violated=95.0,
        ),
        BusinessRule(
            name="order_total_immutability",
            description="Client cannot modify order total/subtotal",
            rule_type=RuleType.FIELD_IMMUTABILITY,
            target_fields=["total", "subtotal", "grandTotal", "grand_total",
                           "orderTotal", "order_total", "finalPrice"],
            target_endpoints=[
                r"/checkout", r"/order", r"/payment",
                r"/api/.*/checkout", r"/api/.*/order",
            ],
            test_values=[0, 0.01, 1],
            severity="CRITICAL",
            confidence_if_violated=90.0,
        ),
        BusinessRule(
            name="refund_authorization",
            description="Refunds require proper authorization",
            rule_type=RuleType.AUTHORIZATION,
            target_fields=["refund", "amount", "reason"],
            target_endpoints=[
                r"/refund", r"/return", r"/api/.*/refund",
            ],
            test_values=[{"amount": 99999, "reason": "test"}],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
    ],
    workflows=[
        WorkflowTemplate(
            name="checkout_flow",
            states=["cart", "address", "payment", "confirmation"],
            transitions={
                "cart": ["address"],
                "address": ["payment", "cart"],
                "payment": ["confirmation"],
            },
            endpoint_patterns={
                "cart": [r"/cart", r"/basket", r"/api/.*/cart"],
                "address": [r"/address", r"/shipping", r"/delivery"],
                "payment": [r"/payment", r"/checkout", r"/pay"],
                "confirmation": [r"/confirm", r"/order", r"/api/.*/order"],
            },
            skip_tests=[
                ("cart", "payment"),          # Skip address
                ("cart", "confirmation"),      # Skip payment entirely
                ("address", "confirmation"),   # Skip payment
            ],
        ),
        WorkflowTemplate(
            name="refund_flow",
            states=["order", "request_refund", "review", "refund_processed"],
            transitions={
                "order": ["request_refund"],
                "request_refund": ["review"],
                "review": ["refund_processed"],
            },
            endpoint_patterns={
                "order": [r"/order", r"/api/.*/order"],
                "request_refund": [r"/refund", r"/return", r"/api/.*/refund"],
                "review": [r"/review", r"/approve"],
                "refund_processed": [r"/process", r"/complete"],
            },
            skip_tests=[
                ("order", "refund_processed"),     # Skip review
                ("request_refund", "refund_processed"),  # Skip review
            ],
        ),
    ],
    bypass_patterns=[
        BypassPattern(
            name="negative_quantity",
            description="Negative quantity for credit/refund",
            method="PUT",
            field="quantity",
            payloads=[-1, -100, -999999],
            endpoint_patterns=[r"/cart", r"/basket", r"/items", r"/api/.*/items"],
            success_indicators=["200", "success", "updated", "total"],
            severity="CRITICAL",
            confidence_if_violated=90.0,
        ),
        BypassPattern(
            name="zero_price_checkout",
            description="Set price to zero during checkout",
            method="POST",
            field="price",
            payloads=[0, 0.00, "0", "0.00"],
            endpoint_patterns=[r"/checkout", r"/payment", r"/order"],
            success_indicators=["200", "201", "success", "order_id", "confirmed"],
            severity="CRITICAL",
            confidence_if_violated=90.0,
        ),
        BypassPattern(
            name="coupon_replay",
            description="Apply same coupon/discount code multiple times",
            method="POST",
            field="coupon",
            payloads=["TESTCODE50", "DISCOUNT", "PROMO"],
            endpoint_patterns=[r"/coupon", r"/discount", r"/promo"],
            success_indicators=["200", "applied", "discount", "success"],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
        BypassPattern(
            name="modify_order_total",
            description="Set order total/subtotal in request body",
            method="POST",
            field="total",
            payloads=[0, 0.01, 1],
            endpoint_patterns=[r"/checkout", r"/order", r"/payment"],
            success_indicators=["200", "201", "success", "order_id"],
            severity="CRITICAL",
            confidence_if_violated=90.0,
        ),
        BypassPattern(
            name="free_shipping",
            description="Set shipping cost to zero",
            method="POST",
            field="shipping",
            payloads=[0, "0", "free"],
            endpoint_patterns=[r"/checkout", r"/shipping", r"/delivery"],
            success_indicators=["200", "success", "updated"],
            severity="MEDIUM",
            confidence_if_violated=80.0,
        ),
    ],
    critical_operations=["checkout", "payment", "refund", "coupon", "order"],
    race_condition_targets=[
        "coupon", "checkout", "payment", "refund", "redeem", "points",
    ],
)


# =============================================================================
# SaaS Archetype
# =============================================================================

SAAS_ARCHETYPE = BusinessArchetype(
    domain=BusinessDomain.SAAS,
    name="SaaS Platform",
    guiding_questions=[
        "Can a free-tier user access premium features?",
        "Can I exceed the seat/user limit for my plan?",
        "Can I access another tenant's data by swapping IDs?",
        "Can I extend my trial indefinitely?",
        "Can I set feature flags via the request body?",
        "Can I downgrade without losing data access?",
    ],
    rules=[
        BusinessRule(
            name="plan_enforcement",
            description="Free plan cannot access premium features",
            rule_type=RuleType.AUTHORIZATION,
            target_fields=["plan", "tier", "plan_id", "planId", "subscription",
                           "level", "feature_tier"],
            target_endpoints=[
                r"/api/.*/plan", r"/subscription", r"/billing",
                r"/api/.*/features", r"/api/.*/upgrade",
            ],
            test_values=["enterprise", "pro", "premium", "unlimited", "business"],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
        BusinessRule(
            name="seat_limit",
            description="Cannot exceed seat count for current plan",
            rule_type=RuleType.BOUNDS_ENFORCEMENT,
            target_fields=["seats", "users", "members", "invites", "max_users",
                           "team_size", "seat_count"],
            target_endpoints=[
                r"/invite", r"/team", r"/members", r"/seats",
                r"/api/.*/invite", r"/api/.*/team",
            ],
            test_values=[999, 99999, -1],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
        BusinessRule(
            name="tenant_isolation",
            description="Cannot access another organization's data",
            rule_type=RuleType.ISOLATION,
            target_fields=["tenant_id", "org_id", "workspace_id", "team_id",
                           "tenantId", "orgId", "workspaceId", "organization_id"],
            target_endpoints=[
                r"/api/.*", r"/dashboard", r"/workspace",
                r"/settings", r"/team",
            ],
            test_values=["other_tenant_id", "00000000-0000-0000-0000-000000000000",
                         "1", "999"],
            severity="CRITICAL",
            confidence_if_violated=95.0,
        ),
        BusinessRule(
            name="trial_abuse_prevention",
            description="Trial period cannot be extended or reset",
            rule_type=RuleType.IDEMPOTENCY,
            target_fields=["trial", "trial_end", "trial_expires", "trialEnd"],
            target_endpoints=[
                r"/trial", r"/api/.*/trial", r"/subscription",
            ],
            test_values=["2099-12-31", 99999999, True],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
        BusinessRule(
            name="feature_gating",
            description="Feature flags cannot be client-controlled",
            rule_type=RuleType.FIELD_IMMUTABILITY,
            target_fields=["features", "flags", "feature_flags", "featureFlags",
                           "enabled_features", "capabilities"],
            target_endpoints=[
                r"/api/.*/features", r"/api/.*/settings",
                r"/api/.*/profile", r"/api/.*/account",
            ],
            test_values=[{"premium": True, "unlimited": True},
                         ["premium", "analytics", "api_access"]],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
    ],
    workflows=[
        WorkflowTemplate(
            name="subscription_flow",
            states=["trial", "subscribe", "active", "upgrade", "cancel"],
            transitions={
                "trial": ["subscribe", "cancel"],
                "subscribe": ["active"],
                "active": ["upgrade", "cancel"],
                "upgrade": ["active"],
            },
            endpoint_patterns={
                "trial": [r"/trial", r"/api/.*/trial"],
                "subscribe": [r"/subscribe", r"/api/.*/subscribe", r"/billing"],
                "active": [r"/subscription", r"/api/.*/subscription"],
                "upgrade": [r"/upgrade", r"/api/.*/upgrade", r"/plan"],
                "cancel": [r"/cancel", r"/api/.*/cancel"],
            },
            skip_tests=[
                ("trial", "active"),       # Skip payment
                ("trial", "upgrade"),      # Skip subscription entirely
                ("cancel", "active"),      # Reactivate without payment
            ],
        ),
        WorkflowTemplate(
            name="onboarding_flow",
            states=["signup", "create_workspace", "invite_team", "configure"],
            transitions={
                "signup": ["create_workspace"],
                "create_workspace": ["invite_team", "configure"],
                "invite_team": ["configure"],
            },
            endpoint_patterns={
                "signup": [r"/signup", r"/register"],
                "create_workspace": [r"/workspace", r"/org", r"/team"],
                "invite_team": [r"/invite", r"/team/add"],
                "configure": [r"/settings", r"/configure", r"/setup"],
            },
            skip_tests=[
                ("signup", "configure"),           # Skip setup
                ("signup", "invite_team"),          # Skip workspace creation
            ],
        ),
    ],
    bypass_patterns=[
        BypassPattern(
            name="plan_parameter_tampering",
            description="Set plan=enterprise in request body",
            method="POST",
            field="plan",
            payloads=["enterprise", "pro", "premium", "unlimited"],
            endpoint_patterns=[r"/subscribe", r"/subscription", r"/plan", r"/billing"],
            success_indicators=["200", "success", "upgraded", "active"],
            severity="CRITICAL",
            confidence_if_violated=90.0,
        ),
        BypassPattern(
            name="seat_overflow",
            description="Add users beyond plan seat limit",
            method="POST",
            field="email",
            payloads=["overflow_user@test.example.com"],
            endpoint_patterns=[r"/invite", r"/team", r"/members", r"/add-user"],
            success_indicators=["200", "201", "invited", "success", "added"],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
        BypassPattern(
            name="tenant_id_swap",
            description="Change tenant/org ID in request to access other org data",
            method="GET",
            field="tenant_id",
            payloads=["other_tenant", "1", "00000000-0000-0000-0000-000000000000"],
            endpoint_patterns=[r"/api/.*", r"/dashboard", r"/workspace"],
            success_indicators=["200", "data", "name", "users"],
            severity="CRITICAL",
            confidence_if_violated=95.0,
        ),
        BypassPattern(
            name="feature_flag_injection",
            description="Set feature flags in request body",
            method="PUT",
            field="features",
            payloads=[{"premium": True}, {"unlimited_api": True}, ["all"]],
            endpoint_patterns=[r"/settings", r"/profile", r"/account", r"/api/.*/settings"],
            success_indicators=["200", "success", "updated"],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
    ],
    critical_operations=["subscription", "billing", "invite", "upgrade", "workspace"],
    race_condition_targets=[
        "invite", "seat", "plan", "trial", "upgrade",
    ],
)


# =============================================================================
# Fintech Archetype
# =============================================================================

FINTECH_ARCHETYPE = BusinessArchetype(
    domain=BusinessDomain.FINTECH,
    name="Fintech / Banking Application",
    guiding_questions=[
        "Can I transfer a negative amount (crediting myself)?",
        "Can I exceed my daily transfer limit?",
        "Can I skip 2FA/MFA on a transfer?",
        "Can I exploit floating-point rounding in currency conversion?",
        "Can I double-spend by sending parallel transfers?",
        "Does the balance go negative if I'm fast enough?",
    ],
    rules=[
        BusinessRule(
            name="balance_conservation",
            description="Debits must equal credits — no money creation",
            rule_type=RuleType.BOUNDS_ENFORCEMENT,
            target_fields=["amount", "value", "sum", "total", "transfer_amount"],
            target_endpoints=[
                r"/transfer", r"/send", r"/pay", r"/withdraw",
                r"/api/.*/transfer", r"/api/.*/transaction",
            ],
            test_values=[-100, -0.01, 0, 99999999999],
            severity="CRITICAL",
            confidence_if_violated=95.0,
        ),
        BusinessRule(
            name="transfer_authorization",
            description="Transfers need 2FA/confirmation step",
            rule_type=RuleType.AUTHORIZATION,
            target_fields=["otp", "2fa_code", "confirmation", "pin",
                           "mfa_token", "verify_code"],
            target_endpoints=[
                r"/transfer", r"/send", r"/withdraw",
                r"/api/.*/execute", r"/api/.*/confirm",
            ],
            test_values=["000000", "123456", "", None],
            severity="CRITICAL",
            confidence_if_violated=95.0,
        ),
        BusinessRule(
            name="negative_prevention",
            description="Balance/amount cannot go negative",
            rule_type=RuleType.BOUNDS_ENFORCEMENT,
            target_fields=["amount", "value", "balance", "quantity"],
            target_endpoints=[
                r"/transfer", r"/withdraw", r"/send", r"/pay",
                r"/api/.*/transfer",
            ],
            test_values=[-1, -0.01, -999999],
            severity="CRITICAL",
            confidence_if_violated=95.0,
        ),
        BusinessRule(
            name="daily_limits",
            description="Transfers are capped per day",
            rule_type=RuleType.BOUNDS_ENFORCEMENT,
            target_fields=["amount", "value", "total"],
            target_endpoints=[
                r"/transfer", r"/send", r"/withdraw",
            ],
            test_values=[999999999, 99999999, 10000000],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
        BusinessRule(
            name="precision_integrity",
            description="No floating-point manipulation for rounding exploits",
            rule_type=RuleType.BOUNDS_ENFORCEMENT,
            target_fields=["amount", "value", "price", "rate", "exchange_rate"],
            target_endpoints=[
                r"/transfer", r"/exchange", r"/convert", r"/pay",
                r"/api/.*/transaction",
            ],
            test_values=[0.000000001, 1e-10, 9.999999999, 0.001],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
    ],
    workflows=[
        WorkflowTemplate(
            name="transfer_flow",
            states=["initiate", "verify_2fa", "authorize", "execute", "confirm"],
            transitions={
                "initiate": ["verify_2fa"],
                "verify_2fa": ["authorize"],
                "authorize": ["execute"],
                "execute": ["confirm"],
            },
            endpoint_patterns={
                "initiate": [r"/transfer/new", r"/send", r"/api/.*/transfer"],
                "verify_2fa": [r"/verify", r"/2fa", r"/mfa", r"/otp"],
                "authorize": [r"/authorize", r"/approve", r"/confirm"],
                "execute": [r"/execute", r"/process", r"/submit"],
                "confirm": [r"/receipt", r"/status", r"/complete"],
            },
            skip_tests=[
                ("initiate", "execute"),      # Skip 2FA + authorization
                ("initiate", "authorize"),     # Skip 2FA
                ("verify_2fa", "execute"),     # Skip authorization
            ],
        ),
        WorkflowTemplate(
            name="withdrawal_flow",
            states=["request", "verify", "process", "complete"],
            transitions={
                "request": ["verify"],
                "verify": ["process"],
                "process": ["complete"],
            },
            endpoint_patterns={
                "request": [r"/withdraw", r"/cashout", r"/payout"],
                "verify": [r"/verify", r"/confirm", r"/otp"],
                "process": [r"/process", r"/execute"],
                "complete": [r"/complete", r"/receipt"],
            },
            skip_tests=[
                ("request", "process"),    # Skip verification
                ("request", "complete"),   # Skip everything
            ],
        ),
    ],
    bypass_patterns=[
        BypassPattern(
            name="negative_transfer",
            description="Transfer negative amount to credit instead of debit",
            method="POST",
            field="amount",
            payloads=[-100, -0.01, -999999],
            endpoint_patterns=[r"/transfer", r"/send", r"/pay", r"/api/.*/transfer"],
            success_indicators=["200", "success", "transferred", "completed"],
            severity="CRITICAL",
            confidence_if_violated=95.0,
        ),
        BypassPattern(
            name="precision_overflow",
            description="Ultra-small amount that rounds to 0 but processes",
            method="POST",
            field="amount",
            payloads=[0.000000001, 1e-10, 0.001],
            endpoint_patterns=[r"/transfer", r"/exchange", r"/convert"],
            success_indicators=["200", "success", "processed"],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
        BypassPattern(
            name="skip_2fa",
            description="Jump from initiation directly to execution without 2FA",
            method="POST",
            field="",
            payloads=[{}],
            endpoint_patterns=[r"/execute", r"/process", r"/submit", r"/api/.*/execute"],
            success_indicators=["200", "success", "processed"],
            severity="CRITICAL",
            confidence_if_violated=95.0,
        ),
        BypassPattern(
            name="currency_conversion_rounding",
            description="Exploit rounding in currency conversion",
            method="POST",
            field="amount",
            payloads=[0.005, 0.004999, 1.005, 100.005],
            endpoint_patterns=[r"/exchange", r"/convert", r"/api/.*/exchange"],
            success_indicators=["200", "converted", "rate"],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
    ],
    critical_operations=["transfer", "withdraw", "exchange", "deposit", "payment"],
    race_condition_targets=[
        "transfer", "withdraw", "deposit", "exchange", "pay",
    ],
)


# =============================================================================
# Marketplace Archetype
# =============================================================================

MARKETPLACE_ARCHETYPE = BusinessArchetype(
    domain=BusinessDomain.MARKETPLACE,
    name="Marketplace / Multi-Vendor Platform",
    guiding_questions=[
        "Can a seller buy their own listing (money laundering)?",
        "Can I bypass escrow and get direct payment?",
        "Can I set the commission percentage to zero?",
        "Can I submit a review without purchasing?",
        "Can I mark an item as delivered without shipping?",
        "Can a buyer access seller admin functions?",
    ],
    rules=[
        BusinessRule(
            name="buyer_seller_separation",
            description="Cannot buy own listings (self-purchase)",
            rule_type=RuleType.ISOLATION,
            target_fields=["listing_id", "seller_id", "vendor_id", "product_id"],
            target_endpoints=[
                r"/buy", r"/purchase", r"/order",
                r"/api/.*/purchase", r"/api/.*/order",
            ],
            test_values=["own_listing_id"],  # Will be dynamically resolved
            severity="CRITICAL",
            confidence_if_violated=90.0,
        ),
        BusinessRule(
            name="escrow_integrity",
            description="Payment held in escrow until delivery confirmed",
            rule_type=RuleType.STATE_FORWARD_ONLY,
            target_fields=["status", "escrow_status", "release", "payment_status"],
            target_endpoints=[
                r"/escrow", r"/release", r"/api/.*/escrow",
                r"/api/.*/payment/release",
            ],
            test_values=["released", "completed", "paid"],
            severity="CRITICAL",
            confidence_if_violated=90.0,
        ),
        BusinessRule(
            name="commission_immutability",
            description="Commission percentage cannot be client-set",
            rule_type=RuleType.FIELD_IMMUTABILITY,
            target_fields=["commission", "fee", "platform_fee", "service_fee",
                           "commission_rate", "fee_percent"],
            target_endpoints=[
                r"/listing", r"/sell", r"/api/.*/listing",
                r"/api/.*/sell",
            ],
            test_values=[0, 0.0, "0", -1],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
        BusinessRule(
            name="review_authenticity",
            description="Cannot review without valid purchase",
            rule_type=RuleType.AUTHORIZATION,
            target_fields=["review", "rating", "comment", "feedback"],
            target_endpoints=[
                r"/review", r"/feedback", r"/rating",
                r"/api/.*/review",
            ],
            test_values=[{"rating": 5, "comment": "test review"}],
            severity="MEDIUM",
            confidence_if_violated=80.0,
        ),
        BusinessRule(
            name="dispute_authorization",
            description="Only buyer/seller can open dispute",
            rule_type=RuleType.AUTHORIZATION,
            target_fields=["dispute", "claim", "reason"],
            target_endpoints=[
                r"/dispute", r"/claim", r"/api/.*/dispute",
            ],
            test_values=[{"reason": "test dispute"}],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
    ],
    workflows=[
        WorkflowTemplate(
            name="purchase_flow",
            states=["browse", "offer", "escrow", "deliver", "release", "review"],
            transitions={
                "browse": ["offer"],
                "offer": ["escrow"],
                "escrow": ["deliver"],
                "deliver": ["release"],
                "release": ["review"],
            },
            endpoint_patterns={
                "browse": [r"/listing", r"/product", r"/search"],
                "offer": [r"/offer", r"/bid", r"/buy"],
                "escrow": [r"/escrow", r"/pay", r"/checkout"],
                "deliver": [r"/deliver", r"/ship", r"/tracking"],
                "release": [r"/release", r"/confirm-delivery"],
                "review": [r"/review", r"/feedback"],
            },
            skip_tests=[
                ("offer", "release"),      # Skip escrow+delivery
                ("offer", "deliver"),      # Skip escrow
                ("browse", "escrow"),      # Skip offer
            ],
        ),
        WorkflowTemplate(
            name="listing_flow",
            states=["create", "review", "publish", "deactivate"],
            transitions={
                "create": ["review"],
                "review": ["publish"],
                "publish": ["deactivate"],
            },
            endpoint_patterns={
                "create": [r"/listing/new", r"/sell", r"/create"],
                "review": [r"/review", r"/moderate"],
                "publish": [r"/publish", r"/activate"],
                "deactivate": [r"/deactivate", r"/remove", r"/delete"],
            },
            skip_tests=[
                ("create", "publish"),    # Skip review/moderation
            ],
        ),
    ],
    bypass_patterns=[
        BypassPattern(
            name="self_purchase",
            description="Buy own listing for money laundering",
            method="POST",
            field="listing_id",
            payloads=["own_listing"],
            endpoint_patterns=[r"/buy", r"/purchase", r"/order"],
            success_indicators=["200", "201", "success", "order_id"],
            severity="CRITICAL",
            confidence_if_violated=90.0,
        ),
        BypassPattern(
            name="skip_escrow",
            description="Direct payment bypassing escrow",
            method="POST",
            field="payment_method",
            payloads=["direct", "instant", "no_escrow"],
            endpoint_patterns=[r"/pay", r"/checkout", r"/api/.*/payment"],
            success_indicators=["200", "paid", "success"],
            severity="CRITICAL",
            confidence_if_violated=90.0,
        ),
        BypassPattern(
            name="commission_zero",
            description="Set commission to zero in request",
            method="POST",
            field="commission",
            payloads=[0, "0", 0.0, -1],
            endpoint_patterns=[r"/listing", r"/sell", r"/api/.*/listing"],
            success_indicators=["200", "201", "created", "success"],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
        BypassPattern(
            name="fake_delivery",
            description="Mark as delivered without shipping",
            method="POST",
            field="status",
            payloads=["delivered", "completed", "received"],
            endpoint_patterns=[r"/deliver", r"/ship", r"/tracking", r"/api/.*/order"],
            success_indicators=["200", "updated", "success"],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
        BypassPattern(
            name="review_without_purchase",
            description="Submit review for unpurchased item",
            method="POST",
            field="rating",
            payloads=[5, 1],
            endpoint_patterns=[r"/review", r"/feedback", r"/rating"],
            success_indicators=["200", "201", "success", "created"],
            severity="MEDIUM",
            confidence_if_violated=80.0,
        ),
    ],
    critical_operations=["escrow", "payment", "listing", "dispute", "delivery"],
    race_condition_targets=[
        "escrow", "payment", "offer", "bid", "dispute",
    ],
)


# =============================================================================
# Auth-Centric Archetype
# =============================================================================

AUTH_CENTRIC_ARCHETYPE = BusinessArchetype(
    domain=BusinessDomain.AUTH_CENTRIC,
    name="Auth-Centric / Identity Provider",
    guiding_questions=[
        "Can I skip MFA and access protected resources?",
        "Can I register with admin role/privileges?",
        "Can I access another user's session?",
        "Do tokens actually expire when they should?",
        "Can I skip OAuth consent and grant all scopes?",
        "Can I reuse a password-reset token?",
    ],
    rules=[
        BusinessRule(
            name="session_isolation",
            description="Cannot access other user's sessions",
            rule_type=RuleType.ISOLATION,
            target_fields=["session_id", "user_id", "userId", "uid",
                           "session", "sid"],
            target_endpoints=[
                r"/session", r"/api/.*/session", r"/whoami",
                r"/api/.*/me", r"/profile",
            ],
            test_values=["other_user_id", "1", "admin",
                         "00000000-0000-0000-0000-000000000000"],
            severity="CRITICAL",
            confidence_if_violated=95.0,
        ),
        BusinessRule(
            name="privilege_boundary",
            description="Cannot self-elevate role/permissions",
            rule_type=RuleType.FIELD_IMMUTABILITY,
            target_fields=["role", "permissions", "scope", "admin", "is_admin",
                           "isAdmin", "groups", "claims", "authority"],
            target_endpoints=[
                r"/register", r"/signup", r"/profile", r"/account",
                r"/api/.*/user", r"/api/.*/profile",
            ],
            test_values=["admin", "superadmin", ["admin", "user"],
                         {"admin": True}],
            severity="CRITICAL",
            confidence_if_violated=95.0,
        ),
        BusinessRule(
            name="mfa_enforcement",
            description="MFA cannot be skipped for protected operations",
            rule_type=RuleType.AUTHORIZATION,
            target_fields=["otp", "mfa_code", "2fa_code", "totp",
                           "verification_code"],
            target_endpoints=[
                r"/mfa", r"/2fa", r"/verify", r"/otp",
                r"/api/.*/verify",
            ],
            test_values=["000000", "123456", "", None],
            severity="CRITICAL",
            confidence_if_violated=95.0,
        ),
        BusinessRule(
            name="token_lifetime",
            description="Tokens must expire and cannot be reused after logout",
            rule_type=RuleType.IDEMPOTENCY,
            target_fields=["token", "refresh_token", "access_token"],
            target_endpoints=[
                r"/token", r"/refresh", r"/api/.*/token",
                r"/oauth/token",
            ],
            test_values=["expired_token_placeholder"],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
        BusinessRule(
            name="consent_required",
            description="OAuth scopes need explicit user consent",
            rule_type=RuleType.AUTHORIZATION,
            target_fields=["scope", "scopes", "consent", "approved_scopes"],
            target_endpoints=[
                r"/oauth/authorize", r"/authorize", r"/consent",
                r"/api/.*/authorize",
            ],
            test_values=["admin read write", "openid profile email admin",
                         "all"],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
    ],
    workflows=[
        WorkflowTemplate(
            name="oauth_flow",
            states=["authorize", "consent", "callback", "token_exchange"],
            transitions={
                "authorize": ["consent"],
                "consent": ["callback"],
                "callback": ["token_exchange"],
            },
            endpoint_patterns={
                "authorize": [r"/oauth/authorize", r"/authorize"],
                "consent": [r"/consent", r"/approve", r"/allow"],
                "callback": [r"/callback", r"/redirect", r"/oauth/callback"],
                "token_exchange": [r"/oauth/token", r"/token"],
            },
            skip_tests=[
                ("authorize", "callback"),       # Skip consent
                ("authorize", "token_exchange"),  # Skip consent + callback
            ],
        ),
        WorkflowTemplate(
            name="password_reset_flow",
            states=["request", "email_sent", "verify_token", "new_password"],
            transitions={
                "request": ["email_sent"],
                "email_sent": ["verify_token"],
                "verify_token": ["new_password"],
            },
            endpoint_patterns={
                "request": [r"/forgot-password", r"/reset-password", r"/password/reset"],
                "email_sent": [r"/email", r"/sent"],
                "verify_token": [r"/verify", r"/confirm", r"/token"],
                "new_password": [r"/password/new", r"/change-password", r"/reset"],
            },
            skip_tests=[
                ("request", "new_password"),     # Skip email verification
                ("request", "verify_token"),     # Skip email delivery
            ],
        ),
    ],
    bypass_patterns=[
        BypassPattern(
            name="role_injection",
            description="Set role=admin during registration or profile update",
            method="POST",
            field="role",
            payloads=["admin", "superadmin", "administrator", "root"],
            endpoint_patterns=[r"/register", r"/signup", r"/profile",
                               r"/api/.*/user", r"/api/.*/register"],
            success_indicators=["200", "201", "created", "success"],
            severity="CRITICAL",
            confidence_if_violated=95.0,
        ),
        BypassPattern(
            name="mfa_skip",
            description="Access protected resource without completing MFA",
            method="GET",
            field="",
            payloads=[{}],
            endpoint_patterns=[r"/dashboard", r"/admin", r"/settings",
                               r"/api/.*/protected"],
            success_indicators=["200", "data", "user"],
            severity="CRITICAL",
            confidence_if_violated=95.0,
        ),
        BypassPattern(
            name="consent_bypass",
            description="Skip OAuth consent screen",
            method="POST",
            field="consent",
            payloads=[True, "approved", "allow"],
            endpoint_patterns=[r"/oauth/authorize", r"/authorize", r"/consent"],
            success_indicators=["302", "redirect", "code="],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
        BypassPattern(
            name="token_reuse",
            description="Use expired or revoked tokens",
            method="GET",
            field="",
            payloads=[{}],
            endpoint_patterns=[r"/api/.*", r"/dashboard", r"/profile"],
            success_indicators=["200", "data", "user"],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
        BypassPattern(
            name="registration_role_injection",
            description="Register with admin privileges via body parameter",
            method="POST",
            field="role",
            payloads=["admin", "administrator", {"admin": True}],
            endpoint_patterns=[r"/register", r"/signup", r"/api/.*/register"],
            success_indicators=["200", "201", "created"],
            severity="CRITICAL",
            confidence_if_violated=95.0,
        ),
    ],
    critical_operations=["login", "register", "oauth", "mfa", "password_reset"],
    race_condition_targets=[
        "login", "token_refresh", "email_verify", "password_reset",
    ],
)


# =============================================================================
# Content Archetype (CMS, Blogs, Media)
# =============================================================================

CONTENT_ARCHETYPE = BusinessArchetype(
    domain=BusinessDomain.CONTENT,
    name="Content Management / Media Platform",
    guiding_questions=[
        "Can I publish content without review/moderation?",
        "Can I edit/delete another user's content?",
        "Can I bypass content restrictions (paywall)?",
        "Can I upload unrestricted file types?",
        "Can I access draft/unpublished content?",
    ],
    rules=[
        BusinessRule(
            name="content_ownership",
            description="Cannot edit/delete another user's content",
            rule_type=RuleType.ISOLATION,
            target_fields=["author_id", "user_id", "owner_id", "creator_id"],
            target_endpoints=[
                r"/post", r"/article", r"/content", r"/media",
                r"/api/.*/post", r"/api/.*/content",
            ],
            test_values=["other_user_id", "1", "admin"],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
        BusinessRule(
            name="publish_authorization",
            description="Content requires review before publishing",
            rule_type=RuleType.AUTHORIZATION,
            target_fields=["status", "published", "state", "visibility"],
            target_endpoints=[
                r"/publish", r"/api/.*/publish", r"/api/.*/status",
            ],
            test_values=["published", True, "public", "live"],
            severity="MEDIUM",
            confidence_if_violated=80.0,
        ),
        BusinessRule(
            name="paywall_enforcement",
            description="Premium content requires valid subscription",
            rule_type=RuleType.AUTHORIZATION,
            target_fields=["premium", "paid", "subscription"],
            target_endpoints=[
                r"/article", r"/content", r"/api/.*/content",
                r"/premium",
            ],
            test_values=[True, "premium", "paid"],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
    ],
    workflows=[
        WorkflowTemplate(
            name="content_publish_flow",
            states=["draft", "review", "approved", "published"],
            transitions={
                "draft": ["review"],
                "review": ["approved", "draft"],
                "approved": ["published"],
            },
            endpoint_patterns={
                "draft": [r"/draft", r"/api/.*/draft", r"/content/new"],
                "review": [r"/review", r"/moderate", r"/submit"],
                "approved": [r"/approve", r"/accept"],
                "published": [r"/publish", r"/live"],
            },
            skip_tests=[
                ("draft", "published"),    # Skip review
                ("draft", "approved"),     # Skip review
            ],
        ),
    ],
    bypass_patterns=[
        BypassPattern(
            name="direct_publish",
            description="Publish content skipping review/moderation",
            method="POST",
            field="status",
            payloads=["published", "live", "public"],
            endpoint_patterns=[r"/content", r"/post", r"/article", r"/api/.*/content"],
            success_indicators=["200", "201", "published", "success"],
            severity="MEDIUM",
            confidence_if_violated=80.0,
        ),
        BypassPattern(
            name="access_draft_content",
            description="Access unpublished/draft content",
            method="GET",
            field="status",
            payloads=["draft", "pending", "hidden"],
            endpoint_patterns=[r"/content", r"/post", r"/article", r"/api/.*/content"],
            success_indicators=["200", "data", "content", "body"],
            severity="MEDIUM",
            confidence_if_violated=80.0,
        ),
    ],
    critical_operations=["publish", "delete", "moderate", "upload"],
    race_condition_targets=["publish", "upload", "like", "vote", "comment"],
)


# =============================================================================
# API Service Archetype (Pure API Backends)
# =============================================================================

API_SERVICE_ARCHETYPE = BusinessArchetype(
    domain=BusinessDomain.API_SERVICE,
    name="API Service / Backend",
    guiding_questions=[
        "Can I exceed my API rate limit?",
        "Can I access endpoints outside my API key scope?",
        "Can I escalate my API key's permissions?",
        "Are API keys properly validated on every endpoint?",
        "Can I access other users' data through the API?",
    ],
    rules=[
        BusinessRule(
            name="api_key_scope",
            description="API key cannot access endpoints outside its scope",
            rule_type=RuleType.AUTHORIZATION,
            target_fields=["api_key", "x-api-key", "apikey", "key", "token"],
            target_endpoints=[r"/api/.*"],
            test_values=["invalid_key", "test", ""],
            severity="HIGH",
            confidence_if_violated=85.0,
        ),
        BusinessRule(
            name="rate_limit_enforcement",
            description="API rate limits are enforced per key/user",
            rule_type=RuleType.RATE_LIMITING,
            target_fields=[],
            target_endpoints=[r"/api/.*"],
            test_values=[],
            severity="MEDIUM",
            confidence_if_violated=80.0,
        ),
        BusinessRule(
            name="data_isolation",
            description="Cannot access other users' data through API",
            rule_type=RuleType.ISOLATION,
            target_fields=["user_id", "account_id", "org_id", "id"],
            target_endpoints=[r"/api/.*"],
            test_values=["other_user", "1", "999", "admin"],
            severity="CRITICAL",
            confidence_if_violated=90.0,
        ),
    ],
    workflows=[],  # API services typically don't have multi-step workflows
    bypass_patterns=[
        BypassPattern(
            name="rate_limit_bypass",
            description="Bypass rate limiting via header manipulation",
            method="GET",
            field="",
            payloads=[{}],
            endpoint_patterns=[r"/api/.*"],
            success_indicators=["200", "data"],
            severity="MEDIUM",
            confidence_if_violated=80.0,
        ),
        BypassPattern(
            name="api_key_escalation",
            description="Escalate API key permissions",
            method="PUT",
            field="permissions",
            payloads=[["read", "write", "admin"], "all", {"admin": True}],
            endpoint_patterns=[r"/api/.*/key", r"/api/.*/settings"],
            success_indicators=["200", "updated", "success"],
            severity="CRITICAL",
            confidence_if_violated=90.0,
        ),
    ],
    critical_operations=["api_key", "permissions", "data_access"],
    race_condition_targets=["api_key", "quota", "usage"],
)


# =============================================================================
# Registry
# =============================================================================

_ARCHETYPE_REGISTRY: dict[BusinessDomain, BusinessArchetype] = {
    BusinessDomain.ECOMMERCE: ECOMMERCE_ARCHETYPE,
    BusinessDomain.SAAS: SAAS_ARCHETYPE,
    BusinessDomain.FINTECH: FINTECH_ARCHETYPE,
    BusinessDomain.MARKETPLACE: MARKETPLACE_ARCHETYPE,
    BusinessDomain.AUTH_CENTRIC: AUTH_CENTRIC_ARCHETYPE,
    BusinessDomain.CONTENT: CONTENT_ARCHETYPE,
    BusinessDomain.API_SERVICE: API_SERVICE_ARCHETYPE,
}


def get_archetype(domain: BusinessDomain) -> BusinessArchetype | None:
    """Get the archetype for a given domain. Returns None for UNKNOWN."""
    return _ARCHETYPE_REGISTRY.get(domain)


def get_all_archetypes() -> dict[BusinessDomain, BusinessArchetype]:
    """Get all registered archetypes."""
    return dict(_ARCHETYPE_REGISTRY)


def match_endpoint_pattern(endpoint: str, patterns: list[str]) -> bool:
    """Check if an endpoint matches any of the given regex patterns."""
    path = urlparse_path(endpoint)
    for pattern in patterns:
        if re.search(pattern, path, re.IGNORECASE):
            return True
    return False


def urlparse_path(url: str) -> str:
    """Extract path from URL, handling both full URLs and paths."""
    from urllib.parse import urlparse
    if url.startswith("http"):
        return urlparse(url).path
    return url
