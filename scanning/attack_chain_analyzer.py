"""
PHANTOM AI - Attack Chain Analyzer

Focuses on realistic attack chain analysis where individually moderate issues
combine into critical outcomes. Chained exploitation is the most common path
to real incidents.

Philosophy: "The sum is greater than the parts"
A MEDIUM XSS + MEDIUM CORS + LOW missing header → CRITICAL Account Takeover

Key Capabilities:
1. Chain Discovery — Identifies which findings can chain together
2. Severity Elevation — Calculates combined severity based on chain impact
3. Attack Narrative — Generates human-readable attack stories
4. Probability Scoring — How realistic is this chain in practice?
5. Prerequisite Mapping — What conditions must be met?
6. Business Impact — What's the real-world outcome?

Example Chains:
- Info Disclosure → SQLi crafting → Data Exfil (LOW+HIGH → CRITICAL)
- XSS → Token Theft → Account Takeover (MEDIUM → CRITICAL)
- CORS + Missing Auth → Cross-Origin Data Theft (LOW+LOW → HIGH)
- IDOR + Weak Session → Mass User Enumeration (MEDIUM+MEDIUM → CRITICAL)
- Business Logic + Session Abuse → Financial Fraud (HIGH+HIGH → CRITICAL)
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any
from urllib.parse import urlparse

from utils.logger import get_logger

logger = get_logger(__name__)

# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API — Exported symbols
# ═══════════════════════════════════════════════════════════════════════════════
__all__ = [
    "AttackChainAnalyzer",
    "AttackChain",
    "ChainStep",
    "ChainPattern",
    "ChainCategory",
    "ChainConfidence",
    "CHAIN_PATTERNS",
    # L1: Exported constants
    "CONFIDENCE_PROVEN",
    "CONFIDENCE_HIGH",
    "CONFIDENCE_MEDIUM",
    "INFRA_PROBABILITY_MIN",
    "INFRA_PROBABILITY_MAX",
    # M7: Data-driven dynamic chains
    "DynamicChainSpec",
    "DYNAMIC_CHAIN_SPECS",
]

# Import incident learning for real-world probability adjustment
try:
    from scanning.incident_learning import (
        get_incident_engine,
        ChainType,
        KNOWN_CHAIN_PATTERNS,
    )
    INCIDENT_LEARNING_AVAILABLE = True
except ImportError:
    INCIDENT_LEARNING_AVAILABLE = False
    logger.warning(
        "[CHAIN_ANALYZER] Incident learning not available — "
        "chain probability scoring will use defaults"
    )


class ChainCategory(Enum):
    """Categories of attack chains."""
    DATA_EXFILTRATION = auto()      # Chain leads to data theft
    ACCOUNT_TAKEOVER = auto()       # Chain leads to ATO
    PRIVILEGE_ESCALATION = auto()   # Chain leads to admin access
    FINANCIAL_FRAUD = auto()        # Chain leads to monetary loss
    CODE_EXECUTION = auto()         # Chain leads to RCE
    LATERAL_MOVEMENT = auto()       # Chain enables further attacks
    DENIAL_OF_SERVICE = auto()      # Chain leads to availability impact
    COMPLIANCE_VIOLATION = auto()   # Chain exposes regulated data


class ChainConfidence(Enum):
    """How confident are we this chain is exploitable?"""
    PROVEN = "proven"           # Actually executed the full chain
    HIGH = "high"               # All steps verified independently
    TECHNICAL = "technical"     # Infrastructure-grade: technically realistic, attacker-knows-this
    MEDIUM = "medium"           # Some steps verified, others inferred
    THEORETICAL = "theoretical" # Logically possible but not verified


# ═══════════════════════════════════════════════════════════════════════════════
# L1 FIX 2026-02-12: Magic number constants
# ═══════════════════════════════════════════════════════════════════════════════

# Confidence thresholds (percent)
CONFIDENCE_PROVEN = 95.0
CONFIDENCE_HIGH = 85.0
CONFIDENCE_MEDIUM = 70.0
CONFIDENCE_LOW = 50.0

# Infrastructure chain probability caps
INFRA_PROBABILITY_MIN = 65.0
INFRA_PROBABILITY_MAX = 75.0

# Chain consolidation limits
MAX_CHAINS_PER_PATTERN = 3
MAX_TECHNICAL_PER_FINDING = 2

# Severity escalation threshold
MIN_CONFIDENCE_FOR_ESCALATION = 50.0


# ═══════════════════════════════════════════════════════════════════════════════
# M7 FIX 2026-02-12: Data-driven dynamic chain discovery
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class DynamicChainSpec:
    """
    Specification for dynamic chain discovery.

    Instead of repetitive loops, define chain patterns declaratively.
    The analyzer will find matching findings and create chains automatically.
    """
    name: str
    type_a_keys: list[str]  # Keys to look up in _by_type for first finding
    type_b_keys: list[str]  # Keys to look up in _by_type for second finding
    category: str  # ChainCategory name (resolved at runtime)
    severity: str
    probability: float
    impact: str


# Data-driven specs replacing repetitive loops in _discover_dynamic_chains
DYNAMIC_CHAIN_SPECS: list[DynamicChainSpec] = [
    # XSS + Session → ATO
    DynamicChainSpec(
        name="XSS + Session Weakness → Full ATO",
        type_a_keys=["xss", "dom_xss"],
        type_b_keys=["session_abuse", "session"],
        category="ACCOUNT_TAKEOVER",
        severity="CRITICAL",
        probability=88,
        impact="Complete account takeover via combined XSS and session flaws",
    ),
    # SQLi + IDOR → Mass Data Breach
    DynamicChainSpec(
        name="SQLi + IDOR → Mass User Data Breach",
        type_a_keys=["sql_injection", "sqli", "nosql_injection"],
        type_b_keys=["idor", "authorization"],
        category="DATA_EXFILTRATION",
        severity="CRITICAL",
        probability=90,
        impact="SQLi extracts user IDs, IDOR enumerates all users' data",
    ),
    # XXE + SSRF → Internal Network
    DynamicChainSpec(
        name="XXE + SSRF → Internal Network Pivot",
        type_a_keys=["xxe"],
        type_b_keys=["ssrf"],
        category="LATERAL_MOVEMENT",
        severity="CRITICAL",
        probability=85,
        impact="XXE reads configs, SSRF accesses internal services",
    ),
    # LFI + Credential → Full Compromise
    DynamicChainSpec(
        name="LFI + Credential Exposure → Full Compromise",
        type_a_keys=["lfi", "path_traversal"],
        type_b_keys=["credential_exposure", "info_disclosure"],
        category="CODE_EXECUTION",
        severity="CRITICAL",
        probability=88,
        impact="LFI extracts creds, attacker gains system access",
    ),
    # Auth Bypass + HIGH → Unauth Exploitation
    DynamicChainSpec(
        name="Auth Bypass + HIGH Finding → Unauthenticated Exploitation",
        type_a_keys=["auth_bypass", "authentication_bypass"],
        type_b_keys=["__HIGH_SEVERITY__"],  # Special: filter by severity
        category="PRIVILEGE_ESCALATION",
        severity="CRITICAL",
        probability=92,
        impact="Auth bypass enables unauthenticated access to critical vuln",
    ),
    # Price + Bypass → Complete Fraud
    DynamicChainSpec(
        name="Price Manipulation + Workflow Bypass → Complete Fraud",
        type_a_keys=["price_manipulation", "negative_quantity", "zero_price"],
        type_b_keys=["workflow_bypass", "checkout_bypass", "verification_bypass"],
        category="FINANCIAL_FRAUD",
        severity="CRITICAL",
        probability=95,
        impact="Set arbitrary prices + skip verification = free goods",
    ),
    # Race + Coupon → Mass Discount
    DynamicChainSpec(
        name="Race Condition + Coupon Abuse → Mass Discount Fraud",
        type_a_keys=["race_condition"],
        type_b_keys=["coupon_reuse", "coupon_abuse"],
        category="FINANCIAL_FRAUD",
        severity="CRITICAL",
        probability=90,
        impact="Exploit timing window to apply coupons multiple times",
    ),
    # Rate Limit + Business Logic → Automated Fraud
    DynamicChainSpec(
        name="Rate Limit Bypass + Business Logic → Automated Fraud",
        type_a_keys=["rate_limit_bypass", "missing_rate_limit"],
        type_b_keys=["price_manipulation", "negative_quantity", "coupon_reuse", "coupon_abuse"],
        category="FINANCIAL_FRAUD",
        severity="HIGH",
        probability=85,
        impact="No rate limits enables automated exploitation at scale",
    ),
]


# ═══════════════════════════════════════════════════════════════════════════════
# M3 FIX 2026-02-12: Pattern validation dataclass
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class ChainPattern:
    """
    Validated chain pattern definition.

    Required fields are enforced at creation time to prevent runtime KeyError.
    """
    name: str
    entry_types: list[str]
    category: ChainCategory
    severity: str
    probability: float
    pivot_types: list[str] = field(default_factory=list)
    target_outcome: str = ""
    requires_data: list[str] = field(default_factory=list)
    requires_same_target: bool = False
    allow_cross_host: bool = False
    entry_sufficient: bool = False
    narrative: str = ""
    impact: str = ""
    mitigations: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate pattern on creation."""
        if not self.name:
            raise ValueError("ChainPattern requires a name")
        if not self.entry_types:
            raise ValueError(f"ChainPattern '{self.name}' requires entry_types")
        if not isinstance(self.category, ChainCategory):
            raise ValueError(f"ChainPattern '{self.name}' requires valid ChainCategory")
        if self.severity not in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            raise ValueError(f"ChainPattern '{self.name}' has invalid severity: {self.severity}")
        if not 0 <= self.probability <= 100:
            raise ValueError(f"ChainPattern '{self.name}' probability must be 0-100")

    def to_dict(self) -> dict:
        """Convert to dict format for backward compatibility."""
        return {
            "name": self.name,
            "entry_types": self.entry_types,
            "pivot_types": self.pivot_types,
            "target_outcome": self.target_outcome,
            "category": self.category,
            "severity": self.severity,
            "probability": self.probability,
            "requires_data": self.requires_data,
            "requires_same_target": self.requires_same_target,
            "allow_cross_host": self.allow_cross_host,
            "entry_sufficient": self.entry_sufficient,
            "narrative": self.narrative,
            "impact": self.impact,
            "mitigations": self.mitigations,
        }


def _validate_pattern(pattern: dict) -> bool:
    """
    Validate a pattern dict has required fields.

    M3 FIX: Runtime validation for backward-compatible dict patterns.

    Args:
        pattern: Pattern dict to validate

    Returns:
        True if valid, False otherwise (logs warning)
    """
    required = ["name", "entry_types", "category", "severity", "probability"]
    for field in required:
        if field not in pattern:
            logger.warning(f"[CHAIN_ANALYZER] Invalid pattern missing '{field}': {pattern}")
            return False

    if not isinstance(pattern.get("category"), ChainCategory):
        logger.warning(f"[CHAIN_ANALYZER] Pattern '{pattern.get('name')}' has invalid category")
        return False

    prob = pattern.get("probability", 0)
    if not (0 <= prob <= 100):
        logger.warning(f"[CHAIN_ANALYZER] Pattern '{pattern.get('name')}' has invalid probability: {prob}")
        return False

    return True


@dataclass
class ChainStep:
    """A single step in an attack chain."""
    finding: dict                   # The original finding
    role: str                       # "entry", "pivot", "target"
    action: str                     # What attacker does at this step
    data_obtained: str              # What data/access gained
    prerequisite: str = ""          # What's needed to reach this step


@dataclass
class AttackChain:
    """A complete attack chain from entry to impact."""
    name: str                       # "XSS → Token Theft → ATO"
    category: ChainCategory
    steps: list[ChainStep] = field(default_factory=list)
    combined_severity: str = "HIGH"
    chain_confidence: ChainConfidence = ChainConfidence.MEDIUM
    probability_score: float = 0.0  # 0-100
    business_impact: str = ""
    attack_narrative: str = ""
    prerequisites: list[str] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)

    def _best_endpoint(self) -> str:
        """Get the most specific endpoint from chain steps.

        Prefer entry step's own endpoint. Each step's finding carries its own
        matched_at/endpoint/url — use the first non-empty one found across
        the step's finding fields.
        """
        for step in self.steps:
            f = step.finding
            ep = (
                f.get("matched_at")
                or f.get("endpoint")
                or f.get("url")
                or f.get("host")
                or ""
            )
            if ep:
                return ep
        return ""

    def to_finding_dict(self) -> dict:
        """Convert to finding dict for reporting."""
        return {
            "name": f"Attack Chain: {self.name}",
            "severity": self.combined_severity,
            "confidence": self.probability_score,
            "vuln_type": "attack_chain",
            "vulnerability_type": "attack_chain",
            "module_name": "attack_chain_analyzer",
            "description": self.attack_narrative,
            "matched_at": self._best_endpoint(),
            "evidence": [
                f"Chain: {' → '.join(s.action for s in self.steps)}",
                f"Category: {self.category.name}",
                f"Confidence: {self.chain_confidence.value}",
                f"Business Impact: {self.business_impact}",
            ],
            "metadata": {
                "chain_name": self.name,
                "chain_category": self.category.name,
                "chain_steps": [
                    {
                        "finding_name": s.finding.get("name", ""),
                        "role": s.role,
                        "action": s.action,
                        "data_obtained": s.data_obtained,
                    }
                    for s in self.steps
                ],
                "combined_severity": self.combined_severity,
                "chain_confidence": self.chain_confidence.value,
                "probability_score": self.probability_score,
                "business_impact": self.business_impact,
                "prerequisites": self.prerequisites,
                "mitigations": self.mitigations,
                "is_chain": True,
                "is_cross_module": len({s.finding.get("module_name") for s in self.steps}) > 1,
                "linked_findings": [s.finding.get("name", "") for s in self.steps],
            },
        }


# ═══════════════════════════════════════════════════════════════════════════════
# CHAIN PATTERNS — Realistic attack chains from real-world incidents
# ═══════════════════════════════════════════════════════════════════════════════

# Each pattern defines:
# - entry_types: Finding types that can start this chain
# - pivot_types: Finding types that enable the next step
# - target_types: Finding types that represent the final impact
# - severity_elevation: How severity should be elevated
# - category: What kind of impact this chain has

CHAIN_PATTERNS = [
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # DATA EXFILTRATION CHAINS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "SQLi → Credential Extraction → Admin Access",
        "entry_types": ["sql_injection", "sqli", "nosql_injection"],
        "pivot_types": [],  # Direct chain
        "target_outcome": "admin_credentials",
        "category": ChainCategory.PRIVILEGE_ESCALATION,
        "severity": "CRITICAL",
        "probability": 90,
        "requires_data": ["extracted_data", "credentials"],
        "narrative": (
            "An attacker exploits the SQL injection at {entry_url} to extract "
            "user credentials from the database. Using the extracted admin "
            "credentials, the attacker gains full administrative access to "
            "the application, enabling complete system compromise."
        ),
        "impact": "Full administrative access and potential data breach",
        "mitigations": ["Parameterized queries", "Password hashing", "MFA for admin"],
    },
    {
        "name": "CORS Misconfiguration → Authenticated Data Theft",
        "entry_types": ["cors_arbitrary", "cors_null", "cors_wildcard"],
        "pivot_types": ["xss", "dom_xss"],  # XSS can deliver the CORS attack
        "target_outcome": "data_theft",
        "category": ChainCategory.DATA_EXFILTRATION,
        "severity": "HIGH",
        "probability": 75,
        "requires_same_target": True,
        "narrative": (
            "The CORS misconfiguration at {entry_url} allows any origin to "
            "make authenticated cross-origin requests. An attacker hosts a "
            "malicious page that, when visited by an authenticated user, "
            "silently exfiltrates their data via cross-origin requests."
        ),
        "impact": "Theft of authenticated user data across all users",
        "mitigations": ["Strict Origin validation", "SameSite cookies", "CSRF tokens"],
    },
    {
        "name": "IDOR → Mass User Enumeration → Data Breach",
        "entry_types": ["idor", "authorization", "access_control"],
        "pivot_types": ["business_logic"],
        "target_outcome": "mass_data",
        "category": ChainCategory.DATA_EXFILTRATION,
        "severity": "CRITICAL",
        "probability": 85,
        "requires_data": ["user_id", "enumerable"],
        "narrative": (
            "The IDOR vulnerability at {entry_url} allows accessing other "
            "users' resources by manipulating identifiers. An attacker "
            "enumerates all user IDs (1, 2, 3...) to extract complete "
            "database contents, affecting all platform users."
        ),
        "impact": "Complete user database exfiltration",
        "mitigations": ["Authorization checks", "UUID identifiers", "Rate limiting"],
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # ACCOUNT TAKEOVER CHAINS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "XSS → Session Theft → Account Takeover",
        "entry_types": ["xss", "dom_xss", "csti"],
        "pivot_types": ["session", "session_abuse", "cors"],
        "target_outcome": "ato",
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "severity": "CRITICAL",
        "probability": 85,
        "requires_same_target": True,
        "narrative": (
            "The XSS vulnerability at {entry_url} allows injecting JavaScript "
            "into pages viewed by other users. An attacker crafts a payload "
            "that steals the victim's session token and sends it to an "
            "attacker-controlled server. Using the stolen token, the attacker "
            "fully impersonates the victim."
        ),
        "impact": "Complete account takeover for any targeted user",
        "mitigations": ["HttpOnly cookies", "Content Security Policy", "Input sanitization"],
    },
    {
        "name": "Session Weakness → Token Forge → Admin Takeover",
        "entry_types": ["session_abuse", "session", "jwt"],
        "pivot_types": ["business_logic", "authorization"],
        "target_outcome": "admin_ato",
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "severity": "CRITICAL",
        "probability": 90,
        "requires_data": ["privilege_escalation", "admin"],
        "narrative": (
            "The session vulnerability at {entry_url} allows forging JWT tokens "
            "with elevated privileges. An attacker modifies the 'role' or 'admin' "
            "claim to gain administrative access, enabling full control over "
            "the application and all user accounts."
        ),
        "impact": "Administrative access and ability to compromise all accounts",
        "mitigations": ["Strong JWT signing", "Role verification on server", "Token binding"],
    },
    {
        "name": "CORS + XSS → Persistent Account Takeover",
        "entry_types": ["cors_arbitrary", "cors_null"],
        "pivot_types": ["xss", "dom_xss"],
        "target_outcome": "persistent_ato",
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "severity": "CRITICAL",
        "probability": 80,
        "narrative": (
            "Combining the CORS misconfiguration with XSS creates a powerful "
            "attack chain. The XSS delivers the CORS exploit to victims, which "
            "then makes authenticated requests to steal data or perform actions. "
            "This enables persistent access even after the victim changes passwords."
        ),
        "impact": "Persistent account access for targeted users",
        "mitigations": ["Fix CORS origin validation", "Deploy CSP", "HttpOnly sessions"],
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # FINANCIAL FRAUD CHAINS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "Business Logic → Price Manipulation → Fraud",
        "entry_types": ["business_logic", "price_manipulation", "quantity"],
        "pivot_types": ["session_abuse", "idor"],
        "target_outcome": "financial_fraud",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "CRITICAL",
        "probability": 88,
        "narrative": (
            "The business logic flaw at {entry_url} allows manipulating order "
            "totals, quantities, or prices. An attacker purchases items at "
            "significantly reduced prices (negative quantities, zero prices, "
            "or modified totals), causing direct financial loss to the platform."
        ),
        "impact": "Direct financial loss through fraudulent transactions",
        "mitigations": ["Server-side price validation", "Quantity constraints", "Order review"],
    },
    {
        "name": "IDOR + Business Logic → Cross-User Fraud",
        "entry_types": ["idor", "authorization"],
        "pivot_types": ["business_logic"],
        "target_outcome": "cross_user_fraud",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "CRITICAL",
        "probability": 82,
        "narrative": (
            "Combining IDOR with business logic flaws enables cross-user fraud. "
            "An attacker uses IDOR to access other users' carts or accounts, "
            "then applies discounts, uses stored payment methods, or redirects "
            "orders to attacker-controlled addresses."
        ),
        "impact": "Fraud against other platform users",
        "mitigations": ["Authorization on all resources", "Payment confirmation", "Alerts"],
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # BUSINESS LOGIC COMPOUND CHAINS (multiple business flaws → greater impact)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "Negative Quantity + Coupon Reuse → Unlimited Discounts",
        "entry_types": ["negative_quantity", "negative_value", "quantity_manipulation"],
        "pivot_types": ["coupon_reuse", "coupon_abuse", "discount_abuse"],
        "target_outcome": "unlimited_discounts",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "CRITICAL",
        "probability": 92,
        "narrative": (
            "Combining negative quantity manipulation with coupon reuse creates a "
            "compound fraud vector. An attacker adds items with negative quantities "
            "to generate store credit, then stacks unlimited coupon applications to "
            "multiply discounts. This enables obtaining goods for free or even "
            "generating profit through refund abuse."
        ),
        "impact": "Unlimited discounts leading to significant financial loss",
        "mitigations": [
            "Server-side quantity validation (reject ≤0)",
            "Single-use coupon tokens",
            "Order total floor check (total ≥ 0)",
            "Fraud detection on discount stacking",
        ],
    },
    {
        "name": "Rate Limit Bypass + Coupon → Mass Discount Abuse",
        "entry_types": ["rate_limit_bypass", "missing_rate_limit"],
        "pivot_types": ["coupon_reuse", "coupon_abuse"],
        "target_outcome": "mass_coupon_abuse",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "HIGH",
        "probability": 85,
        "narrative": (
            "Missing rate limits on coupon validation combined with reusable coupons "
            "enables mass discount abuse. An attacker scripts automated coupon "
            "application across thousands of orders or generates unlimited discount "
            "codes, causing widespread revenue loss."
        ),
        "impact": "Automated mass fraud affecting platform revenue",
        "mitigations": [
            "Rate limiting on coupon endpoints",
            "Coupon usage tracking per user/IP",
            "Anomaly detection on discount patterns",
        ],
    },
    {
        "name": "Price Manipulation + Workflow Bypass → Complete Checkout Fraud",
        "entry_types": ["price_manipulation", "zero_price"],
        "pivot_types": ["workflow_bypass", "checkout_bypass", "verification_bypass"],
        "target_outcome": "checkout_fraud",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "CRITICAL",
        "probability": 88,
        "narrative": (
            "Price manipulation combined with workflow bypass enables complete "
            "checkout fraud. An attacker modifies prices to zero or negative values, "
            "then skips payment verification steps, completing orders without actual "
            "payment. This can be automated for mass fraud."
        ),
        "impact": "Free goods acquisition through checkout exploitation",
        "mitigations": [
            "Server-side price enforcement",
            "Mandatory workflow state validation",
            "Payment gateway confirmation before fulfillment",
        ],
    },
    {
        "name": "IDOR Basket + Negative Quantity → Cross-User Credit Theft",
        "entry_types": ["idor", "idor_basket", "authorization"],
        "pivot_types": ["negative_quantity", "quantity_manipulation"],
        "target_outcome": "cross_user_credit_theft",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "CRITICAL",
        "probability": 80,
        "narrative": (
            "IDOR on shopping baskets combined with negative quantity manipulation "
            "enables cross-user credit theft. An attacker accesses other users' "
            "baskets via IDOR, adds items with negative quantities to generate "
            "refund credits on the victim's account, then uses IDOR to transfer "
            "or spend those credits."
        ),
        "impact": "Theft of store credits from other users",
        "mitigations": [
            "Basket ownership validation",
            "Quantity constraints",
            "Credit transfer restrictions",
        ],
    },
    {
        "name": "Inventory Manipulation + Race Condition → Stock Exhaustion Attack",
        "entry_types": ["inventory_manipulation", "stock_manipulation"],
        "pivot_types": ["race_condition", "toctou"],
        "target_outcome": "stock_exhaustion",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "HIGH",
        "probability": 75,
        "narrative": (
            "Inventory manipulation combined with race conditions enables stock "
            "exhaustion attacks. An attacker exploits TOCTOU vulnerabilities to "
            "reserve more items than available, then either completes fraudulent "
            "purchases or holds inventory hostage, preventing legitimate sales."
        ),
        "impact": "Denial of sales through inventory manipulation",
        "mitigations": [
            "Atomic inventory operations",
            "Reservation timeouts",
            "Fraud detection on reservation patterns",
        ],
    },
    {
        "name": "Session Abuse + Business Logic → Account-Level Fraud",
        "entry_types": ["session_abuse", "jwt_manipulation", "token_not_invalidated"],
        "pivot_types": ["business_logic", "price_manipulation", "workflow_bypass"],
        "target_outcome": "account_fraud",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "CRITICAL",
        "probability": 85,
        "narrative": (
            "Session weaknesses combined with business logic flaws enable persistent "
            "account-level fraud. An attacker exploits JWT manipulation or session "
            "persistence to maintain unauthorized access, then leverages business "
            "logic flaws for ongoing fraudulent transactions that appear legitimate."
        ),
        "impact": "Persistent fraud through compromised sessions",
        "mitigations": [
            "Proper JWT validation",
            "Session invalidation on logout",
            "Transaction anomaly detection",
        ],
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # CODE EXECUTION CHAINS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "SSTI → RCE → Full Compromise",
        "entry_types": ["ssti", "template_injection"],
        "pivot_types": [],
        "target_outcome": "rce",
        "category": ChainCategory.CODE_EXECUTION,
        "severity": "CRITICAL",
        "probability": 95,
        "requires_data": ["rce_output", "command_output"],
        "narrative": (
            "The Server-Side Template Injection at {entry_url} allows executing "
            "arbitrary code on the server. An attacker escalates from template "
            "injection to full remote code execution, gaining complete control "
            "of the server and access to all data and connected systems."
        ),
        "impact": "Complete server compromise and potential lateral movement",
        "mitigations": ["Sandbox templates", "Input validation", "WAF rules"],
    },
    {
        "name": "XXE → File Read → Credential Theft → Access",
        "entry_types": ["xxe", "xml_injection"],
        "pivot_types": ["lfi", "path_traversal"],
        "target_outcome": "credential_theft",
        "category": ChainCategory.CODE_EXECUTION,
        "severity": "CRITICAL",
        "probability": 80,
        "requires_data": ["file_content"],
        "narrative": (
            "The XXE vulnerability at {entry_url} enables reading arbitrary "
            "server files. An attacker reads configuration files containing "
            "database credentials, API keys, or SSH keys, then uses these "
            "credentials to access backend systems directly."
        ),
        "impact": "Backend system access via stolen credentials",
        "mitigations": ["Disable external entities", "Secure file permissions", "Secrets vault"],
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # MODERATE + MODERATE = HIGH/CRITICAL CHAINS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "Info Disclosure + Missing Rate Limit → Brute Force",
        "entry_types": ["information_disclosure", "verbose_error", "stack_trace"],
        "pivot_types": ["missing_rate_limit", "weak_auth"],
        "target_outcome": "credential_brute",
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "severity": "HIGH",
        "probability": 70,
        "narrative": (
            "Information disclosure reveals valid usernames or email formats. "
            "Combined with missing rate limiting on login, an attacker can "
            "efficiently brute-force passwords for disclosed accounts, leading "
            "to account compromise."
        ),
        "impact": "Targeted account compromise via informed brute force",
        "mitigations": ["Generic error messages", "Rate limiting", "Account lockout"],
    },
    {
        "name": "Header Weakness + XSS → Clickjacking + Phishing",
        "entry_types": ["headers", "missing_header", "x-frame-options"],
        "pivot_types": ["xss", "open_redirect"],
        "target_outcome": "phishing",
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "severity": "HIGH",
        "probability": 65,
        "narrative": (
            "Missing X-Frame-Options allows embedding the site in iframes. "
            "Combined with XSS or open redirect, an attacker creates a "
            "convincing phishing page that captures credentials while "
            "appearing to be on the legitimate domain."
        ),
        "impact": "Credential theft via convincing phishing attacks",
        "mitigations": ["X-Frame-Options: DENY", "CSP frame-ancestors", "Fix XSS"],
    },
    {
        "name": "Weak Session + CORS → Session Riding",
        "entry_types": ["session", "weak_session", "predictable_session"],
        "pivot_types": ["cors_arbitrary", "cors_null"],
        "target_outcome": "session_riding",
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "severity": "HIGH",
        "probability": 72,
        "narrative": (
            "Weak session management (no regeneration, long validity) combined "
            "with CORS misconfiguration enables session riding attacks. An "
            "attacker can make authenticated requests on behalf of victims "
            "who visit a malicious page."
        ),
        "impact": "Actions performed as victim without their knowledge",
        "mitigations": ["Session regeneration", "Short session lifetime", "CORS restrictions"],
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # ADDITIONAL HIGH-VALUE CHAINS (Added 2026-02-07)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "Cache Poisoning + CORS → Persistent XSS Delivery",
        "entry_types": ["cache_poisoning", "cache_deception", "web_cache"],
        "pivot_types": ["cors_arbitrary", "cors_null", "xss"],
        "target_outcome": "persistent_xss",
        "category": ChainCategory.DATA_EXFILTRATION,
        "severity": "CRITICAL",
        "probability": 78,
        "narrative": (
            "Cache poisoning combined with CORS misconfiguration enables persistent "
            "attack delivery. An attacker poisons the cache with malicious content "
            "that includes cross-origin data exfiltration payloads. All subsequent "
            "users receive the poisoned response, enabling mass credential theft."
        ),
        "impact": "Persistent attack affecting all users via cached malicious content",
        "mitigations": [
            "Cache-Control: private for sensitive responses",
            "Vary header on Host and Origin",
            "Cache key normalization",
        ],
    },
    {
        "name": "Auth Bypass + SQLi → Unauthenticated Data Breach",
        "entry_types": ["auth_bypass", "authentication_bypass", "authorization"],
        "pivot_types": ["sql_injection", "sqli", "nosql_injection"],
        "target_outcome": "unauth_data_breach",
        "category": ChainCategory.DATA_EXFILTRATION,
        "severity": "CRITICAL",
        "probability": 92,
        "narrative": (
            "Authentication bypass combined with SQL injection enables unauthenticated "
            "database access. An attacker bypasses auth controls to reach SQL-injectable "
            "endpoints, then extracts complete database contents without any valid "
            "credentials. This is the most efficient path to mass data breach."
        ),
        "impact": "Complete database extraction without authentication",
        "mitigations": [
            "Defense in depth (auth + input validation)",
            "WAF rules for SQLi",
            "Database activity monitoring",
        ],
    },
    {
        "name": "LFI + Credential File → Backend Access",
        "entry_types": ["lfi", "path_traversal", "directory_traversal"],
        "pivot_types": ["information_disclosure"],
        "target_outcome": "backend_access",
        "category": ChainCategory.CODE_EXECUTION,
        "severity": "CRITICAL",
        "probability": 85,
        "requires_data": ["file_content", "credential"],
        "narrative": (
            "Local File Inclusion enables reading configuration files containing "
            "database credentials, API keys, or cloud secrets. An attacker reads "
            "/etc/passwd, .env, config.php, or application.yml to extract credentials, "
            "then pivots to backend systems or cloud infrastructure."
        ),
        "impact": "Backend system compromise via credential extraction",
        "mitigations": [
            "Strict path validation",
            "Secrets vault instead of file-based config",
            "Least privilege file permissions",
        ],
    },
    {
        "name": "Race Condition + Checkout → Double-Spend Attack",
        "entry_types": ["race_condition", "toctou", "concurrency"],
        "pivot_types": ["business_logic", "checkout_bypass"],
        "target_outcome": "double_spend",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "CRITICAL",
        "probability": 82,
        "narrative": (
            "Race conditions in checkout flow enable double-spend attacks. An attacker "
            "sends concurrent checkout requests with the same payment/wallet balance, "
            "completing multiple orders before the balance is updated. This exploits "
            "TOCTOU vulnerabilities in payment verification."
        ),
        "impact": "Multiple orders completed with single payment",
        "mitigations": [
            "Database locks on balance checks",
            "Idempotency keys",
            "Sequential checkout processing",
        ],
    },
    {
        "name": "IDOR + Session Abuse → Mass Account Takeover",
        "entry_types": ["idor", "authorization"],
        "pivot_types": ["session_abuse", "jwt", "token_not_invalidated"],
        "target_outcome": "mass_ato",
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "severity": "CRITICAL",
        "probability": 88,
        "narrative": (
            "IDOR on user resources combined with session weaknesses enables mass "
            "account takeover. An attacker enumerates user IDs via IDOR, extracts "
            "session tokens or resets passwords for each account, then uses session "
            "persistence flaws to maintain access even after password changes."
        ),
        "impact": "Compromise of all platform user accounts",
        "mitigations": [
            "Authorization on all resources",
            "Session invalidation on password change",
            "UUID instead of sequential IDs",
        ],
    },
    {
        "name": "SSRF + Cloud Metadata → Infrastructure Compromise",
        "entry_types": ["ssrf", "server_side_request_forgery"],
        "pivot_types": ["cloud", "information_disclosure"],
        "target_outcome": "cloud_compromise",
        "category": ChainCategory.CODE_EXECUTION,
        "severity": "CRITICAL",
        "probability": 90,
        "requires_data": ["cloud_metadata", "aws", "gcp", "azure"],
        "narrative": (
            "SSRF targeting cloud metadata endpoints (169.254.169.254) exposes "
            "instance credentials. An attacker retrieves IAM role credentials, "
            "then uses them to access S3 buckets, databases, or other cloud "
            "resources, potentially compromising the entire infrastructure."
        ),
        "impact": "Cloud infrastructure compromise via metadata theft",
        "mitigations": [
            "IMDSv2 enforcement",
            "SSRF allowlist",
            "Network segmentation",
        ],
    },
    {
        "name": "Refresh Token Abuse + Session Fixation → Persistent Access",
        "entry_types": ["session_abuse", "refresh_token", "token_reuse"],
        "pivot_types": ["session_fixation", "session"],
        "target_outcome": "persistent_access",
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "severity": "HIGH",
        "probability": 75,
        "narrative": (
            "Refresh token mishandling combined with session fixation enables "
            "persistent unauthorized access. An attacker captures a refresh token "
            "that doesn't rotate or expire properly, maintaining access indefinitely "
            "even after the victim changes passwords or logs out."
        ),
        "impact": "Permanent account access despite security measures",
        "mitigations": [
            "Refresh token rotation",
            "Absolute token expiration",
            "Token binding to device/IP",
        ],
    },
    {
        "name": "GraphQL Introspection + IDOR → API Data Breach",
        "entry_types": ["graphql", "graphql_introspection", "api_exposure"],
        "pivot_types": ["idor", "authorization"],
        "target_outcome": "api_breach",
        "category": ChainCategory.DATA_EXFILTRATION,
        "severity": "HIGH",
        "probability": 80,
        "narrative": (
            "GraphQL introspection reveals the complete API schema including hidden "
            "queries and mutations. Combined with IDOR vulnerabilities, an attacker "
            "discovers undocumented endpoints that bypass authorization, enabling "
            "extraction of data not intended for their access level."
        ),
        "impact": "API abuse via schema discovery and authorization bypass",
        "mitigations": [
            "Disable introspection in production",
            "Field-level authorization",
            "Query complexity limits",
        ],
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # SAAS DOMAIN CHAINS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "Plan Bypass + Feature Flag Injection → Premium Access",
        "entry_types": ["business_logic", "plan_bypass", "subscription_bypass"],
        "pivot_types": ["authorization", "idor", "feature_flag"],
        "target_outcome": "premium_access",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "CRITICAL",
        "probability": 85,
        "narrative": (
            "SaaS plan enforcement bypass combined with feature flag injection enables "
            "unauthorized premium access. An attacker modifies subscription tier in requests "
            "or injects feature flags, then accesses enterprise features without payment."
        ),
        "impact": "Free access to premium SaaS features, revenue loss",
        "mitigations": [
            "Server-side plan validation",
            "Feature gates on backend, not client",
            "Subscription status caching with validation",
        ],
    },
    {
        "name": "IDOR Tenant + Data Access → Multi-Tenant Data Breach",
        "entry_types": ["idor", "authorization", "tenant_isolation"],
        "pivot_types": ["business_logic", "data_exposure"],
        "target_outcome": "tenant_breach",
        "category": ChainCategory.DATA_EXFILTRATION,
        "severity": "CRITICAL",
        "probability": 90,
        "narrative": (
            "Tenant isolation bypass via IDOR enables accessing other organizations' data. "
            "An attacker swaps tenant_id or org_id parameters to access confidential data "
            "from other companies on the same SaaS platform, affecting all tenants."
        ),
        "impact": "Complete data breach affecting multiple customer organizations",
        "mitigations": [
            "Tenant ID derived from session, not request",
            "Row-level security in database",
            "Multi-tenant access logging",
        ],
    },
    {
        "name": "Seat Limit Bypass + Invite Abuse → Unlimited Team Access",
        "entry_types": ["business_logic", "seat_limit_bypass", "quota_bypass"],
        "pivot_types": ["rate_limit_bypass", "race_condition"],
        "target_outcome": "unlimited_seats",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "HIGH",
        "probability": 80,
        "narrative": (
            "Seat limit bypass combined with invite abuse enables unlimited team members. "
            "An attacker exploits race conditions or quota checks to add users beyond plan "
            "limits, gaining enterprise-level access on a starter plan."
        ),
        "impact": "SaaS usage fraud, revenue loss from plan abuse",
        "mitigations": [
            "Atomic seat count operations",
            "Invite validation against plan limits",
            "Billing reconciliation checks",
        ],
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # FINTECH DOMAIN CHAINS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "2FA Bypass + Transfer → Unauthorized Money Transfer",
        "entry_types": ["mfa_bypass", "2fa_bypass", "otp_bypass", "business_logic"],
        "pivot_types": ["workflow_bypass", "authorization"],
        "target_outcome": "unauthorized_transfer",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "CRITICAL",
        "probability": 95,
        "narrative": (
            "Bypassing 2FA verification on money transfers enables unauthorized fund movement. "
            "An attacker skips or spoofs OTP verification, then initiates transfers from "
            "compromised accounts, causing direct financial theft."
        ),
        "impact": "Direct financial theft from user accounts",
        "mitigations": [
            "Server-side 2FA state validation",
            "Transaction signing",
            "Out-of-band confirmation for large transfers",
        ],
    },
    {
        "name": "Negative Amount + Race Condition → Balance Manipulation",
        "entry_types": ["negative_value", "business_logic", "input_validation"],
        "pivot_types": ["race_condition", "toctou"],
        "target_outcome": "balance_manipulation",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "CRITICAL",
        "probability": 88,
        "narrative": (
            "Negative amount acceptance combined with race conditions enables balance "
            "manipulation. An attacker sends concurrent transfer requests with negative "
            "amounts, reversing debits into credits and creating money from nothing."
        ),
        "impact": "Fraudulent balance inflation, financial system integrity compromise",
        "mitigations": [
            "Strict positive amount validation",
            "Database locks on balance operations",
            "Reconciliation audits",
        ],
    },
    {
        "name": "Daily Limit Bypass + Mass Transfer → Account Drain",
        "entry_types": ["business_logic", "limit_bypass", "rate_limit_bypass"],
        "pivot_types": ["race_condition", "workflow_bypass"],
        "target_outcome": "account_drain",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "CRITICAL",
        "probability": 82,
        "narrative": (
            "Bypassing daily transfer limits enables complete account drainage. An attacker "
            "exploits limit check timing or resets limit counters, then transfers entire "
            "account balance in rapid succession before controls activate."
        ),
        "impact": "Complete account balance theft",
        "mitigations": [
            "Atomic limit checking",
            "Progressive security for large withdrawals",
            "Real-time fraud detection",
        ],
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # AUTH-CENTRIC DOMAIN CHAINS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "OAuth Consent Bypass + Scope Escalation → Full Account Access",
        "entry_types": ["oauth_bypass", "consent_bypass", "business_logic"],
        "pivot_types": ["authorization", "privilege_escalation"],
        "target_outcome": "oauth_takeover",
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "severity": "CRITICAL",
        "probability": 85,
        "narrative": (
            "OAuth consent bypass combined with scope escalation enables unauthorized account "
            "access. An attacker skips the consent screen and requests elevated scopes "
            "(admin, write), gaining full control over victim accounts via OAuth flow."
        ),
        "impact": "Mass account compromise via OAuth abuse",
        "mitigations": [
            "Mandatory consent for sensitive scopes",
            "Scope validation against client registration",
            "Consent audit logging",
        ],
    },
    {
        "name": "MFA Enrollment Bypass + Password Reset → Account Takeover",
        "entry_types": ["mfa_bypass", "2fa_bypass", "business_logic"],
        "pivot_types": ["password_reset", "workflow_bypass"],
        "target_outcome": "mfa_ato",
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "severity": "CRITICAL",
        "probability": 90,
        "narrative": (
            "MFA enrollment bypass combined with password reset enables account takeover. "
            "An attacker resets the password (via email/SMS interception or weak reset flow), "
            "then bypasses MFA enrollment to gain full account access."
        ),
        "impact": "Complete account takeover bypassing all security controls",
        "mitigations": [
            "MFA required for password changes",
            "Re-authentication for security settings",
            "Account recovery with identity verification",
        ],
    },
    {
        "name": "Role Injection + Admin Endpoint → Privilege Escalation",
        "entry_types": ["role_injection", "business_logic", "authorization"],
        "pivot_types": ["idor", "admin_bypass"],
        "target_outcome": "admin_access",
        "category": ChainCategory.PRIVILEGE_ESCALATION,
        "severity": "CRITICAL",
        "probability": 88,
        "narrative": (
            "Role injection at registration/profile combined with admin endpoint access "
            "enables privilege escalation. An attacker injects role=admin in signup request, "
            "then accesses admin functionality affecting all users."
        ),
        "impact": "Unauthorized administrative access",
        "mitigations": [
            "Server-side role assignment only",
            "Role changes require admin approval",
            "Admin action audit logging",
        ],
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # CONTENT/CMS DOMAIN CHAINS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "Moderation Bypass + Mass Publish → Content Spam/Defacement",
        "entry_types": ["workflow_bypass", "moderation_bypass", "business_logic"],
        "pivot_types": ["rate_limit_bypass", "authorization"],
        "target_outcome": "content_spam",
        "category": ChainCategory.DENIAL_OF_SERVICE,
        "severity": "HIGH",
        "probability": 78,
        "narrative": (
            "Bypassing content moderation combined with rate limit bypass enables mass "
            "content publishing. An attacker publishes spam, malware links, or defacement "
            "content at scale without review, damaging platform reputation."
        ),
        "impact": "Platform reputation damage, user exposure to malicious content",
        "mitigations": [
            "Server-side moderation status enforcement",
            "Publishing rate limits",
            "Content scanning integration",
        ],
    },
    {
        "name": "Content IDOR + Edit Privilege → Cross-User Content Manipulation",
        "entry_types": ["idor", "authorization", "content_ownership"],
        "pivot_types": ["business_logic", "privilege_escalation"],
        "target_outcome": "content_manipulation",
        "category": ChainCategory.DATA_EXFILTRATION,
        "severity": "HIGH",
        "probability": 82,
        "narrative": (
            "Content ownership bypass via IDOR enables manipulating other users' content. "
            "An attacker modifies post IDs to edit or delete other users' articles, "
            "potentially injecting malicious content under trusted authors' names."
        ),
        "impact": "Content integrity compromise, trust exploitation",
        "mitigations": [
            "Ownership validation on all content operations",
            "Content version history",
            "Edit audit logging",
        ],
    },
    {
        "name": "Paywall Bypass + Download → Content Theft",
        "entry_types": ["authorization", "paywall_bypass", "business_logic"],
        "pivot_types": ["idor", "direct_access"],
        "target_outcome": "content_theft",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "HIGH",
        "probability": 80,
        "narrative": (
            "Bypassing paywall combined with direct resource access enables content theft. "
            "An attacker discovers direct URLs to premium content or manipulates access "
            "tokens to download paid content without subscription."
        ),
        "impact": "Revenue loss from content theft, IP infringement",
        "mitigations": [
            "Signed URLs with expiration",
            "Token-based content delivery",
            "Access logging and anomaly detection",
        ],
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # MARKETPLACE DOMAIN CHAINS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "Escrow Bypass + Self-Release → Seller Fraud",
        "entry_types": ["workflow_bypass", "escrow_bypass", "business_logic"],
        "pivot_types": ["authorization", "state_manipulation"],
        "target_outcome": "escrow_fraud",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "CRITICAL",
        "probability": 88,
        "narrative": (
            "Escrow workflow bypass enables seller fraud. An attacker (seller) marks "
            "items as delivered without shipping, triggering escrow release. Buyer "
            "loses money without receiving goods."
        ),
        "impact": "Buyer financial loss, platform trust damage",
        "mitigations": [
            "Delivery confirmation from buyer required",
            "Shipping carrier integration",
            "Dispute resolution period",
        ],
    },
    {
        "name": "Commission Bypass + Zero Fee → Platform Revenue Theft",
        "entry_types": ["business_logic", "commission_bypass", "price_manipulation"],
        "pivot_types": ["idor", "authorization"],
        "target_outcome": "commission_theft",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "HIGH",
        "probability": 82,
        "narrative": (
            "Commission bypass enables sellers to avoid platform fees. An attacker sets "
            "commission=0 in listing requests or manipulates fee calculations, completing "
            "transactions without paying platform's cut."
        ),
        "impact": "Platform revenue loss from fee evasion",
        "mitigations": [
            "Server-side commission calculation",
            "Fee immutability in requests",
            "Transaction reconciliation",
        ],
    },
    {
        "name": "Self-Purchase + IDOR Payout → Money Laundering",
        "entry_types": ["business_logic", "self_purchase", "buyer_seller_bypass"],
        "pivot_types": ["idor", "payout_manipulation"],
        "target_outcome": "money_laundering",
        "category": ChainCategory.FINANCIAL_FRAUD,
        "severity": "CRITICAL",
        "probability": 75,
        "narrative": (
            "Self-purchase combined with payout manipulation enables money laundering. "
            "An attacker creates listings and purchases them with stolen payment methods, "
            "then requests payout to their account, converting stolen funds to clean money."
        ),
        "impact": "Money laundering, platform legal liability",
        "mitigations": [
            "Buyer-seller separation enforcement",
            "Payment method velocity checks",
            "KYC for sellers",
        ],
    },
    {
        "name": "Review Fraud + Rating Manipulation → Trust Exploitation",
        "entry_types": ["business_logic", "review_fraud", "authorization"],
        "pivot_types": ["idor", "rate_limit_bypass"],
        "target_outcome": "trust_manipulation",
        "category": ChainCategory.COMPLIANCE_VIOLATION,
        "severity": "MEDIUM",
        "probability": 85,
        "narrative": (
            "Review validation bypass enables fake review injection. An attacker posts "
            "reviews without purchasing, manipulates ratings, or deletes negative reviews, "
            "artificially boosting seller reputation or damaging competitors."
        ),
        "impact": "Marketplace trust integrity, consumer deception",
        "mitigations": [
            "Purchase verification for reviews",
            "Review velocity limits",
            "Fraud detection on review patterns",
        ],
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # INFRASTRUCTURE CHAINS — Technical chains beyond app-level logic
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "SSRF → Internal Service → Database Access",
        "entry_types": ["ssrf", "server_side_request_forgery"],
        "pivot_types": ["information_disclosure", "internal_service"],
        "target_outcome": "internal_db_access",
        "category": ChainCategory.DATA_EXFILTRATION,
        "severity": "CRITICAL",
        "probability": 88,
        "requires_data": ["internal_ip", "database", "redis", "elasticsearch"],
        "narrative": (
            "SSRF enables accessing internal services not exposed to the internet. "
            "An attacker probes internal network (10.x, 172.x, 192.168.x) to discover "
            "unprotected databases (Redis, Elasticsearch, MongoDB) and extracts data "
            "directly without authentication."
        ),
        "impact": "Direct database access bypassing all application security",
        "mitigations": [
            "SSRF allowlist validation",
            "Network segmentation",
            "Internal service authentication",
            "Egress filtering",
        ],
    },
    {
        "name": "Exposed Debug Endpoint → Env Dump → Cloud Credential Theft",
        "entry_types": ["debug_endpoint", "actuator", "phpinfo", "info_disclosure"],
        "pivot_types": ["information_disclosure", "cloud"],
        "target_outcome": "cloud_credential_theft",
        "category": ChainCategory.CODE_EXECUTION,
        "severity": "CRITICAL",
        "probability": 92,
        "requires_data": ["env", "aws", "azure", "gcp", "api_key"],
        "narrative": (
            "Exposed debug endpoints (/actuator/env, /debug, phpinfo) leak environment "
            "variables containing cloud credentials. An attacker extracts AWS_SECRET_KEY, "
            "AZURE_CLIENT_SECRET, or GCP service account keys, then pivots to cloud "
            "infrastructure for complete compromise."
        ),
        "impact": "Cloud infrastructure compromise via credential theft",
        "mitigations": [
            "Disable debug endpoints in production",
            "Secret masking in debug output",
            "Credential rotation",
            "IAM least privilege",
        ],
    },
    {
        "name": "Kubernetes Dashboard → Container Escape → Node Compromise",
        "entry_types": ["kubernetes", "k8s_dashboard", "container_exposure"],
        "pivot_types": ["privilege_escalation", "container_escape"],
        "target_outcome": "k8s_node_compromise",
        "category": ChainCategory.CODE_EXECUTION,
        "severity": "CRITICAL",
        "probability": 85,
        "requires_data": ["kubernetes", "container", "pod", "node"],
        "narrative": (
            "Exposed Kubernetes dashboard or API enables container access. An attacker "
            "deploys a privileged pod or exploits existing container misconfigurations "
            "to escape to the host node, gaining control of the entire cluster."
        ),
        "impact": "Complete Kubernetes cluster compromise",
        "mitigations": [
            "RBAC for dashboard access",
            "Pod Security Standards",
            "Network policies",
            "Runtime security monitoring",
        ],
    },
    {
        "name": "CI/CD Exposure → Pipeline Injection → Supply Chain Attack",
        "entry_types": ["ci_exposure", "jenkins", "github_actions", "gitlab_ci"],
        "pivot_types": ["code_injection", "command_injection"],
        "target_outcome": "supply_chain_attack",
        "category": ChainCategory.CODE_EXECUTION,
        "severity": "CRITICAL",
        "probability": 80,
        "requires_data": ["ci", "pipeline", "build", "artifact"],
        "narrative": (
            "Exposed CI/CD systems (Jenkins, GitLab CI, GitHub Actions) enable pipeline "
            "manipulation. An attacker injects malicious code into build pipelines, "
            "compromising all downstream artifacts and deployments."
        ),
        "impact": "Supply chain compromise affecting all users of built artifacts",
        "mitigations": [
            "CI/CD authentication required",
            "Pipeline approval workflows",
            "Artifact signing",
            "Build environment isolation",
        ],
    },
    {
        "name": "Subdomain Takeover → Phishing → Credential Harvest",
        "entry_types": ["subdomain_takeover", "dangling_dns", "cname_vulnerability"],
        "pivot_types": ["xss", "phishing"],
        "target_outcome": "credential_harvest",
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "severity": "HIGH",
        "probability": 82,
        "narrative": (
            "Subdomain takeover enables hosting malicious content on trusted domain. "
            "An attacker claims an orphaned subdomain (old S3 bucket, Heroku app), "
            "hosts a convincing login page, and harvests credentials from users who "
            "trust the legitimate parent domain."
        ),
        "impact": "Credential theft via trusted domain abuse",
        "mitigations": [
            "DNS record audit",
            "Subdomain monitoring",
            "Decommissioning procedures",
            "CAA records",
        ],
    },
    {
        "name": "Docker Registry Exposure → Image Pull → Credential Extraction",
        "entry_types": ["docker_registry", "container_registry", "information_disclosure"],
        "pivot_types": ["lfi", "credential_exposure"],
        "target_outcome": "registry_credential_theft",
        "category": ChainCategory.DATA_EXFILTRATION,
        "severity": "CRITICAL",
        "probability": 85,
        "requires_data": ["docker", "registry", "image", "layer"],
        "narrative": (
            "Exposed Docker registry without authentication allows image access. "
            "An attacker pulls images containing hardcoded credentials, API keys, "
            "or configuration files, then uses extracted secrets to access "
            "production systems."
        ),
        "impact": "Credential theft from container images",
        "mitigations": [
            "Registry authentication",
            "Image scanning for secrets",
            "Secret management (not in images)",
            "Network access controls",
        ],
    },
    {
        "name": "Git Exposure → Source Code → Hardcoded Secrets",
        "entry_types": ["git_exposure", "source_exposure", ".git", "information_disclosure"],
        "pivot_types": ["credential_exposure"],
        "target_outcome": "source_secret_theft",
        "category": ChainCategory.DATA_EXFILTRATION,
        "severity": "CRITICAL",
        "probability": 90,
        "requires_data": ["git", "source", "code", "secret"],
        "narrative": (
            "Exposed .git directory enables complete source code reconstruction. "
            "An attacker downloads git objects, reconstructs the repository including "
            "history, and extracts API keys, database passwords, or encryption keys "
            "from current or historical commits."
        ),
        "impact": "Source code theft and credential extraction",
        "mitigations": [
            "Block .git access in web server",
            "Pre-commit secret scanning",
            "BFG Repo-Cleaner for history",
            "Credential rotation",
        ],
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # LATERAL MOVEMENT CHAINS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "RCE → Internal Scan → Pivot to Backend",
        "entry_types": ["rce", "command_injection", "ssti"],
        "pivot_types": ["ssrf", "information_disclosure"],
        "target_outcome": "internal_pivot",
        "category": ChainCategory.LATERAL_MOVEMENT,
        "severity": "CRITICAL",
        "probability": 90,
        "requires_data": ["command_output", "internal_ip", "network"],
        "narrative": (
            "Initial RCE enables internal network reconnaissance. An attacker runs "
            "network scans from the compromised server, discovers internal services "
            "(databases, admin panels, message queues), and pivots to higher-value "
            "targets not exposed to the internet."
        ),
        "impact": "Internal network compromise via lateral movement",
        "mitigations": [
            "Network segmentation",
            "Zero trust networking",
            "Internal service authentication",
            "Egress monitoring",
        ],
    },
    {
        "name": "Database Access → Credential Dump → Multi-System Compromise",
        "entry_types": ["sql_injection", "sqli", "database_access"],
        "pivot_types": ["credential_exposure", "privilege_escalation"],
        "target_outcome": "multi_system_compromise",
        "category": ChainCategory.LATERAL_MOVEMENT,
        "severity": "CRITICAL",
        "probability": 85,
        "requires_data": ["credentials", "password", "hash", "admin"],
        "narrative": (
            "Database access enables extracting stored credentials. An attacker "
            "dumps password hashes, cracks them or uses pass-the-hash, then uses "
            "credential reuse to access other internal systems (SSH, RDP, admin panels) "
            "with the same passwords."
        ),
        "impact": "Multi-system compromise via credential reuse",
        "mitigations": [
            "Unique passwords per system",
            "Password hashing (bcrypt, argon2)",
            "Privileged access management",
            "Credential monitoring",
        ],
    },
    {
        "name": "Webhook Injection → Internal Service Call → SSRF Chain",
        "entry_types": ["webhook_injection", "callback_ssrf", "ssrf"],
        "pivot_types": ["information_disclosure", "internal_service"],
        "target_outcome": "webhook_ssrf_chain",
        "category": ChainCategory.LATERAL_MOVEMENT,
        "severity": "HIGH",
        "probability": 78,
        "narrative": (
            "Webhook configuration injection enables blind SSRF. An attacker sets "
            "webhook URLs to internal services, triggering the application to make "
            "authenticated requests to internal APIs on the attacker's behalf."
        ),
        "impact": "Internal service access via webhook abuse",
        "mitigations": [
            "Webhook URL validation",
            "Internal IP blocking",
            "Webhook authentication",
            "Request signing",
        ],
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # PERSISTENCE & BACKDOOR CHAINS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "File Upload → Web Shell → Persistent Access",
        "entry_types": ["file_upload", "unrestricted_upload"],
        "pivot_types": ["rce", "command_injection"],
        "target_outcome": "webshell_persistence",
        "category": ChainCategory.CODE_EXECUTION,
        "severity": "CRITICAL",
        "probability": 92,
        "requires_data": ["upload", "shell", "php", "jsp", "aspx"],
        "narrative": (
            "Unrestricted file upload enables web shell deployment. An attacker uploads "
            "a PHP/JSP/ASPX shell, gains command execution, and maintains persistent "
            "access even after the original vulnerability is patched."
        ),
        "impact": "Persistent backdoor access to server",
        "mitigations": [
            "File type validation (magic bytes)",
            "Upload to non-executable storage",
            "Randomized filenames",
            "Web application firewall",
        ],
    },
    {
        "name": "Admin Access → User Creation → Persistent Backdoor Account",
        "entry_types": ["authorization", "admin_access", "privilege_escalation"],
        "pivot_types": ["business_logic", "idor"],
        "target_outcome": "backdoor_account",
        "category": ChainCategory.CODE_EXECUTION,
        "severity": "CRITICAL",
        "probability": 88,
        "narrative": (
            "Unauthorized admin access enables creating backdoor accounts. An attacker "
            "creates a new admin user or modifies an existing low-profile account, "
            "maintaining access even after the original attack vector is closed."
        ),
        "impact": "Persistent administrative access",
        "mitigations": [
            "Admin action audit logging",
            "User creation alerts",
            "Periodic access reviews",
            "Anomaly detection",
        ],
    },
    {
        "name": "Cron/Scheduled Task Injection → Persistent RCE",
        "entry_types": ["command_injection", "rce", "ssti"],
        "pivot_types": ["privilege_escalation", "persistence"],
        "target_outcome": "cron_persistence",
        "category": ChainCategory.CODE_EXECUTION,
        "severity": "CRITICAL",
        "probability": 80,
        "requires_data": ["cron", "scheduled", "task", "persistence"],
        "narrative": (
            "Command execution enables scheduled task manipulation. An attacker adds "
            "malicious cron jobs or scheduled tasks that execute periodically, "
            "maintaining persistent access and surviving server reboots."
        ),
        "impact": "Persistent code execution via scheduled tasks",
        "mitigations": [
            "Cron/task monitoring",
            "Integrity verification",
            "Least privilege for web user",
            "File integrity monitoring",
        ],
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # REQUEST SMUGGLING & PROTOCOL CHAINS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "HTTP Smuggling → Cache Poisoning → Mass XSS",
        "entry_types": ["http_smuggling", "request_smuggling", "cl_te", "te_cl"],
        "pivot_types": ["cache_poisoning", "xss"],
        "target_outcome": "mass_xss_via_smuggling",
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "severity": "CRITICAL",
        "probability": 78,
        "narrative": (
            "HTTP request smuggling enables cache poisoning attacks. An attacker "
            "smuggles a request that gets cached with malicious content, causing "
            "all subsequent users to receive XSS payloads from the poisoned cache."
        ),
        "impact": "Mass XSS delivery via cache poisoning",
        "mitigations": [
            "Consistent request parsing (proxy/backend)",
            "HTTP/2 end-to-end",
            "Cache key normalization",
            "Request smuggling detection",
        ],
    },
    {
        "name": "HTTP Smuggling → Request Hijacking → Session Theft",
        "entry_types": ["http_smuggling", "request_smuggling"],
        "pivot_types": ["session_abuse", "authorization"],
        "target_outcome": "session_hijack_via_smuggling",
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "severity": "CRITICAL",
        "probability": 75,
        "narrative": (
            "Request smuggling enables hijacking other users' requests. An attacker "
            "prepends a partial request that combines with a victim's subsequent "
            "request, capturing their cookies or redirecting their authenticated "
            "requests to attacker-controlled endpoints."
        ),
        "impact": "Session hijacking of arbitrary users",
        "mitigations": [
            "Normalize Content-Length/Transfer-Encoding",
            "Reject ambiguous requests",
            "HTTP/2 with no downgrade",
            "WAF smuggling detection",
        ],
    },
    {
        "name": "WebSocket Hijacking → Real-time Data Theft",
        "entry_types": ["websocket", "ws_hijacking", "cors"],
        "pivot_types": ["session_abuse", "xss"],
        "target_outcome": "realtime_data_theft",
        "category": ChainCategory.DATA_EXFILTRATION,
        "severity": "HIGH",
        "probability": 72,
        "narrative": (
            "WebSocket origin validation bypass enables cross-origin connection. "
            "An attacker's page connects to the victim's WebSocket endpoint using "
            "their session, receiving real-time data (chat messages, notifications, "
            "financial updates) without the victim's knowledge."
        ),
        "impact": "Real-time data exfiltration via WebSocket",
        "mitigations": [
            "WebSocket origin validation",
            "Token-based WS authentication",
            "SameSite cookies",
            "Rate limiting on connections",
        ],
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # DESERIALIZATION & MEMORY CORRUPTION CHAINS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "Deserialization → RCE → Full Server Compromise",
        "entry_types": ["deserialization", "insecure_deserialization", "java_serial"],
        "pivot_types": ["rce", "command_injection"],
        "target_outcome": "deser_rce",
        "category": ChainCategory.CODE_EXECUTION,
        "severity": "CRITICAL",
        "probability": 95,
        "requires_data": ["gadget", "ysoserial", "pickle", "serialize"],
        "narrative": (
            "Insecure deserialization enables arbitrary code execution. An attacker "
            "crafts a malicious serialized object (Java, PHP, Python pickle) that "
            "executes commands upon deserialization, gaining complete server control."
        ),
        "impact": "Complete server compromise via deserialization",
        "mitigations": [
            "Avoid native serialization",
            "Input validation before deserialize",
            "Restrict allowed classes",
            "Runtime application protection",
        ],
    },
    {
        "name": "Prototype Pollution → XSS/RCE → Client/Server Compromise",
        "entry_types": ["prototype_pollution", "javascript_injection"],
        "pivot_types": ["xss", "rce"],
        "target_outcome": "proto_pollution_chain",
        "category": ChainCategory.CODE_EXECUTION,
        "severity": "HIGH",
        "probability": 75,
        "narrative": (
            "Prototype pollution enables modifying JavaScript object prototypes. "
            "An attacker pollutes Object.prototype with malicious properties that "
            "trigger XSS (client-side) or RCE (server-side Node.js) when accessed "
            "by unsuspecting code."
        ),
        "impact": "Code execution via prototype chain abuse",
        "mitigations": [
            "Object.freeze prototypes",
            "Use Map instead of Object",
            "Input validation on merge/extend",
            "CSP for XSS mitigation",
        ],
    },

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # CRYPTOGRAPHIC CHAINS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    {
        "name": "Weak JWT + IDOR → Mass Token Forgery",
        "entry_types": ["jwt", "weak_jwt", "alg_none", "weak_secret"],
        "pivot_types": ["idor", "authorization"],
        "target_outcome": "mass_token_forgery",
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "severity": "CRITICAL",
        "probability": 90,
        "narrative": (
            "Weak JWT implementation enables token forgery. An attacker cracks the "
            "weak secret or exploits alg:none, then combines with user enumeration "
            "to forge tokens for any user, enabling mass account takeover."
        ),
        "impact": "Mass account compromise via token forgery",
        "mitigations": [
            "Strong JWT secrets (256+ bits)",
            "Explicit algorithm validation",
            "Token binding",
            "Short expiration",
        ],
    },
    {
        "name": "Padding Oracle → Decrypt Session → Session Hijack",
        "entry_types": ["padding_oracle", "crypto_weakness"],
        "pivot_types": ["session_abuse", "authorization"],
        "target_outcome": "oracle_session_hijack",
        "category": ChainCategory.ACCOUNT_TAKEOVER,
        "severity": "CRITICAL",
        "probability": 70,
        "requires_data": ["oracle", "decrypt", "padding"],
        "narrative": (
            "Padding oracle vulnerability enables decrypting encrypted session data. "
            "An attacker uses the oracle to decrypt session tokens byte-by-byte, "
            "then modifies the plaintext (e.g., user_id) and re-encrypts to hijack "
            "other users' sessions."
        ),
        "impact": "Session forgery via cryptographic attack",
        "mitigations": [
            "Authenticated encryption (GCM)",
            "Constant-time comparison",
            "Generic error messages",
            "HMAC before decrypt",
        ],
    },
]


class AttackChainAnalyzer:
    """
    Analyzes findings to discover realistic attack chains.

    Takes individually moderate findings and identifies how they combine
    into critical attack paths based on real-world exploitation patterns.
    """

    # ═══════════════════════════════════════════════════════════════════════
    # BUDGET-03 FIX: Chain iteration limits to prevent state explosion
    # 50 XSS × 50 session = 2,500 combinations is too many
    # ═══════════════════════════════════════════════════════════════════════
    # AUDIT-FIX 2026-02-11: Increased from 10 to 25 - was filtering too many findings
    MAX_FINDINGS_PER_TYPE = 25      # Max findings to consider per type
    MAX_CHAINS_TOTAL = 50           # Max chains to generate
    MAX_COMBINATIONS_PER_PATTERN = 25  # Max combos to try per pattern

    # ═══════════════════════════════════════════════════════════════════════
    # H2 FIX 2026-02-12: Thread-safe singleton lock
    # ═══════════════════════════════════════════════════════════════════════
    _instance_lock = threading.Lock()

    def __init__(
        self,
        intent_profile: Any | None = None,
        max_findings_per_type: int = 25,
        max_chains_total: int = 50,
        max_combinations: int = 25,
    ) -> None:
        # Analysis state (reset per analyze() call)
        self._findings: list[dict] = []
        self._by_type: dict[str, list[dict]] = {}
        self._by_endpoint: dict[str, list[dict]] = {}
        self._chains: list[AttackChain] = []
        self._chain_ids: set[str] = set()  # Dedup
        self._intent_profile = intent_profile  # Optional AttackerProfile for priority boost
        self._chain_count = 0  # BUDGET-03: Track chain count

        # M1 FIX 2026-02-12: Configurable budget limits
        self._max_findings_per_type = max_findings_per_type
        self._max_chains_total = max_chains_total
        self._max_combinations = max_combinations

        # H2 FIX 2026-02-12: Thread-safe operation lock
        self._analyze_lock = threading.Lock()

        # H1 FIX 2026-02-12: Metrics tracking
        self._metrics: dict[str, Any] = self._init_metrics()

    def set_intent_profile(self, profile: Any) -> None:
        """Set intent profile for goal-based chain prioritization."""
        self._intent_profile = profile

    # ═══════════════════════════════════════════════════════════════════════
    # H1 FIX 2026-02-12: Metrics Tracking
    # ═══════════════════════════════════════════════════════════════════════

    def _init_metrics(self) -> dict[str, Any]:
        """Initialize metrics dictionary."""
        return {
            "findings_analyzed": 0,
            "chains_created": 0,
            "chains_suppressed": 0,
            "chains_consolidated": 0,
            "patterns_matched": 0,
            "dynamic_chains": 0,
            "infrastructure_chains": 0,
            "by_category": {},
            "by_confidence": {},
            "errors": 0,
            "errors_by_type": {},
        }

    def get_metrics(self) -> dict[str, Any]:
        """
        Get current metrics.

        Returns:
            Dictionary with analysis metrics including:
            - findings_analyzed: Total findings processed
            - chains_created: Total chains discovered
            - chains_suppressed: Chains filtered by consolidation
            - patterns_matched: Static patterns that matched
            - dynamic_chains: Dynamically discovered chains
            - by_category: Chain counts by ChainCategory
            - by_confidence: Chain counts by ChainConfidence
            - errors: Error count during analysis
        """
        metrics = dict(self._metrics)
        # Add computed values
        if self._chains:
            probs = [c.probability_score for c in self._chains]
            metrics["avg_probability"] = sum(probs) / len(probs)
            metrics["min_probability"] = min(probs)
            metrics["max_probability"] = max(probs)
        else:
            metrics["avg_probability"] = 0.0
            metrics["min_probability"] = 0.0
            metrics["max_probability"] = 0.0
        return metrics

    def reset_metrics(self) -> None:
        """Reset all metrics counters."""
        self._metrics = self._init_metrics()

    def _record_error(self, error_type: str, message: str) -> None:
        """Record an error for metrics tracking (H1 fix)."""
        self._metrics["errors"] += 1
        if error_type not in self._metrics["errors_by_type"]:
            self._metrics["errors_by_type"][error_type] = 0
        self._metrics["errors_by_type"][error_type] += 1
        logger.warning(f"[CHAIN_ANALYZER] Error ({error_type}): {message}")

    def analyze(self, findings: list[dict]) -> list[dict]:
        """
        Analyze findings and return enhanced list with chain findings.

        Thread-safe: Uses lock to prevent concurrent analysis corruption.

        Args:
            findings: List of finding dicts from scanners

        Returns:
            Original findings + new chain findings
        """
        # H2 FIX 2026-02-12: Thread safety via lock
        with self._analyze_lock:
            return self._analyze_internal(findings)

    def _analyze_internal(self, findings: list[dict]) -> list[dict]:
        """Internal analysis implementation (called under lock)."""
        # H2 FIX 2026-02-12: Reset state for thread safety
        self._findings = findings
        self._by_type = {}
        self._by_endpoint = {}
        self._chains = []
        self._chain_ids = set()
        self._chain_count = 0

        # H1 FIX 2026-02-12: Track metrics
        self._metrics["findings_analyzed"] += len(findings)

        self._index_findings()

        logger.info(f"[CHAIN_ANALYZER] Analyzing {len(findings)} findings for attack chains")

        # Phase 1: Pattern matching
        # H4 FIX 2026-02-12: Exception handling per pattern
        for pattern in CHAIN_PATTERNS:
            try:
                self._match_pattern(pattern)
            except Exception as e:
                self._record_error("pattern_match", f"Pattern '{pattern.get('name', 'unknown')}': {e}")

        # Phase 2: Dynamic chain discovery
        try:
            self._discover_dynamic_chains()
        except Exception as e:
            self._record_error("dynamic_discovery", str(e))

        # Phase 3: Calculate chain properties
        # ISSUE-5 FIX 2026-02-11: Intent boost now applied INSIDE _calculate_probability()
        # H4 FIX 2026-02-12: Exception handling per chain
        for chain in self._chains:
            try:
                self._calculate_probability(chain)
                self._generate_narrative(chain)
            except Exception as e:
                self._record_error("chain_calculation", f"Chain '{chain.name}': {e}")

        # H1 FIX 2026-02-12: Track chain counts by category and confidence
        for chain in self._chains:
            cat_name = chain.category.name
            if cat_name not in self._metrics["by_category"]:
                self._metrics["by_category"][cat_name] = 0
            self._metrics["by_category"][cat_name] += 1

            conf_name = chain.chain_confidence.value
            if conf_name not in self._metrics["by_confidence"]:
                self._metrics["by_confidence"][conf_name] = 0
            self._metrics["by_confidence"][conf_name] += 1

            # Track infrastructure chains
            for step in chain.steps:
                metadata = step.finding.get("metadata", {})
                if isinstance(metadata, dict) and metadata.get("infrastructure_chain"):
                    self._metrics["infrastructure_chains"] += 1
                    break

        self._metrics["chains_created"] = len(self._chains)
        logger.info(f"[CHAIN_ANALYZER] Discovered {len(self._chains)} attack chains")

        # ═══════════════════════════════════════════════════════════════════
        # ANTI-SPAM: Consolidate duplicate chains per pattern type
        # Instead of 50 "IDOR + Business Logic" chains, create 1 with list of URLs
        # ═══════════════════════════════════════════════════════════════════
        consolidated_chains = self._consolidate_chains(self._chains)
        chains_suppressed = len(self._chains) - len(consolidated_chains)
        self._metrics["chains_suppressed"] = chains_suppressed
        self._metrics["chains_consolidated"] = len(consolidated_chains)
        logger.info(f"[CHAIN_ANALYZER] Consolidated {len(self._chains)} → {len(consolidated_chains)} chains")

        # Convert chains to findings, filtering low-confidence chains
        # FIX 2026-03-02: Suppress chains below minimum confidence threshold.
        # Chains at exactly 60.0 were passing with >=; use > to exclude boundary.
        _MIN_CHAIN_CONFIDENCE = 60.0
        chain_findings = [
            c.to_finding_dict()
            for c in consolidated_chains
            if c.probability_score > _MIN_CHAIN_CONFIDENCE
        ]
        suppressed_low_conf = len(consolidated_chains) - len(chain_findings)
        if suppressed_low_conf:
            logger.info(f"[CHAIN_ANALYZER] Suppressed {suppressed_low_conf} chains below confidence {_MIN_CHAIN_CONFIDENCE}")

        # Return original + chain findings
        return findings + chain_findings

    def analyze_parallel(self, findings: list[dict], max_workers: int = 4) -> list[dict]:
        """
        Analyze findings with parallel pattern matching.

        PERFORMANCE IMPROVEMENT: Batch processes patterns in parallel using thread pool.

        Args:
            findings: List of finding dicts from scanners
            max_workers: Maximum parallel workers for pattern matching

        Returns:
            Original findings + new chain findings
        """
        import concurrent.futures

        with self._analyze_lock:
            # Reset state
            self._findings = findings
            self._by_type = {}
            self._by_endpoint = {}
            self._chains = []
            self._chain_ids = set()
            self._chain_count = 0

            self._metrics["findings_analyzed"] += len(findings)
            self._index_findings()

            logger.info(f"[CHAIN_ANALYZER] Parallel analyzing {len(findings)} findings "
                        f"(max_workers: {max_workers})")

            # Phase 1: Batch pattern matching in parallel
            patterns_to_match = list(CHAIN_PATTERNS)
            matched_chains_lock = threading.Lock()

            def match_pattern_safe(pattern: dict) -> list:
                """Thread-safe pattern matching."""
                try:
                    local_chains = []
                    # Match pattern (simplified version for parallel execution)
                    required_types = pattern.get("required_types", [])
                    if len(required_types) < 2:
                        return []

                    type1, type2 = required_types[0], required_types[1]
                    findings1 = self._by_type.get(type1, [])[:self._max_findings_per_type]
                    findings2 = self._by_type.get(type2, [])[:self._max_findings_per_type]

                    if not findings1 or not findings2:
                        return []

                    combos = 0
                    for f1 in findings1:
                        for f2 in findings2:
                            if combos >= self._max_combinations:
                                break
                            if f1.get("id") == f2.get("id"):
                                continue

                            chain = self._create_chain_from_pattern(pattern, [f1, f2])
                            if chain:
                                local_chains.append(chain)
                                combos += 1
                        if combos >= self._max_combinations:
                            break

                    return local_chains
                except Exception as e:
                    self._record_error("parallel_pattern_match", str(e))
                    return []

            # Execute pattern matching in thread pool
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_pattern = {
                    executor.submit(match_pattern_safe, p): p
                    for p in patterns_to_match
                }

                for future in concurrent.futures.as_completed(future_to_pattern):
                    try:
                        chains = future.result()
                        with matched_chains_lock:
                            for chain in chains:
                                if chain and self._chain_count < self._max_chains_total:
                                    chain_id = self._generate_chain_id(chain)
                                    if chain_id not in self._chain_ids:
                                        self._chain_ids.add(chain_id)
                                        self._chains.append(chain)
                                        self._chain_count += 1
                                        self._metrics["patterns_matched"] += 1
                    except Exception as e:
                        self._record_error("parallel_future", str(e))

            # Phase 2: Dynamic chain discovery (sequential - modifies state)
            try:
                self._discover_dynamic_chains()
            except Exception as e:
                self._record_error("dynamic_discovery", str(e))

            # Phase 3: Calculate chain properties
            for chain in self._chains:
                try:
                    self._calculate_probability(chain)
                    self._generate_narrative(chain)
                except Exception as e:
                    self._record_error("chain_calculation", f"Chain '{chain.name}': {e}")

            # Track metrics
            for chain in self._chains:
                cat_name = chain.category.name
                if cat_name not in self._metrics["by_category"]:
                    self._metrics["by_category"][cat_name] = 0
                self._metrics["by_category"][cat_name] += 1

                conf_name = chain.chain_confidence.value
                if conf_name not in self._metrics["by_confidence"]:
                    self._metrics["by_confidence"][conf_name] = 0
                self._metrics["by_confidence"][conf_name] += 1

            self._metrics["chains_created"] = len(self._chains)
            logger.info(f"[CHAIN_ANALYZER] Parallel discovered {len(self._chains)} attack chains")

            # Consolidate and convert
            consolidated_chains = self._consolidate_chains(self._chains)
            self._metrics["chains_suppressed"] = len(self._chains) - len(consolidated_chains)
            self._metrics["chains_consolidated"] = len(consolidated_chains)

            _MIN_CHAIN_CONFIDENCE = 60.0
            chain_findings = [
                c.to_finding_dict()
                for c in consolidated_chains
                if c.probability_score > _MIN_CHAIN_CONFIDENCE
            ]
            return findings + chain_findings

    def _create_chain_from_pattern(self, pattern: dict, findings: list[dict]) -> "AttackChain | None":
        """Create chain from pattern and findings (for parallel execution)."""
        try:
            if len(findings) < 2:
                return None

            steps = []
            for i, finding in enumerate(findings):
                step = ChainStep(
                    order=i + 1,
                    finding=finding,
                    action=pattern.get("step_actions", ["Exploit"])[min(i, len(pattern.get("step_actions", ["Exploit"])) - 1)],
                    output=pattern.get("step_outputs", ["Access gained"])[min(i, len(pattern.get("step_outputs", ["Access gained"])) - 1)] if pattern.get("step_outputs") else "Access gained",
                    prerequisites=[],
                )
                steps.append(step)

            chain = AttackChain(
                id=f"chain_{hashlib.md5(str([f.get('id', '') for f in findings]).encode()).hexdigest()[:8]}",
                name=pattern.get("name", "Unknown Chain"),
                steps=steps,
                category=ChainCategory[pattern.get("category", "DATA_BREACH")],
                business_impact=pattern.get("business_impact", "Security breach"),
                combined_severity="HIGH",
                chain_confidence=ChainConfidence.THEORETICAL,
            )
            return chain
        except Exception:
            return None

    def _generate_chain_id(self, chain: "AttackChain") -> str:
        """Generate unique ID for chain deduplication."""
        finding_ids = [s.finding.get("id", "") for s in chain.steps]
        return hashlib.md5(f"{chain.name}:{':'.join(finding_ids)}".encode()).hexdigest()

    def _consolidate_chains(self, chains: list) -> list:
        """
        Consolidate duplicate chains of the same pattern type.

        Instead of creating 50 separate "IDOR + Business Logic" chains,
        create 1 chain with all affected URLs listed.

        Limits:
        - MAX_CHAINS_PER_PATTERN: 3 (representative examples, not spam)
        - MAX_TECHNICAL_PER_FINDING: 2 (2-3 good > 10 mediocre)
        """
        # L1 FIX 2026-02-12: Use module-level constants instead of local defs

        # ═══════════════════════════════════════════════════════════════════
        # PHASE 1: Limit TECHNICAL chains per source finding
        # "2-3 boas > 10 medianas"
        # ═══════════════════════════════════════════════════════════════════
        technical_by_source: dict[str, list] = {}
        non_technical_chains = []

        for chain in chains:
            if chain.chain_confidence == ChainConfidence.TECHNICAL:
                # Key by first step's finding matched_at
                source_key = ""
                if chain.steps:
                    source_key = chain.steps[0].finding.get("matched_at", "unknown")
                if source_key not in technical_by_source:
                    technical_by_source[source_key] = []
                technical_by_source[source_key].append(chain)
            else:
                non_technical_chains.append(chain)

        # Keep only top 2 TECHNICAL chains per source finding
        filtered_technical = []
        for source_key, tech_chains in technical_by_source.items():
            if len(tech_chains) <= MAX_TECHNICAL_PER_FINDING:
                filtered_technical.extend(tech_chains)
            else:
                # Keep best 2 by probability
                sorted_tech = sorted(
                    tech_chains,
                    key=lambda c: c.probability_score,
                    reverse=True
                )
                filtered_technical.extend(sorted_tech[:MAX_TECHNICAL_PER_FINDING])
                suppressed = len(tech_chains) - MAX_TECHNICAL_PER_FINDING
                # THEME-12: Promote to INFO for auditability
                logger.info(
                    f"[AUDIT] Chains suppressed: {suppressed} TECHNICAL chains from {source_key} "
                    f"(kept best {MAX_TECHNICAL_PER_FINDING} by probability)"
                )

        # Combine filtered technical with non-technical
        chains = non_technical_chains + filtered_technical

        # ═══════════════════════════════════════════════════════════════════
        # PHASE 2: Smart pattern consolidation
        # AUDIT-FIX 2026-02-11: Don't merge chains on different resource types
        # "IDOR on /users" and "IDOR on /orders" are DIFFERENT issues to fix
        # ═══════════════════════════════════════════════════════════════════
        by_pattern: dict[str, list] = {}
        for chain in chains:
            # Extract resource type from first step's URL
            resource_type = "unknown"
            if chain.steps:
                url = chain.steps[0].finding.get("matched_at", "")
                # Extract meaningful resource from URL path
                # /api/v1/users/123 → "users"
                # /api/orders/456/items → "orders"
                # M2 FIX 2026-02-12: Removed duplicate `import re` - already at top
                match = re.search(r'/(?:api/)?(?:v\d+/)?([a-zA-Z_]+)(?:/|$|\?)', url)
                if match:
                    resource_type = match.group(1).lower()

            # Key includes pattern name + resource type
            # This keeps "IDOR on users" separate from "IDOR on orders"
            consolidation_key = f"{chain.name}::{resource_type}"
            if consolidation_key not in by_pattern:
                by_pattern[consolidation_key] = []
            by_pattern[consolidation_key].append(chain)

        consolidated = []
        for consolidation_key, pattern_chains in by_pattern.items():
            # Extract original pattern name from key (before ::)
            display_name = consolidation_key.split("::")[0] if "::" in consolidation_key else consolidation_key

            if len(pattern_chains) <= MAX_CHAINS_PER_PATTERN:
                # Few enough to keep all
                consolidated.extend(pattern_chains)
            else:
                # ISSUE-6 FIX 2026-02-11: Keep top 3 by probability, add scope info
                sorted_chains = sorted(
                    pattern_chains,
                    key=lambda c: c.probability_score,
                    reverse=True
                )

                # Keep top 3, add scope info to first one
                kept_chains = sorted_chains[:MAX_CHAINS_PER_PATTERN]
                suppressed_chains = sorted_chains[MAX_CHAINS_PER_PATTERN:]

                # ISSUE-6 FIX: Show total affected count in first chain's narrative
                if suppressed_chains:
                    suppressed_urls = [
                        c.steps[0].finding.get("matched_at", "unknown")
                        for c in suppressed_chains
                        if c.steps
                    ]
                    resource_note = consolidation_key.split("::")[-1] if "::" in consolidation_key else ""
                    kept_chains[0].attack_narrative = (
                        f"{kept_chains[0].attack_narrative}\n\n"
                        f"**Scope:** This pattern affects **{len(pattern_chains)}** endpoints "
                        f"in the '{resource_note}' resource (showing top {MAX_CHAINS_PER_PATTERN} examples). "
                        f"Additional affected URLs: {', '.join(suppressed_urls[:5])}"
                        f"{'...' if len(suppressed_urls) > 5 else ''}"
                    )

                consolidated.extend(kept_chains)
                # THEME-12: Promote to INFO for auditability
                suppressed_count = len(pattern_chains) - MAX_CHAINS_PER_PATTERN
                logger.info(
                    f"[AUDIT] Chains consolidated: {len(pattern_chains)} '{display_name}' on same resource → {MAX_CHAINS_PER_PATTERN} "
                    f"(suppressed {suppressed_count} duplicates)"
                )

        return consolidated

    # LOGIC-V4 FIX 2026-02-11: Removed dead code _apply_intent_boost()
    # Intent boost is now applied INSIDE _calculate_probability() (ISSUE-5 FIX)
    # See lines 2873-2894 for the active implementation

    def _index_findings(self) -> None:
        """Index findings by type and endpoint for efficient lookup."""
        self._by_type = {}
        self._by_endpoint = {}

        for f in self._findings:
            # By type - check "vuln_type", "vulnerability_type", and "type" keys
            # Finding.to_dict() uses "vuln_type", some modules use "vulnerability_type" or "type"
            vuln_type = self._normalize_type(
                f.get("vuln_type") or f.get("vuln_type") or f.get("vulnerability_type") or f.get("type", "")
            )
            if vuln_type not in self._by_type:
                self._by_type[vuln_type] = []
            self._by_type[vuln_type].append(f)

            # Also index by module name as type fallback
            module = f.get("module_name", "")
            if module and module != vuln_type:
                if module not in self._by_type:
                    self._by_type[module] = []
                self._by_type[module].append(f)

            # By endpoint
            endpoint = self._normalize_endpoint(f.get("matched_at", ""))
            if endpoint:
                if endpoint not in self._by_endpoint:
                    self._by_endpoint[endpoint] = []
                self._by_endpoint[endpoint].append(f)

    def _normalize_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type for matching."""
        if not vuln_type:
            return ""
        t = vuln_type.lower().replace("-", "_").replace(" ", "_")

        # Normalize common variants
        if "sql" in t and ("inject" in t or "sqli" in t):
            return "sql_injection"
        if t.startswith("cors"):
            return t  # Keep cors_arbitrary, cors_null, etc.
        if "xss" in t or "cross_site_script" in t:
            return "xss"
        if "idor" in t or "insecure_direct" in t:
            return "idor"
        if "session" in t and "abuse" not in t:
            return "session_abuse"

        # ═══════════════════════════════════════════════════════════════════
        # BUSINESS LOGIC SUBTYPES — Preserve for chain matching
        # These specific subtypes enable compound chain detection:
        # - negative_quantity + coupon_reuse → unlimited discounts
        # - price_manipulation + workflow_bypass → checkout fraud
        # ═══════════════════════════════════════════════════════════════════
        business_subtypes = {
            # Price/Quantity (CRITICAL)
            "negative_quantity", "negative_value", "quantity_manipulation",
            "price_manipulation", "zero_price",
            # Workflow (HIGH)
            "workflow_bypass", "checkout_bypass", "verification_bypass",
            "state_machine_bypass",
            # Coupon (MEDIUM-HIGH)
            "coupon_reuse", "coupon_abuse", "discount_abuse",
            # Race conditions (HIGH)
            "race_condition", "toctou", "double_spend",
            # Inventory (HIGH)
            "inventory_manipulation", "stock_manipulation",
            # Rate limits (MEDIUM)
            "rate_limit_bypass", "missing_rate_limit",
        }

        # Check if this is a specific business logic subtype
        for subtype in business_subtypes:
            if subtype in t:
                return subtype

        # Generic business logic fallback
        if "business" in t:
            return "business_logic"

        return t

    def _normalize_endpoint(self, url: str) -> str:
        """Normalize endpoint for grouping."""
        if not url:
            return ""
        try:
            parsed = urlparse(url)
            # Strip query params and fragments
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        except Exception:
            return url.split("?")[0].split("#")[0]

    # ═══════════════════════════════════════════════════════════════════════════════
    # INFRASTRUCTURE CHAIN ALLOWANCE
    # "Infra findings críticos SEM mitigação ativa → permitem chains técnicas"
    # ═══════════════════════════════════════════════════════════════════════════════

    # Infrastructure finding types that can chain without proof.can_chain
    # These are technically realistic attack paths that any skilled attacker knows
    INFRASTRUCTURE_CHAIN_TYPES = frozenset({
        # Network/Protocol level
        "http_smuggling", "request_smuggling", "http2_smuggling",
        "dns_rebinding", "host_header_injection", "cache_poisoning",
        # Container/Cloud
        "kubernetes", "k8s_dashboard", "container_exposure", "docker_exposure",
        "cloud_metadata", "ssrf_cloud", "imds_exposure",
        # CI/CD & Source
        "git_exposure", "ci_exposure", "cicd_exposure", "pipeline_injection",
        "source_code_exposure", "env_exposure", ".git_exposure",
        # Infrastructure misconfiguration
        "subdomain_takeover", "dns_takeover", "s3_misconfiguration",
        "open_redirect", "open_redirect_chain",
        # Cryptographic
        "padding_oracle", "weak_crypto", "jwt_alg_none", "jwt_weak_secret",
        # Protocol exploitation
        "websocket", "websocket_hijack", "grpc_reflection", "graphql_introspection",
        # Deserialization (infra-level impact)
        "deserialization", "java_deserialization", "pickle_deserialization",
        # File operations
        "file_upload", "unrestricted_upload", "path_traversal_write",
        # Prototype pollution (chain enabler)
        "prototype_pollution", "prototype_pollution_gadget",
    })

    def _is_infrastructure_finding(self, finding: dict) -> bool:
        """
        Check if finding is infrastructure-grade.

        Infrastructure findings can chain even without proof.can_chain because:
        1. They represent well-known attack paths (any skilled attacker knows these)
        2. Their exploitation is technically deterministic (not speculative)
        3. Real-world incidents consistently show these chains work

        Returns True if the finding should be allowed to chain at TECHNICAL confidence.
        """
        vuln_type = self._normalize_type(
            finding.get("vuln_type") or finding.get("vulnerability_type") or finding.get("type", "")
        )
        module_name = finding.get("module_name", "").lower()
        severity = finding.get("severity", "").upper()
        metadata = finding.get("metadata", {})

        # Must be HIGH or CRITICAL severity
        if severity not in ("HIGH", "CRITICAL"):
            return False

        # Check type match
        if vuln_type in self.INFRASTRUCTURE_CHAIN_TYPES:
            return True

        # Check module name for infra scanners
        infra_modules = {
            "smuggling", "kubernetes", "docker", "cloud", "cicd",
            "git", "subdomain", "deserialization", "websocket",
            "grpc", "graphql", "cache", "dns", "file_upload",
        }
        if any(m in module_name for m in infra_modules):
            return True

        # Check metadata for infrastructure indicators
        infra_indicators = [
            "container", "kubernetes", "docker", "pod", "node",
            "cloud_provider", "aws", "gcp", "azure", "metadata_service",
            "smuggling_type", "desync", "pipeline", "cicd",
        ]
        if any(ind in str(metadata).lower() for ind in infra_indicators):
            return True

        return False

    def _has_active_mitigation(self, finding: dict) -> bool:
        """
        Check if finding has active mitigations that would block chain exploitation.

        Mitigations that block chains:
        - WAF detected and blocking
        - Rate limiting active
        - Authentication required (and not bypassed)
        """
        metadata = finding.get("metadata", {})

        # WAF detected and blocking
        # LOGIC-V3 FIX: was using undefined 'data'
        if isinstance(metadata, dict):
            if metadata.get("waf_detected") and metadata.get("waf_blocking"):
                return True
            # Rate limiting active
            if metadata.get("rate_limited"):
                return True

        # Check evidence for mitigation indicators
        evidence = finding.get("evidence", [])
        mitigation_indicators = [
            "blocked by waf", "waf blocked", "rate limit exceeded",
            "too many requests", "access denied", "forbidden",
        ]
        for e in evidence:
            e_lower = str(e).lower()
            if any(ind in e_lower for ind in mitigation_indicators):
                return True

        return False

    def _match_pattern(self, pattern: dict) -> None:
        """Try to match a chain pattern against indexed findings."""
        # M3 FIX 2026-02-12: Validate pattern before use
        if not _validate_pattern(pattern):
            return

        entry_types = pattern["entry_types"]
        pivot_types = pattern.get("pivot_types", [])
        requires_same_target = pattern.get("requires_same_target", False)
        requires_data = pattern.get("requires_data", [])
        # AUDIT 2026-02-07: Cross-host chains are rare; default to requiring same host
        allow_cross_host = pattern.get("allow_cross_host", False)

        # Find entry findings
        entry_findings = []
        for entry_type in entry_types:
            entry_findings.extend(self._by_type.get(entry_type, []))

        # ═══════════════════════════════════════════════════════════════════
        # GAP-2.1: Only create chains for findings with proven chain potential
        # Speculative chains based on unvalidated findings cause FP spam
        # ═══════════════════════════════════════════════════════════════════
        entry_findings = self._filter_chainable_findings(entry_findings)

        if not entry_findings:
            return

        for entry in entry_findings:
            # Check data requirements
            if requires_data:
                metadata = entry.get("metadata", {})
                if not any(self._has_data(metadata, req) for req in requires_data):
                    continue

            # Find pivot findings if required
            pivot_findings = []
            entry_host = self._get_host(entry.get("matched_at", ""))

            if pivot_types:
                for pivot_type in pivot_types:
                    candidates = self._by_type.get(pivot_type, [])

                    # AUDIT 2026-02-07: Filter by same host unless allow_cross_host
                    if not allow_cross_host and entry_host:
                        candidates = [
                            c for c in candidates
                            if self._get_host(c.get("matched_at", "")) == entry_host
                        ]

                    if requires_same_target:
                        entry_endpoint = self._normalize_endpoint(entry.get("matched_at", ""))
                        candidates = [
                            c for c in candidates
                            if self._normalize_endpoint(c.get("matched_at", "")) == entry_endpoint
                        ]
                    pivot_findings.extend(candidates)

                # GAP-2.1: Filter pivot findings too
                pivot_findings = self._filter_chainable_findings(pivot_findings)

            # Build chain
            if pivot_types and not pivot_findings:
                # If pivots required but not found, check if entry alone is sufficient
                if pattern.get("entry_sufficient", False):
                    self._create_chain(pattern, [entry], [])
            else:
                # AUDIT-FIX 2026-02-11: Create chains for multiple pivots, not just first
                # Was [:1] which blocked discovery of alternative attack paths
                for pivot in pivot_findings[:3]:  # Allow up to 3 different chains per entry
                    self._create_chain(pattern, [entry], [pivot])

    def _filter_chainable_findings(self, findings: list[dict]) -> list[dict]:
        """
        Filter findings to only include those with proven chain potential.

        GAP-2.1 Fix: Only create chains for validated findings, not speculative ones.
        GAP-2.4 Fix: Allow infrastructure findings without proof.can_chain.

        A finding is chainable if:
        1. proof.can_chain = True (explicit from proof engine)
        2. confidence >= 75% + concrete evidence (app-level validated)
        3. exploitability.classification = FULL
        4. Chain confidence already set (proven/high/technical)
        5. NEW: Infrastructure finding + CRITICAL + no active mitigation

        Returns:
            List of findings that are eligible for chaining
        """
        chainable = []
        infra_chainable = []  # Track infra findings separately for logging

        for f in findings:
            metadata = f.get("metadata", {})
            # LOGIC-V3 FIX: was using undefined 'data', fixed cascading var
            proof = metadata.get("proof", {}) if isinstance(metadata, dict) else {}
            confidence = f.get("confidence", 0)
            severity = f.get("severity", "").upper()

            # 1. Explicit proof.can_chain (best evidence)
            if isinstance(proof, dict) and proof.get("can_chain"):
                chainable.append(f)
                continue

            # 2. High confidence + high severity = likely validated
            # AUDIT-FIX 2026-02-19: Raised back to 75% from 65%
            # Rationale: 65% × 65% = 42% chain probability - unacceptable for bug bounty
            # Two 75% findings = 56% probability - still risky but defensible
            # Also tightened evidence indicators - "200", "401", "403" are too broad
            if confidence >= 75 and severity in ("HIGH", "CRITICAL"):
                # Verify it has CONCRETE evidence (tightened from previous)
                evidence = f.get("evidence", [])
                has_concrete_evidence = any(
                    any(ind in str(e).lower() for ind in [
                        # Data extraction evidence (specific)
                        "extracted", "data:", "password", "email@",
                        "user_id", "token:", "session_id",
                        # Proof of exploitation (specific)
                        "vulnerable to", "successfully", "confirmed",
                        "payload executed", "command output",
                        # Access control evidence (specific, not just status codes)
                        "admin access", "privilege escalat", "role bypass",
                        "unauthorized access confirmed", "forced browsing successful",
                    ])
                    for e in evidence
                )
                if has_concrete_evidence:
                    chainable.append(f)
                    continue

            # 3. Exploitability classification = FULL
            # LOGIC-V3 FIX: was using undefined 'data', fixed cascading var
            expl = metadata.get("exploitability", {}) if isinstance(metadata, dict) else {}
            if isinstance(expl, dict) and expl.get("classification") == "FULL":
                chainable.append(f)
                continue

            # 4. Chain confidence already set from previous analysis
            # LOGIC-V3 FIX: was using undefined 'data', fixed cascading var
            chain_conf = metadata.get("chain_confidence", "") if isinstance(metadata, dict) else ""
            if chain_conf in ("proven", "high", "technical"):
                chainable.append(f)
                continue

            # ═══════════════════════════════════════════════════════════════════
            # 5. INFRASTRUCTURE CHAIN ALLOWANCE (GAP-2.4)
            # "Infra findings críticos SEM mitigação ativa → permitem chains técnicas"
            # These are well-known attack paths any skilled attacker knows
            # ═══════════════════════════════════════════════════════════════════
            if self._is_infrastructure_finding(f) and not self._has_active_mitigation(f):
                # Mark as technical-grade chainable
                f.setdefault("metadata", {})["chain_confidence"] = "technical"
                f.setdefault("metadata", {})["infrastructure_chain"] = True
                chainable.append(f)
                infra_chainable.append(f)
                logger.debug(
                    f"[CHAIN_ANALYZER] Infrastructure finding chainable: "
                    f"{f.get('name', 'unknown')} (TECHNICAL confidence)"
                )
                continue

            # Skip this finding - not validated enough for chaining
            logger.debug(
                f"[CHAIN_ANALYZER] Skipping unchainable finding: "
                f"{f.get('name', 'unknown')} (confidence={confidence}, severity={severity})"
            )

        # Log summary
        if infra_chainable:
            logger.info(
                f"[CHAIN_ANALYZER] Allowed {len(infra_chainable)} infrastructure "
                f"findings to chain at TECHNICAL confidence"
            )

        # THEME-12: Promote to INFO for auditability
        skipped_count = len(findings) - len(chainable)
        if skipped_count > 0:
            logger.info(
                f"[AUDIT] Findings filtered from chaining: {len(findings)} → {len(chainable)} "
                f"(skipped {skipped_count} as unchainable)"
            )
        return chainable

    def _has_data(self, metadata: dict, data_key: str) -> bool:
        """Check if metadata contains the required data indicator."""
        if data_key in metadata and metadata[data_key]:
            return True

        # Check nested proof data
        # LOGIC-V3 FIX: was using undefined 'data', fixed cascading var
        proof = metadata.get("proof", {}) if isinstance(metadata, dict) else {}
        if isinstance(proof, dict):
            if data_key in proof and proof[data_key]:
                return True
            if data_key == "credentials" and proof.get("can_escalate"):
                return True
            if data_key == "admin" and "admin" in str(proof.get("escalation", "")).lower():
                return True

        # Check exploitability data
        # LOGIC-V3 FIX: was using undefined 'data', fixed cascading var
        expl = metadata.get("exploitability", {}) if isinstance(metadata, dict) else {}
        if isinstance(expl, dict):
            if data_key == "privilege_escalation" and expl.get("has_privilege_escalation"):
                return True

        return False

    def _create_chain(
        self,
        pattern: dict,
        entries: list[dict],
        pivots: list[dict],
    ) -> None:
        """Create an attack chain from pattern match."""
        if not entries:
            return

        entry = entries[0]

        # Generate unique chain ID
        chain_id = hashlib.md5(
            f"{pattern['name']}:{entry.get('matched_at', '')}".encode()
        ).hexdigest()[:12]

        if chain_id in self._chain_ids:
            return

        # BUDGET-03 FIX: Check total chain limit
        if self._chain_count >= self.MAX_CHAINS_TOTAL:
            logger.debug(f"[BUDGET-03] Chain limit reached ({self.MAX_CHAINS_TOTAL})")
            return

        self._chain_ids.add(chain_id)
        self._chain_count += 1  # BUDGET-03: Track chain count

        # Build steps
        steps = []

        # Entry step
        steps.append(ChainStep(
            finding=entry,
            role="entry",
            action=self._get_action_for_type(entry.get("vuln_type") or entry.get("vulnerability_type") or entry.get("type", "")),
            data_obtained=self._get_data_obtained(entry),
        ))

        # Pivot steps
        for pivot in pivots:
            steps.append(ChainStep(
                finding=pivot,
                role="pivot",
                action=self._get_action_for_type(pivot.get("vuln_type") or pivot.get("vulnerability_type") or pivot.get("type", "")),
                data_obtained=self._get_data_obtained(pivot),
                prerequisite=steps[-1].data_obtained,
            ))

        # ═══════════════════════════════════════════════════════════════════
        # GAP-2.3: Determine chain confidence label (speculative vs confirmed)
        # ═══════════════════════════════════════════════════════════════════
        chain_confidence = self._determine_chain_confidence(steps)

        # ═══════════════════════════════════════════════════════════════════
        # FEEDBACK-03 FIX: Chain probability = MIN of component confidences
        # A chain is only as strong as its weakest link
        # Pattern probability is a CEILING, not the final score
        # ═══════════════════════════════════════════════════════════════════
        min_component_confidence = self._get_min_component_confidence(steps)
        # Chain probability is capped at MIN component confidence
        # E.g., if pattern says 90% but one finding is 60%, chain is 60%
        capped_probability = min(pattern["probability"], min_component_confidence)

        chain = AttackChain(
            name=pattern["name"],
            category=pattern["category"],
            steps=steps,
            combined_severity=pattern["severity"],
            chain_confidence=chain_confidence,
            probability_score=capped_probability,
            business_impact=pattern.get("impact", ""),
            mitigations=pattern.get("mitigations", []),
        )

        self._chains.append(chain)

    def _get_min_component_confidence(self, steps: list[ChainStep]) -> float:
        """
        Get minimum confidence from all step findings.

        FEEDBACK-03 FIX: Chain is only as strong as its weakest link.

        Returns:
            Minimum confidence (0-100) from all steps, or 50 if no confidence found
        """
        if not steps:
            return 50.0

        min_conf = 100.0
        for step in steps:
            finding = step.finding
            confidence = finding.get("confidence", 50)

            # Handle string confidence
            if isinstance(confidence, str):
                confidence = {
                    "critical": 95, "high": 85, "medium": 65, "low": 40, "info": 20
                }.get(confidence.lower(), 50)

            min_conf = min(min_conf, float(confidence))

        return min_conf

    def _determine_chain_confidence(self, steps: list[ChainStep]) -> ChainConfidence:
        """
        Determine chain confidence based on step findings' evidence.

        GAP-2.3 Fix: Mark chains as speculative vs confirmed.
        GAP-2.4 Fix: Add TECHNICAL confidence for infrastructure chains.

        Returns:
            ChainConfidence.PROVEN if all steps have proof.can_chain
            ChainConfidence.HIGH if all steps have confidence >= 85%
            ChainConfidence.TECHNICAL if any step is infrastructure-grade
            ChainConfidence.MEDIUM if all steps have confidence >= 70%
            ChainConfidence.THEORETICAL otherwise
        """
        if not steps:
            return ChainConfidence.THEORETICAL

        all_proven = True
        all_high = True
        all_medium = True
        has_infrastructure = False

        for step in steps:
            finding = step.finding
            metadata = finding.get("metadata", {})
            # LOGIC-V3 FIX: was using undefined 'data', fixed cascading var
            proof = metadata.get("proof", {}) if isinstance(metadata, dict) else {}
            confidence = finding.get("confidence", 0)

            # Check if step is proven
            if not (isinstance(proof, dict) and proof.get("can_chain")):
                all_proven = False

            # Check confidence levels
            # L1 FIX 2026-02-12: Use module-level constants
            if confidence < CONFIDENCE_HIGH:
                all_high = False
            # AUDIT-FIX 2026-02-19: Restored to 70% (CONFIDENCE_MEDIUM)
            # Rationale: 60% threshold was too permissive - chains need reliable components
            if confidence < CONFIDENCE_MEDIUM:  # 70%
                all_medium = False

            # Check for infrastructure findings (GAP-2.4)
            # LOGIC-V3 FIX: was using undefined 'data'
            if isinstance(metadata, dict):
                if metadata.get("infrastructure_chain") or metadata.get("chain_confidence") == "technical":
                    has_infrastructure = True

        if all_proven:
            return ChainConfidence.PROVEN
        elif all_high:
            return ChainConfidence.HIGH
        elif has_infrastructure:
            # Infrastructure chains get TECHNICAL confidence
            # "Technically realistic, attacker-knows-this, not yet fully validated"
            return ChainConfidence.TECHNICAL
        elif all_medium:
            return ChainConfidence.MEDIUM
        else:
            return ChainConfidence.THEORETICAL

    def _get_action_for_type(self, vuln_type: str) -> str:
        """Get human-readable action for vulnerability type."""
        actions = {
            "sql_injection": "Extract data via SQL injection",
            "sqli": "Extract data via SQL injection",
            "xss": "Inject malicious JavaScript",
            "dom_xss": "Execute DOM-based XSS",
            "csti": "Inject client-side template code",
            "cors": "Make cross-origin authenticated requests",
            "cors_arbitrary": "Exploit arbitrary origin CORS",
            "cors_null": "Exploit null origin CORS bypass",
            "idor": "Access unauthorized resources",
            "session_abuse": "Forge or hijack sessions",
            "business_logic": "Exploit business logic flaw",
            "ssti": "Execute server-side template injection",
            "xxe": "Read server files via XXE",
            "lfi": "Read local files",
            "authorization": "Bypass authorization controls",
            "headers": "Exploit missing security headers",
        }
        t = self._normalize_type(vuln_type)
        return actions.get(t, f"Exploit {vuln_type}")

    def _get_data_obtained(self, finding: dict) -> str:
        """Determine what data/access was obtained from this finding."""
        metadata = finding.get("metadata", {})

        if isinstance(metadata, dict):
            # SQLi-specific: build detailed description from extracted_data
            extracted = metadata.get("extracted_data")
            if isinstance(extracted, dict):
                parts = []
                if extracted.get("db_version"):
                    parts.append(f"DB version: {extracted['db_version']}")
                if extracted.get("current_db"):
                    parts.append(f"database: {extracted['current_db']}")
                if extracted.get("tables"):
                    table_count = len(extracted["tables"])
                    sample = ", ".join(str(t) for t in extracted["tables"][:3])
                    parts.append(f"{table_count} tables ({sample})")
                if parts:
                    return f"database contents ({'; '.join(parts)})"
                return "database contents"

            if metadata.get("credentials"):
                return "user credentials"

            # Database type from SQLi metadata
            db_type = metadata.get("database_type")

            proof = metadata.get("proof", {})
            if isinstance(proof, dict):
                if proof.get("can_escalate") and "admin" in str(proof.get("escalation", "")).lower():
                    return "administrative access"
                if proof.get("can_escalate"):
                    return "elevated privileges"

            expl = metadata.get("exploitability", {})
            if isinstance(expl, dict):
                if expl.get("has_privilege_escalation"):
                    return "elevated privileges"
                if expl.get("has_extracted_data"):
                    return "extracted data"

            # SQLi with known DB type but no extracted data
            if db_type and db_type != "Unknown":
                vuln_type = self._normalize_type(
                    finding.get("vuln_type") or finding.get("vulnerability_type") or finding.get("type", "")
                )
                if vuln_type == "sql_injection":
                    return f"database query control ({db_type})"

        vuln_type = self._normalize_type(finding.get("vuln_type") or finding.get("vulnerability_type") or finding.get("type", ""))
        data_by_type = {
            "xss": "JavaScript execution in victim browser",
            "cors": "cross-origin request capability",
            "idor": "access to other users' resources",
            "session_abuse": "forged session tokens",
            "sql_injection": "database query control",
            # Business logic subtypes
            "negative_quantity": "ability to manipulate order values",
            "price_manipulation": "ability to set arbitrary prices",
            "coupon_reuse": "ability to reuse discount codes",
            "workflow_bypass": "ability to skip verification steps",
            "race_condition": "ability to exploit timing windows",
        }
        return data_by_type.get(vuln_type, "exploit capability")

    def _discover_dynamic_chains(self) -> None:
        """
        Discover chains based on finding combinations.

        M7 FIX 2026-02-12: Refactored to data-driven approach.
        Uses DYNAMIC_CHAIN_SPECS for standard patterns, with special handlers
        for complex filtering (CORS+sensitive, credential keywords).
        """
        # ═══════════════════════════════════════════════════════════════════
        # DATA-DRIVEN CHAIN DISCOVERY (M7 refactor)
        # ═══════════════════════════════════════════════════════════════════
        for spec in DYNAMIC_CHAIN_SPECS:
            if self._chain_count >= self.MAX_CHAINS_TOTAL:
                break

            # Get findings for type A
            findings_a = self._get_findings_for_spec(spec.type_a_keys)
            if not findings_a:
                continue

            # Get findings for type B (special handling for severity filter)
            if "__HIGH_SEVERITY__" in spec.type_b_keys:
                findings_b = [
                    f for f in self._findings
                    if f.get("severity", "").upper() in ("HIGH", "CRITICAL")
                ]
            else:
                findings_b = self._get_findings_for_spec(spec.type_b_keys)

            if not findings_b:
                continue

            # Resolve category from string name
            try:
                category = ChainCategory[spec.category]
            except KeyError:
                logger.warning(f"[M7] Invalid category '{spec.category}' in spec {spec.name}")
                continue

            # Match findings on same host
            combo_count = 0
            for fa in findings_a[:self.MAX_FINDINGS_PER_TYPE]:
                if self._chain_count >= self.MAX_CHAINS_TOTAL:
                    break
                for fb in findings_b[:self.MAX_FINDINGS_PER_TYPE]:
                    if fa == fb:
                        continue  # Skip self-pairing
                    combo_count += 1
                    if combo_count > self.MAX_COMBINATIONS_PER_PATTERN:
                        break

                    host_a = self._get_host(fa.get("matched_at", ""))
                    host_b = self._get_host(fb.get("matched_at", ""))

                    if host_a and host_a == host_b:
                        self._create_dynamic_chain(
                            name=spec.name,
                            category=category,
                            findings=[fa, fb],
                            severity=spec.severity,
                            probability=spec.probability,
                            impact=spec.impact,
                        )

        # ═══════════════════════════════════════════════════════════════════
        # SPECIAL CASES — Complex filtering not expressible in specs
        # ═══════════════════════════════════════════════════════════════════

        # CORS + Sensitive endpoint (requires custom filtering)
        self._discover_cors_sensitive_chains()

        # LFI + Credential exposure (requires keyword search)
        self._discover_lfi_credential_chains()

        # AUDIT-FIX 2026-02-19: XSS + CORS cross-host chains
        self._discover_xss_cors_cross_host_chains()

        # JWT compound weaknesses (alg:none + missing expiration → indefinite forgery)
        self._discover_jwt_compound_chains()

    def _discover_jwt_compound_chains(self) -> None:
        """JWT alg:none + missing expiration → indefinite token forgery."""
        jwt_findings = self._get_findings_for_spec(["jwt", "jwt_vulnerability"])
        if len(jwt_findings) < 2:
            return

        # Classify JWT findings by weakness type
        alg_weaknesses = []  # alg:none, weak secret, algorithm confusion
        expiry_weaknesses = []  # no expiration, excessive lifetime, bypass

        alg_keywords = {"none", "algorithm", "alg", "secret", "weak_secret", "confusion", "kid", "jku", "jwk", "signature"}
        expiry_keywords = {"expir", "lifetime", "nbf", "claims", "missing"}

        for f in jwt_findings:
            name_lower = (f.get("name", "") or "").lower()
            attack_type = (f.get("metadata", {}).get("attack_type", "") or "").lower()
            combined = f"{name_lower} {attack_type}"

            if any(kw in combined for kw in alg_keywords):
                alg_weaknesses.append(f)
            if any(kw in combined for kw in expiry_keywords):
                expiry_weaknesses.append(f)

        # Chain: algorithm weakness + expiration weakness = indefinite forgery
        for alg_f in alg_weaknesses[:self.MAX_FINDINGS_PER_TYPE]:
            if self._chain_count >= self.MAX_CHAINS_TOTAL:
                break
            alg_host = self._get_host(alg_f.get("matched_at", ""))
            for exp_f in expiry_weaknesses[:self.MAX_FINDINGS_PER_TYPE]:
                if alg_f is exp_f:
                    continue
                exp_host = self._get_host(exp_f.get("matched_at", ""))
                if alg_host and alg_host == exp_host:
                    self._create_dynamic_chain(
                        name="JWT Algorithm Weakness + No Expiration → Indefinite Token Forgery",
                        category=ChainCategory.ACCOUNT_TAKEOVER,
                        findings=[alg_f, exp_f],
                        severity="CRITICAL",
                        probability=90,
                        impact="Attacker forges JWT tokens that never expire, enabling permanent account takeover",
                    )

    def _get_findings_for_spec(self, type_keys: list[str]) -> list[dict]:
        """Get findings matching any of the type keys."""
        results = []
        for key in type_keys:
            results.extend(self._by_type.get(key, []))
        return results[:self.MAX_FINDINGS_PER_TYPE]

    def _discover_cors_sensitive_chains(self) -> None:
        """CORS + Sensitive endpoint chains (special filtering)."""
        cors_findings = [
            f for f in self._findings
            if (f.get("vuln_type") or f.get("vulnerability_type") or f.get("type", "")).startswith("cors")
        ]
        sensitive_endpoints = [
            f for f in self._findings
            if f.get("metadata", {}).get("sensitive_data")
            or f.get("metadata", {}).get("auth_required")
            or "user" in f.get("matched_at", "").lower()
            or "account" in f.get("matched_at", "").lower()
        ]

        for cors in cors_findings[:self.MAX_FINDINGS_PER_TYPE]:
            if self._chain_count >= self.MAX_CHAINS_TOTAL:
                break
            cors_url = cors.get("matched_at", "")
            cors_host = self._get_host(cors_url)
            for sens in sensitive_endpoints[:self.MAX_FINDINGS_PER_TYPE]:
                sens_url = sens.get("matched_at", "")
                sens_host = self._get_host(sens_url)
                # AUDIT-FIX 2026-02-19: Use same-DOMAIN matching (not just same-host)
                # This catches subdomain scenarios where CORS on api.example.com
                # could allow theft of data from www.example.com via wildcard policies.
                #
                # NOTE: Same-domain check IS correct here because:
                # - The CORS finding says "this domain has weak CORS"
                # - The sensitive endpoint says "this domain has sensitive data"
                # - Attack originates from external attacker domain (not in scan scope)
                if cors_host and (cors_host == sens_host or self._same_domain(cors_url, sens_url)):
                    # Same-host = higher probability, same-domain = lower
                    prob = 80 if cors_host == sens_host else 65
                    self._create_dynamic_chain(
                        name="CORS + Sensitive Endpoint → Data Theft",
                        category=ChainCategory.DATA_EXFILTRATION,
                        findings=[cors, sens],
                        severity="HIGH",
                        probability=prob,
                        impact="Cross-origin theft of sensitive user data",
                    )

    def _discover_lfi_credential_chains(self) -> None:
        """LFI + Credential exposure chains (keyword search)."""
        lfi_findings = self._get_findings_for_spec(["lfi", "path_traversal"])
        cred_findings = [
            f for f in self._findings
            if any(kw in str(f).lower() for kw in [
                "credential", "password", "secret", "api_key", "token"
            ])
        ]

        for lfi in lfi_findings[:self.MAX_FINDINGS_PER_TYPE]:
            if self._chain_count >= self.MAX_CHAINS_TOTAL:
                break
            lfi_host = self._get_host(lfi.get("matched_at", ""))
            for cred in cred_findings[:self.MAX_FINDINGS_PER_TYPE]:
                cred_host = self._get_host(cred.get("matched_at", ""))
                if lfi_host and lfi_host == cred_host:
                    self._create_dynamic_chain(
                        name="LFI + Credential Exposure → Full Compromise",
                        category=ChainCategory.CODE_EXECUTION,
                        findings=[lfi, cred],
                        severity="CRITICAL",
                        probability=88,
                        impact="LFI extracts creds, attacker gains system access",
                    )

    def _discover_xss_cors_cross_host_chains(self) -> None:
        """
        XSS + CORS cross-host chains.

        AUDIT-FIX 2026-02-19: This is a TRUE cross-host chain:
        - XSS on Host A allows executing attacker's JavaScript
        - CORS misconfiguration on Host B allows Host A as trusted origin
        - Combined: Attacker uses XSS on A to steal data from B

        This differs from _discover_cors_sensitive_chains which requires same-domain
        because HERE we're chaining two separate vulnerabilities on different hosts.
        """
        xss_findings = self._get_findings_for_spec(["xss", "reflected_xss", "stored_xss", "dom_xss"])
        cors_findings = [
            f for f in self._findings
            if (f.get("vuln_type") or f.get("vulnerability_type") or f.get("type", "")).startswith("cors")
        ]

        for xss in xss_findings[:self.MAX_FINDINGS_PER_TYPE]:
            if self._chain_count >= self.MAX_CHAINS_TOTAL:
                break
            xss_url = xss.get("matched_at", "")
            xss_host = self._get_host(xss_url)
            for cors in cors_findings[:self.MAX_FINDINGS_PER_TYPE]:
                cors_url = cors.get("matched_at", "")
                cors_host = self._get_host(cors_url)
                # Cross-host check: XSS and CORS should be on DIFFERENT hosts
                # (if same host, _discover_cors_sensitive_chains handles it)
                if xss_host and cors_host and xss_host != cors_host:
                    # Check if CORS metadata indicates it allows the XSS origin
                    cors_meta = cors.get("metadata", {})
                    allowed_origins = cors_meta.get("allowed_origins", [])
                    allows_wildcard = cors_meta.get("allows_wildcard", False)
                    allows_null = cors_meta.get("allows_null", False)

                    # Chain is valid if CORS allows XSS origin or has weak config
                    chain_valid = (
                        allows_wildcard or
                        allows_null or
                        xss_host in str(allowed_origins) or
                        self._same_domain(xss_url, cors_url)  # Same domain = might share trust
                    )

                    if chain_valid:
                        self._create_dynamic_chain(
                            name="XSS + CORS → Cross-Host Data Theft",
                            category=ChainCategory.DATA_EXFILTRATION,
                            findings=[xss, cors],
                            severity="CRITICAL",
                            probability=70,
                            impact=f"XSS on {xss_host} exploits CORS on {cors_host} to steal data",
                        )

    def _create_dynamic_chain(
        self,
        name: str,
        category: ChainCategory,
        findings: list[dict],
        severity: str,
        probability: float,
        impact: str,
    ) -> None:
        """Create a dynamically discovered chain."""
        # BUDGET-03 FIX: Check total chain limit
        if self._chain_count >= self.MAX_CHAINS_TOTAL:
            logger.debug(f"[BUDGET-03] Chain limit reached ({self.MAX_CHAINS_TOTAL}), skipping {name}")
            return

        first_match = findings[0].get('matched_at', '') if findings else ''
        chain_id = hashlib.md5(
            f"{name}:{first_match}".encode()
        ).hexdigest()[:12]

        if chain_id in self._chain_ids:
            return
        self._chain_ids.add(chain_id)
        self._chain_count += 1  # BUDGET-03: Track chain count

        steps = []
        for i, f in enumerate(findings):
            steps.append(ChainStep(
                finding=f,
                role="entry" if i == 0 else "pivot",
                action=self._get_action_for_type(f.get("vuln_type") or f.get("vulnerability_type") or f.get("type", "")),
                data_obtained=self._get_data_obtained(f),
            ))

        # AUDIT 2026-02-07: Escalate severity based on combined finding types
        escalated_severity = self._escalate_chain_severity(severity, findings)

        # LOGIC-V3 FIX: Cap probability by minimum component confidence
        # A chain is only as strong as its weakest link
        min_component_confidence = self._get_min_component_confidence(steps)
        capped_probability = min(probability, min_component_confidence)

        chain = AttackChain(
            name=name,
            category=category,
            steps=steps,
            combined_severity=escalated_severity,
            probability_score=capped_probability,
            business_impact=impact,
        )

        self._chains.append(chain)

    def _get_host(self, url: str) -> str:
        """Extract host from URL."""
        try:
            return urlparse(url).netloc
        except Exception:
            return ""

    def _get_domain(self, url: str) -> str:
        """
        Extract registrable domain from URL.

        AUDIT-FIX 2026-02-19: For CORS chains, we need same-domain matching
        (not just same-host) to catch subdomain scenarios like:
        - api.example.com (CORS misconfiguration)
        - www.example.com (sensitive data)

        Returns the last 2-3 parts of the domain (handles .co.uk, etc.)
        """
        try:
            host = urlparse(url).netloc.lower()
            if not host:
                return ""
            # Remove port
            host = host.split(':')[0]
            parts = host.split('.')
            if len(parts) <= 2:
                return host
            # Handle common 2-part TLDs (.co.uk, .com.br, etc.)
            two_part_tlds = ['co.uk', 'com.br', 'com.au', 'co.nz', 'co.jp', 'org.uk']
            if len(parts) >= 3:
                potential_tld = '.'.join(parts[-2:])
                if potential_tld in two_part_tlds:
                    return '.'.join(parts[-3:])
            return '.'.join(parts[-2:])
        except Exception:
            return ""

    def _same_domain(self, url1: str, url2: str) -> bool:
        """Check if two URLs are on the same registrable domain."""
        domain1 = self._get_domain(url1)
        domain2 = self._get_domain(url2)
        return bool(domain1 and domain1 == domain2)

    def _escalate_chain_severity(self, base_severity: str, findings: list[dict]) -> str:
        """
        Escalate chain severity based on combined finding types.

        AUDIT 2026-02-07: Chains that combine HIGH+HIGH or specific type combinations
        should escalate to CRITICAL when the combined impact is greater than parts.

        CHAIN-03 FIX: Chain severity is CAPPED by weakest component confidence.
        Low-confidence findings cannot escalate to CRITICAL.

        Examples:
        - SQLi + Auth Bypass → CRITICAL (RCE potential)
        - XSS + CORS → CRITICAL (full ATO)
        - IDOR + Session Weakness → CRITICAL (mass user access)
        - LFI + Credential Exposure → CRITICAL (code execution via creds)
        """
        # Get all finding types in the chain
        types = set()
        severities = []
        confidences = []
        for f in findings:
            ftype = f.get("type", f.get("vulnerability_type", "")).lower()
            types.add(ftype)
            sev = f.get("severity", "MEDIUM").upper()
            severities.append(sev)
            conf = f.get("confidence", 50.0)
            if isinstance(conf, str):
                conf = {"CRITICAL": 95, "HIGH": 85, "MEDIUM": 65, "LOW": 40}.get(conf.upper(), 50)
            confidences.append(float(conf))

        # ═══════════════════════════════════════════════════════════════════════════
        # CHAIN-03 FIX: Cap severity by minimum component confidence
        # Weak components (< 70% confidence) should NOT escalate chain severity
        # ═══════════════════════════════════════════════════════════════════════════
        min_confidence = min(confidences) if confidences else 50.0
        # Normalize severities to valid values, default invalid ones to MEDIUM
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        valid_severities = [s if s in severity_order else "MEDIUM" for s in severities]
        min_severity = min(valid_severities, key=lambda s: severity_order.index(s)) if valid_severities else "MEDIUM"

        # If any component has low confidence, cap the chain severity
        # AUDIT-FIX 2026-02-11: Lowered from 70% to 50% - was capping too many valid chains
        if min_confidence < 50.0:
            # Chain cannot be higher than the weakest component's severity
            # M4 FIX 2026-02-12: Removed duplicate severity_order definition
            max_allowed_idx = severity_order.index(min_severity)
            # Cap at HIGH maximum for low-confidence chains
            max_allowed_idx = min(max_allowed_idx, severity_order.index("HIGH"))
            logger.debug(f"[CHAIN-03] Low confidence ({min_confidence:.0f}%) caps severity at {severity_order[max_allowed_idx]}")
            base_severity = severity_order[max_allowed_idx]
            # Don't escalate further - return early
            return base_severity

        # Count HIGH+ findings
        critical_count = severities.count("CRITICAL")
        high_count = severities.count("HIGH")

        # ═══════════════════════════════════════════════════════════════════════════
        # GAP-3 FIX 2026-02-13: Confidence gate for CRITICAL escalation
        # Chains should only escalate to CRITICAL if min_confidence >= 75%
        # This prevents exaggerated impact from low-confidence findings
        # ═══════════════════════════════════════════════════════════════════════════

        # ESCALATION RULES
        # Rule 1: Two or more HIGH findings → CRITICAL (only if high confidence)
        if high_count >= 2 or critical_count >= 1:
            if min_confidence >= 75.0:
                return "CRITICAL"
            elif min_confidence >= 60.0:
                # Downgrade to HIGH if medium confidence
                logger.debug(f"[GAP-3] 2×HIGH but confidence={min_confidence:.0f}% < 75%, capping at HIGH")
                return "HIGH"
            else:
                # Downgrade to MEDIUM if low confidence
                logger.debug(f"[GAP-3] 2×HIGH but confidence={min_confidence:.0f}% < 60%, capping at MEDIUM")
                return "MEDIUM"

        # Rule 2: Specific type combinations → CRITICAL
        critical_combos = [
            # Injection + Auth = full compromise
            ({"sqli", "sql_injection"}, {"auth_bypass", "authentication_bypass", "session_abuse"}),
            ({"cmdi", "command_injection", "rce"}, {"auth_bypass", "session_abuse"}),
            # XSS + CORS = account takeover
            ({"xss", "dom_xss", "stored_xss", "reflected_xss"}, {"cors_arbitrary", "cors_null", "cors_wildcard"}),
            # IDOR + Session = mass access
            ({"idor", "insecure_direct_object_reference"}, {"session_abuse", "jwt_weakness", "session_fixation"}),
            # LFI + Credential = code execution
            ({"lfi", "local_file_inclusion", "path_traversal"}, {"credential_exposure", "info_disclosure"}),
            # SSRF + Cloud = infrastructure compromise
            ({"ssrf", "server_side_request_forgery"}, {"aws_exposure", "cloud_metadata", "s3_misconfiguration"}),
            # XXE + SSRF = internal network access
            ({"xxe", "xml_external_entity"}, {"ssrf", "server_side_request_forgery"}),
            # ═══════════════════════════════════════════════════════════════════
            # BUSINESS LOGIC COMPOUND COMBOS — financial fraud escalation
            # ═══════════════════════════════════════════════════════════════════
            # Negative quantity + Coupon = unlimited discounts
            ({"negative_quantity", "negative_value", "quantity_manipulation"},
             {"coupon_reuse", "coupon_abuse", "discount_abuse"}),
            # Price manipulation + Workflow bypass = checkout fraud
            ({"price_manipulation", "zero_price"},
             {"workflow_bypass", "checkout_bypass", "verification_bypass"}),
            # Inventory manipulation + Checkout bypass = stock fraud
            ({"inventory_manipulation", "stock_manipulation"},
             {"checkout_bypass", "workflow_bypass", "race_condition"}),
            # IDOR + Business logic = cross-user exploitation
            ({"idor", "authorization"}, {"negative_quantity", "price_manipulation", "coupon_reuse"}),
            # Session abuse + Business logic = account fraud
            ({"session_abuse", "jwt_manipulation"}, {"business_logic", "price_manipulation", "workflow_bypass"}),
        ]

        for combo_a, combo_b in critical_combos:
            if (types & combo_a) and (types & combo_b):
                # GAP-3 FIX 2026-02-13: Require proof.can_chain for CRITICAL combos
                # Combos without chain proof should downgrade to HIGH
                has_chain_proof = all(
                    f.get("metadata", {}).get("proof", {}).get("can_chain", False)
                    for f in findings
                )
                if has_chain_proof and min_confidence >= 75.0:
                    return "CRITICAL"
                elif min_confidence >= 60.0:
                    logger.debug(f"[GAP-3] Combo matched but no chain proof or low confidence, capping at HIGH")
                    return "HIGH"
                else:
                    return "MEDIUM"

        # Rule 3: HIGH + Any other finding → HIGH (preserve at minimum)
        if high_count >= 1:
            return "HIGH"

        # Default: use base severity
        return base_severity.upper()

    def _calculate_probability(self, chain: AttackChain) -> None:
        """
        Calculate realistic exploitation probability.

        Incorporates:
        1. Base probability from pattern
        2. Step count penalty (more steps = harder)
        3. Finding quality (exploitability, proof)
        4. INCIDENT LEARNING — real-world data from breaches and bounties
        5. INFRASTRUCTURE CAP — technical chains capped at 65-75%
        """
        import math
        base_prob = chain.probability_score

        # AUDIT 2026-02-07: Changed from linear (-5 per step) to logarithmic scaling
        # Linear was too aggressive - 3-step chains lost 10 points unfairly
        # Logarithmic: 2 steps = -3, 3 steps = -5, 4 steps = -6, 5 steps = -7
        step_count = len(chain.steps)
        if step_count > 1:
            step_penalty = int(3 * math.log2(step_count))
        else:
            step_penalty = 0
        base_prob -= step_penalty

        # Check if this is an infrastructure chain (GAP-2.4)
        is_infrastructure_chain = False
        for step in chain.steps:
            metadata = step.finding.get("metadata", {})
            # BUG-FIX: Fixed broken if statement (data->metadata, fixed indentation)
            if isinstance(metadata, dict):
                if metadata.get("infrastructure_chain") or metadata.get("chain_confidence") == "technical":
                    is_infrastructure_chain = True
                    break

        # Boost if steps have high confidence
        for step in chain.steps:
            expl = step.finding.get("metadata", {}).get("exploitability", {})
            if expl.get("tier") == "full":
                base_prob += 5
            elif expl.get("tier") == "partial":
                pass  # No change
            else:
                # For infrastructure chains, don't penalize missing exploitability tier
                # They're technically realistic even without full proof
                if not is_infrastructure_chain:
                    base_prob -= 5

            # Boost if proof exists
            if step.finding.get("metadata", {}).get("proof", {}).get("can_repeat"):
                base_prob += 3

        # ═══════════════════════════════════════════════════════════════════
        # INCIDENT LEARNING ADJUSTMENT
        # Use real-world data to adjust probability
        # ═══════════════════════════════════════════════════════════════════
        incident_adjustment = 0.0
        incident_confidence = 0.0

        if INCIDENT_LEARNING_AVAILABLE:
            try:
                engine = get_incident_engine()
                chain_type = self._map_chain_to_incident_type(chain)

                if chain_type:
                    learned_prob, learned_conf = engine.get_chain_probability(chain_type)

                    # Only adjust if we have confidence in the learned data
                    if learned_conf >= 0.3:
                        # Calculate adjustment: difference from default probability
                        default_prob = 0.5
                        incident_adjustment = (learned_prob - default_prob) * 20

                        # Store for metadata
                        incident_confidence = learned_conf

                        logger.debug(
                            f"[CHAIN_ANALYZER] Incident adjustment for {chain.name}: "
                            f"{incident_adjustment:+.1f} (conf={learned_conf:.2f})"
                        )
            except Exception as e:
                logger.debug(f"[CHAIN_ANALYZER] Incident learning error: {e}")

        base_prob += incident_adjustment

        # ═══════════════════════════════════════════════════════════════════
        # GAP-3 FIX 2026-02-13: Calculate min_confidence for conditional boost
        # ═══════════════════════════════════════════════════════════════════
        step_confidences = []
        for step in chain.steps:
            conf = step.finding.get("confidence", 50.0)
            if isinstance(conf, str):
                conf = {"CRITICAL": 95, "HIGH": 85, "MEDIUM": 65, "LOW": 40}.get(conf.upper(), 50)
            step_confidences.append(float(conf))
        min_confidence = min(step_confidences) if step_confidences else 50.0

        # ═══════════════════════════════════════════════════════════════════
        # ISSUE-5 FIX 2026-02-11: Apply intent boost INSIDE probability calculation
        # GAP-3 FIX 2026-02-13: Only apply intent boost if high confidence components
        # This prevents low-confidence chains from being artificially boosted
        # ═══════════════════════════════════════════════════════════════════
        if self._intent_profile:
            try:
                from scanning.attacker_intent_engine import AttackerGoal
                category_to_goal = {
                    ChainCategory.DATA_EXFILTRATION: AttackerGoal.DATA_THEFT,
                    ChainCategory.ACCOUNT_TAKEOVER: AttackerGoal.ACCOUNT_TAKEOVER,
                    ChainCategory.PRIVILEGE_ESCALATION: AttackerGoal.ADMIN_ACCESS,
                    ChainCategory.FINANCIAL_FRAUD: AttackerGoal.FINANCIAL_GAIN,
                    ChainCategory.CODE_EXECUTION: AttackerGoal.CODE_EXECUTION,
                    ChainCategory.LATERAL_MOVEMENT: AttackerGoal.LATERAL_MOVEMENT,
                }
                primary_goals = getattr(self._intent_profile, 'primary_goals', [])
                target_goal = category_to_goal.get(chain.category)
                if target_goal and target_goal in primary_goals:
                    # GAP-3 FIX: Only boost if min_confidence >= 75%
                    if min_confidence >= 75.0:
                        intent_boost = 10.0  # Reduced from 15.0
                        base_prob += intent_boost
                        logger.debug(
                            f"[CHAIN_ANALYZER] Intent boost applied: {chain.name} +{intent_boost}pts "
                            f"(aligns with goal: {target_goal.name}, confidence={min_confidence:.0f}%)"
                        )
                    else:
                        logger.debug(
                            f"[GAP-3] Intent boost SKIPPED for {chain.name}: "
                            f"confidence={min_confidence:.0f}% < 75%"
                        )
            except Exception as e:
                logger.debug(f"[CHAIN_ANALYZER] Intent boost error: {e}")

        # BUG-FIX 2026-02-08: Clamp probability BEFORE confidence determination
        # to prevent base_prob > 100 from affecting confidence level assignment
        base_prob = max(10, min(100, base_prob))

        # ═══════════════════════════════════════════════════════════════════
        # INFRASTRUCTURE CHAIN HANDLING (GAP-2.4)
        # "Technically realistic but not yet fully validated"
        # Cap at 65-75% to be professionally honest
        # ═══════════════════════════════════════════════════════════════════
        # LOGIC-V3 FIX: Don't overwrite PROVEN confidence set during chain creation
        # PROVEN chains have been fully validated via proof.can_chain on all steps
        if chain.chain_confidence == ChainConfidence.PROVEN:
            # Preserve PROVEN - these chains have full proof.can_chain validation
            logger.debug(
                f"[CHAIN_ANALYZER] PROVEN chain '{chain.name}': "
                f"preserving confidence (probability {base_prob:.0f}%)"
            )
        elif is_infrastructure_chain:
            # Cap probability at 75% for infrastructure chains
            # L1 FIX 2026-02-12: Use module-level constants
            base_prob = max(INFRA_PROBABILITY_MIN, min(INFRA_PROBABILITY_MAX, base_prob))
            chain.chain_confidence = ChainConfidence.TECHNICAL

            logger.debug(
                f"[CHAIN_ANALYZER] Infrastructure chain '{chain.name}': "
                f"capped at {base_prob:.0f}% (TECHNICAL confidence)"
            )
        else:
            # Standard confidence determination
            # L1 FIX 2026-02-12: Use module-level constants
            if base_prob >= CONFIDENCE_HIGH:
                chain.chain_confidence = ChainConfidence.HIGH
            elif base_prob >= 60:
                chain.chain_confidence = ChainConfidence.MEDIUM
            else:
                chain.chain_confidence = ChainConfidence.THEORETICAL

        chain.probability_score = max(10, min(100, base_prob))

        # Store incident learning data in first step's metadata for reporting
        if incident_adjustment != 0 and chain.steps:
            chain.steps[0].finding.setdefault("metadata", {})["incident_learning"] = {
                "adjustment": round(incident_adjustment, 2),
                "confidence": round(incident_confidence, 2),
                "chain_type": self._map_chain_to_incident_type(chain) or "unknown",
            }

        # Store infrastructure chain metadata
        if is_infrastructure_chain and chain.steps:
            chain.steps[0].finding.setdefault("metadata", {})["technical_chain"] = {
                "is_infrastructure": True,
                "confidence_cap": "65-75%",
                "validation_note": "Technically realistic attack path, not yet fully validated",
            }

    def _map_chain_to_incident_type(self, chain: AttackChain) -> str | None:
        """Map chain to incident learning chain type."""
        if not INCIDENT_LEARNING_AVAILABLE:
            return None

        # Map by category + entry vuln type
        category = chain.category
        entry_type = ""
        if chain.steps:
            f = chain.steps[0].finding
            entry_type = self._normalize_type(
                f.get("vuln_type") or f.get("vulnerability_type") or f.get("type", "")
            )

        # Direct mappings
        if category == ChainCategory.DATA_EXFILTRATION:
            if "sql" in entry_type:
                return ChainType.SQLI_TO_DATA_THEFT.value
            if "idor" in entry_type:
                return ChainType.IDOR_TO_DATA.value
            if "cors" in entry_type:
                return ChainType.CORS_TO_DATA_THEFT.value

        if category == ChainCategory.ACCOUNT_TAKEOVER:
            if "xss" in entry_type:
                return ChainType.XSS_TO_ATO.value
            if "session" in entry_type:
                return ChainType.SESSION_TO_ATO.value

        if category == ChainCategory.PRIVILEGE_ESCALATION:
            if "sql" in entry_type:
                return ChainType.SQLI_TO_ADMIN.value
            if "idor" in entry_type:
                return ChainType.IDOR_TO_PRIVESC.value
            if "auth" in entry_type:
                return ChainType.AUTH_BYPASS_TO_ADMIN.value

        if category == ChainCategory.FINANCIAL_FRAUD:
            return ChainType.BUSINESS_LOGIC_FRAUD.value

        if category == ChainCategory.CODE_EXECUTION:
            if "ssrf" in entry_type:
                return ChainType.SSRF_TO_RCE.value
            if "sql" in entry_type:
                return ChainType.SQLI_TO_RCE.value

        if category == ChainCategory.LATERAL_MOVEMENT:
            if "ssrf" in entry_type:
                return ChainType.SSRF_TO_INTERNAL.value

        return None

    def _generate_narrative(self, chain: AttackChain) -> None:
        """Generate human-readable attack narrative with real exploitation context."""
        # ═══════════════════════════════════════════════════════════════════
        # FIX 2026-02-18: Extract ACTUAL exploitation data from findings
        # Instead of generic "data obtained", show real tokens/creds/data
        # ═══════════════════════════════════════════════════════════════════

        # Collect all exploitation evidence across steps
        exploitation_evidence = self._collect_exploitation_evidence(chain)

        if chain.attack_narrative:
            # Already has narrative from pattern — enhance with real data
            entry_url = chain.steps[0].finding.get("matched_at", "the vulnerable endpoint") if chain.steps else "the vulnerable endpoint"
            chain.attack_narrative = chain.attack_narrative.replace("{entry_url}", entry_url)

            # Replace additional placeholders with actual exploitation data
            chain.attack_narrative = self._populate_narrative_placeholders(
                chain.attack_narrative, exploitation_evidence
            )
        else:
            parts = []
            parts.append(f"This attack chain combines {len(chain.steps)} vulnerabilities to achieve {chain.category.name.replace('_', ' ').title()}.")
            parts.append("")

            for i, step in enumerate(chain.steps, 1):
                name = step.finding.get("name", "Unknown vulnerability")
                url = step.finding.get("matched_at", "")
                metadata = step.finding.get("metadata", {}) if isinstance(step.finding.get("metadata"), dict) else {}
                proof = metadata.get("proof", {}) if isinstance(metadata.get("proof"), dict) else {}

                parts.append(f"**Step {i}:** {step.action}")
                parts.append(f"   Using: {name}")
                if url:
                    parts.append(f"   At: {url}")

                # FIX: Show ACTUAL result from proof, not generic description
                actual_result = self._get_actual_step_result(step, proof)
                parts.append(f"   Result: {actual_result}")
                parts.append("")

            parts.append(f"**Business Impact:** {chain.business_impact}")

            chain.attack_narrative = "\n".join(parts)

        # ═══════════════════════════════════════════════════════════════════
        # FIX 2026-02-18: Add "Real Exploitation Evidence" section
        # Shows what was ACTUALLY extracted/accessed (tokens, creds, data)
        # ═══════════════════════════════════════════════════════════════════
        if exploitation_evidence["has_evidence"]:
            chain.attack_narrative += "\n\n**🔓 Real Exploitation Evidence:**"

            if exploitation_evidence["credentials"]:
                chain.attack_narrative += f"\n- Credentials extracted: {', '.join(exploitation_evidence['credentials'][:5])}"

            if exploitation_evidence["tokens"]:
                chain.attack_narrative += f"\n- Tokens/secrets at risk: {', '.join(exploitation_evidence['tokens'][:5])}"

            if exploitation_evidence["data_items"]:
                chain.attack_narrative += f"\n- Data accessed: {', '.join(exploitation_evidence['data_items'][:5])}"

            if exploitation_evidence["privileges"]:
                chain.attack_narrative += f"\n- Privileges gained: {', '.join(exploitation_evidence['privileges'])}"

            if exploitation_evidence["actions"]:
                chain.attack_narrative += f"\n- Actions performed: {', '.join(exploitation_evidence['actions'][:3])}"

            if exploitation_evidence["internal_services"]:
                chain.attack_narrative += f"\n- Internal services reached: {', '.join(exploitation_evidence['internal_services'][:5])}"

            # Store evidence in chain metadata for structured access
            if chain.steps:
                chain.steps[0].finding.setdefault("metadata", {})["exploitation_evidence"] = exploitation_evidence

        # ═══════════════════════════════════════════════════════════════════
        # TECHNICAL CONFIDENCE DISCLAIMER + VALIDATION STEPS (GAP-2.4)
        # Professionally honest + actionable for human operator
        # ═══════════════════════════════════════════════════════════════════
        if chain.chain_confidence == ChainConfidence.TECHNICAL:
            # Check if any step is infrastructure
            has_infra = any(
                step.finding.get("metadata", {}).get("infrastructure_chain")
                for step in chain.steps
            )
            if has_infra:
                chain.attack_narrative += (
                    "\n\n**Technical Confidence Note:** This chain represents a "
                    "technically realistic attack path based on well-known infrastructure "
                    "exploitation techniques. While the individual components have been "
                    "validated, the full chain execution has not been demonstrated. "
                    "A skilled attacker would recognize this pattern and attempt exploitation."
                )
            else:
                chain.attack_narrative += (
                    "\n\n**Technical Confidence Note:** This chain is technically realistic "
                    "but has not been fully validated through end-to-end exploitation. "
                    "The probability score reflects this uncertainty (capped at 65-75%)."
                )

            # Add recommended validation steps for human operator
            validation_steps = self._get_validation_steps_for_chain(chain)
            if validation_steps:
                chain.attack_narrative += (
                    "\n\n**Recommended Validation Steps:**\n" +
                    "\n".join(f"  {i}. {step}" for i, step in enumerate(validation_steps, 1))
                )

                # Also store in metadata for structured access
                if chain.steps:
                    chain.steps[0].finding.setdefault("metadata", {})["validation_steps"] = validation_steps

    def _collect_exploitation_evidence(self, chain: AttackChain) -> dict:
        """
        FIX 2026-02-18: Collect ACTUAL exploitation evidence from all chain steps.

        Extracts real data from proof results instead of using generic descriptions.
        Returns structured evidence for narrative generation.
        """
        evidence = {
            "has_evidence": False,
            "credentials": [],      # "admin@site.com:***"
            "tokens": [],           # "jwt_token", "session_id", "csrf_token"
            "data_items": [],       # "50 user records", "payment_info"
            "privileges": [],       # "admin", "root", "cloud_credentials"
            "actions": [],          # "modified cart total", "bypassed 2FA"
            "internal_services": [],  # "redis:6379", "mysql:3306"
            "tables_accessed": [],  # "users", "orders", "payments"
        }

        for step in chain.steps:
            metadata = step.finding.get("metadata", {}) if isinstance(step.finding.get("metadata"), dict) else {}
            proof = metadata.get("proof", {}) if isinstance(metadata.get("proof"), dict) else {}

            # Extract from proof.data_extracted (list of strings with prefixes)
            data_extracted = proof.get("data_extracted", [])
            if isinstance(data_extracted, list):
                for item in data_extracted:
                    if not isinstance(item, str):
                        continue
                    item_lower = item.lower()

                    # Parse prefixed items from proof engine
                    if item.startswith("cred:"):
                        evidence["credentials"].append(item[5:])
                    elif item.startswith("token:") or item.startswith("token_at_risk:"):
                        evidence["tokens"].append(item.split(":", 1)[1])
                    elif item.startswith("table:"):
                        evidence["tables_accessed"].append(item[6:])
                    elif item.startswith("email:"):
                        evidence["data_items"].append(f"email:{item[6:]}")
                    elif item.startswith("count:"):
                        evidence["data_items"].append(f"{item[6:]} records")
                    elif item.startswith("sample:"):
                        evidence["data_items"].append(item[7:])
                    elif item.startswith("internal_service:"):
                        evidence["internal_services"].append(item[17:])
                    elif item.startswith("financial_impact:"):
                        evidence["actions"].append(item[17:])
                    elif "cookie:" in item_lower:
                        evidence["tokens"].append(item)
                    elif any(x in item_lower for x in ["user", "admin", "password", "secret"]):
                        evidence["data_items"].append(item)

            # Extract from proof.privilege_gained
            privilege = proof.get("privilege_gained", "")
            if privilege and isinstance(privilege, str):
                evidence["privileges"].append(privilege)

            # Extract from proof.action_performed
            action = proof.get("action_performed", "")
            if action and isinstance(action, str):
                evidence["actions"].append(action)

            # Extract from proof.impact_evidence
            impact = proof.get("impact_evidence", "")
            if impact and isinstance(impact, str) and impact not in evidence["data_items"]:
                evidence["data_items"].append(impact)

            # Also check metadata.extracted_data (older format)
            extracted = metadata.get("extracted_data", {})
            if isinstance(extracted, dict):
                if extracted.get("emails"):
                    evidence["data_items"].extend([f"email:{e}" for e in extracted["emails"][:3]])
                if extracted.get("usernames"):
                    evidence["data_items"].extend([f"user:{u}" for u in extracted["usernames"][:3]])
                if extracted.get("tokens"):
                    evidence["tokens"].extend(extracted["tokens"][:3])

        # Deduplicate
        for key in evidence:
            if isinstance(evidence[key], list):
                evidence[key] = list(dict.fromkeys(evidence[key]))  # Preserve order

        # Set has_evidence flag
        evidence["has_evidence"] = any(
            evidence[k] for k in ["credentials", "tokens", "data_items", "privileges", "actions", "internal_services"]
        )

        return evidence

    def _populate_narrative_placeholders(self, narrative: str, evidence: dict) -> str:
        """
        FIX 2026-02-18: Replace template placeholders with actual exploitation data.

        Supports placeholders like:
        - {extracted_data} → "50 user records, admin credentials"
        - {compromised_user} → "admin@example.com"
        - {accessed_resource} → "users table, payment_info"
        - {stolen_token} → "JWT session token, CSRF token"
        - {privilege_gained} → "admin access"
        """
        replacements = {
            "{extracted_data}": ", ".join(evidence["data_items"][:3]) if evidence["data_items"] else "sensitive data",
            "{compromised_user}": evidence["credentials"][0].split(":")[0] if evidence["credentials"] else "target user",
            "{accessed_resource}": ", ".join(evidence["tables_accessed"][:3]) if evidence["tables_accessed"] else "protected resources",
            "{stolen_token}": ", ".join(evidence["tokens"][:3]) if evidence["tokens"] else "session tokens",
            "{privilege_gained}": ", ".join(evidence["privileges"]) if evidence["privileges"] else "elevated privileges",
            "{internal_service}": ", ".join(evidence["internal_services"][:3]) if evidence["internal_services"] else "internal services",
            "{action_performed}": ", ".join(evidence["actions"][:2]) if evidence["actions"] else "state manipulation",
        }

        for placeholder, value in replacements.items():
            narrative = narrative.replace(placeholder, value)

        return narrative

    def _get_actual_step_result(self, step, proof: dict) -> str:
        """
        FIX 2026-02-18: Return ACTUAL step result from proof data.

        Instead of generic "data obtained", shows real exploitation result.
        """
        # Priority 1: impact_evidence from proof (most descriptive)
        impact = proof.get("impact_evidence", "")
        if impact and isinstance(impact, str):
            return impact

        # Priority 2: action_performed
        action = proof.get("action_performed", "")
        if action and isinstance(action, str):
            return action

        # Priority 3: privilege_gained
        privilege = proof.get("privilege_gained", "")
        if privilege and isinstance(privilege, str):
            return f"Gained {privilege}"

        # Priority 4: Summarize data_extracted
        data = proof.get("data_extracted", [])
        if data and isinstance(data, list) and len(data) > 0:
            # Categorize extracted data
            creds = sum(1 for d in data if isinstance(d, str) and d.startswith("cred:"))
            tokens = sum(1 for d in data if isinstance(d, str) and ("token" in d.lower() or "cookie" in d.lower()))
            records = sum(1 for d in data if isinstance(d, str) and d.startswith("count:"))

            parts = []
            if creds:
                parts.append(f"{creds} credentials")
            if tokens:
                parts.append(f"{tokens} tokens")
            if records:
                # Extract count value
                for d in data:
                    if isinstance(d, str) and d.startswith("count:"):
                        parts.append(f"{d[6:]} records")
                        break

            if parts:
                return f"Extracted: {', '.join(parts)}"
            elif len(data) <= 3:
                return f"Extracted: {', '.join(str(d) for d in data[:3])}"
            else:
                return f"Extracted {len(data)} data items"

        # Priority 5: Check can_* flags for exploitation capability
        capabilities = []
        if proof.get("can_repeat"):
            capabilities.append("repeatable")
        if proof.get("can_escalate"):
            capabilities.append("escalatable")
        if proof.get("can_chain"):
            capabilities.append("chainable")

        if capabilities:
            return f"Exploitation confirmed ({', '.join(capabilities)})"

        # Fallback: Use step's generic data_obtained
        return step.data_obtained if step.data_obtained else "Vulnerability exploited"

    def _get_validation_steps_for_chain(self, chain: AttackChain) -> list[str]:
        """
        Generate recommended validation steps for TECHNICAL chains.

        These help human operators validate the chain manually.
        """
        steps = []

        # Get entry vulnerability type
        entry_type = ""
        if chain.steps:
            f = chain.steps[0].finding
            entry_type = self._normalize_type(
                f.get("vuln_type") or f.get("vulnerability_type") or f.get("type", "")
            )

        # Category-based validation steps
        category_steps = {
            ChainCategory.CODE_EXECUTION: [
                "Attempt to execute a benign command (e.g., 'id', 'whoami')",
                "Check if output is reflected in response or logs",
                "Verify process isolation and sandbox boundaries",
            ],
            ChainCategory.DATA_EXFILTRATION: [
                "Attempt to extract a known test record",
                "Verify data belongs to different user/tenant",
                "Check for pagination to assess full exposure scope",
            ],
            ChainCategory.ACCOUNT_TAKEOVER: [
                "Test with a controlled test account",
                "Verify session/token can be used for authentication",
                "Check if 2FA/MFA can be bypassed",
            ],
            ChainCategory.PRIVILEGE_ESCALATION: [
                "Test admin endpoints with escalated privileges",
                "Verify admin actions are actually executed",
                "Check audit logs for privilege changes",
            ],
            ChainCategory.FINANCIAL_FRAUD: [
                "Test with minimal safe values first (e.g., $0.01)",
                "Verify transaction state changes in database",
                "Check if reversal/rollback is possible",
            ],
            ChainCategory.LATERAL_MOVEMENT: [
                "Map internal network topology first",
                "Test connectivity to internal services",
                "Verify credentials work on other systems",
            ],
        }

        # Entry type-based validation steps
        entry_steps = {
            "http_smuggling": [
                "Send CL.TE/TE.CL probe and verify desync",
                "Attempt to poison another user's request",
                "Test if cache poisoning is achievable",
            ],
            "kubernetes": [
                "Check RBAC permissions with 'kubectl auth can-i'",
                "Verify pod/node access with kubectl exec",
                "Test if secrets can be accessed",
            ],
            "container_exposure": [
                "Verify container escape with test file creation",
                "Check host filesystem access",
                "Test network access to host services",
            ],
            "git_exposure": [
                "Download .git/HEAD and verify repo structure",
                "Extract sensitive files (config, .env)",
                "Check for credentials in commit history",
            ],
            "cicd_exposure": [
                "Verify pipeline access level",
                "Check for secret variable exposure",
                "Test if code injection in pipeline is possible",
            ],
            "subdomain_takeover": [
                "Verify DNS CNAME still points to unclaimed resource",
                "Attempt to claim the resource (safely)",
                "Check for sensitive cookie scope overlap",
            ],
            "deserialization": [
                "Test with a benign deserialization payload first",
                "Verify code execution with command output",
                "Check classpath for exploitable gadgets",
            ],
            "file_upload": [
                "Upload test file and verify execution",
                "Check for path traversal in upload location",
                "Verify MIME type restrictions",
            ],
        }

        # Add category-specific steps
        if chain.category in category_steps:
            steps.extend(category_steps[chain.category])

        # Add entry-type-specific steps
        if entry_type in entry_steps:
            steps.extend(entry_steps[entry_type])

        # Deduplicate while preserving order
        seen = set()
        unique_steps = []
        for step in steps:
            if step not in seen:
                seen.add(step)
                unique_steps.append(step)

        # Limit to 5 most relevant steps
        return unique_steps[:5]

    def get_summary(self) -> dict:
        """Get analysis summary."""
        by_category = {}
        for chain in self._chains:
            cat = chain.category.name
            if cat not in by_category:
                by_category[cat] = 0
            by_category[cat] += 1

        return {
            "total_chains": len(self._chains),
            "by_category": by_category,
            "critical_chains": sum(1 for c in self._chains if c.combined_severity == "CRITICAL"),
            "high_chains": sum(1 for c in self._chains if c.combined_severity == "HIGH"),
        }
