"""
PHANTOM AI - Impact Assessment Module

Enterprise-grade business impact assessment and CIA triad scoring.
Calculates potential financial losses, regulatory implications, and risk scores.

Version: 3.0.0
Date: 2026-01-30

Features:
- CIA Triad scoring (Confidentiality, Integrity, Availability)
- CVSS v3.1 compatible base metrics
- Business impact quantification
- Industry-specific context (HIPAA, PCI DSS, GDPR, SOX)
- Chain impact amplification
- Financial loss estimation
- Regulatory compliance impact
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS - CVSS v3.1 COMPATIBLE
# =============================================================================


class AttackVector(Enum):
    """CVSS v3.1 Attack Vector metric."""

    NETWORK = "N"          # 0.85 - Remotely exploitable
    ADJACENT = "A"         # 0.62 - Adjacent network
    LOCAL = "L"            # 0.55 - Local access required
    PHYSICAL = "P"         # 0.20 - Physical access required

    @property
    def score(self) -> float:
        """Get CVSS score for attack vector."""
        scores = {
            "N": 0.85,
            "A": 0.62,
            "L": 0.55,
            "P": 0.20,
        }
        return scores[self.value]


class AttackComplexity(Enum):
    """CVSS v3.1 Attack Complexity metric."""

    LOW = "L"              # 0.77 - No special conditions
    HIGH = "H"             # 0.44 - Special conditions required

    @property
    def score(self) -> float:
        """Get CVSS score for attack complexity."""
        return 0.77 if self.value == "L" else 0.44


class PrivilegesRequired(Enum):
    """CVSS v3.1 Privileges Required metric."""

    NONE = "N"             # 0.85 - No privileges needed
    LOW = "L"              # 0.62/0.68 - Low privileges
    HIGH = "H"             # 0.27/0.50 - High privileges

    def get_score(self, scope_changed: bool = False) -> float:
        """Get CVSS score for privileges required."""
        if self.value == "N":
            return 0.85
        elif self.value == "L":
            return 0.68 if scope_changed else 0.62
        else:  # HIGH
            return 0.50 if scope_changed else 0.27


class UserInteraction(Enum):
    """CVSS v3.1 User Interaction metric."""

    NONE = "N"             # 0.85 - No user interaction
    REQUIRED = "R"         # 0.62 - User interaction required

    @property
    def score(self) -> float:
        """Get CVSS score for user interaction."""
        return 0.85 if self.value == "N" else 0.62


class Scope(Enum):
    """CVSS v3.1 Scope metric."""

    UNCHANGED = "U"        # Exploited component only
    CHANGED = "C"          # Impacts beyond exploited component

    @property
    def changed(self) -> bool:
        """Check if scope is changed."""
        return self.value == "C"


class ImpactLevel(Enum):
    """CVSS v3.1 Impact levels for CIA."""

    NONE = "N"             # 0.00 - No impact
    LOW = "L"              # 0.22 - Low impact
    HIGH = "H"             # 0.56 - High impact

    @property
    def score(self) -> float:
        """Get CVSS score for impact level."""
        scores = {"N": 0.00, "L": 0.22, "H": 0.56}
        return scores[self.value]


class SeverityLevel(Enum):
    """Overall severity level."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_cvss(cls, score: float) -> "SeverityLevel":
        """Get severity level from CVSS score."""
        if score == 0.0:
            return cls.NONE
        elif score < 4.0:
            return cls.LOW
        elif score < 7.0:
            return cls.MEDIUM
        elif score < 9.0:
            return cls.HIGH
        else:
            return cls.CRITICAL


class IndustryContext(Enum):
    """Industry context for regulatory compliance."""

    GENERAL = auto()
    HEALTHCARE = auto()     # HIPAA
    FINANCIAL = auto()      # PCI DSS, SOX, GLBA
    GOVERNMENT = auto()     # FedRAMP, FISMA
    ECOMMERCE = auto()      # PCI DSS
    EDUCATION = auto()      # FERPA
    TECHNOLOGY = auto()     # SOC 2
    CRITICAL_INFRASTRUCTURE = auto()  # NERC CIP


class DataClassification(Enum):
    """Data classification levels."""

    PUBLIC = 1              # Publicly available
    INTERNAL = 2            # Internal use only
    CONFIDENTIAL = 3        # Business sensitive
    RESTRICTED = 4          # Highly sensitive
    TOP_SECRET = 5          # Maximum classification

    @property
    def multiplier(self) -> float:
        """Get impact multiplier for data classification."""
        multipliers = {1: 1.0, 2: 1.5, 3: 2.0, 4: 3.0, 5: 5.0}
        return multipliers[self.value]


class AssetCriticality(Enum):
    """Asset criticality levels."""

    LOW = 1                 # Non-critical asset
    MEDIUM = 2              # Supporting asset
    HIGH = 3                # Important asset
    CRITICAL = 4            # Business critical
    MISSION_CRITICAL = 5    # Mission-critical asset

    @property
    def multiplier(self) -> float:
        """Get impact multiplier for asset criticality."""
        multipliers = {1: 1.0, 2: 1.5, 3: 2.0, 4: 3.0, 5: 4.0}
        return multipliers[self.value]


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class CIATriad:
    """CIA Triad impact scoring."""

    confidentiality: ImpactLevel = ImpactLevel.NONE
    integrity: ImpactLevel = ImpactLevel.NONE
    availability: ImpactLevel = ImpactLevel.NONE

    @property
    def impact_subscore(self) -> float:
        """
        Calculate CVSS v3.1 Impact Sub-Score (ISS).
        ISS = 1 - [(1 - C) × (1 - I) × (1 - A)]
        """
        c = self.confidentiality.score
        i = self.integrity.score
        a = self.availability.score
        return 1 - ((1 - c) * (1 - i) * (1 - a))

    @property
    def total_score(self) -> float:
        """Get total CIA impact (0-10 scale)."""
        return self.impact_subscore * 10

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "confidentiality": self.confidentiality.name,
            "integrity": self.integrity.name,
            "availability": self.availability.name,
            "impact_subscore": round(self.impact_subscore, 2),
            "total_score": round(self.total_score, 2),
        }


@dataclass
class CVSSVector:
    """CVSS v3.1 Base Score Vector."""

    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    cia: CIATriad = field(default_factory=CIATriad)

    @property
    def exploitability_subscore(self) -> float:
        """
        Calculate CVSS v3.1 Exploitability Sub-Score.
        ESS = 8.22 × AV × AC × PR × UI
        """
        return (
            8.22
            * self.attack_vector.score
            * self.attack_complexity.score
            * self.privileges_required.get_score(self.scope.changed)
            * self.user_interaction.score
        )

    @property
    def impact_subscore(self) -> float:
        """
        Calculate CVSS v3.1 Impact Sub-Score.
        """
        iss = self.cia.impact_subscore

        if self.scope.changed:
            # Scope Changed formula
            return 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)
        else:
            # Scope Unchanged formula
            return 6.42 * iss

    @property
    def base_score(self) -> float:
        """
        Calculate CVSS v3.1 Base Score.
        """
        iss = self.cia.impact_subscore

        if iss <= 0:
            return 0.0

        impact = self.impact_subscore
        exploitability = self.exploitability_subscore

        if self.scope.changed:
            score = min(1.08 * (impact + exploitability), 10)
        else:
            score = min(impact + exploitability, 10)

        # Round up to nearest 0.1
        return round(score * 10) / 10

    @property
    def severity(self) -> SeverityLevel:
        """Get severity level from base score."""
        return SeverityLevel.from_cvss(self.base_score)

    @property
    def vector_string(self) -> str:
        """Generate CVSS v3.1 vector string."""
        return (
            f"CVSS:3.1/AV:{self.attack_vector.value}/"
            f"AC:{self.attack_complexity.value}/"
            f"PR:{self.privileges_required.value}/"
            f"UI:{self.user_interaction.value}/"
            f"S:{self.scope.value}/"
            f"C:{self.cia.confidentiality.value}/"
            f"I:{self.cia.integrity.value}/"
            f"A:{self.cia.availability.value}"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "vector_string": self.vector_string,
            "base_score": self.base_score,
            "severity": self.severity.value,
            "exploitability_subscore": round(self.exploitability_subscore, 2),
            "impact_subscore": round(self.impact_subscore, 2),
            "attack_vector": self.attack_vector.name,
            "attack_complexity": self.attack_complexity.name,
            "privileges_required": self.privileges_required.name,
            "user_interaction": self.user_interaction.name,
            "scope": self.scope.name,
            "cia": self.cia.to_dict(),
        }


@dataclass
class FinancialImpact:
    """Financial impact estimation."""

    # Direct costs
    incident_response: float = 0.0       # IR team, forensics
    legal_fees: float = 0.0              # Legal counsel, litigation
    regulatory_fines: float = 0.0        # Compliance penalties
    notification_costs: float = 0.0      # Breach notification
    credit_monitoring: float = 0.0       # For affected users

    # Indirect costs
    business_interruption: float = 0.0   # Downtime costs
    reputational_damage: float = 0.0     # Brand impact
    customer_churn: float = 0.0          # Lost customers
    stock_price_impact: float = 0.0      # Market cap loss

    # Recovery costs
    remediation: float = 0.0             # Fix vulnerabilities
    security_improvements: float = 0.0   # Enhanced security

    @property
    def direct_costs(self) -> float:
        """Total direct costs."""
        return (
            self.incident_response
            + self.legal_fees
            + self.regulatory_fines
            + self.notification_costs
            + self.credit_monitoring
        )

    @property
    def indirect_costs(self) -> float:
        """Total indirect costs."""
        return (
            self.business_interruption
            + self.reputational_damage
            + self.customer_churn
            + self.stock_price_impact
        )

    @property
    def recovery_costs(self) -> float:
        """Total recovery costs."""
        return self.remediation + self.security_improvements

    @property
    def total_impact(self) -> float:
        """Total financial impact."""
        return self.direct_costs + self.indirect_costs + self.recovery_costs

    @property
    def range_estimate(self) -> Tuple[float, float]:
        """Get range estimate (min, max)."""
        base = self.total_impact
        return (base * 0.7, base * 1.5)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        min_est, max_est = self.range_estimate
        return {
            "direct_costs": {
                "incident_response": self.incident_response,
                "legal_fees": self.legal_fees,
                "regulatory_fines": self.regulatory_fines,
                "notification_costs": self.notification_costs,
                "credit_monitoring": self.credit_monitoring,
                "total": self.direct_costs,
            },
            "indirect_costs": {
                "business_interruption": self.business_interruption,
                "reputational_damage": self.reputational_damage,
                "customer_churn": self.customer_churn,
                "stock_price_impact": self.stock_price_impact,
                "total": self.indirect_costs,
            },
            "recovery_costs": {
                "remediation": self.remediation,
                "security_improvements": self.security_improvements,
                "total": self.recovery_costs,
            },
            "total_impact": self.total_impact,
            "range_estimate": {
                "min": min_est,
                "max": max_est,
            },
        }


@dataclass
class RegulatoryImpact:
    """Regulatory and compliance impact."""

    applicable_regulations: List[str] = field(default_factory=list)
    potential_violations: List[str] = field(default_factory=list)
    notification_required: bool = False
    notification_deadline_days: Optional[int] = None
    max_fine_amount: float = 0.0
    fine_calculation_basis: str = ""
    audit_trigger: bool = False
    license_risk: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "applicable_regulations": self.applicable_regulations,
            "potential_violations": self.potential_violations,
            "notification_required": self.notification_required,
            "notification_deadline_days": self.notification_deadline_days,
            "max_fine_amount": self.max_fine_amount,
            "fine_calculation_basis": self.fine_calculation_basis,
            "audit_trigger": self.audit_trigger,
            "license_risk": self.license_risk,
        }


@dataclass
class BusinessContext:
    """Business context for impact assessment."""

    industry: IndustryContext = IndustryContext.GENERAL
    company_size: str = "medium"  # small, medium, large, enterprise
    annual_revenue: float = 0.0   # Annual revenue in USD
    user_base_size: int = 0       # Number of users
    data_classification: DataClassification = DataClassification.INTERNAL
    asset_criticality: AssetCriticality = AssetCriticality.MEDIUM
    public_facing: bool = True
    handles_pii: bool = False
    handles_financial_data: bool = False
    handles_health_data: bool = False
    geographic_scope: List[str] = field(default_factory=lambda: ["US"])

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "industry": self.industry.name,
            "company_size": self.company_size,
            "annual_revenue": self.annual_revenue,
            "user_base_size": self.user_base_size,
            "data_classification": self.data_classification.name,
            "asset_criticality": self.asset_criticality.name,
            "public_facing": self.public_facing,
            "handles_pii": self.handles_pii,
            "handles_financial_data": self.handles_financial_data,
            "handles_health_data": self.handles_health_data,
            "geographic_scope": self.geographic_scope,
        }


@dataclass
class ImpactAssessmentResult:
    """Complete impact assessment result."""

    vulnerability_id: str
    vulnerability_type: str
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Technical impact
    cvss: CVSSVector = field(default_factory=CVSSVector)

    # Business impact
    financial_impact: FinancialImpact = field(default_factory=FinancialImpact)
    regulatory_impact: RegulatoryImpact = field(default_factory=RegulatoryImpact)

    # Context
    business_context: Optional[BusinessContext] = None

    # Chain impact
    is_chain_component: bool = False
    chain_amplification_factor: float = 1.0
    chain_position: Optional[int] = None

    # Scores
    technical_score: float = 0.0
    business_score: float = 0.0
    overall_risk_score: float = 0.0

    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    remediation_priority: str = "medium"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "vulnerability_id": self.vulnerability_id,
            "vulnerability_type": self.vulnerability_type,
            "timestamp": self.timestamp.isoformat(),
            "cvss": self.cvss.to_dict(),
            "financial_impact": self.financial_impact.to_dict(),
            "regulatory_impact": self.regulatory_impact.to_dict(),
            "business_context": self.business_context.to_dict() if self.business_context else None,
            "is_chain_component": self.is_chain_component,
            "chain_amplification_factor": self.chain_amplification_factor,
            "chain_position": self.chain_position,
            "scores": {
                "technical": round(self.technical_score, 2),
                "business": round(self.business_score, 2),
                "overall_risk": round(self.overall_risk_score, 2),
            },
            "severity": self.cvss.severity.value,
            "recommendations": self.recommendations,
            "remediation_priority": self.remediation_priority,
        }


# =============================================================================
# VULNERABILITY TYPE PROFILES
# =============================================================================


# Default CIA and CVSS profiles for common vulnerability types
VULNERABILITY_PROFILES: Dict[str, Dict[str, Any]] = {
    # Injection vulnerabilities
    "sqli": {
        "cia": CIATriad(ImpactLevel.HIGH, ImpactLevel.HIGH, ImpactLevel.LOW),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.UNCHANGED,
        "data_risk": ["PII", "credentials", "financial"],
    },
    "xss": {
        "cia": CIATriad(ImpactLevel.LOW, ImpactLevel.LOW, ImpactLevel.NONE),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.REQUIRED,
        "scope": Scope.CHANGED,
        "data_risk": ["session", "PII"],
    },
    "dom_xss": {
        "cia": CIATriad(ImpactLevel.LOW, ImpactLevel.LOW, ImpactLevel.NONE),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.REQUIRED,
        "scope": Scope.CHANGED,
        "data_risk": ["session", "PII"],
    },
    "cmdi": {
        "cia": CIATriad(ImpactLevel.HIGH, ImpactLevel.HIGH, ImpactLevel.HIGH),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.CHANGED,
        "data_risk": ["all"],
    },
    "xxe": {
        "cia": CIATriad(ImpactLevel.HIGH, ImpactLevel.NONE, ImpactLevel.LOW),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.UNCHANGED,
        "data_risk": ["files", "credentials"],
    },
    "ssti": {
        "cia": CIATriad(ImpactLevel.HIGH, ImpactLevel.HIGH, ImpactLevel.HIGH),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.CHANGED,
        "data_risk": ["all"],
    },
    "nosql": {
        "cia": CIATriad(ImpactLevel.HIGH, ImpactLevel.HIGH, ImpactLevel.LOW),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.UNCHANGED,
        "data_risk": ["PII", "credentials"],
    },
    "ldap": {
        "cia": CIATriad(ImpactLevel.HIGH, ImpactLevel.LOW, ImpactLevel.NONE),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.UNCHANGED,
        "data_risk": ["directory", "credentials"],
    },
    "crlf": {
        "cia": CIATriad(ImpactLevel.LOW, ImpactLevel.LOW, ImpactLevel.NONE),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.REQUIRED,
        "scope": Scope.UNCHANGED,
        "data_risk": ["session"],
    },
    "lfi": {
        "cia": CIATriad(ImpactLevel.HIGH, ImpactLevel.NONE, ImpactLevel.NONE),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.UNCHANGED,
        "data_risk": ["files", "credentials", "source_code"],
    },
    "ssrf": {
        "cia": CIATriad(ImpactLevel.HIGH, ImpactLevel.LOW, ImpactLevel.LOW),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.CHANGED,
        "data_risk": ["internal_network", "cloud_metadata", "credentials"],
    },

    # Authentication vulnerabilities
    "auth_bypass": {
        "cia": CIATriad(ImpactLevel.HIGH, ImpactLevel.HIGH, ImpactLevel.NONE),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.UNCHANGED,
        "data_risk": ["PII", "credentials", "all_user_data"],
    },
    "broken_auth": {
        "cia": CIATriad(ImpactLevel.HIGH, ImpactLevel.HIGH, ImpactLevel.NONE),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.UNCHANGED,
        "data_risk": ["PII", "credentials"],
    },
    "jwt_vuln": {
        "cia": CIATriad(ImpactLevel.HIGH, ImpactLevel.HIGH, ImpactLevel.NONE),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.UNCHANGED,
        "data_risk": ["session", "PII"],
    },
    "session_fixation": {
        "cia": CIATriad(ImpactLevel.HIGH, ImpactLevel.LOW, ImpactLevel.NONE),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.REQUIRED,
        "scope": Scope.UNCHANGED,
        "data_risk": ["session"],
    },
    "csrf": {
        "cia": CIATriad(ImpactLevel.NONE, ImpactLevel.LOW, ImpactLevel.NONE),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.REQUIRED,
        "scope": Scope.UNCHANGED,
        "data_risk": ["integrity"],
    },

    # Authorization vulnerabilities
    "idor": {
        "cia": CIATriad(ImpactLevel.HIGH, ImpactLevel.HIGH, ImpactLevel.NONE),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.LOW,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.UNCHANGED,
        "data_risk": ["PII", "other_user_data"],
    },
    "privilege_escalation": {
        "cia": CIATriad(ImpactLevel.HIGH, ImpactLevel.HIGH, ImpactLevel.HIGH),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.LOW,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.CHANGED,
        "data_risk": ["all"],
    },

    # Infrastructure vulnerabilities
    "misconfiguration": {
        "cia": CIATriad(ImpactLevel.LOW, ImpactLevel.NONE, ImpactLevel.NONE),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.UNCHANGED,
        "data_risk": ["configuration", "internal_paths"],
    },
    "info_disclosure": {
        "cia": CIATriad(ImpactLevel.LOW, ImpactLevel.NONE, ImpactLevel.NONE),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.UNCHANGED,
        "data_risk": ["configuration", "stack_trace"],
    },
    "cors": {
        "cia": CIATriad(ImpactLevel.LOW, ImpactLevel.LOW, ImpactLevel.NONE),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.REQUIRED,
        "scope": Scope.UNCHANGED,
        "data_risk": ["session", "PII"],
    },
    "ssl_tls": {
        "cia": CIATriad(ImpactLevel.LOW, ImpactLevel.LOW, ImpactLevel.NONE),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.HIGH,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.UNCHANGED,
        "data_risk": ["transit_data"],
    },

    # Deserialization
    "insecure_deserialization": {
        "cia": CIATriad(ImpactLevel.HIGH, ImpactLevel.HIGH, ImpactLevel.HIGH),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.CHANGED,
        "data_risk": ["all"],
    },

    # File upload
    "file_upload": {
        "cia": CIATriad(ImpactLevel.HIGH, ImpactLevel.HIGH, ImpactLevel.HIGH),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.LOW,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.CHANGED,
        "data_risk": ["all"],
    },

    # Default profile for unknown types
    "unknown": {
        "cia": CIATriad(ImpactLevel.LOW, ImpactLevel.LOW, ImpactLevel.NONE),
        "attack_vector": AttackVector.NETWORK,
        "attack_complexity": AttackComplexity.LOW,
        "privileges_required": PrivilegesRequired.NONE,
        "user_interaction": UserInteraction.NONE,
        "scope": Scope.UNCHANGED,
        "data_risk": [],
    },
}


# =============================================================================
# REGULATORY PROFILES
# =============================================================================


REGULATORY_PROFILES: Dict[str, Dict[str, Any]] = {
    "GDPR": {
        "applies_to": ["EU", "EEA"],
        "data_types": ["PII", "personal_data"],
        "notification_deadline": 72,  # hours
        "max_fine_basis": "revenue",
        "max_fine_percentage": 4.0,
        "max_fine_fixed": 20_000_000,
    },
    "HIPAA": {
        "applies_to": ["US"],
        "data_types": ["PHI", "health_data"],
        "notification_deadline": 60 * 24,  # 60 days in hours
        "max_fine_basis": "per_violation",
        "max_fine_per_violation": 50_000,
        "max_fine_annual": 1_500_000,
    },
    "PCI_DSS": {
        "applies_to": ["global"],
        "data_types": ["cardholder_data", "financial"],
        "notification_deadline": 24,  # hours (immediate)
        "max_fine_basis": "per_month",
        "max_fine_per_month": 100_000,
    },
    "CCPA": {
        "applies_to": ["US-CA"],
        "data_types": ["PII", "personal_data"],
        "notification_deadline": None,  # "expedient" manner
        "max_fine_basis": "per_violation",
        "max_fine_per_violation": 7_500,
    },
    "SOX": {
        "applies_to": ["US"],
        "data_types": ["financial"],
        "notification_deadline": None,
        "max_fine_basis": "criminal",
        "max_fine_fixed": 5_000_000,
    },
    "FERPA": {
        "applies_to": ["US"],
        "data_types": ["education_records"],
        "notification_deadline": None,
        "max_fine_basis": "funding_loss",
    },
    "GLBA": {
        "applies_to": ["US"],
        "data_types": ["financial", "PII"],
        "notification_deadline": None,
        "max_fine_basis": "per_violation",
        "max_fine_per_violation": 100_000,
    },
}


# =============================================================================
# INDUSTRY COST FACTORS
# =============================================================================


# Average cost per record breach by industry (USD)
COST_PER_RECORD: Dict[IndustryContext, float] = {
    IndustryContext.HEALTHCARE: 429.0,      # Highest due to HIPAA
    IndustryContext.FINANCIAL: 388.0,       # PCI DSS, SOX compliance
    IndustryContext.TECHNOLOGY: 183.0,
    IndustryContext.ECOMMERCE: 167.0,
    IndustryContext.EDUCATION: 142.0,
    IndustryContext.GOVERNMENT: 194.0,
    IndustryContext.GENERAL: 164.0,
    IndustryContext.CRITICAL_INFRASTRUCTURE: 512.0,
}


# Average breach costs by company size (USD)
BASE_BREACH_COST: Dict[str, float] = {
    "small": 150_000,       # < 500 employees
    "medium": 500_000,      # 500-1000 employees
    "large": 2_000_000,     # 1000-5000 employees
    "enterprise": 8_000_000,  # > 5000 employees
}


# =============================================================================
# IMPACT ASSESSMENT ENGINE
# =============================================================================


class ImpactAssessmentEngine:
    """
    PHANTOM AI Impact Assessment Engine.

    Provides comprehensive business impact assessment including:
    - CVSS v3.1 scoring
    - CIA triad analysis
    - Financial impact estimation
    - Regulatory compliance impact
    - Chain amplification calculation
    """

    VERSION = "3.0.0"

    def __init__(
        self,
        business_context: Optional[BusinessContext] = None,
    ) -> None:
        """
        Initialize impact assessment engine.

        Args:
            business_context: Optional business context for assessments
        """
        self.business_context = business_context or BusinessContext()
        self._assessment_cache: Dict[str, ImpactAssessmentResult] = {}

        logger.info(f"ImpactAssessmentEngine v{self.VERSION} initialized")

    def assess_vulnerability(
        self,
        vulnerability_id: str,
        vulnerability_type: str,
        custom_cvss: Optional[CVSSVector] = None,
        affected_records: int = 0,
        is_chain_component: bool = False,
        chain_position: Optional[int] = None,
        chain_size: int = 1,
    ) -> ImpactAssessmentResult:
        """
        Assess impact of a single vulnerability.

        Args:
            vulnerability_id: Unique identifier for the vulnerability
            vulnerability_type: Type of vulnerability (e.g., "sqli", "xss")
            custom_cvss: Optional custom CVSS vector
            affected_records: Number of potentially affected records
            is_chain_component: Whether this is part of a chain
            chain_position: Position in the chain (if applicable)
            chain_size: Total size of the chain

        Returns:
            Complete impact assessment result
        """
        # Get vulnerability profile
        vuln_type_lower = vulnerability_type.lower()
        profile = VULNERABILITY_PROFILES.get(
            vuln_type_lower,
            VULNERABILITY_PROFILES["unknown"]
        )

        # Build CVSS vector
        if custom_cvss:
            cvss = custom_cvss
        else:
            cvss = CVSSVector(
                attack_vector=profile["attack_vector"],
                attack_complexity=profile["attack_complexity"],
                privileges_required=profile["privileges_required"],
                user_interaction=profile["user_interaction"],
                scope=profile["scope"],
                cia=profile["cia"],
            )

        # Calculate financial impact
        financial_impact = self._calculate_financial_impact(
            vulnerability_type=vuln_type_lower,
            cvss_score=cvss.base_score,
            affected_records=affected_records,
            data_risk=profile.get("data_risk", []),
        )

        # Calculate regulatory impact
        regulatory_impact = self._calculate_regulatory_impact(
            vulnerability_type=vuln_type_lower,
            data_risk=profile.get("data_risk", []),
            cvss_score=cvss.base_score,
        )

        # Calculate chain amplification
        chain_amplification = self._calculate_chain_amplification(
            is_chain_component=is_chain_component,
            chain_position=chain_position,
            chain_size=chain_size,
            cvss_score=cvss.base_score,
        )

        # Calculate scores
        technical_score = cvss.base_score
        business_score = self._calculate_business_score(
            cvss_score=cvss.base_score,
            financial_impact=financial_impact,
            regulatory_impact=regulatory_impact,
        )
        overall_risk_score = self._calculate_overall_risk(
            technical_score=technical_score,
            business_score=business_score,
            chain_amplification=chain_amplification,
        )

        # Generate recommendations
        recommendations = self._generate_recommendations(
            vulnerability_type=vuln_type_lower,
            cvss=cvss,
            regulatory_impact=regulatory_impact,
        )

        # Determine remediation priority
        remediation_priority = self._determine_priority(overall_risk_score)

        result = ImpactAssessmentResult(
            vulnerability_id=vulnerability_id,
            vulnerability_type=vulnerability_type,
            cvss=cvss,
            financial_impact=financial_impact,
            regulatory_impact=regulatory_impact,
            business_context=self.business_context,
            is_chain_component=is_chain_component,
            chain_amplification_factor=chain_amplification,
            chain_position=chain_position,
            technical_score=technical_score,
            business_score=business_score,
            overall_risk_score=overall_risk_score,
            recommendations=recommendations,
            remediation_priority=remediation_priority,
        )

        # Cache result
        self._assessment_cache[vulnerability_id] = result

        logger.debug(
            f"Assessed {vulnerability_type}: "
            f"CVSS={cvss.base_score}, Risk={overall_risk_score:.1f}"
        )

        return result

    def assess_chain(
        self,
        chain_vulnerabilities: List[Dict[str, Any]],
        chain_id: str,
    ) -> Dict[str, Any]:
        """
        Assess impact of a vulnerability chain.

        Args:
            chain_vulnerabilities: List of vulnerabilities in the chain
            chain_id: Unique identifier for the chain

        Returns:
            Chain impact assessment
        """
        if not chain_vulnerabilities:
            return {
                "chain_id": chain_id,
                "error": "No vulnerabilities in chain",
            }

        chain_size = len(chain_vulnerabilities)
        assessments: List[ImpactAssessmentResult] = []

        # Assess each vulnerability in context of chain
        for idx, vuln in enumerate(chain_vulnerabilities):
            assessment = self.assess_vulnerability(
                vulnerability_id=vuln.get("id", f"{chain_id}_vuln_{idx}"),
                vulnerability_type=vuln.get("type", "unknown"),
                affected_records=vuln.get("affected_records", 0),
                is_chain_component=True,
                chain_position=idx,
                chain_size=chain_size,
            )
            assessments.append(assessment)

        # Calculate chain-level metrics
        max_cvss = max(a.cvss.base_score for a in assessments)
        total_financial = sum(a.financial_impact.total_impact for a in assessments)

        # Chain amplification increases with each step
        chain_amplification = 1.0 + (0.2 * (chain_size - 1))
        amplified_cvss = min(max_cvss * chain_amplification, 10.0)

        # Aggregate regulatory impacts
        all_regulations = set()
        all_violations = set()
        notification_required = False
        min_notification_deadline = None

        for assessment in assessments:
            all_regulations.update(assessment.regulatory_impact.applicable_regulations)
            all_violations.update(assessment.regulatory_impact.potential_violations)
            if assessment.regulatory_impact.notification_required:
                notification_required = True
                if assessment.regulatory_impact.notification_deadline_days:
                    if min_notification_deadline is None:
                        min_notification_deadline = assessment.regulatory_impact.notification_deadline_days
                    else:
                        min_notification_deadline = min(
                            min_notification_deadline,
                            assessment.regulatory_impact.notification_deadline_days
                        )

        # Determine chain severity
        if amplified_cvss >= 9.0:
            chain_severity = "CRITICAL"
        elif amplified_cvss >= 7.0:
            chain_severity = "HIGH"
        elif amplified_cvss >= 4.0:
            chain_severity = "MEDIUM"
        else:
            chain_severity = "LOW"

        # Generate chain-specific recommendations
        chain_recommendations = [
            f"Address the root vulnerability first: {chain_vulnerabilities[0].get('type', 'unknown')}",
            f"This chain involves {chain_size} vulnerabilities - prioritize blocking any step",
        ]

        if chain_size >= 3:
            chain_recommendations.append(
                "Multi-step chain detected - implement defense-in-depth controls"
            )

        return {
            "chain_id": chain_id,
            "chain_size": chain_size,
            "individual_assessments": [a.to_dict() for a in assessments],
            "chain_metrics": {
                "max_individual_cvss": max_cvss,
                "chain_amplification_factor": chain_amplification,
                "amplified_cvss": round(amplified_cvss, 1),
                "chain_severity": chain_severity,
                "total_financial_impact": total_financial,
                "financial_impact_range": {
                    "min": total_financial * 0.7 * chain_amplification,
                    "max": total_financial * 1.5 * chain_amplification,
                },
            },
            "regulatory_aggregate": {
                "applicable_regulations": list(all_regulations),
                "potential_violations": list(all_violations),
                "notification_required": notification_required,
                "notification_deadline_days": min_notification_deadline,
            },
            "recommendations": chain_recommendations,
            "remediation_priority": "critical" if chain_severity == "CRITICAL" else "high",
        }

    def _calculate_financial_impact(
        self,
        vulnerability_type: str,
        cvss_score: float,
        affected_records: int,
        data_risk: List[str],
    ) -> FinancialImpact:
        """Calculate financial impact of vulnerability."""
        ctx = self.business_context

        # Base breach cost
        base_cost = BASE_BREACH_COST.get(ctx.company_size, BASE_BREACH_COST["medium"])

        # Cost per record
        cost_per_record = COST_PER_RECORD.get(ctx.industry, COST_PER_RECORD[IndustryContext.GENERAL])

        # Severity multiplier
        severity_mult = cvss_score / 10.0

        # Data sensitivity multiplier
        data_mult = ctx.data_classification.multiplier

        # Asset criticality multiplier
        asset_mult = ctx.asset_criticality.multiplier

        # Calculate costs
        impact = FinancialImpact()

        # Records-based costs
        if affected_records > 0:
            record_cost = affected_records * cost_per_record * data_mult
            impact.notification_costs = min(affected_records * 2.0, 500_000)  # $2/notification
            impact.credit_monitoring = min(affected_records * 15.0, 1_000_000)  # $15/person/year
        else:
            # Estimate based on user base
            estimated_records = ctx.user_base_size * 0.1 * severity_mult
            record_cost = estimated_records * cost_per_record * data_mult
            impact.notification_costs = min(estimated_records * 2.0, 200_000)
            impact.credit_monitoring = min(estimated_records * 15.0, 500_000)

        # Incident response (scales with severity)
        impact.incident_response = base_cost * 0.15 * severity_mult * asset_mult

        # Legal fees (higher for certain data types)
        legal_mult = 1.0
        if "PII" in data_risk or "credentials" in data_risk:
            legal_mult = 1.5
        if "health_data" in data_risk or "financial" in data_risk:
            legal_mult = 2.0
        impact.legal_fees = base_cost * 0.1 * legal_mult * severity_mult

        # Business interruption
        if cvss_score >= 7.0:
            # High severity - significant downtime
            impact.business_interruption = base_cost * 0.3 * severity_mult
        else:
            impact.business_interruption = base_cost * 0.1 * severity_mult

        # Reputational damage (harder to quantify)
        if ctx.public_facing:
            impact.reputational_damage = base_cost * 0.4 * severity_mult * data_mult
        else:
            impact.reputational_damage = base_cost * 0.1 * severity_mult

        # Customer churn (estimate 2-5% based on severity)
        churn_rate = 0.02 + (0.03 * severity_mult)
        if ctx.annual_revenue > 0:
            impact.customer_churn = ctx.annual_revenue * churn_rate * severity_mult

        # Remediation costs
        impact.remediation = base_cost * 0.05 * asset_mult
        impact.security_improvements = base_cost * 0.1

        return impact

    def _calculate_regulatory_impact(
        self,
        vulnerability_type: str,
        data_risk: List[str],
        cvss_score: float,
    ) -> RegulatoryImpact:
        """Calculate regulatory and compliance impact."""
        ctx = self.business_context
        impact = RegulatoryImpact()

        # Determine applicable regulations based on geography and data types
        for reg_name, reg_info in REGULATORY_PROFILES.items():
            applies = False

            # Check geographic applicability
            if "global" in reg_info["applies_to"]:
                applies = True
            else:
                for geo in ctx.geographic_scope:
                    if geo in reg_info["applies_to"] or f"US-{geo}" in reg_info["applies_to"]:
                        applies = True
                        break

            # Check data type applicability
            if applies:
                data_match = False
                for data_type in reg_info["data_types"]:
                    if data_type in data_risk:
                        data_match = True
                        break
                    # Special checks
                    if data_type == "PHI" and ctx.handles_health_data:
                        data_match = True
                    if data_type == "cardholder_data" and ctx.handles_financial_data:
                        data_match = True
                    if data_type == "personal_data" and ctx.handles_pii:
                        data_match = True

                if data_match:
                    impact.applicable_regulations.append(reg_name)

        # Calculate potential violations and fines
        max_fine = 0.0
        notification_deadlines = []

        for reg in impact.applicable_regulations:
            reg_info = REGULATORY_PROFILES[reg]

            # Notification requirements
            if reg_info.get("notification_deadline"):
                impact.notification_required = True
                notification_deadlines.append(reg_info["notification_deadline"])

            # Calculate potential fine
            fine_basis = reg_info.get("max_fine_basis", "")
            if fine_basis == "revenue" and ctx.annual_revenue > 0:
                percentage = reg_info.get("max_fine_percentage", 0)
                fixed = reg_info.get("max_fine_fixed", 0)
                fine = max(ctx.annual_revenue * (percentage / 100), fixed)
            elif fine_basis == "per_violation":
                # Assume significant number of violations for high severity
                estimated_violations = int(100 * (cvss_score / 10))
                fine = estimated_violations * reg_info.get("max_fine_per_violation", 0)
            elif fine_basis == "per_month":
                # Assume 3 months exposure
                fine = 3 * reg_info.get("max_fine_per_month", 0)
            else:
                fine = reg_info.get("max_fine_fixed", 0)

            if fine > max_fine:
                max_fine = fine
                impact.fine_calculation_basis = f"{reg}: {fine_basis}"

        impact.max_fine_amount = max_fine

        if notification_deadlines:
            # Convert hours to days and get minimum
            impact.notification_deadline_days = min(d // 24 for d in notification_deadlines)

        # Determine if audit trigger
        if cvss_score >= 7.0 and impact.applicable_regulations:
            impact.audit_trigger = True

        # License risk for certain industries
        if ctx.industry in [IndustryContext.HEALTHCARE, IndustryContext.FINANCIAL]:
            if cvss_score >= 9.0:
                impact.license_risk = True

        # Add potential violations
        if "PII" in data_risk:
            impact.potential_violations.append("Unauthorized PII disclosure")
        if "credentials" in data_risk:
            impact.potential_violations.append("Credential exposure")
        if "financial" in data_risk:
            impact.potential_violations.append("Financial data breach")
        if "health_data" in data_risk:
            impact.potential_violations.append("PHI breach")

        return impact

    def _calculate_chain_amplification(
        self,
        is_chain_component: bool,
        chain_position: Optional[int],
        chain_size: int,
        cvss_score: float,
    ) -> float:
        """Calculate chain amplification factor."""
        if not is_chain_component or chain_size <= 1:
            return 1.0

        # Base amplification increases with chain length
        base_amp = 1.0 + (0.15 * (chain_size - 1))

        # Position-based modifier (later steps can be more impactful)
        if chain_position is not None:
            position_mod = 1.0 + (0.05 * chain_position)
        else:
            position_mod = 1.0

        # High severity vulnerabilities amplify more
        severity_mod = 1.0 + (0.1 * (cvss_score / 10))

        return base_amp * position_mod * severity_mod

    def _calculate_business_score(
        self,
        cvss_score: float,
        financial_impact: FinancialImpact,
        regulatory_impact: RegulatoryImpact,
    ) -> float:
        """Calculate business impact score (0-10)."""
        # Normalize financial impact to 0-10 scale
        # $10M+ = 10, $1M = 7, $100K = 4, $10K = 1
        total_financial = financial_impact.total_impact
        if total_financial >= 10_000_000:
            financial_score = 10.0
        elif total_financial >= 1_000_000:
            financial_score = 7.0 + (3.0 * (total_financial - 1_000_000) / 9_000_000)
        elif total_financial >= 100_000:
            financial_score = 4.0 + (3.0 * (total_financial - 100_000) / 900_000)
        elif total_financial >= 10_000:
            financial_score = 1.0 + (3.0 * (total_financial - 10_000) / 90_000)
        else:
            financial_score = total_financial / 10_000

        # Regulatory score
        reg_score = 0.0
        if regulatory_impact.applicable_regulations:
            reg_score += 2.0 * len(regulatory_impact.applicable_regulations)
        if regulatory_impact.notification_required:
            reg_score += 2.0
        if regulatory_impact.audit_trigger:
            reg_score += 2.0
        if regulatory_impact.license_risk:
            reg_score += 3.0
        reg_score = min(reg_score, 10.0)

        # Weighted combination
        business_score = (financial_score * 0.6) + (reg_score * 0.4)

        return min(business_score, 10.0)

    def _calculate_overall_risk(
        self,
        technical_score: float,
        business_score: float,
        chain_amplification: float,
    ) -> float:
        """Calculate overall risk score (0-10)."""
        # Weighted combination of technical and business
        base_risk = (technical_score * 0.5) + (business_score * 0.5)

        # Apply chain amplification
        amplified_risk = base_risk * chain_amplification

        return min(amplified_risk, 10.0)

    def _generate_recommendations(
        self,
        vulnerability_type: str,
        cvss: CVSSVector,
        regulatory_impact: RegulatoryImpact,
    ) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []

        # Severity-based recommendations
        if cvss.base_score >= 9.0:
            recommendations.append("CRITICAL: Immediate remediation required within 24 hours")
            recommendations.append("Implement emergency mitigation controls")
        elif cvss.base_score >= 7.0:
            recommendations.append("HIGH: Remediation required within 7 days")
        elif cvss.base_score >= 4.0:
            recommendations.append("MEDIUM: Remediation required within 30 days")
        else:
            recommendations.append("LOW: Remediation recommended within 90 days")

        # Vulnerability-specific recommendations
        vuln_recommendations = {
            "sqli": [
                "Use parameterized queries/prepared statements",
                "Implement input validation and sanitization",
                "Apply least privilege database permissions",
            ],
            "xss": [
                "Implement context-aware output encoding",
                "Use Content-Security-Policy headers",
                "Enable HttpOnly and Secure cookie flags",
            ],
            "cmdi": [
                "Avoid system command execution where possible",
                "Use safe APIs instead of shell commands",
                "Implement strict input validation with allowlists",
            ],
            "ssrf": [
                "Implement URL allowlisting for outbound requests",
                "Block requests to internal/private IP ranges",
                "Use separate network segments for external requests",
            ],
            "auth_bypass": [
                "Implement multi-factor authentication",
                "Review and strengthen authentication logic",
                "Add rate limiting and account lockout",
            ],
            "idor": [
                "Implement proper authorization checks",
                "Use indirect object references",
                "Add access control at the data layer",
            ],
        }

        if vulnerability_type in vuln_recommendations:
            recommendations.extend(vuln_recommendations[vulnerability_type])

        # Regulatory recommendations
        if regulatory_impact.notification_required:
            deadline = regulatory_impact.notification_deadline_days or "required"
            recommendations.append(
                f"Prepare breach notification (deadline: {deadline} days)"
            )

        if regulatory_impact.audit_trigger:
            recommendations.append(
                "Document incident for potential regulatory audit"
            )

        return recommendations

    def _determine_priority(self, risk_score: float) -> str:
        """Determine remediation priority from risk score."""
        if risk_score >= 9.0:
            return "critical"
        elif risk_score >= 7.0:
            return "high"
        elif risk_score >= 4.0:
            return "medium"
        else:
            return "low"

    def get_statistics(self) -> Dict[str, Any]:
        """Get assessment statistics."""
        if not self._assessment_cache:
            return {
                "assessments_count": 0,
                "average_cvss": 0.0,
                "average_risk": 0.0,
            }

        assessments = list(self._assessment_cache.values())
        return {
            "assessments_count": len(assessments),
            "average_cvss": sum(a.cvss.base_score for a in assessments) / len(assessments),
            "average_risk": sum(a.overall_risk_score for a in assessments) / len(assessments),
            "severity_distribution": {
                "critical": sum(1 for a in assessments if a.cvss.severity == SeverityLevel.CRITICAL),
                "high": sum(1 for a in assessments if a.cvss.severity == SeverityLevel.HIGH),
                "medium": sum(1 for a in assessments if a.cvss.severity == SeverityLevel.MEDIUM),
                "low": sum(1 for a in assessments if a.cvss.severity == SeverityLevel.LOW),
            },
            "total_financial_impact": sum(a.financial_impact.total_impact for a in assessments),
            "regulations_triggered": list(set(
                reg for a in assessments for reg in a.regulatory_impact.applicable_regulations
            )),
        }

    def clear_cache(self) -> None:
        """Clear assessment cache."""
        self._assessment_cache.clear()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def assess_vulnerability(
    vulnerability_id: str,
    vulnerability_type: str,
    business_context: Optional[BusinessContext] = None,
    **kwargs,
) -> ImpactAssessmentResult:
    """
    Convenience function to assess a single vulnerability.

    Args:
        vulnerability_id: Unique identifier
        vulnerability_type: Type of vulnerability
        business_context: Optional business context
        **kwargs: Additional arguments for assessment

    Returns:
        Impact assessment result
    """
    engine = ImpactAssessmentEngine(business_context=business_context)
    return engine.assess_vulnerability(
        vulnerability_id=vulnerability_id,
        vulnerability_type=vulnerability_type,
        **kwargs,
    )


def get_vulnerability_profile(vulnerability_type: str) -> Dict[str, Any]:
    """
    Get default vulnerability profile.

    Args:
        vulnerability_type: Type of vulnerability

    Returns:
        Vulnerability profile dictionary
    """
    return VULNERABILITY_PROFILES.get(
        vulnerability_type.lower(),
        VULNERABILITY_PROFILES["unknown"]
    )


def calculate_cvss_score(
    attack_vector: str = "N",
    attack_complexity: str = "L",
    privileges_required: str = "N",
    user_interaction: str = "N",
    scope: str = "U",
    confidentiality: str = "N",
    integrity: str = "N",
    availability: str = "N",
) -> Tuple[float, str]:
    """
    Calculate CVSS v3.1 base score from metrics.

    Args:
        attack_vector: N/A/L/P
        attack_complexity: L/H
        privileges_required: N/L/H
        user_interaction: N/R
        scope: U/C
        confidentiality: N/L/H
        integrity: N/L/H
        availability: N/L/H

    Returns:
        Tuple of (score, vector_string)
    """
    cvss = CVSSVector(
        attack_vector=AttackVector(attack_vector),
        attack_complexity=AttackComplexity(attack_complexity),
        privileges_required=PrivilegesRequired(privileges_required),
        user_interaction=UserInteraction(user_interaction),
        scope=Scope(scope),
        cia=CIATriad(
            confidentiality=ImpactLevel(confidentiality),
            integrity=ImpactLevel(integrity),
            availability=ImpactLevel(availability),
        ),
    )
    return cvss.base_score, cvss.vector_string


# =============================================================================
# EXPORTS
# =============================================================================


__all__ = [
    # Version
    "ImpactAssessmentEngine",

    # Enums
    "AttackVector",
    "AttackComplexity",
    "PrivilegesRequired",
    "UserInteraction",
    "Scope",
    "ImpactLevel",
    "SeverityLevel",
    "IndustryContext",
    "DataClassification",
    "AssetCriticality",

    # Data classes
    "CIATriad",
    "CVSSVector",
    "FinancialImpact",
    "RegulatoryImpact",
    "BusinessContext",
    "ImpactAssessmentResult",

    # Constants
    "VULNERABILITY_PROFILES",
    "REGULATORY_PROFILES",
    "COST_PER_RECORD",
    "BASE_BREACH_COST",

    # Convenience functions
    "assess_vulnerability",
    "get_vulnerability_profile",
    "calculate_cvss_score",
]
