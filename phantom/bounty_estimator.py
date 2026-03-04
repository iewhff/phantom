"""
PHANTOM AI - Bounty Estimator Module

Estimates bug bounty values for discovered vulnerabilities.
Supports HackerOne, Bugcrowd, Intigriti, and custom programs.

Version: 3.0.0
Date: 2026-01-30

Features:
- Platform-specific bounty ranges
- Severity-based calculations
- Vulnerability type modifiers
- Chain bonus calculations
- Impact multipliers
- Historical data integration
- Program-specific customization
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS
# =============================================================================


class BountyPlatform(Enum):
    """Bug bounty platforms."""

    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    SYNACK = "synack"
    YESWEHACK = "yeswehack"
    COBALT = "cobalt"
    PRIVATE = "private"
    CUSTOM = "custom"
    OTHER = "other"


class ProgramTier(Enum):
    """Program tier levels based on typical bounty ranges."""

    ENTRY = auto()          # Small companies, low bounties
    STANDARD = auto()       # Medium companies
    PREMIUM = auto()        # Large companies
    ENTERPRISE = auto()     # Enterprise companies
    TOP_TIER = auto()       # Tech giants (Google, Meta, etc.)


class SeverityLevel(Enum):
    """Vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class VulnerabilityImpact(Enum):
    """Vulnerability impact categories."""

    RCE = "rce"                          # Remote Code Execution
    ACCOUNT_TAKEOVER = "account_takeover"
    DATA_BREACH = "data_breach"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    BUSINESS_LOGIC = "business_logic"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    LOW_IMPACT = "low_impact"


# =============================================================================
# BOUNTY RANGE DATA
# =============================================================================


# Base bounty ranges by platform and tier (min, max in USD)
PLATFORM_RANGES: Dict[BountyPlatform, Dict[ProgramTier, Dict[SeverityLevel, Tuple[int, int]]]] = {
    BountyPlatform.HACKERONE: {
        ProgramTier.ENTRY: {
            SeverityLevel.CRITICAL: (500, 3000),
            SeverityLevel.HIGH: (200, 1500),
            SeverityLevel.MEDIUM: (100, 500),
            SeverityLevel.LOW: (50, 200),
            SeverityLevel.INFORMATIONAL: (0, 50),
        },
        ProgramTier.STANDARD: {
            SeverityLevel.CRITICAL: (3000, 10000),
            SeverityLevel.HIGH: (1000, 5000),
            SeverityLevel.MEDIUM: (300, 1500),
            SeverityLevel.LOW: (100, 500),
            SeverityLevel.INFORMATIONAL: (0, 100),
        },
        ProgramTier.PREMIUM: {
            SeverityLevel.CRITICAL: (10000, 25000),
            SeverityLevel.HIGH: (3000, 10000),
            SeverityLevel.MEDIUM: (1000, 3000),
            SeverityLevel.LOW: (250, 1000),
            SeverityLevel.INFORMATIONAL: (0, 250),
        },
        ProgramTier.ENTERPRISE: {
            SeverityLevel.CRITICAL: (15000, 50000),
            SeverityLevel.HIGH: (5000, 15000),
            SeverityLevel.MEDIUM: (1500, 5000),
            SeverityLevel.LOW: (500, 1500),
            SeverityLevel.INFORMATIONAL: (0, 500),
        },
        ProgramTier.TOP_TIER: {
            SeverityLevel.CRITICAL: (30000, 100000),
            SeverityLevel.HIGH: (10000, 30000),
            SeverityLevel.MEDIUM: (3000, 10000),
            SeverityLevel.LOW: (1000, 3000),
            SeverityLevel.INFORMATIONAL: (100, 1000),
        },
    },
    BountyPlatform.BUGCROWD: {
        ProgramTier.ENTRY: {
            SeverityLevel.CRITICAL: (400, 2500),
            SeverityLevel.HIGH: (150, 1200),
            SeverityLevel.MEDIUM: (75, 400),
            SeverityLevel.LOW: (25, 150),
            SeverityLevel.INFORMATIONAL: (0, 25),
        },
        ProgramTier.STANDARD: {
            SeverityLevel.CRITICAL: (2500, 8000),
            SeverityLevel.HIGH: (800, 4000),
            SeverityLevel.MEDIUM: (250, 1200),
            SeverityLevel.LOW: (75, 400),
            SeverityLevel.INFORMATIONAL: (0, 75),
        },
        ProgramTier.PREMIUM: {
            SeverityLevel.CRITICAL: (8000, 20000),
            SeverityLevel.HIGH: (2500, 8000),
            SeverityLevel.MEDIUM: (800, 2500),
            SeverityLevel.LOW: (200, 800),
            SeverityLevel.INFORMATIONAL: (0, 200),
        },
        ProgramTier.ENTERPRISE: {
            SeverityLevel.CRITICAL: (12000, 40000),
            SeverityLevel.HIGH: (4000, 12000),
            SeverityLevel.MEDIUM: (1200, 4000),
            SeverityLevel.LOW: (400, 1200),
            SeverityLevel.INFORMATIONAL: (0, 400),
        },
        ProgramTier.TOP_TIER: {
            SeverityLevel.CRITICAL: (25000, 80000),
            SeverityLevel.HIGH: (8000, 25000),
            SeverityLevel.MEDIUM: (2500, 8000),
            SeverityLevel.LOW: (800, 2500),
            SeverityLevel.INFORMATIONAL: (50, 800),
        },
    },
    BountyPlatform.INTIGRITI: {
        ProgramTier.ENTRY: {
            SeverityLevel.CRITICAL: (300, 2000),
            SeverityLevel.HIGH: (100, 1000),
            SeverityLevel.MEDIUM: (50, 300),
            SeverityLevel.LOW: (25, 100),
            SeverityLevel.INFORMATIONAL: (0, 25),
        },
        ProgramTier.STANDARD: {
            SeverityLevel.CRITICAL: (2000, 7000),
            SeverityLevel.HIGH: (700, 3500),
            SeverityLevel.MEDIUM: (200, 1000),
            SeverityLevel.LOW: (50, 350),
            SeverityLevel.INFORMATIONAL: (0, 50),
        },
        ProgramTier.PREMIUM: {
            SeverityLevel.CRITICAL: (7000, 18000),
            SeverityLevel.HIGH: (2000, 7000),
            SeverityLevel.MEDIUM: (700, 2000),
            SeverityLevel.LOW: (150, 700),
            SeverityLevel.INFORMATIONAL: (0, 150),
        },
        ProgramTier.ENTERPRISE: {
            SeverityLevel.CRITICAL: (10000, 35000),
            SeverityLevel.HIGH: (3500, 10000),
            SeverityLevel.MEDIUM: (1000, 3500),
            SeverityLevel.LOW: (350, 1000),
            SeverityLevel.INFORMATIONAL: (0, 350),
        },
        ProgramTier.TOP_TIER: {
            SeverityLevel.CRITICAL: (20000, 70000),
            SeverityLevel.HIGH: (7000, 20000),
            SeverityLevel.MEDIUM: (2000, 7000),
            SeverityLevel.LOW: (700, 2000),
            SeverityLevel.INFORMATIONAL: (50, 700),
        },
    },
}

# Default ranges for platforms not explicitly defined
DEFAULT_RANGES: Dict[ProgramTier, Dict[SeverityLevel, Tuple[int, int]]] = {
    ProgramTier.ENTRY: {
        SeverityLevel.CRITICAL: (300, 2000),
        SeverityLevel.HIGH: (100, 1000),
        SeverityLevel.MEDIUM: (50, 300),
        SeverityLevel.LOW: (25, 100),
        SeverityLevel.INFORMATIONAL: (0, 25),
    },
    ProgramTier.STANDARD: {
        SeverityLevel.CRITICAL: (2000, 8000),
        SeverityLevel.HIGH: (800, 4000),
        SeverityLevel.MEDIUM: (250, 1200),
        SeverityLevel.LOW: (75, 400),
        SeverityLevel.INFORMATIONAL: (0, 75),
    },
    ProgramTier.PREMIUM: {
        SeverityLevel.CRITICAL: (8000, 20000),
        SeverityLevel.HIGH: (2500, 8000),
        SeverityLevel.MEDIUM: (800, 2500),
        SeverityLevel.LOW: (200, 800),
        SeverityLevel.INFORMATIONAL: (0, 200),
    },
    ProgramTier.ENTERPRISE: {
        SeverityLevel.CRITICAL: (12000, 40000),
        SeverityLevel.HIGH: (4000, 12000),
        SeverityLevel.MEDIUM: (1200, 4000),
        SeverityLevel.LOW: (400, 1200),
        SeverityLevel.INFORMATIONAL: (0, 400),
    },
    ProgramTier.TOP_TIER: {
        SeverityLevel.CRITICAL: (25000, 80000),
        SeverityLevel.HIGH: (8000, 25000),
        SeverityLevel.MEDIUM: (2500, 8000),
        SeverityLevel.LOW: (800, 2500),
        SeverityLevel.INFORMATIONAL: (50, 800),
    },
}


# =============================================================================
# VULNERABILITY TYPE MODIFIERS
# =============================================================================


# Modifiers adjust the base bounty range based on vulnerability type
VULNERABILITY_MODIFIERS: Dict[str, float] = {
    # Injection vulnerabilities
    "sqli": 1.0,
    "nosql": 0.95,
    "cmdi": 1.15,           # Command injection is very impactful
    "ssti": 1.1,
    "xxe": 0.95,
    "ldap": 0.85,
    "crlf": 0.7,
    "lfi": 0.9,
    "rfi": 1.0,

    # XSS variants
    "xss": 0.75,            # Reflected XSS is common
    "stored_xss": 0.9,      # Stored XSS is more impactful
    "dom_xss": 0.7,

    # Authentication/Authorization
    "auth_bypass": 1.1,
    "broken_auth": 1.0,
    "session_fixation": 0.8,
    "session_hijacking": 0.9,
    "jwt_vuln": 0.95,
    "oauth_vuln": 0.95,
    "saml_vuln": 0.95,
    "mfa_bypass": 1.1,

    # Access Control
    "idor": 0.85,
    "privilege_escalation": 1.05,
    "horizontal_priv_esc": 0.9,
    "vertical_priv_esc": 1.0,

    # Server-Side
    "ssrf": 1.0,
    "rce": 1.25,            # RCE is the holy grail
    "insecure_deserialization": 1.1,
    "file_upload": 0.95,

    # Client-Side
    "csrf": 0.65,           # CSRF is less impactful now
    "clickjacking": 0.5,
    "cors": 0.6,
    "open_redirect": 0.5,

    # Information Disclosure
    "info_disclosure": 0.5,
    "path_disclosure": 0.4,
    "stack_trace": 0.35,
    "sensitive_data_exposure": 0.8,
    "pii_exposure": 0.9,

    # Infrastructure
    "ssl_tls": 0.4,
    "misconfiguration": 0.5,
    "security_headers": 0.35,
    "subdomain_takeover": 0.75,

    # Business Logic
    "business_logic": 0.85,
    "rate_limiting": 0.55,
    "race_condition": 0.8,

    # API-specific
    "api_vuln": 0.8,
    "graphql_vuln": 0.8,
    "mass_assignment": 0.7,
    "api_key_exposure": 0.7,

    # Default
    "unknown": 0.7,
}


# =============================================================================
# IMPACT MODIFIERS
# =============================================================================


IMPACT_MODIFIERS: Dict[VulnerabilityImpact, float] = {
    VulnerabilityImpact.RCE: 1.3,
    VulnerabilityImpact.ACCOUNT_TAKEOVER: 1.2,
    VulnerabilityImpact.DATA_BREACH: 1.25,
    VulnerabilityImpact.PRIVILEGE_ESCALATION: 1.1,
    VulnerabilityImpact.AUTHENTICATION_BYPASS: 1.1,
    VulnerabilityImpact.SENSITIVE_DATA_EXPOSURE: 1.0,
    VulnerabilityImpact.BUSINESS_LOGIC: 0.9,
    VulnerabilityImpact.INFORMATION_DISCLOSURE: 0.7,
    VulnerabilityImpact.DENIAL_OF_SERVICE: 0.6,
    VulnerabilityImpact.LOW_IMPACT: 0.5,
}


# =============================================================================
# CHAIN BONUSES
# =============================================================================


# Bonus multipliers for vulnerability chains
CHAIN_BONUSES: Dict[int, float] = {
    1: 1.0,     # Single vulnerability (no bonus)
    2: 1.2,     # 2-step chain (+20%)
    3: 1.4,     # 3-step chain (+40%)
    4: 1.6,     # 4-step chain (+60%)
    5: 1.8,     # 5+ step chain (+80%)
}


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class ProgramConfig:
    """Bug bounty program configuration."""

    name: str
    platform: BountyPlatform = BountyPlatform.HACKERONE
    tier: ProgramTier = ProgramTier.STANDARD
    custom_ranges: Optional[Dict[SeverityLevel, Tuple[int, int]]] = None
    bonus_multiplier: float = 1.0  # For special bonuses/promotions
    in_scope_bonus: float = 1.0    # For critical scope items
    vdp_only: bool = False         # Vulnerability Disclosure Program (no bounty)

    def get_range(self, severity: SeverityLevel) -> Tuple[int, int]:
        """Get bounty range for severity level."""
        if self.vdp_only:
            return (0, 0)

        if self.custom_ranges and severity in self.custom_ranges:
            return self.custom_ranges[severity]

        platform_ranges = PLATFORM_RANGES.get(
            self.platform,
            DEFAULT_RANGES
        )

        if isinstance(platform_ranges, dict) and self.tier in platform_ranges:
            tier_ranges = platform_ranges[self.tier]
        else:
            tier_ranges = DEFAULT_RANGES[self.tier]

        return tier_ranges.get(severity, (0, 0))


@dataclass
class BountyEstimate:
    """Bounty estimate result."""

    vulnerability_id: str
    vulnerability_type: str
    severity: SeverityLevel
    estimated_range: Tuple[int, int]
    expected_value: float
    confidence: float
    modifiers_applied: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Chain info
    is_chain: bool = False
    chain_size: int = 1
    chain_bonus: float = 1.0

    # Program info
    program_name: Optional[str] = None
    platform: Optional[str] = None

    @property
    def formatted_range(self) -> str:
        """Get formatted range string."""
        min_val, max_val = self.estimated_range
        if min_val == 0 and max_val == 0:
            return "N/A (VDP)"
        return f"${min_val:,} - ${max_val:,}"

    @property
    def formatted_expected(self) -> str:
        """Get formatted expected value."""
        if self.expected_value == 0:
            return "N/A"
        return f"${self.expected_value:,.0f}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "vulnerability_id": self.vulnerability_id,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity.value,
            "estimated_range": {
                "min": self.estimated_range[0],
                "max": self.estimated_range[1],
                "formatted": self.formatted_range,
            },
            "expected_value": self.expected_value,
            "expected_formatted": self.formatted_expected,
            "confidence": self.confidence,
            "modifiers_applied": self.modifiers_applied,
            "notes": self.notes,
            "is_chain": self.is_chain,
            "chain_size": self.chain_size,
            "chain_bonus": self.chain_bonus,
            "program_name": self.program_name,
            "platform": self.platform,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ChainBountyEstimate:
    """Bounty estimate for a vulnerability chain."""

    chain_id: str
    chain_size: int
    individual_estimates: List[BountyEstimate]
    total_range: Tuple[int, int]
    total_expected: float
    chain_bonus_applied: float
    severity: SeverityLevel
    notes: List[str] = field(default_factory=list)

    @property
    def formatted_total(self) -> str:
        """Get formatted total range."""
        min_val, max_val = self.total_range
        return f"${min_val:,} - ${max_val:,}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "chain_id": self.chain_id,
            "chain_size": self.chain_size,
            "individual_estimates": [e.to_dict() for e in self.individual_estimates],
            "total_range": {
                "min": self.total_range[0],
                "max": self.total_range[1],
                "formatted": self.formatted_total,
            },
            "total_expected": self.total_expected,
            "chain_bonus_applied": self.chain_bonus_applied,
            "severity": self.severity.value,
            "notes": self.notes,
        }


# =============================================================================
# BOUNTY ESTIMATOR ENGINE
# =============================================================================


class BountyEstimator:
    """
    PHANTOM AI Bounty Estimator.

    Estimates bug bounty values for discovered vulnerabilities
    based on platform, program tier, severity, and impact.
    """

    VERSION = "3.0.0"

    def __init__(
        self,
        program: Optional[ProgramConfig] = None,
    ) -> None:
        """
        Initialize bounty estimator.

        Args:
            program: Optional program configuration
        """
        self.program = program or ProgramConfig(
            name="Default Program",
            platform=BountyPlatform.HACKERONE,
            tier=ProgramTier.STANDARD,
        )
        self._estimates: List[BountyEstimate] = []

        logger.info(f"BountyEstimator v{self.VERSION} initialized")

    def set_program(self, program: ProgramConfig) -> None:
        """
        Set program configuration.

        Args:
            program: Program configuration
        """
        self.program = program
        logger.info(f"Program set to: {program.name} ({program.platform.value})")

    def estimate(
        self,
        vulnerability_id: str,
        vulnerability_type: str,
        severity: str,
        cvss_score: Optional[float] = None,
        impact: Optional[VulnerabilityImpact] = None,
        is_chain: bool = False,
        chain_size: int = 1,
        in_scope: bool = True,
        quality_bonus: float = 1.0,
    ) -> BountyEstimate:
        """
        Estimate bounty for a vulnerability.

        Args:
            vulnerability_id: Unique identifier
            vulnerability_type: Type of vulnerability
            severity: Severity level (critical, high, medium, low, informational)
            cvss_score: Optional CVSS score for adjustment
            impact: Impact category
            is_chain: Whether this is part of a chain
            chain_size: Size of the chain
            in_scope: Whether target is in critical scope
            quality_bonus: Quality of report bonus (1.0 = standard)

        Returns:
            BountyEstimate with range and expected value
        """
        # Parse severity
        try:
            severity_level = SeverityLevel(severity.lower())
        except ValueError:
            severity_level = self._cvss_to_severity(cvss_score) if cvss_score else SeverityLevel.MEDIUM

        # Get base range from program config
        base_min, base_max = self.program.get_range(severity_level)

        # Apply vulnerability type modifier
        vuln_modifier = VULNERABILITY_MODIFIERS.get(
            vulnerability_type.lower(),
            VULNERABILITY_MODIFIERS["unknown"]
        )

        # Apply impact modifier
        impact_modifier = 1.0
        if impact:
            impact_modifier = IMPACT_MODIFIERS.get(impact, 1.0)

        # Apply chain bonus
        chain_bonus = 1.0
        if is_chain and chain_size > 1:
            chain_bonus = CHAIN_BONUSES.get(
                min(chain_size, 5),
                CHAIN_BONUSES[5]
            )

        # Apply scope bonus
        scope_modifier = self.program.in_scope_bonus if in_scope else 1.0

        # Apply program bonus (promotions, etc.)
        program_bonus = self.program.bonus_multiplier

        # Calculate final modifiers
        total_modifier = (
            vuln_modifier
            * impact_modifier
            * chain_bonus
            * scope_modifier
            * program_bonus
            * quality_bonus
        )

        # Calculate adjusted range
        adjusted_min = int(base_min * total_modifier)
        adjusted_max = int(base_max * total_modifier)

        # Calculate expected value (weighted average)
        # Assumes normal distribution around 60% of range
        expected = adjusted_min + (adjusted_max - adjusted_min) * 0.6

        # Calculate confidence based on data quality
        confidence = self._calculate_confidence(
            severity_level=severity_level,
            has_cvss=cvss_score is not None,
            has_impact=impact is not None,
            is_standard_type=vulnerability_type.lower() in VULNERABILITY_MODIFIERS,
        )

        # Build modifiers list
        modifiers_applied = []
        if vuln_modifier != 1.0:
            modifiers_applied.append(f"vuln_type:{vuln_modifier:.2f}")
        if impact_modifier != 1.0:
            modifiers_applied.append(f"impact:{impact_modifier:.2f}")
        if chain_bonus != 1.0:
            modifiers_applied.append(f"chain:{chain_bonus:.2f}")
        if scope_modifier != 1.0:
            modifiers_applied.append(f"scope:{scope_modifier:.2f}")
        if program_bonus != 1.0:
            modifiers_applied.append(f"program:{program_bonus:.2f}")
        if quality_bonus != 1.0:
            modifiers_applied.append(f"quality:{quality_bonus:.2f}")

        # Build notes
        notes = []
        if self.program.vdp_only:
            notes.append("VDP program - no monetary bounty expected")
        if chain_size > 1:
            notes.append(f"Chain of {chain_size} vulnerabilities")
        if cvss_score and cvss_score >= 9.0:
            notes.append("Critical CVSS score may warrant higher payout")

        estimate = BountyEstimate(
            vulnerability_id=vulnerability_id,
            vulnerability_type=vulnerability_type,
            severity=severity_level,
            estimated_range=(adjusted_min, adjusted_max),
            expected_value=expected,
            confidence=confidence,
            modifiers_applied=modifiers_applied,
            notes=notes,
            is_chain=is_chain,
            chain_size=chain_size,
            chain_bonus=chain_bonus,
            program_name=self.program.name,
            platform=self.program.platform.value,
        )

        self._estimates.append(estimate)
        return estimate

    def estimate_chain(
        self,
        chain: Dict[str, Any],
        in_scope: bool = True,
    ) -> ChainBountyEstimate:
        """
        Estimate bounty for a vulnerability chain.

        Args:
            chain: Chain data from ChainActionsEngine
            in_scope: Whether target is in critical scope

        Returns:
            ChainBountyEstimate with total range
        """
        chain_id = chain.get("chain_id", "unknown")
        vulnerabilities = chain.get("vulnerabilities", [])
        chain_size = len(vulnerabilities)

        # Estimate each vulnerability
        individual_estimates: List[BountyEstimate] = []
        max_severity = SeverityLevel.INFORMATIONAL

        for vuln in vulnerabilities:
            estimate = self.estimate(
                vulnerability_id=vuln.get("id", ""),
                vulnerability_type=vuln.get("type", "unknown"),
                severity=vuln.get("severity", "medium"),
                cvss_score=vuln.get("cvss_score"),
                is_chain=True,
                chain_size=chain_size,
                in_scope=in_scope,
            )
            individual_estimates.append(estimate)

            # Track max severity
            if self._severity_rank(estimate.severity) > self._severity_rank(max_severity):
                max_severity = estimate.severity

        # Chain bonus for total
        chain_bonus = CHAIN_BONUSES.get(
            min(chain_size, 5),
            CHAIN_BONUSES[5]
        )

        # For chains, use the highest severity individual bounty
        # with additional chain bonus
        if individual_estimates:
            # Get the highest estimate
            best_estimate = max(
                individual_estimates,
                key=lambda e: e.expected_value
            )

            # Apply chain-level bonus
            total_min = int(best_estimate.estimated_range[0] * chain_bonus)
            total_max = int(best_estimate.estimated_range[1] * chain_bonus)
            total_expected = best_estimate.expected_value * chain_bonus
        else:
            total_min, total_max = 0, 0
            total_expected = 0

        notes = [
            f"Chain of {chain_size} vulnerabilities",
            f"Chain bonus: {chain_bonus:.1f}x",
        ]

        if chain.get("outcome"):
            notes.append(f"Chain outcome: {chain['outcome']}")

        return ChainBountyEstimate(
            chain_id=chain_id,
            chain_size=chain_size,
            individual_estimates=individual_estimates,
            total_range=(total_min, total_max),
            total_expected=total_expected,
            chain_bonus_applied=chain_bonus,
            severity=max_severity,
            notes=notes,
        )

    def estimate_findings(
        self,
        findings: List[Dict[str, Any]],
        in_scope: bool = True,
    ) -> List[BountyEstimate]:
        """
        Estimate bounties for multiple findings.

        Args:
            findings: List of finding dictionaries
            in_scope: Whether targets are in critical scope

        Returns:
            List of bounty estimates
        """
        estimates = []
        for finding in findings:
            estimate = self.estimate(
                vulnerability_id=finding.get("id", ""),
                vulnerability_type=finding.get("type", "unknown"),
                severity=finding.get("severity", "medium"),
                cvss_score=finding.get("cvss_score"),
                in_scope=in_scope,
            )
            estimates.append(estimate)
        return estimates

    def get_total_estimate(self) -> Dict[str, Any]:
        """
        Get total estimated bounty for all findings.

        Returns:
            Dictionary with total ranges and statistics
        """
        if not self._estimates:
            return {
                "total_min": 0,
                "total_max": 0,
                "total_expected": 0,
                "finding_count": 0,
            }

        total_min = sum(e.estimated_range[0] for e in self._estimates)
        total_max = sum(e.estimated_range[1] for e in self._estimates)
        total_expected = sum(e.expected_value for e in self._estimates)

        # Severity distribution
        severity_dist = {}
        for severity in SeverityLevel:
            count = sum(1 for e in self._estimates if e.severity == severity)
            if count > 0:
                severity_dist[severity.value] = count

        return {
            "total_min": total_min,
            "total_max": total_max,
            "total_expected": total_expected,
            "formatted_range": f"${total_min:,} - ${total_max:,}",
            "formatted_expected": f"${total_expected:,.0f}",
            "finding_count": len(self._estimates),
            "severity_distribution": severity_dist,
            "program": self.program.name,
            "platform": self.program.platform.value,
            "tier": self.program.tier.name,
        }

    def _cvss_to_severity(self, cvss: float) -> SeverityLevel:
        """Convert CVSS score to severity level."""
        if cvss >= 9.0:
            return SeverityLevel.CRITICAL
        elif cvss >= 7.0:
            return SeverityLevel.HIGH
        elif cvss >= 4.0:
            return SeverityLevel.MEDIUM
        elif cvss > 0:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFORMATIONAL

    def _severity_rank(self, severity: SeverityLevel) -> int:
        """Get numeric rank for severity comparison."""
        ranks = {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH: 4,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFORMATIONAL: 1,
        }
        return ranks.get(severity, 0)

    def _calculate_confidence(
        self,
        severity_level: SeverityLevel,
        has_cvss: bool,
        has_impact: bool,
        is_standard_type: bool,
    ) -> float:
        """Calculate estimation confidence."""
        base_confidence = 0.6

        # Adjustments
        if has_cvss:
            base_confidence += 0.1
        if has_impact:
            base_confidence += 0.1
        if is_standard_type:
            base_confidence += 0.1

        # Lower confidence for extreme severities (more variance)
        if severity_level == SeverityLevel.CRITICAL:
            base_confidence -= 0.1
        elif severity_level == SeverityLevel.INFORMATIONAL:
            base_confidence -= 0.05

        return min(max(base_confidence, 0.3), 0.95)

    def clear_estimates(self) -> None:
        """Clear stored estimates."""
        self._estimates.clear()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def estimate_bounty(
    vulnerability_type: str,
    severity: str,
    platform: str = "hackerone",
    tier: str = "standard",
    cvss_score: Optional[float] = None,
) -> BountyEstimate:
    """
    Quick bounty estimation.

    Args:
        vulnerability_type: Type of vulnerability
        severity: Severity level
        platform: Bug bounty platform
        tier: Program tier
        cvss_score: Optional CVSS score

    Returns:
        BountyEstimate
    """
    program = ProgramConfig(
        name="Quick Estimate",
        platform=BountyPlatform(platform.lower()),
        tier=ProgramTier[tier.upper()],
    )

    estimator = BountyEstimator(program=program)
    return estimator.estimate(
        vulnerability_id="quick-estimate",
        vulnerability_type=vulnerability_type,
        severity=severity,
        cvss_score=cvss_score,
    )


def create_program_config(
    name: str,
    platform: str = "hackerone",
    tier: str = "standard",
    custom_ranges: Optional[Dict[str, Tuple[int, int]]] = None,
    vdp_only: bool = False,
) -> ProgramConfig:
    """
    Create a program configuration.

    Args:
        name: Program name
        platform: Platform name
        tier: Program tier
        custom_ranges: Optional custom bounty ranges
        vdp_only: Whether program is VDP only

    Returns:
        ProgramConfig
    """
    ranges = None
    if custom_ranges:
        ranges = {
            SeverityLevel(k): v for k, v in custom_ranges.items()
        }

    return ProgramConfig(
        name=name,
        platform=BountyPlatform(platform.lower()),
        tier=ProgramTier[tier.upper()],
        custom_ranges=ranges,
        vdp_only=vdp_only,
    )


# =============================================================================
# EXPORTS
# =============================================================================


__all__ = [
    # Main class
    "BountyEstimator",

    # Data classes
    "ProgramConfig",
    "BountyEstimate",
    "ChainBountyEstimate",

    # Enums
    "BountyPlatform",
    "ProgramTier",
    "SeverityLevel",
    "VulnerabilityImpact",

    # Constants
    "PLATFORM_RANGES",
    "DEFAULT_RANGES",
    "VULNERABILITY_MODIFIERS",
    "IMPACT_MODIFIERS",
    "CHAIN_BONUSES",

    # Convenience functions
    "estimate_bounty",
    "create_program_config",
]
