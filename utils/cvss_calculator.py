"""
CVSS (Common Vulnerability Scoring System) calculator.

Supports CVSS v3.1 calculations.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)


class AttackVector(Enum):
    """CVSS Attack Vector (AV)."""
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"


class AttackComplexity(Enum):
    """CVSS Attack Complexity (AC)."""
    LOW = "L"
    HIGH = "H"


class PrivilegesRequired(Enum):
    """CVSS Privileges Required (PR)."""
    NONE = "N"
    LOW = "L"
    HIGH = "H"


class UserInteraction(Enum):
    """CVSS User Interaction (UI)."""
    NONE = "N"
    REQUIRED = "R"


class Scope(Enum):
    """CVSS Scope (S)."""
    UNCHANGED = "U"
    CHANGED = "C"


class Impact(Enum):
    """CVSS Impact (C/I/A)."""
    NONE = "N"
    LOW = "L"
    HIGH = "H"


@dataclass
class CVSSVector:
    """CVSS v3.1 vector."""
    
    attack_vector: AttackVector = AttackVector.NETWORK
    attack_complexity: AttackComplexity = AttackComplexity.LOW
    privileges_required: PrivilegesRequired = PrivilegesRequired.NONE
    user_interaction: UserInteraction = UserInteraction.NONE
    scope: Scope = Scope.UNCHANGED
    confidentiality: Impact = Impact.NONE
    integrity: Impact = Impact.NONE
    availability: Impact = Impact.NONE
    
    @classmethod
    def from_string(cls, vector_string: str) -> CVSSVector:
        """
        Parse CVSS vector string.
        
        Args:
            vector_string: CVSS vector (e.g., "CVSS:3.1/AV:N/AC:L/...")
            
        Returns:
            Parsed CVSSVector
        """
        # Remove prefix
        if vector_string.startswith("CVSS:"):
            parts = vector_string.split("/")[1:]  # Skip version
        else:
            parts = vector_string.split("/")
        
        values = {}
        for part in parts:
            if ":" in part:
                key, value = part.split(":", 1)
                values[key] = value
        
        return cls(
            attack_vector=AttackVector(values.get("AV", "N")),
            attack_complexity=AttackComplexity(values.get("AC", "L")),
            privileges_required=PrivilegesRequired(values.get("PR", "N")),
            user_interaction=UserInteraction(values.get("UI", "N")),
            scope=Scope(values.get("S", "U")),
            confidentiality=Impact(values.get("C", "N")),
            integrity=Impact(values.get("I", "N")),
            availability=Impact(values.get("A", "N")),
        )
    
    def to_string(self) -> str:
        """
        Convert to CVSS vector string.
        
        Returns:
            CVSS vector string
        """
        return (
            f"CVSS:3.1/AV:{self.attack_vector.value}/"
            f"AC:{self.attack_complexity.value}/"
            f"PR:{self.privileges_required.value}/"
            f"UI:{self.user_interaction.value}/"
            f"S:{self.scope.value}/"
            f"C:{self.confidentiality.value}/"
            f"I:{self.integrity.value}/"
            f"A:{self.availability.value}"
        )


class CVSSCalculator:
    """
    CVSS v3.1 score calculator.
    
    Based on CVSS v3.1 specification.
    """
    
    # Weight values for CVSS v3.1
    AV_WEIGHTS = {
        AttackVector.NETWORK: 0.85,
        AttackVector.ADJACENT: 0.62,
        AttackVector.LOCAL: 0.55,
        AttackVector.PHYSICAL: 0.2,
    }
    
    AC_WEIGHTS = {
        AttackComplexity.LOW: 0.77,
        AttackComplexity.HIGH: 0.44,
    }
    
    PR_WEIGHTS_UNCHANGED = {
        PrivilegesRequired.NONE: 0.85,
        PrivilegesRequired.LOW: 0.62,
        PrivilegesRequired.HIGH: 0.27,
    }
    
    PR_WEIGHTS_CHANGED = {
        PrivilegesRequired.NONE: 0.85,
        PrivilegesRequired.LOW: 0.68,
        PrivilegesRequired.HIGH: 0.50,
    }
    
    UI_WEIGHTS = {
        UserInteraction.NONE: 0.85,
        UserInteraction.REQUIRED: 0.62,
    }
    
    IMPACT_WEIGHTS = {
        Impact.NONE: 0,
        Impact.LOW: 0.22,
        Impact.HIGH: 0.56,
    }
    
    def calculate(self, vector: CVSSVector) -> dict[str, Any]:
        """
        Calculate CVSS score from vector.
        
        Args:
            vector: CVSS vector
            
        Returns:
            Dictionary with score, severity, and components
        """
        # Exploitability
        av = self.AV_WEIGHTS[vector.attack_vector]
        ac = self.AC_WEIGHTS[vector.attack_complexity]
        
        if vector.scope == Scope.UNCHANGED:
            pr = self.PR_WEIGHTS_UNCHANGED[vector.privileges_required]
        else:
            pr = self.PR_WEIGHTS_CHANGED[vector.privileges_required]
        
        ui = self.UI_WEIGHTS[vector.user_interaction]
        
        exploitability = 8.22 * av * ac * pr * ui
        
        # Impact
        isc_conf = self.IMPACT_WEIGHTS[vector.confidentiality]
        isc_integ = self.IMPACT_WEIGHTS[vector.integrity]
        isc_avail = self.IMPACT_WEIGHTS[vector.availability]
        
        isc = 1 - (1 - isc_conf) * (1 - isc_integ) * (1 - isc_avail)
        
        if vector.scope == Scope.UNCHANGED:
            impact = 6.42 * isc
        else:
            impact = 7.52 * (isc - 0.029) - 3.25 * pow(isc - 0.02, 15)
        
        # Base score
        if impact <= 0:
            base_score = 0.0
        else:
            if vector.scope == Scope.UNCHANGED:
                base_score = min(impact + exploitability, 10)
            else:
                base_score = min(1.08 * (impact + exploitability), 10)
        
        # Round up to 1 decimal place
        base_score = self._roundup(base_score)
        
        return {
            "score": base_score,
            "severity": self._get_severity(base_score),
            "exploitability": round(exploitability, 2),
            "impact": round(impact, 2),
            "vector_string": vector.to_string(),
        }
    
    def calculate_from_string(self, vector_string: str) -> dict[str, Any]:
        """
        Calculate score from vector string.
        
        Args:
            vector_string: CVSS vector string
            
        Returns:
            Score dictionary
        """
        vector = CVSSVector.from_string(vector_string)
        return self.calculate(vector)
    
    def estimate_from_vulnerability(
        self,
        vuln_type: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Estimate CVSS from vulnerability type.
        
        Args:
            vuln_type: Vulnerability type/name
            context: Additional context
            
        Returns:
            Estimated score dictionary
        """
        vuln_type = vuln_type.upper()
        context = context or {}
        
        # Common vulnerability patterns
        patterns = {
            "SQL_INJECTION": CVSSVector(
                attack_vector=AttackVector.NETWORK,
                attack_complexity=AttackComplexity.LOW,
                privileges_required=PrivilegesRequired.NONE,
                user_interaction=UserInteraction.NONE,
                scope=Scope.UNCHANGED,
                confidentiality=Impact.HIGH,
                integrity=Impact.HIGH,
                availability=Impact.HIGH,
            ),
            "XSS": CVSSVector(
                attack_vector=AttackVector.NETWORK,
                attack_complexity=AttackComplexity.LOW,
                privileges_required=PrivilegesRequired.NONE,
                user_interaction=UserInteraction.REQUIRED,
                scope=Scope.CHANGED,
                confidentiality=Impact.LOW,
                integrity=Impact.LOW,
                availability=Impact.NONE,
            ),
            "RCE": CVSSVector(
                attack_vector=AttackVector.NETWORK,
                attack_complexity=AttackComplexity.LOW,
                privileges_required=PrivilegesRequired.NONE,
                user_interaction=UserInteraction.NONE,
                scope=Scope.CHANGED,
                confidentiality=Impact.HIGH,
                integrity=Impact.HIGH,
                availability=Impact.HIGH,
            ),
            "SSRF": CVSSVector(
                attack_vector=AttackVector.NETWORK,
                attack_complexity=AttackComplexity.LOW,
                privileges_required=PrivilegesRequired.NONE,
                user_interaction=UserInteraction.NONE,
                scope=Scope.CHANGED,
                confidentiality=Impact.HIGH,
                integrity=Impact.LOW,
                availability=Impact.LOW,
            ),
            "IDOR": CVSSVector(
                attack_vector=AttackVector.NETWORK,
                attack_complexity=AttackComplexity.LOW,
                privileges_required=PrivilegesRequired.LOW,
                user_interaction=UserInteraction.NONE,
                scope=Scope.UNCHANGED,
                confidentiality=Impact.HIGH,
                integrity=Impact.LOW,
                availability=Impact.NONE,
            ),
            "LFI": CVSSVector(
                attack_vector=AttackVector.NETWORK,
                attack_complexity=AttackComplexity.LOW,
                privileges_required=PrivilegesRequired.NONE,
                user_interaction=UserInteraction.NONE,
                scope=Scope.UNCHANGED,
                confidentiality=Impact.HIGH,
                integrity=Impact.NONE,
                availability=Impact.NONE,
            ),
            "XXE": CVSSVector(
                attack_vector=AttackVector.NETWORK,
                attack_complexity=AttackComplexity.LOW,
                privileges_required=PrivilegesRequired.NONE,
                user_interaction=UserInteraction.NONE,
                scope=Scope.UNCHANGED,
                confidentiality=Impact.HIGH,
                integrity=Impact.LOW,
                availability=Impact.LOW,
            ),
            "CSRF": CVSSVector(
                attack_vector=AttackVector.NETWORK,
                attack_complexity=AttackComplexity.LOW,
                privileges_required=PrivilegesRequired.NONE,
                user_interaction=UserInteraction.REQUIRED,
                scope=Scope.UNCHANGED,
                confidentiality=Impact.NONE,
                integrity=Impact.HIGH,
                availability=Impact.NONE,
            ),
        }
        
        # Find matching pattern
        vector = None
        for pattern_name, pattern_vector in patterns.items():
            if pattern_name in vuln_type:
                vector = pattern_vector
                break
        
        if not vector:
            # Default medium severity
            vector = CVSSVector(
                attack_vector=AttackVector.NETWORK,
                attack_complexity=AttackComplexity.LOW,
                privileges_required=PrivilegesRequired.LOW,
                user_interaction=UserInteraction.NONE,
                scope=Scope.UNCHANGED,
                confidentiality=Impact.LOW,
                integrity=Impact.LOW,
                availability=Impact.NONE,
            )
        
        # Apply context adjustments
        if context.get("requires_auth"):
            vector.privileges_required = PrivilegesRequired.LOW
        
        if context.get("requires_user_action"):
            vector.user_interaction = UserInteraction.REQUIRED
        
        result = self.calculate(vector)
        result["estimated"] = True
        return result
    
    @staticmethod
    def _roundup(value: float) -> float:
        """Round up to 1 decimal place per CVSS spec."""
        import math
        return math.ceil(value * 10) / 10
    
    @staticmethod
    def _get_severity(score: float) -> str:
        """
        Get severity rating from score.
        
        Args:
            score: CVSS score
            
        Returns:
            Severity string
        """
        if score == 0:
            return "NONE"
        elif score < 4.0:
            return "LOW"
        elif score < 7.0:
            return "MEDIUM"
        elif score < 9.0:
            return "HIGH"
        else:
            return "CRITICAL"
    
    @staticmethod
    def severity_to_score_range(severity: str) -> tuple[float, float]:
        """
        Get score range for severity.
        
        Args:
            severity: Severity string
            
        Returns:
            Tuple of (min_score, max_score)
        """
        ranges = {
            "NONE": (0.0, 0.0),
            "LOW": (0.1, 3.9),
            "MEDIUM": (4.0, 6.9),
            "HIGH": (7.0, 8.9),
            "CRITICAL": (9.0, 10.0),
        }
        return ranges.get(severity.upper(), (0.0, 10.0))


def calculate_cvss(vector_string: str) -> dict[str, Any]:
    """
    Convenience function to calculate CVSS score.
    
    Args:
        vector_string: CVSS vector string
        
    Returns:
        Score dictionary
    """
    calculator = CVSSCalculator()
    return calculator.calculate_from_string(vector_string)


def estimate_cvss(vuln_type: str, **context: Any) -> dict[str, Any]:
    """
    Convenience function to estimate CVSS score.
    
    Args:
        vuln_type: Vulnerability type
        **context: Additional context
        
    Returns:
        Estimated score dictionary
    """
    calculator = CVSSCalculator()
    return calculator.estimate_from_vulnerability(vuln_type, context)
