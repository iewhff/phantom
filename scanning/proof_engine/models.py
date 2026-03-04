"""
PHANTOM AI - Proof Engine Models

Core enums, dataclasses, and constants for the exploitation proof engine.
Extracted from scanning/exploit_proof_engine.py.
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field
from enum import Enum, auto
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# Module-level constants (replacing magic numbers)
# =============================================================================

# Confidence modifiers (applied to finding confidence based on proof outcome)
CONFIDENCE_BOOST_PROVEN = 0.15       # +15% for fully proven exploit
CONFIDENCE_BOOST_PARTIAL = 0.05      # +5% for partial proof (1-2 questions)
CONFIDENCE_PENALTY_FAILED = -0.10    # -10% for tested-not-vulnerable
CONFIDENCE_PENALTY_UNCERTAIN = -0.05 # -5% for not attempted (uncertainty)

# Request settings
DEFAULT_REQUEST_TIMEOUT = 10.0  # seconds


# =============================================================================
# ProofOutcome enum
# =============================================================================

class ProofOutcome(Enum):
    """
    THEME-10 FIX: Explicit outcome states for proof attempts.

    The core problem: "couldn't test" was being treated as "not vulnerable".
    This enum forces explicit tracking of what actually happened.
    """
    NOT_ATTEMPTED = "not_attempted"       # URL missing, budget exhausted, blocked
    ATTEMPTED_FAILED = "attempted_failed"  # Tested, conclusively not vulnerable
    ATTEMPTED_PARTIAL = "attempted_partial"  # 1-2 questions answered, inconclusive
    PROVEN = "proven"                      # All 4 questions answered affirmatively

    def is_uncertain(self) -> bool:
        """Check if this outcome represents uncertainty (not definitive)."""
        return self in (ProofOutcome.NOT_ATTEMPTED, ProofOutcome.ATTEMPTED_PARTIAL)

    def confidence_modifier(self) -> float:
        """
        Get the confidence modifier for this outcome.

        THEME-10: Uncertain outcomes should REDUCE confidence, not leave it neutral.
        """
        if self == ProofOutcome.PROVEN:
            return CONFIDENCE_BOOST_PROVEN
        elif self == ProofOutcome.ATTEMPTED_FAILED:
            return CONFIDENCE_PENALTY_FAILED
        elif self == ProofOutcome.ATTEMPTED_PARTIAL:
            return CONFIDENCE_BOOST_PARTIAL
        else:  # NOT_ATTEMPTED
            return CONFIDENCE_PENALTY_UNCERTAIN


# =============================================================================
# Safety Limits
# =============================================================================

SAFE_MODE = os.environ.get("PHANTOM_SAFE_MODE", "safe").lower()


def _load_proof_limits() -> dict[str, dict]:
    """Load proof engine limits from config, fall back to defaults."""
    try:
        from core.config_manager import get_scanner_limits
        limits_cfg = get_scanner_limits().proof_engine
        return {
            "safe": {
                "max_requests": limits_cfg.safe.max_requests,
                "allow_write": limits_cfg.safe.allow_write,
                "allow_auth": limits_cfg.safe.allow_auth,
            },
            "cautious": {
                "max_requests": limits_cfg.cautious.max_requests,
                "allow_write": limits_cfg.cautious.allow_write,
                "allow_auth": limits_cfg.cautious.allow_auth,
            },
            "standard": {
                "max_requests": limits_cfg.standard.max_requests,
                "allow_write": limits_cfg.standard.allow_write,
                "allow_auth": limits_cfg.standard.allow_auth,
            },
            "aggressive": {
                "max_requests": limits_cfg.aggressive.max_requests,
                "allow_write": limits_cfg.aggressive.allow_write,
                "allow_auth": limits_cfg.aggressive.allow_auth,
            },
        }
    except Exception:
        # Fallback to hardcoded defaults if config unavailable
        return {
            "safe":       {"max_requests": 0,  "allow_write": False, "allow_auth": False},
            "cautious":   {"max_requests": 5,  "allow_write": False, "allow_auth": False},
            "standard":   {"max_requests": 15, "allow_write": False, "allow_auth": True},
            "aggressive": {"max_requests": 50, "allow_write": True,  "allow_auth": True},
        }

PROOF_LIMITS = _load_proof_limits()


# =============================================================================
# ProofResult dataclass
# =============================================================================

@dataclass
class ProofResult:
    """Result of proving a finding's exploitability."""
    can_repeat: bool = False
    can_mutate: bool = False
    can_escalate: bool = False
    can_chain: bool = False
    repeat_count: int = 0
    mutations: list[str] = field(default_factory=list)
    escalation: str = ""
    chain_targets: list[str] = field(default_factory=list)
    impact_narrative: str = ""
    proven_impact: str = "Unproven"
    requests_used: int = 0
    new_findings: list[dict] = field(default_factory=list)

    # STATE-02: Persistence verification
    state_persisted: bool = False
    persistence_evidence: list[str] = field(default_factory=list)
    confidence_boost: float = 0.0

    # THEME-10 FIX: Uncertainty tracking
    proof_outcome: str = "not_attempted"
    not_attempted_reason: str = ""
    questions_answered: int = 0

    # THEME-15 FIX: Impact Demonstration
    data_extracted: list[str] = field(default_factory=list)
    action_performed: str = ""
    privilege_gained: str = ""
    impact_evidence: dict = field(default_factory=dict)
    impact_type: str = ""

    @property
    def impact_demonstrated(self) -> bool:
        """True if we proved what an attacker can actually DO."""
        return bool(self.data_extracted or self.action_performed or self.privilege_gained)

    def get_outcome(self) -> ProofOutcome:
        """Get the ProofOutcome enum from the stored string."""
        try:
            return ProofOutcome(self.proof_outcome)
        except ValueError:
            return ProofOutcome.NOT_ATTEMPTED

    def calculate_outcome(self) -> ProofOutcome:
        """Calculate the outcome based on the 4 questions."""
        answered = sum([
            self.can_repeat,
            self.can_mutate,
            self.can_escalate,
            self.can_chain,
        ])
        self.questions_answered = answered

        if self.not_attempted_reason:
            return ProofOutcome.NOT_ATTEMPTED
        elif answered == 0:
            return ProofOutcome.ATTEMPTED_FAILED
        elif answered <= 3:
            return ProofOutcome.ATTEMPTED_PARTIAL
        else:  # answered == 4
            return ProofOutcome.PROVEN

    def finalize(self) -> ProofResult:
        """Finalize the result by calculating outcome and impact narrative."""
        outcome = self.calculate_outcome()
        self.proof_outcome = outcome.value

        # THEME-15: Classify impact type
        self._classify_impact_type()

        # Update proven_impact based on outcome AND impact demonstration
        if self.impact_demonstrated:
            if self.data_extracted:
                self.proven_impact = "Data Extraction Confirmed"
            elif self.action_performed:
                self.proven_impact = "State Change Confirmed"
            elif self.privilege_gained:
                self.proven_impact = "Privilege Escalation Confirmed"
            else:
                self.proven_impact = "Impact Demonstrated"
        elif outcome == ProofOutcome.PROVEN:
            self.proven_impact = "Technically Exploitable"
        elif outcome == ProofOutcome.ATTEMPTED_PARTIAL:
            self.proven_impact = "Partially Proven"
        elif outcome == ProofOutcome.ATTEMPTED_FAILED:
            self.proven_impact = "Not Exploitable"
        else:
            self.proven_impact = "Untested"

        # THEME-15: Enhance impact narrative with demonstrated impact
        if self.impact_demonstrated and not self.impact_narrative:
            self.impact_narrative = self._generate_impact_narrative()

        return self

    def _classify_impact_type(self) -> None:
        """THEME-15: Classify the type of demonstrated impact."""
        if self.data_extracted:
            self.impact_type = "DATA_LEAK"
        elif self.privilege_gained:
            self.impact_type = "PRIVILEGE_ESCALATION"
        elif self.action_performed:
            self.impact_type = "STATE_CHANGE"
        elif self.state_persisted:
            self.impact_type = "PERSISTENT_CHANGE"
        else:
            self.impact_type = "NONE"

    def _generate_impact_narrative(self) -> str:
        """THEME-15: Generate a human-readable impact narrative."""
        parts = []

        if self.data_extracted:
            data_types = set()
            for item in self.data_extracted[:10]:
                if "@" in item:
                    data_types.add("emails")
                elif item.startswith("$") or item.replace(".", "").isdigit():
                    data_types.add("financial data")
                elif len(item) > 30 and not " " in item:
                    data_types.add("tokens/secrets")
                else:
                    data_types.add("user data")

            parts.append(f"Extracted {len(self.data_extracted)} items ({', '.join(data_types)})")

        if self.action_performed:
            parts.append(f"Performed action: {self.action_performed}")

        if self.privilege_gained:
            parts.append(f"Gained access: {self.privilege_gained}")

        if self.state_persisted:
            parts.append("Change persisted in target system")

        return "; ".join(parts) if parts else ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def not_attempted(cls, reason: str) -> ProofResult:
        """Create a result that explicitly says 'not attempted'."""
        result = cls()
        result.proof_outcome = ProofOutcome.NOT_ATTEMPTED.value
        result.not_attempted_reason = reason
        result.proven_impact = "Untested"
        return result
