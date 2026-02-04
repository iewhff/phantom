"""
Finding State Machine - Vulnerability Lifecycle Management

Implements a professional state machine for vulnerability findings:
- DETECTED: Initial detection via passive/heuristic analysis
- CONFIRMED: Verified with safe payload that proves vulnerability exists
- EXPLOITABLE: Demonstrated exploitability with controlled impact
- EXPLOITED: Full exploitation performed (with consent)

This differentiation is CRITICAL for:
1. Report credibility (no more "maybe vulnerable")
2. Prioritization (confirmed > detected)
3. Compliance (audit trail of verification)
4. Ethics (clear boundary between detection and exploitation)

Usage:
    from utils.finding_state_machine import FindingState, FindingStateMachine

    finding = Finding(...)
    state_machine = FindingStateMachine(finding)

    # Transition through states
    state_machine.transition_to(FindingState.CONFIRMED, evidence="...")
    state_machine.transition_to(FindingState.EXPLOITABLE, evidence="...")

    # Check current state
    if state_machine.current_state >= FindingState.CONFIRMED:
        # High confidence finding
        pass

Author: PetNTester AI Enterprise
Version: 1.0.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum, auto
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


class FindingState(IntEnum):
    """
    Vulnerability finding states - ordered by confidence level.

    Using IntEnum allows comparison: CONFIRMED > DETECTED
    """
    SUSPECTED = 0       # Heuristic match, low confidence
    DETECTED = 1        # Pattern matched, medium confidence
    CONFIRMED = 2       # Verified with safe payload, high confidence
    EXPLOITABLE = 3     # Demonstrated exploitability
    EXPLOITED = 4       # Full exploitation performed (with consent)


class FindingConfidence(IntEnum):
    """Confidence levels mapped to states."""
    SUSPECTED = 25      # 25% confidence
    DETECTED = 50       # 50% confidence
    CONFIRMED = 85      # 85% confidence
    EXPLOITABLE = 95    # 95% confidence
    EXPLOITED = 100     # 100% confidence


@dataclass
class StateTransition:
    """Record of a state transition."""
    from_state: FindingState
    to_state: FindingState
    timestamp: datetime
    evidence: str
    method: str  # How the transition was verified
    tool: Optional[str] = None


@dataclass
class FindingStateMachine:
    """
    State machine for vulnerability finding lifecycle.

    Tracks the progression of a finding from detection to exploitation,
    with full audit trail of evidence for each transition.
    """
    finding_id: str
    finding_type: str
    current_state: FindingState = FindingState.DETECTED
    confidence: float = 50.0
    transitions: List[StateTransition] = field(default_factory=list)
    evidence_chain: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    # Verification requirements for state transitions
    TRANSITION_REQUIREMENTS: Dict[FindingState, Dict[str, Any]] = {
        FindingState.SUSPECTED: {
            "min_evidence": 0,
            "requires_payload": False,
            "description": "Heuristic or pattern match",
        },
        FindingState.DETECTED: {
            "min_evidence": 1,
            "requires_payload": False,
            "description": "Clear indicator found",
        },
        FindingState.CONFIRMED: {
            "min_evidence": 2,
            "requires_payload": True,
            "description": "Verified with safe payload",
        },
        FindingState.EXPLOITABLE: {
            "min_evidence": 3,
            "requires_payload": True,
            "requires_impact_demo": True,
            "description": "Demonstrated real impact",
        },
        FindingState.EXPLOITED: {
            "min_evidence": 4,
            "requires_payload": True,
            "requires_consent": True,
            "description": "Full exploitation with consent",
        },
    }

    def can_transition_to(self, target_state: FindingState) -> bool:
        """Check if transition to target state is valid."""
        # Can only move forward or stay same
        if target_state < self.current_state:
            return False

        # Check requirements
        requirements = self.TRANSITION_REQUIREMENTS.get(target_state, {})
        min_evidence = requirements.get("min_evidence", 0)

        return len(self.evidence_chain) >= min_evidence

    def transition_to(
        self,
        target_state: FindingState,
        evidence: str,
        method: str = "automated",
        tool: Optional[str] = None,
        payload: Optional[str] = None,
        response: Optional[str] = None,
    ) -> bool:
        """
        Transition finding to a new state.

        Args:
            target_state: Target state to transition to
            evidence: Description of evidence supporting transition
            method: Verification method used
            tool: Tool used for verification (if any)
            payload: Payload used (if applicable)
            response: Response received (if applicable)

        Returns:
            True if transition successful
        """
        if not self.can_transition_to(target_state):
            logger.warning(
                f"Cannot transition {self.finding_id} from "
                f"{self.current_state.name} to {target_state.name}"
            )
            return False

        # Record transition
        transition = StateTransition(
            from_state=self.current_state,
            to_state=target_state,
            timestamp=datetime.now(),
            evidence=evidence,
            method=method,
            tool=tool,
        )
        self.transitions.append(transition)

        # Add evidence to chain
        self.evidence_chain.append({
            "state": target_state.name,
            "evidence": evidence,
            "method": method,
            "tool": tool,
            "payload": payload,
            "response": response[:500] if response else None,  # Truncate
            "timestamp": datetime.now().isoformat(),
        })

        # Update state and confidence
        old_state = self.current_state
        self.current_state = target_state
        self.confidence = float(FindingConfidence[target_state.name].value)
        self.updated_at = datetime.now()

        logger.info(
            f"Finding {self.finding_id}: {old_state.name} → {target_state.name} "
            f"(confidence: {self.confidence}%)"
        )

        return True

    def get_state_description(self) -> str:
        """Get human-readable description of current state."""
        descriptions = {
            FindingState.SUSPECTED: "Suspected vulnerability based on heuristics",
            FindingState.DETECTED: "Vulnerability indicator detected",
            FindingState.CONFIRMED: "Vulnerability confirmed with verification payload",
            FindingState.EXPLOITABLE: "Exploitability demonstrated with controlled impact",
            FindingState.EXPLOITED: "Full exploitation performed (authorized)",
        }
        return descriptions.get(self.current_state, "Unknown state")

    def get_credibility_label(self) -> str:
        """Get credibility label for reports."""
        labels = {
            FindingState.SUSPECTED: "⚠️ SUSPECTED",
            FindingState.DETECTED: "🔍 DETECTED",
            FindingState.CONFIRMED: "✅ CONFIRMED",
            FindingState.EXPLOITABLE: "🎯 EXPLOITABLE",
            FindingState.EXPLOITED: "💥 EXPLOITED",
        }
        return labels.get(self.current_state, "❓ UNKNOWN")

    def get_severity_modifier(self) -> float:
        """
        Get severity modifier based on confirmation level.

        Confirmed findings should be prioritized over suspected ones.
        """
        modifiers = {
            FindingState.SUSPECTED: 0.5,    # Reduce severity for suspected
            FindingState.DETECTED: 0.8,     # Slight reduction
            FindingState.CONFIRMED: 1.0,    # Full severity
            FindingState.EXPLOITABLE: 1.2,  # Increase severity
            FindingState.EXPLOITED: 1.3,    # Highest priority
        }
        return modifiers.get(self.current_state, 1.0)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "finding_id": self.finding_id,
            "finding_type": self.finding_type,
            "current_state": self.current_state.name,
            "state_description": self.get_state_description(),
            "credibility_label": self.get_credibility_label(),
            "confidence": self.confidence,
            "severity_modifier": self.get_severity_modifier(),
            "evidence_chain": self.evidence_chain,
            "transitions": [
                {
                    "from": t.from_state.name,
                    "to": t.to_state.name,
                    "timestamp": t.timestamp.isoformat(),
                    "evidence": t.evidence,
                    "method": t.method,
                    "tool": t.tool,
                }
                for t in self.transitions
            ],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class FindingStateManager:
    """
    Manager for tracking all finding states in a scan.

    Provides utilities for:
    - Creating state machines for findings
    - Querying findings by state
    - Generating state-based reports
    """

    def __init__(self):
        self._findings: Dict[str, FindingStateMachine] = {}

    def create_finding(
        self,
        finding_id: str,
        finding_type: str,
        initial_state: FindingState = FindingState.DETECTED,
        initial_evidence: str = "",
    ) -> FindingStateMachine:
        """Create a new finding state machine."""
        fsm = FindingStateMachine(
            finding_id=finding_id,
            finding_type=finding_type,
            current_state=initial_state,
            confidence=float(FindingConfidence[initial_state.name].value),
        )

        if initial_evidence:
            fsm.evidence_chain.append({
                "state": initial_state.name,
                "evidence": initial_evidence,
                "timestamp": datetime.now().isoformat(),
            })

        self._findings[finding_id] = fsm
        return fsm

    def get_finding(self, finding_id: str) -> Optional[FindingStateMachine]:
        """Get a finding by ID."""
        return self._findings.get(finding_id)

    def get_findings_by_state(self, state: FindingState) -> List[FindingStateMachine]:
        """Get all findings in a specific state."""
        return [f for f in self._findings.values() if f.current_state == state]

    def get_confirmed_findings(self) -> List[FindingStateMachine]:
        """Get all confirmed or higher findings."""
        return [
            f for f in self._findings.values()
            if f.current_state >= FindingState.CONFIRMED
        ]

    def get_high_confidence_findings(self, min_confidence: float = 85.0) -> List[FindingStateMachine]:
        """Get findings above confidence threshold."""
        return [f for f in self._findings.values() if f.confidence >= min_confidence]

    def get_statistics(self) -> Dict[str, Any]:
        """Get state statistics."""
        by_state = {}
        for state in FindingState:
            count = len(self.get_findings_by_state(state))
            if count > 0:
                by_state[state.name] = count

        total = len(self._findings)
        confirmed = len(self.get_confirmed_findings())

        return {
            "total_findings": total,
            "by_state": by_state,
            "confirmed_count": confirmed,
            "confirmation_rate": f"{confirmed/total*100:.1f}%" if total > 0 else "0%",
            "average_confidence": (
                sum(f.confidence for f in self._findings.values()) / total
                if total > 0 else 0
            ),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Convert all findings to dictionary."""
        return {
            fid: fsm.to_dict()
            for fid, fsm in self._findings.items()
        }


def enhance_finding_with_state(
    finding: Dict[str, Any],
    state: FindingState,
    evidence: str = "",
) -> Dict[str, Any]:
    """
    Enhance a finding dictionary with state information.

    This is a convenience function for integrating with existing code
    that uses dictionary-based findings.
    """
    finding["vulnerability_state"] = state.name
    finding["state_confidence"] = float(FindingConfidence[state.name].value)
    finding["credibility_label"] = {
        FindingState.SUSPECTED: "⚠️ SUSPECTED",
        FindingState.DETECTED: "🔍 DETECTED",
        FindingState.CONFIRMED: "✅ CONFIRMED",
        FindingState.EXPLOITABLE: "🎯 EXPLOITABLE",
        FindingState.EXPLOITED: "💥 EXPLOITED",
    }.get(state, "❓ UNKNOWN")

    if evidence:
        if "evidence_chain" not in finding:
            finding["evidence_chain"] = []
        finding["evidence_chain"].append({
            "state": state.name,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat(),
        })

    # Adjust confidence based on state
    current_confidence = finding.get("confidence", 50.0)
    state_confidence = float(FindingConfidence[state.name].value)
    finding["confidence"] = max(current_confidence, state_confidence)

    return finding
