"""
PHANTOM AI - Proof Gate

Prevents over-escalation by gating severity based on actual proof outcome.

Gate Levels:
- DETECTED: Pattern matched, no verification attempted or verification failed
- VERIFIED: Proof engine confirmed repeatability/mutability
- EXPLOITED: Proof engine demonstrated real impact (data extracted, action performed, privilege gained)

Severity Caps:
- DETECTED: Maximum HIGH (never CRITICAL without verification)
- VERIFIED: CRITICAL only if exploitability tier is FULL_EXPLOIT
- EXPLOITED: No cap (full severity allowed)

Runs as Phase 4.46a in the postprocessing pipeline, AFTER proof engine (4.2)
and exploitability classification (4.45).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# Gate Level Enum
# =============================================================================

class ProofGateLevel(Enum):
    """Proof gate levels determining maximum allowed severity."""

    DETECTED = "detected"       # Pattern matched, no proof
    VERIFIED = "verified"       # Proof engine confirmed behavior
    EXPLOITED = "exploited"     # Impact demonstrated


# =============================================================================
# Gate Result
# =============================================================================

@dataclass
class ProofGateResult:
    """Result of proof gate evaluation."""

    level: ProofGateLevel
    reason: str
    capped_severity: str       # Severity after gating
    original_severity: str     # Severity before gating
    was_capped: bool = False   # True if severity was actually reduced

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "reason": self.reason,
            "capped_severity": self.capped_severity,
            "original_severity": self.original_severity,
            "was_capped": self.was_capped,
        }


# =============================================================================
# Internal helpers
# =============================================================================

_SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _severity_rank(severity: str) -> int:
    """Get numeric rank for severity (0=INFO, 4=CRITICAL)."""
    try:
        return _SEVERITY_ORDER.index(severity.upper())
    except ValueError:
        return 2  # default MEDIUM


def _cap_severity(current: str, maximum: str) -> tuple[str, bool]:
    """Cap severity to maximum. Returns (capped, was_changed)."""
    cur = current.upper()
    cap = maximum.upper()
    if _severity_rank(cur) > _severity_rank(cap):
        return cap, True
    return cur, False


# =============================================================================
# Gate Level Determination
# =============================================================================

def _determine_gate_level(
    proof: dict,
    exploitability: dict,
) -> tuple[ProofGateLevel, str]:
    """Determine proof gate level from proof and exploitability data."""

    proof_outcome = proof.get("proof_outcome", "not_attempted")
    data_extracted = proof.get("data_extracted", [])
    action_performed = proof.get("action_performed", "")
    privilege_gained = proof.get("privilege_gained", "")
    can_repeat = proof.get("can_repeat", False)
    can_mutate = proof.get("can_mutate", False)

    # EXPLOITED: proof_outcome=="proven" AND real impact demonstrated
    if proof_outcome == "proven" and (data_extracted or action_performed or privilege_gained):
        reasons = []
        if data_extracted:
            reasons.append(f"data extracted ({len(data_extracted)} items)")
        if action_performed:
            reasons.append(f"action: {action_performed[:80]}")
        if privilege_gained:
            reasons.append(f"privilege: {privilege_gained[:80]}")
        return ProofGateLevel.EXPLOITED, f"Impact demonstrated: {'; '.join(reasons)}"

    # VERIFIED: proof confirmed behavior (repeatable or mutable)
    if proof_outcome in ("proven", "attempted_partial") and (can_repeat or can_mutate):
        caps = []
        if can_repeat:
            caps.append("repeatable")
        if can_mutate:
            caps.append("mutable")
        return ProofGateLevel.VERIFIED, f"Behavior confirmed: {', '.join(caps)}"

    # DETECTED: everything else
    if not proof:
        return ProofGateLevel.DETECTED, "No proof data"
    if proof_outcome == "not_attempted":
        reason = proof.get("not_attempted_reason", "unknown")
        return ProofGateLevel.DETECTED, f"Proof not attempted: {reason}"
    if proof_outcome == "attempted_failed":
        return ProofGateLevel.DETECTED, "Proof attempted, not exploitable"
    if proof_outcome == "attempted_partial":
        return ProofGateLevel.DETECTED, "Partial proof without confirmed behavior"

    return ProofGateLevel.DETECTED, "Insufficient proof data"


def _apply_severity_cap(
    severity: str,
    level: ProofGateLevel,
    exploitability: dict,
) -> tuple[str, bool]:
    """Apply severity cap based on gate level.

    Rules:
    - DETECTED: cap at HIGH (never CRITICAL without verification)
    - VERIFIED: CRITICAL only if exploitability tier is FULL_EXPLOIT
    - EXPLOITED: no cap
    """
    if level == ProofGateLevel.EXPLOITED:
        return severity.upper(), False

    if level == ProofGateLevel.VERIFIED:
        tier = exploitability.get("tier", "exposure")
        if tier == "full":
            return severity.upper(), False
        return _cap_severity(severity, "HIGH")

    # DETECTED: hard cap at HIGH
    return _cap_severity(severity, "HIGH")


# =============================================================================
# Public API
# =============================================================================

def apply_proof_gate(finding: dict) -> ProofGateResult:
    """
    Apply proof gate to a single finding.

    Reads metadata["proof"] and metadata["exploitability"] to determine
    the gate level, then caps severity accordingly.
    """
    metadata = finding.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}
    proof = metadata.get("proof") or {}
    if not isinstance(proof, dict):
        proof = {}
    exploitability = metadata.get("exploitability") or {}
    if not isinstance(exploitability, dict):
        exploitability = {}
    original_severity = finding.get("severity", "MEDIUM").upper()

    level, reason = _determine_gate_level(proof, exploitability)
    capped, was_capped = _apply_severity_cap(original_severity, level, exploitability)

    return ProofGateResult(
        level=level,
        reason=reason,
        capped_severity=capped,
        original_severity=original_severity,
        was_capped=was_capped,
    )


def apply_proof_gate_to_findings(findings: list[dict]) -> list[dict]:
    """
    Apply proof gate to all findings in a list.

    Modifies findings in-place: sets metadata["proof_gate"]
    and caps finding["severity"] if needed.
    """
    gated_count = 0
    level_counts: dict[str, int] = {"detected": 0, "verified": 0, "exploited": 0}

    for finding in findings:
        gate = apply_proof_gate(finding)

        # Write gate result to metadata
        finding.setdefault("metadata", {})["proof_gate"] = gate.to_dict()

        # Cap severity if needed
        if gate.was_capped:
            if "original_severity" not in finding:
                finding["original_severity"] = gate.original_severity
            finding["severity"] = gate.capped_severity
            gated_count += 1
            logger.info(
                f"[ProofGate] {finding.get('name', '?')}: "
                f"{gate.original_severity} -> {gate.capped_severity} "
                f"({gate.level.value}: {gate.reason})"
            )

        level_counts[gate.level.value] += 1

    logger.info(
        f"[ProofGate] {len(findings)} findings gated: "
        f"exploited={level_counts['exploited']}, "
        f"verified={level_counts['verified']}, "
        f"detected={level_counts['detected']}, "
        f"severity_capped={gated_count}"
    )

    return findings
