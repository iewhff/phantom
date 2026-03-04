"""Tests for scanning/proof_gate.py — Proof Gating system."""

import pytest

from scanning.proof_gate import (
    ProofGateLevel,
    ProofGateResult,
    apply_proof_gate,
    apply_proof_gate_to_findings,
)


# =============================================================================
# Gate Level Determination
# =============================================================================


class TestGateLevel:
    """Test correct gate level assignment."""

    def test_exploited_with_data_extraction(self):
        finding = {
            "severity": "CRITICAL",
            "metadata": {
                "proof": {
                    "proof_outcome": "proven",
                    "data_extracted": ["user:admin", "email:a@b.com"],
                    "can_repeat": True,
                    "can_mutate": True,
                },
            },
        }
        result = apply_proof_gate(finding)
        assert result.level == ProofGateLevel.EXPLOITED
        assert "data extracted" in result.reason

    def test_exploited_with_action_performed(self):
        finding = {
            "severity": "CRITICAL",
            "metadata": {
                "proof": {
                    "proof_outcome": "proven",
                    "action_performed": "Modified user role to admin",
                    "can_repeat": True,
                },
            },
        }
        result = apply_proof_gate(finding)
        assert result.level == ProofGateLevel.EXPLOITED
        assert "action" in result.reason

    def test_exploited_with_privilege_gained(self):
        finding = {
            "severity": "CRITICAL",
            "metadata": {
                "proof": {
                    "proof_outcome": "proven",
                    "privilege_gained": "admin",
                    "can_repeat": True,
                },
            },
        }
        result = apply_proof_gate(finding)
        assert result.level == ProofGateLevel.EXPLOITED

    def test_proven_no_impact_is_verified(self):
        """proven + can_repeat but NO impact data → VERIFIED (not EXPLOITED)."""
        finding = {
            "severity": "HIGH",
            "metadata": {
                "proof": {
                    "proof_outcome": "proven",
                    "can_repeat": True,
                    "can_mutate": True,
                    "data_extracted": [],
                    "action_performed": "",
                    "privilege_gained": "",
                },
            },
        }
        result = apply_proof_gate(finding)
        assert result.level == ProofGateLevel.VERIFIED

    def test_verified_partial_with_repeat(self):
        finding = {
            "severity": "HIGH",
            "metadata": {
                "proof": {
                    "proof_outcome": "attempted_partial",
                    "can_repeat": True,
                    "can_mutate": False,
                },
            },
        }
        result = apply_proof_gate(finding)
        assert result.level == ProofGateLevel.VERIFIED
        assert "repeatable" in result.reason

    def test_verified_partial_with_mutate(self):
        finding = {
            "severity": "HIGH",
            "metadata": {
                "proof": {
                    "proof_outcome": "attempted_partial",
                    "can_repeat": False,
                    "can_mutate": True,
                },
            },
        }
        result = apply_proof_gate(finding)
        assert result.level == ProofGateLevel.VERIFIED
        assert "mutable" in result.reason

    def test_partial_no_repeat_no_mutate_is_detected(self):
        """attempted_partial without repeat/mutate → DETECTED."""
        finding = {
            "severity": "HIGH",
            "metadata": {
                "proof": {
                    "proof_outcome": "attempted_partial",
                    "can_repeat": False,
                    "can_mutate": False,
                },
            },
        }
        result = apply_proof_gate(finding)
        assert result.level == ProofGateLevel.DETECTED

    def test_detected_not_attempted(self):
        finding = {
            "severity": "CRITICAL",
            "metadata": {
                "proof": {
                    "proof_outcome": "not_attempted",
                    "not_attempted_reason": "safe mode",
                },
            },
        }
        result = apply_proof_gate(finding)
        assert result.level == ProofGateLevel.DETECTED
        assert "safe mode" in result.reason

    def test_detected_attempted_failed(self):
        finding = {
            "severity": "HIGH",
            "metadata": {
                "proof": {
                    "proof_outcome": "attempted_failed",
                },
            },
        }
        result = apply_proof_gate(finding)
        assert result.level == ProofGateLevel.DETECTED
        assert "not exploitable" in result.reason.lower()

    def test_detected_no_proof_data(self):
        finding = {"severity": "CRITICAL", "metadata": {}}
        result = apply_proof_gate(finding)
        assert result.level == ProofGateLevel.DETECTED
        assert "No proof data" in result.reason

    def test_detected_no_metadata(self):
        finding = {"severity": "CRITICAL"}
        result = apply_proof_gate(finding)
        assert result.level == ProofGateLevel.DETECTED

    def test_detected_empty_proof(self):
        finding = {"severity": "HIGH", "metadata": {"proof": {}}}
        result = apply_proof_gate(finding)
        assert result.level == ProofGateLevel.DETECTED


# =============================================================================
# Severity Capping
# =============================================================================


class TestSeverityCap:
    """Test severity cap enforcement."""

    def test_detected_critical_capped_to_high(self):
        finding = {
            "severity": "CRITICAL",
            "metadata": {"proof": {"proof_outcome": "not_attempted"}},
        }
        result = apply_proof_gate(finding)
        assert result.level == ProofGateLevel.DETECTED
        assert result.capped_severity == "HIGH"
        assert result.original_severity == "CRITICAL"
        assert result.was_capped is True

    def test_detected_high_stays_high(self):
        finding = {
            "severity": "HIGH",
            "metadata": {"proof": {"proof_outcome": "not_attempted"}},
        }
        result = apply_proof_gate(finding)
        assert result.capped_severity == "HIGH"
        assert result.was_capped is False

    def test_detected_medium_stays_medium(self):
        finding = {
            "severity": "MEDIUM",
            "metadata": {"proof": {"proof_outcome": "not_attempted"}},
        }
        result = apply_proof_gate(finding)
        assert result.capped_severity == "MEDIUM"
        assert result.was_capped is False

    def test_verified_critical_full_exploit_allowed(self):
        """VERIFIED + tier=full → CRITICAL allowed."""
        finding = {
            "severity": "CRITICAL",
            "metadata": {
                "proof": {
                    "proof_outcome": "proven",
                    "can_repeat": True,
                },
                "exploitability": {"tier": "full"},
            },
        }
        result = apply_proof_gate(finding)
        assert result.level == ProofGateLevel.VERIFIED
        assert result.capped_severity == "CRITICAL"
        assert result.was_capped is False

    def test_verified_critical_partial_exploit_capped(self):
        """VERIFIED + tier=partial → CRITICAL capped to HIGH."""
        finding = {
            "severity": "CRITICAL",
            "metadata": {
                "proof": {
                    "proof_outcome": "attempted_partial",
                    "can_repeat": True,
                },
                "exploitability": {"tier": "partial"},
            },
        }
        result = apply_proof_gate(finding)
        assert result.level == ProofGateLevel.VERIFIED
        assert result.capped_severity == "HIGH"
        assert result.was_capped is True

    def test_exploited_critical_uncapped(self):
        finding = {
            "severity": "CRITICAL",
            "metadata": {
                "proof": {
                    "proof_outcome": "proven",
                    "data_extracted": ["db:users"],
                    "can_repeat": True,
                },
                "exploitability": {"tier": "full"},
            },
        }
        result = apply_proof_gate(finding)
        assert result.level == ProofGateLevel.EXPLOITED
        assert result.capped_severity == "CRITICAL"
        assert result.was_capped is False


# =============================================================================
# Batch Processing
# =============================================================================


class TestBatch:
    """Test apply_proof_gate_to_findings batch function."""

    def test_batch_processing(self):
        findings = [
            {
                "name": "SQLi proven",
                "severity": "CRITICAL",
                "metadata": {
                    "proof": {
                        "proof_outcome": "proven",
                        "data_extracted": ["user:admin"],
                        "can_repeat": True,
                    },
                    "exploitability": {"tier": "full"},
                },
            },
            {
                "name": "JWT not attempted",
                "severity": "CRITICAL",
                "metadata": {
                    "proof": {"proof_outcome": "not_attempted"},
                },
            },
        ]
        result = apply_proof_gate_to_findings(findings)

        # SQLi: EXPLOITED, stays CRITICAL
        assert result[0]["severity"] == "CRITICAL"
        assert result[0]["metadata"]["proof_gate"]["level"] == "exploited"

        # JWT: DETECTED, capped to HIGH
        assert result[1]["severity"] == "HIGH"
        assert result[1]["metadata"]["proof_gate"]["level"] == "detected"
        assert result[1]["metadata"]["proof_gate"]["was_capped"] is True
        assert result[1]["original_severity"] == "CRITICAL"

    def test_metadata_written(self):
        findings = [{"severity": "MEDIUM", "metadata": {}}]
        apply_proof_gate_to_findings(findings)
        assert "proof_gate" in findings[0]["metadata"]
        gate = findings[0]["metadata"]["proof_gate"]
        assert gate["level"] in ("detected", "verified", "exploited")

    def test_empty_list(self):
        result = apply_proof_gate_to_findings([])
        assert result == []

    def test_no_metadata_key(self):
        findings = [{"severity": "HIGH"}]
        apply_proof_gate_to_findings(findings)
        assert "proof_gate" in findings[0].get("metadata", {})

    def test_no_proof_key(self):
        findings = [{"severity": "HIGH", "metadata": {"other": "data"}}]
        apply_proof_gate_to_findings(findings)
        assert findings[0]["metadata"]["proof_gate"]["level"] == "detected"

    def test_original_severity_not_overwritten(self):
        """If original_severity already set by exploitability classifier, don't overwrite."""
        findings = [
            {
                "severity": "CRITICAL",
                "original_severity": "CRITICAL",
                "metadata": {"proof": {"proof_outcome": "not_attempted"}},
            }
        ]
        apply_proof_gate_to_findings(findings)
        assert findings[0]["original_severity"] == "CRITICAL"
        assert findings[0]["severity"] == "HIGH"
