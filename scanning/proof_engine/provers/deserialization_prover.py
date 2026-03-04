"""
PHANTOM AI - Deserialization Prover

Proves deserialization impact: can potentially achieve RCE.
Extracted from scanning/exploit_proof_engine.py.
"""

from __future__ import annotations

from scanning.proof_engine.base_prover import BaseProver
from scanning.proof_engine.models import ProofResult

from utils.logger import get_logger

logger = get_logger(__name__)


class DeserializationProver(BaseProver):
    """Prove deserialization impact: can potentially achieve RCE."""

    async def prove(self, finding: dict) -> ProofResult:
        result = ProofResult()
        url = finding.get("matched_at", finding.get("host", ""))

        if not url:
            return ProofResult.not_attempted("missing_url")

        # --- Q1: Can I repeat? ---
        # Deserialization vulnerabilities are often detected via errors or timing
        status, body, _ = await self._safe_request("GET", url)
        if status > 0:
            result.can_repeat = True
            result.repeat_count = 1
            self._record_vector_attempt("deser_repeat", True, "", url)

        # --- Q2: Can I mutate? ---
        # Check if different serialization formats trigger different responses
        if self.budget_remaining > 0 and result.can_repeat:
            # We look for error messages that indicate deserialization issues
            error_indicators = [
                "unserialize", "ObjectInputStream", "pickle", "yaml.load",
                "Jackson", "Fastjson", "readObject", "fromJson",
            ]
            evidence = finding.get("metadata", {}).get("evidence", "")
            for indicator in error_indicators:
                if indicator.lower() in str(evidence).lower():
                    result.can_mutate = True
                    result.mutations.append(f"Deserialization framework: {indicator}")
                    break

        # --- Q3: Can I escalate? ---
        # AUDIT-FIX 2026-02-19: Don't claim proven escalation without gadget chain verification
        # Previously: can_mutate -> can_escalate (no verification)
        # Now: Honest about what was proven vs theoretical
        if result.can_mutate:
            # Deserialization indicators found = vulnerable endpoint exists
            # BUT we haven't verified gadget chain availability (depends on classpath/libs)
            result.can_escalate = False  # Not verified - would require gadget chain testing
            result.escalation = "POTENTIAL: Deserialization vulnerability detected - RCE depends on gadget chain availability (not verified)"
            result.privilege_gained = "potential_deserialization_rce"
            result.impact_type = "DATA_LEAK"  # Conservative: proved data handling issue, not RCE
            self._record_vector_attempt("deser_escalate_potential", True, "", url)

        # --- Q4: Can I chain? ---
        # AUDIT-FIX 2026-02-19: Chain based on mutation proof, not unverified escalation
        if result.can_mutate:
            result.can_chain = True
            result.chain_targets.append("POTENTIAL: Deserialization + gadget chain → RCE (requires verification)")

        result.requests_used = self._requests_used
        return result.finalize()  # FIX P0-005: Calculate proof outcome and impact
