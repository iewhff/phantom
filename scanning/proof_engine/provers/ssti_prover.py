"""
PHANTOM AI - SSTI Prover

Proves SSTI impact: template injection leading to code execution.
Extracted from scanning/exploit_proof_engine.py.
"""

from __future__ import annotations

from scanning.proof_engine.base_prover import BaseProver
from scanning.proof_engine.models import ProofResult

from utils.logger import get_logger

logger = get_logger(__name__)


class SSTIProver(BaseProver):
    """Prove SSTI impact: template injection leading to code execution."""

    async def prove(self, finding: dict) -> ProofResult:
        result = ProofResult()
        url = finding.get("matched_at", finding.get("host", ""))
        param = (finding.get("metadata") or {}).get("param", "")

        if not url:
            return ProofResult.not_attempted("missing_url")

        # --- Q1: Can I repeat? ---
        original_payload = (finding.get("metadata") or {}).get("payload", "")
        if original_payload and param:
            status, body, _ = await self._safe_request("GET", url, params={param: original_payload})
            # Check for math evaluation (49, 7777777) or other SSTI indicators
            if status == 200 and ("49" in body or "7777777" in body):
                result.can_repeat = True
                result.repeat_count = 1
                self._record_vector_attempt("ssti_repeat", True, original_payload[:30], url)
        else:
            # Try basic SSTI probe
            status, body, _ = await self._safe_request("GET", url, params={param: "{{7*7}}"} if param else {})
            if status == 200 and "49" in body:
                result.can_repeat = True
                self._record_vector_attempt("ssti_repeat", True, "{{7*7}}", url)

        # --- Q2: Can I mutate? (different template engines) ---
        if self.budget_remaining > 0 and result.can_repeat and param:
            ssti_probes = [
                ("jinja2", "{{config.items()}}"),
                ("twig", "{{_self.env.getCache()}}"),
                ("freemarker", "${7*7}"),
                ("velocity", "#set($x=7*7)$x"),
            ]
            for engine, payload in ssti_probes:
                if self.budget_remaining <= 0:
                    break
                status, body, _ = await self._safe_request("GET", url, params={param: payload})
                if status == 200 and ("49" in body or "config" in body.lower() or "cache" in body.lower()):
                    result.can_mutate = True
                    result.mutations.append(f"{engine}: template executed")
                    self._record_vector_attempt(f"ssti_mutate_{engine}", True, payload, url)

        # --- Q3: Can I escalate? (to RCE) ---
        # AUDIT-FIX 2026-02-19: Don't claim proven escalation without actual verification
        # Previously: can_mutate -> can_escalate (no verification)
        # Now: Honest about what was proven vs theoretical
        if result.can_mutate:
            # SSTI mutation proven = we CAN inject template code
            # BUT we haven't verified RCE is achievable (depends on sandbox, engine, filters)
            result.can_escalate = False  # Not verified - would require executing safe RCE probe
            result.escalation = "POTENTIAL: Template injection confirmed - RCE depends on engine/sandbox (not verified)"
            result.privilege_gained = "potential_template_execution"
            result.impact_type = "STATE_CHANGE"  # Conservative: proved injection, not RCE
            self._record_vector_attempt("ssti_escalate_potential", True, "", url)

        # --- Q4: Can I chain? ---
        # AUDIT-FIX 2026-02-19: Chain based on mutation proof, not unverified escalation
        if result.can_mutate:
            result.can_chain = True
            result.chain_targets.append("POTENTIAL: SSTI + permissive engine → RCE (requires verification)")

        result.requests_used = self._requests_used
        return result.finalize()  # FIX P0-005: Calculate proof outcome and impact
