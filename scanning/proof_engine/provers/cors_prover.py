"""
PHANTOM AI - CORS Prover

Proves CORS exploitability: repeat, vary origins, escalate with credentials.
Extracted from scanning/exploit_proof_engine.py.
"""

from __future__ import annotations

from scanning.proof_engine.base_prover import BaseProver
from scanning.proof_engine.models import ProofResult

from utils.logger import get_logger

logger = get_logger(__name__)


class CORSProver(BaseProver):
    """Prove CORS exploitability: repeat, vary origins, escalate with credentials."""

    async def prove(self, finding: dict) -> ProofResult:
        result = ProofResult()
        url = finding.get("matched_at", "")
        metadata = finding.get("metadata", {})

        # THEME-10 FIX: Explicit "not attempted" instead of silent empty result
        if not url:
            return ProofResult.not_attempted("missing_url")

        # --- Q1: Can I repeat? ---
        evil_origin = "https://attacker.example.com"
        status, body, resp_headers = await self._safe_request(
            "GET", url,
            headers={"Origin": evil_origin},
        )
        acao = resp_headers.get("Access-Control-Allow-Origin", resp_headers.get("access-control-allow-origin", ""))
        if evil_origin in acao or acao == "*":
            result.can_repeat = True
            result.repeat_count = 1
            self._record_vector_attempt("cors_repeat", True, evil_origin, url)
        else:
            self._record_vector_attempt("cors_repeat", False, evil_origin, url)

        # --- Q2: Can I mutate? (different origins) ---
        if self.budget_remaining > 0 and result.can_repeat:
            origin_variants = [
                ("null_origin", "null"),
                ("subdomain", "https://evil.target.com"),
                ("protocol_confusion", "http://attacker.example.com"),
            ]
            for label, origin in origin_variants:
                if self.budget_remaining <= 0:
                    break
                status, body, resp_h = await self._safe_request(
                    "GET", url,
                    headers={"Origin": origin},
                )
                acao2 = resp_h.get("Access-Control-Allow-Origin", resp_h.get("access-control-allow-origin", ""))
                if origin in acao2 or acao2 == "*" or acao2 == "null":
                    result.can_mutate = True
                    result.mutations.append(f"{label}: Origin={origin} → ACAO={acao2}")
                    self._record_vector_attempt(f"cors_mutate_{label}", True, origin, url)
                else:
                    self._record_vector_attempt(f"cors_mutate_{label}", False, origin, url)

        # --- Q3: Can I escalate? ---
        acac = resp_headers.get(
            "Access-Control-Allow-Credentials",
            resp_headers.get("access-control-allow-credentials", ""),
        )
        if acac.lower() == "true":
            result.can_escalate = True
            result.escalation = (
                "CORS with credentials:include allows attacker's page to make "
                "authenticated cross-origin requests. User's session data is exfiltrated."
            )
            self._record_vector_attempt("cors_escalate_credentials", True, "", url)

        # --- Q4: Can I chain? ---
        xss_findings = self._find_related_findings(["xss", "dom_xss"])
        if xss_findings:
            result.can_chain = True
            result.chain_targets.append("XSS + CORS = victim's browser exfiltrates authenticated data cross-origin")
            self._record_vector_attempt("cors_chain_xss", True, "", url)

        result.requests_used = self._requests_used
        return result.finalize()  # FIX P0-005: Calculate proof outcome and impact
