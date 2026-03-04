"""
PHANTOM AI - Generic Prover

Minimal proof: just confirm the finding is repeatable.
Extracted from scanning/exploit_proof_engine.py.
"""

from __future__ import annotations

from scanning.proof_engine.base_prover import BaseProver
from scanning.proof_engine.models import ProofResult

from utils.logger import get_logger

logger = get_logger(__name__)


class GenericProver(BaseProver):
    """Minimal proof: just confirm the finding is repeatable."""

    async def prove(self, finding: dict) -> ProofResult:
        result = ProofResult()
        url = (
            finding.get("matched_at")
            or finding.get("endpoint")
            or finding.get("url")
            or finding.get("host", "")
        )

        # THEME-10 FIX: Explicit "not attempted" instead of silent empty result
        if not url:
            return ProofResult.not_attempted("missing_url")
        # Auto-prepend scheme for bare hostnames (e.g., "localhost:8080")
        if url and not url.startswith("http"):
            url = f"http://{url}"

        # --- Q1: Can I repeat? ---
        status, body, _ = await self._safe_request("GET", url)
        if status > 0:
            result.can_repeat = True
            result.repeat_count = 1
            self._record_vector_attempt("generic_repeat", True, "", url)
        else:
            self._record_vector_attempt("generic_repeat", False, "", url)

        result.requests_used = self._requests_used
        return result.finalize()  # FIX P0-005: Calculate proof outcome and impact
