"""
PHANTOM AI - IDOR Prover

Proves IDOR exploitability: repeat, enumerate, escalate read->write.
Extracted from scanning/exploit_proof_engine.py.
"""

from __future__ import annotations

import hashlib
import json
import re

from scanning.proof_engine.base_prover import BaseProver
from scanning.proof_engine.models import ProofResult

from utils.logger import get_logger

logger = get_logger(__name__)


class IDORProver(BaseProver):
    """Prove IDOR exploitability: repeat, enumerate, escalate read->write."""

    async def prove(self, finding: dict) -> ProofResult:
        result = ProofResult()
        url, _, _ = self._parse_matched_at(finding)
        metadata = finding.get("metadata", {})

        # THEME-10 FIX: Explicit "not attempted" instead of silent empty result
        if not url:
            return ProofResult.not_attempted("missing_url")

        # ═══════════════════════════════════════════════════════════════════
        # STATE-01 FIX: Capture baseline for comparison
        # A 200 status alone is NOT proof - response must be DIFFERENT
        # ═══════════════════════════════════════════════════════════════════
        # H4 FIX 2026-02-12: hashlib moved to module level

        # --- Q1: Can I repeat? ---
        status, body, _ = await self._safe_request("GET", url)
        if status == 200 and len(body) > 10:
            result.can_repeat = True
            result.repeat_count = 1
            # Capture baseline hash for comparison
            baseline_hash = hashlib.md5(body.encode() if isinstance(body, str) else body).hexdigest()
            self._record_vector_attempt("idor_repeat", True, "", url)

            # THEME-15 FIX: Extract actual data from response to show what attacker accessed
            extracted = self._extract_user_data_from_response(body)
            if extracted:
                result.data_extracted.extend(extracted)
                result.impact_evidence = {
                    "initial_access": True,
                    "data_types": list(set(e.split(":")[0] for e in extracted if ":" in e)),
                    "item_count": len(extracted),
                }
        else:
            baseline_hash = None
            self._record_vector_attempt("idor_repeat", False, "", url)

        # --- Q2: Can I mutate? (enumerate IDs) ---
        # GAP-4 FIX: Test 20 IDs instead of 4 for enumeration scale proof
        if self.budget_remaining > 0 and result.can_repeat and baseline_hash:
            # Try to find numeric ID in URL and vary it
            id_match = re.search(r'/(\d+)(?:/|$|\?)', url)
            if id_match:
                original_id = int(id_match.group(1))

                # GAP-4 FIX: Generate 20 test IDs for comprehensive enumeration
                test_ids = self._generate_enumeration_ids(original_id, count=20)

                # Track enumeration metrics
                enumeration_metrics = {
                    "tested": 0,
                    "accessible": 0,
                    "horizontal": 0,  # Same user type, different user
                    "vertical": 0,    # Different privilege level
                    "accessible_ids": [],
                }

                for tid in test_ids:
                    if self.budget_remaining <= 0:
                        break
                    enumeration_metrics["tested"] += 1
                    test_url = url[:id_match.start(1)] + str(tid) + url[id_match.end(1):]
                    status, body, _ = await self._safe_request("GET", test_url)
                    if status == 200 and len(body) > 10:
                        # STATE-01 FIX: Compare to baseline - must be DIFFERENT
                        test_hash = hashlib.md5(body.encode() if isinstance(body, str) else body).hexdigest()
                        if test_hash != baseline_hash:
                            enumeration_metrics["accessible"] += 1
                            enumeration_metrics["accessible_ids"].append(tid)

                            # First accessible ID confirms mutation
                            if not result.can_mutate:
                                result.can_mutate = True
                                result.mutations.append(f"ID={tid} returns DIFFERENT data (verified)")
                                self._record_vector_attempt(f"idor_mutate_id_{tid}", True, str(tid), test_url)

                            # THEME-15 FIX: Extract and record OTHER user's data
                            other_user_data = self._extract_user_data_from_response(body)
                            if other_user_data:
                                # Categorize as horizontal or vertical
                                if self._is_elevated_privilege(body):
                                    enumeration_metrics["vertical"] += 1
                                else:
                                    enumeration_metrics["horizontal"] += 1

                                # Record first few user's data
                                if len(result.data_extracted) < 15:
                                    for item in other_user_data[:3]:
                                        result.data_extracted.append(f"other_user_{tid}:{item}")
                        else:
                            # Same response = likely cached or error page, not real IDOR
                            logger.debug(f"[STATE-01] ID={tid} same as baseline - not true IDOR")
                            self._record_vector_attempt(f"idor_mutate_id_{tid}", False, str(tid), test_url)

                # GAP-4 FIX: Record enumeration scale in evidence
                if enumeration_metrics["accessible"] > 0:
                    result.privilege_gained = "horizontal_access" if enumeration_metrics["horizontal"] > 0 else "vertical_access"
                    if not result.impact_evidence:
                        result.impact_evidence = {}
                    result.impact_evidence["enumeration_scale"] = {
                        "ids_tested": enumeration_metrics["tested"],
                        "ids_accessible": enumeration_metrics["accessible"],
                        "horizontal_access": enumeration_metrics["horizontal"],
                        "vertical_access": enumeration_metrics["vertical"],
                        "sample_ids": enumeration_metrics["accessible_ids"][:5],
                    }
                    result.proven_impact = (
                        f"Enumerated {enumeration_metrics['accessible']}/{enumeration_metrics['tested']} IDs accessible. "
                        f"Horizontal: {enumeration_metrics['horizontal']}, Vertical: {enumeration_metrics['vertical']}."
                    )

        # --- Q3: Can I escalate? (read -> write) ---
        # ═══════════════════════════════════════════════════════════════════════
        # STATE-02: 3-step verification for write operations
        # ISSUE-9 CLARIFICATION 2026-02-11: Budget checks appear throughout, but each is
        # BEFORE a distinct request. The pattern is:
        # 1. Check before phase -> 2. Check inside loop before each req -> 3. _safe_request also checks
        # This is intentional: caller checks prevent unnecessary loop iterations
        # ═══════════════════════════════════════════════════════════════════════
        if self.budget_remaining > 0 and self._limits.get("allow_write", False) and result.can_repeat:
            # Try PUT/DELETE on same resource
            for method in ["PUT", "DELETE"]:
                if self.budget_remaining <= 0:
                    break
                status, body, _ = await self._safe_request(method, url, json_data={})
                if status in (200, 201, 204):
                    # STATE-02 FIX: For write ops, verify state PERSISTED
                    # Re-fetch and compare to baseline
                    if baseline_hash and self.budget_remaining > 0:
                        verify_status, verify_body, _ = await self._safe_request("GET", url)
                        verify_hash = hashlib.md5(
                            verify_body.encode() if isinstance(verify_body, str) else verify_body
                        ).hexdigest()

                        if verify_status in (404, 410):
                            # Resource deleted — state change CONFIRMED
                            result.can_escalate = True
                            result.state_persisted = True
                            result.persistence_evidence = [f"Resource deleted (HTTP {verify_status})"]
                            result.confidence_boost = 20.0
                            result.escalation = f"{method} on IDOR resource VERIFIED (deleted)"
                            result.proven_impact = "Persistent deletion verified"
                            # THEME-15 FIX: Record the action performed
                            result.action_performed = f"DELETE resource (verified via HTTP {verify_status})"
                            result.privilege_gained = "write_access"
                            self._record_vector_attempt(f"idor_escalate_{method.lower()}", True, "", url)
                            break
                        elif verify_hash != baseline_hash:
                            # Resource modified — state change CONFIRMED
                            result.can_escalate = True
                            result.state_persisted = True
                            result.persistence_evidence = ["Resource content changed after mutation"]
                            result.confidence_boost = 15.0
                            result.escalation = f"{method} on IDOR resource VERIFIED (state changed)"
                            result.proven_impact = "Persistent modification verified"
                            # THEME-15 FIX: Record the action performed
                            result.action_performed = f"{method} modified resource (verified via re-fetch)"
                            result.privilege_gained = "write_access"
                            self._record_vector_attempt(f"idor_escalate_{method.lower()}", True, "", url)
                            break
                        else:
                            # Same response = mutation NOT persisted
                            logger.debug(f"[STATE-02] {method} returned success but state unchanged")
                            result.persistence_evidence = [f"{method} accepted but state NOT persisted"]
                            result.confidence_boost = -10.0
                            self._record_vector_attempt(f"idor_escalate_{method.lower()}", False, "", url)
                    else:
                        # ═══════════════════════════════════════════════════════════════════════
                        # AUTOMATIC VALIDATION FIX: No baseline? Try to verify NOW
                        # Instead of "unverified - no baseline", we attempt verification automatically
                        # ═══════════════════════════════════════════════════════════════════════
                        if self.budget_remaining > 0:
                            # Try to verify by doing a fresh GET after the write
                            # Success criteria: resource deleted (404) or content changed
                            verify_status, verify_body, _ = await self._safe_request("GET", url)

                            if verify_status in (404, 410):
                                # Resource deleted - write operation VERIFIED
                                result.can_escalate = True
                                result.state_persisted = True
                                result.persistence_evidence = [f"DELETE verified: resource now returns {verify_status}"]
                                result.confidence_boost = 15.0
                                result.escalation = f"{method} on IDOR resource VERIFIED (auto-check: deleted)"
                                result.action_performed = f"DELETE resource (auto-verified: HTTP {verify_status})"
                                result.privilege_gained = "write_access_verified"
                                self._record_vector_attempt(f"idor_escalate_{method.lower()}", True, "", url)
                            elif verify_status == 200 and verify_body:
                                # Resource still exists - check if content likely changed
                                # (we don't have original baseline, but success response suggests write worked)
                                result.can_escalate = True
                                result.state_persisted = False  # Can't confirm without baseline
                                result.persistence_evidence = [f"{method} accepted (HTTP {status}), resource accessible"]
                                result.confidence_boost = 5.0  # Lower boost without baseline
                                result.escalation = (
                                    f"{method} returned {status}. Resource still accessible. "
                                    "State change likely but unconfirmed due to missing baseline."
                                )
                                result.action_performed = f"{method} executed (partial verification)"
                                result.privilege_gained = "write_access_likely"
                                self._record_vector_attempt(f"idor_escalate_{method.lower()}", True, "", url)
                            else:
                                # Verification failed - write operation suspicious
                                result.can_escalate = False
                                result.escalation = f"{method} returned {status} but verification failed ({verify_status})"
                                self._record_vector_attempt(f"idor_escalate_{method.lower()}", False, "", url)
                        else:
                            # Budget exhausted - accept partial proof with reduced confidence
                            result.can_escalate = True
                            result.state_persisted = False
                            result.confidence_boost = 0.0  # No boost without verification
                            result.escalation = f"{method} returned {status} (budget exhausted for verification)"
                            result.persistence_evidence = ["Budget exhausted - verification skipped"]
                            self._record_vector_attempt(f"idor_escalate_{method.lower()}", True, "", url)

        # --- Q4: Can I chain? ---
        if result.can_mutate:
            business_findings = self._find_related_findings(["business_logic"])
            if business_findings:
                result.can_chain = True
                result.chain_targets.append("IDOR + business logic = manipulate other users' resources")
                self._record_vector_attempt("idor_chain_business", True, "", url)

        result.requests_used = self._requests_used
        return result.finalize()  # FIX P0-005: Calculate proof outcome and impact

    # =========================================================================
    # GAP-4 FIX: Helper methods for enumeration scale
    # =========================================================================

    def _generate_enumeration_ids(self, original_id: int, count: int = 20) -> list[int]:
        """
        GAP-4 FIX: Generate test IDs for comprehensive enumeration.

        Strategy:
        - Adjacent IDs (original +/- 1-5)
        - Low IDs (1, 2, 3, 0 -- often admin/system accounts)
        - Sequential range near original
        - Large ID (test for wraparound/overflow)
        """
        test_ids = []

        # Adjacent IDs (most likely to exist)
        for delta in range(1, 6):
            test_ids.append(original_id + delta)
            test_ids.append(original_id - delta)

        # Low IDs (admin accounts often start at 1)
        test_ids.extend([1, 2, 3, 0])

        # Sequential range
        for i in range(original_id - 10, original_id + 10):
            if i > 0 and i not in test_ids:
                test_ids.append(i)

        # Large ID (overflow test)
        test_ids.append(999999)

        # Remove original ID and deduplicate
        test_ids = [i for i in test_ids if i != original_id and i >= 0]
        seen = set()
        unique_ids = []
        for i in test_ids:
            if i not in seen:
                seen.add(i)
                unique_ids.append(i)

        return unique_ids[:count]

    def _is_elevated_privilege(self, body: str) -> bool:
        """
        GAP-4 FIX: Detect if accessed resource belongs to elevated user.

        Returns True if response contains admin/privileged indicators.
        """
        body_lower = body.lower()
        privilege_indicators = [
            '"role":"admin"', '"role": "admin"',
            '"isadmin":true', '"isAdmin":true', '"is_admin":true',
            '"role":"administrator"', '"permission":"admin"',
            '"access_level":"high"', '"privilege":"elevated"',
            '"user_type":"admin"', '"account_type":"premium"',
            '"superuser":true', '"staff":true',
        ]
        return any(indicator in body_lower for indicator in privilege_indicators)

    def _extract_user_data_from_response(self, body: str) -> list[str]:
        """
        THEME-15 FIX: Extract actual user data from IDOR response.

        Converts "accessed resource" into "extracted email, name, balance, etc."
        """
        extracted = []

        # Try to parse as JSON first
        try:
            data = json.loads(body)
            # C1 FIX 2026-02-12: Fixed NameError — was `metadata`, should be `data`
            if isinstance(data, dict):
                # Extract common PII fields
                pii_fields = ["email", "username", "name", "phone", "address", "balance", "credit", "ssn", "password"]
                for field in pii_fields:
                    if field in data and data[field]:
                        value = str(data[field])
                        if field == "password":
                            extracted.append("password:***hash***")
                        elif len(value) < 100:
                            extracted.append(f"{field}:{value[:50]}")

                # Check for nested user data
                if "user" in data and isinstance(data["user"], dict):
                    for field in pii_fields:
                        if field in data["user"] and data["user"][field]:
                            value = str(data["user"][field])
                            if field == "password":
                                extracted.append("password:***hash***")
                            elif len(value) < 100:
                                extracted.append(f"{field}:{value[:50]}")

            elif isinstance(data, list) and len(data) > 0:
                # List of records - extract from first item
                first = data[0] if isinstance(data[0], dict) else {}
                pii_fields = ["email", "username", "name", "id"]
                for field in pii_fields:
                    if field in first:
                        extracted.append(f"{field}:{str(first[field])[:30]}")
                extracted.append(f"records:{len(data)}")

        except (json.JSONDecodeError, TypeError):
            # Not JSON - try regex extraction
            pass

        # Regex extraction for common patterns
        email_pattern = re.compile(r'[\w\.\-]+@[\w\.\-]+\.\w{2,}')
        emails = email_pattern.findall(body)
        for email in emails[:3]:
            if f"email:{email}" not in extracted:
                extracted.append(f"email:{email}")

        # Extract phone numbers
        phone_pattern = re.compile(r'\b[\+]?[(]?[0-9]{1,3}[)]?[-\s\.]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{3,6}\b')
        phones = phone_pattern.findall(body)
        for phone in phones[:2]:
            extracted.append(f"phone:{phone}")

        # Extract monetary values
        money_pattern = re.compile(r'\$[\d,]+\.?\d{0,2}|\d+\.\d{2}')
        amounts = money_pattern.findall(body)
        for amount in amounts[:2]:
            extracted.append(f"amount:{amount}")

        return extracted[:15]  # Limit to prevent bloat
