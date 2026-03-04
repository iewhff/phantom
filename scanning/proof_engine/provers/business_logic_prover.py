"""
PHANTOM AI - Business Logic Prover

Proves business logic exploitability: repeat, amplify, escalate to financial impact.
Extracted from scanning/exploit_proof_engine.py.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from scanning.proof_engine.base_prover import BaseProver
from scanning.proof_engine.models import ProofResult

from utils.logger import get_logger

logger = get_logger(__name__)


class BusinessLogicProver(BaseProver):
    """Prove business logic exploitability: repeat, amplify, escalate to financial impact."""

    async def prove(self, finding: dict) -> ProofResult:
        result = ProofResult()
        url = finding.get("matched_at", "")
        metadata = finding.get("metadata", {})
        evidence = finding.get("evidence", [])
        name = finding.get("name", "").lower()

        # THEME-10 FIX: Explicit "not attempted" instead of silent empty result
        if not url:
            return ProofResult.not_attempted("missing_url")

        # Extract original method and payload from evidence
        method, field_name, payload = self._extract_attack_details(finding)

        # ═══════════════════════════════════════════════════════════════════
        # STATE-02 FIX: 3-step verification — baseline -> mutate -> re-check
        # Philosophy: "Prova consequencias persistentes, nao so aceitacao"
        # ═══════════════════════════════════════════════════════════════════
        # H4 FIX 2026-02-12: hashlib moved to module level

        # Determine baseline URL (e.g., for cart mutation, GET the cart to verify)
        baseline_url = self._infer_baseline_url(url, finding)

        # Step 1: Capture baseline state BEFORE mutation
        baseline_status, baseline_body, _ = await self._safe_request("GET", baseline_url)
        baseline_snapshot: dict[str, Any] = {}
        if baseline_status == 200 and len(baseline_body) > 5:
            baseline_snapshot = {
                "hash": hashlib.md5(baseline_body.encode()).hexdigest(),
                "body": baseline_body,
                "values": self._extract_numeric_values(baseline_body),
            }

        # --- Q1: Can I repeat? ---
        if method and field_name and payload is not None:
            status, body, _ = await self._safe_request(
                method, url,
                json_data={field_name: payload},
                headers={"Content-Type": "application/json"},
            )
            if status in (200, 201) and len(body) > 5:
                result.can_repeat = True
                result.repeat_count = 1
                self._record_vector_attempt("business_repeat", True, str(payload), url)
            else:
                self._record_vector_attempt("business_repeat", False, str(payload), url)

        # --- Q2: Can I mutate? (amplify the attack) ---
        if self.budget_remaining > 0 and result.can_repeat and field_name:
            mutations = self._generate_mutations(name, field_name, payload)
            for label, mut_payload in mutations:
                if self.budget_remaining <= 0:
                    break
                status, body, _ = await self._safe_request(
                    method, url,
                    json_data={field_name: mut_payload},
                    headers={"Content-Type": "application/json"},
                )
                if status in (200, 201) and len(body) > 5:
                    result.can_mutate = True
                    result.mutations.append(f"{label}: {field_name}={mut_payload}")
                    self._record_vector_attempt(f"business_mutate_{label}", True, str(mut_payload), url)
                else:
                    self._record_vector_attempt(f"business_mutate_{label}", False, str(mut_payload), url)

        # ═══════════════════════════════════════════════════════════════════
        # STATE-02: Step 3 — Re-check to verify persistence
        # ═══════════════════════════════════════════════════════════════════
        if result.can_mutate and baseline_snapshot and self.budget_remaining > 0:
            # Re-fetch the resource to see if mutation PERSISTED
            recheck_status, recheck_body, _ = await self._safe_request("GET", baseline_url)

            if recheck_status == 200 and len(recheck_body) > 5:
                recheck_hash = hashlib.md5(recheck_body.encode()).hexdigest()
                recheck_values = self._extract_numeric_values(recheck_body)

                # Compare to baseline
                if recheck_hash != baseline_snapshot["hash"]:
                    # Response different — check what changed
                    changes = self._detect_value_changes(
                        baseline_snapshot["values"],
                        recheck_values,
                        field_name,
                    )

                    if changes:
                        result.state_persisted = True
                        result.persistence_evidence = changes
                        result.confidence_boost = 15.0
                        result.proven_impact = "Persistent state change verified"
                        logger.info(
                            f"[STATE-02] Business logic mutation PERSISTED: {changes}"
                        )

                        # THEME-15 FIX: Record specific action and financial impact
                        result.action_performed = f"Modified {field_name} to invalid value"
                        # Detect financial impact from the changes
                        for change in changes:
                            if any(x in change.lower() for x in ["price", "total", "amount", "balance", "credit"]):
                                result.data_extracted.append(f"financial_impact:{change}")
                        result.impact_evidence = {
                            "mutation_type": "business_logic",
                            "field_affected": field_name,
                            "persistence": "verified",
                            "changes": changes[:5],
                        }
                    else:
                        # Response changed but we can't identify specific field
                        result.state_persisted = True
                        result.persistence_evidence = ["Response body changed after mutation"]
                        result.confidence_boost = 10.0
                        result.proven_impact = "State change detected (unspecified field)"
                        # THEME-15: Still record the action even if we can't quantify impact
                        result.action_performed = f"Modified {field_name} (impact unclear)"
                else:
                    # Same response = mutation NOT persisted (server likely rejected)
                    logger.debug(
                        f"[STATE-02] Business logic mutation NOT persisted: "
                        f"re-check identical to baseline"
                    )
                    result.persistence_evidence = ["Mutation NOT persisted - server rejected"]
                    result.confidence_boost = -10.0

        # --- Q3: Can I escalate? (financial impact) ---
        if result.can_repeat and ("quantity" in name or "price" in name or "total" in name):
            result.can_escalate = True
            self._record_vector_attempt("business_escalate_financial", True, "", url)
            if result.state_persisted:
                result.escalation = (
                    "Business logic flaw VERIFIED: mutation persisted. "
                    "Financial impact confirmed — negative values accepted AND saved."
                )
                # THEME-15 FIX: Record privilege gained from financial manipulation
                result.privilege_gained = "financial_manipulation"
                if not result.action_performed:
                    result.action_performed = f"Manipulated {name} field"
            else:
                result.escalation = (
                    "Business logic flaw detected. "
                    "Negative quantities/prices may lead to credit generation or free goods."
                )

        # --- Q4: Can I chain? ---
        idor_findings = self._find_related_findings(["idor"])
        sqli_findings = self._find_related_findings(["sql_injection"])
        if idor_findings:
            result.can_chain = True
            result.chain_targets.append("IDOR + business logic = manipulate other users' orders")
            self._record_vector_attempt("business_chain_idor", True, "", url)
        if sqli_findings:
            result.can_chain = True
            result.chain_targets.append("SQLi + business logic = bypass all server-side validation")
            self._record_vector_attempt("business_chain_sqli", True, "", url)

        result.requests_used = self._requests_used
        return result.finalize()  # FIX P0-005: Calculate proof outcome and impact

    def _infer_baseline_url(self, mutation_url: str, finding: dict) -> str:
        """Infer the URL to check for state changes after mutation."""
        # For cart item mutations, the baseline is the cart itself
        # /api/cart/items/123 -> /api/cart
        # /api/basket/5 -> /api/basket/5
        url_lower = mutation_url.lower()

        # Cart patterns
        if "/items/" in url_lower or "/basketitems" in url_lower.replace("-", ""):
            # Strip the item ID to get the cart URL
            if "/items/" in mutation_url:
                return mutation_url.split("/items/")[0]
            if "/BasketItems" in mutation_url:
                return mutation_url.replace("/BasketItems", "")

        # For other patterns, use the same URL (GET the resource we mutated)
        return mutation_url

    def _extract_numeric_values(self, body: str) -> dict[str, float]:
        """Extract numeric field values from JSON response."""
        values: dict[str, float] = {}
        try:
            data = json.loads(body) if body.strip().startswith(("{", "[")) else {}
            self._extract_values_recursive(data, "", values)
        except (json.JSONDecodeError, ValueError):
            pass
        return values

    def _extract_values_recursive(
        self,
        data: Any,
        prefix: str,
        values: dict[str, float],
        max_depth: int = 3,
    ) -> None:
        """Recursively extract numeric values."""
        if max_depth <= 0:
            return
        # M3 FIX: Check data (not metadata - was a bug)
        if isinstance(data, dict):
            for k, v in data.items():
                key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (int, float)):
                    values[key] = v
                elif isinstance(v, (dict, list)):
                    self._extract_values_recursive(v, key, values, max_depth - 1)
        elif isinstance(data, list):
            for i, item in enumerate(data[:5]):
                self._extract_values_recursive(item, f"{prefix}[{i}]", values, max_depth - 1)

    def _detect_value_changes(
        self,
        before: dict[str, float],
        after: dict[str, float],
        target_field: str,
    ) -> list[str]:
        """Detect which numeric values changed between baseline and re-check."""
        changes = []
        target_lower = target_field.lower()

        # LOGIC-V4 FIX: Fixed index/key confusion in dict iteration
        for key in before:
            key_lower = key.lower()
            if key in after and before[key] != after[key]:
                # Prioritize changes in the target field
                if target_lower in key_lower or key_lower in target_lower:
                    changes.insert(0, f"{key}: {before[key]} → {after[key]}")
                else:
                    changes.append(f"{key}: {before[key]} → {after[key]}")

        # Check for new keys in after
        for key in after:
            if key not in before:
                changes.append(f"{key}: (new) = {after[key]}")

        return changes[:5]  # Max 5 changes

    def _extract_attack_details(self, finding: dict) -> tuple[str, str, Any]:
        """Extract method, field, and payload from finding evidence."""
        evidence = finding.get("evidence", [])
        # M3 FIX: Single isinstance check with guard clause
        metadata = finding.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        method = metadata.get("method", "POST")
        field_name = metadata.get("field", "")
        payload = metadata.get("payload", None)

        # Try to parse from evidence strings
        if not field_name and evidence:
            for ev in evidence:
                if isinstance(ev, str):
                    m = re.match(r'(GET|POST|PUT|DELETE|PATCH)\s+\S+\s+with\s+(\w+)=(.+?)(?:\s+→|$)', ev)
                    if m:
                        method = m.group(1)
                        field_name = m.group(2)
                        try:
                            payload = json.loads(m.group(3))
                        except (json.JSONDecodeError, ValueError):
                            payload = m.group(3).strip("'\"")
                        break

        return method, field_name, payload

    def _generate_mutations(self, name: str, field_name: str, original_payload: Any) -> list[tuple[str, Any]]:
        """Generate mutation payloads based on the vulnerability type."""
        mutations = []

        if "quantity" in name or "quantity" in field_name:
            mutations = [
                ("extreme_negative", -99999),
                ("fractional_negative", -0.01),
                ("zero", 0),
            ]
        elif "price" in name or "price" in field_name or "total" in field_name:
            mutations = [
                ("zero_price", 0),
                ("negative_price", -1),
                ("penny", 0.01),
            ]
        elif "rating" in name or "rating" in field_name:
            mutations = [
                ("negative_rating", -1),
                ("extreme_rating", 999),
                ("zero_rating", 0),
            ]
        else:
            # Generic mutations
            if isinstance(original_payload, (int, float)):
                mutations = [
                    ("zero", 0),
                    ("negative", -1),
                    ("extreme", 999999),
                ]
            elif isinstance(original_payload, str):
                mutations = [
                    ("empty", ""),
                    ("long", "A" * 1000),
                ]

        return mutations[:3]  # Max 3 mutations
