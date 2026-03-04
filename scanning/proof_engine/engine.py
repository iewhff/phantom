"""
PHANTOM AI - Exploitation Proof Engine (Orchestrator)

Phase 4.2: Prove what each HIGH+ finding can actually DO.
Extracted from scanning/exploit_proof_engine.py.
"""

from __future__ import annotations

import asyncio
from typing import Any

from scanning.proof_engine.models import (
    PROOF_LIMITS,
    SAFE_MODE,
    ProofOutcome,
    ProofResult,
)
from scanning.proof_engine.base_prover import BaseProver
from scanning.proof_engine.provers import (
    BusinessLogicProver,
    CMDIProver,
    CORSProver,
    DeserializationProver,
    GenericProver,
    IDORProver,
    LFIProver,
    SQLiProver,
    SSRFProver,
    SSTIProver,
    SessionProver,
    XSSProver,
    XXEProver,
)
from utils.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# Prover Registry
# =============================================================================

PROVER_MAP: dict[str, type[BaseProver]] = {
    # Injection — SQL/NoSQL
    "sql_injection": SQLiProver,
    "sqli": SQLiProver,  # M4: Common alias
    "nosql_injection": SQLiProver,  # M4: Similar injection pattern
    "nosql": SQLiProver,  # M4: Common alias
    # Injection — XSS
    "xss": XSSProver,
    "dom_xss": XSSProver,
    "reflected_xss": XSSProver,  # M4: XSS variant
    "stored_xss": XSSProver,  # M4: XSS variant
    # Injection — Template/Command
    "ssti": SSTIProver,
    "template_injection": SSTIProver,
    "cmdi": CMDIProver,
    "command_injection": CMDIProver,
    "os_command_injection": CMDIProver,
    # File/Network
    "lfi": LFIProver,
    "local_file_inclusion": LFIProver,
    "path_traversal": LFIProver,
    "file_read": LFIProver,
    "ssrf": SSRFProver,
    "server_side_request_forgery": SSRFProver,
    "xxe": XXEProver,
    "xml_external_entity": XXEProver,
    # Deserialization
    "deserialization": DeserializationProver,
    "insecure_deserialization": DeserializationProver,
    "unsafe_deserialization": DeserializationProver,
    # Access Control
    "idor": IDORProver,
    "authorization": IDORProver,  # M4: Access control
    "access_control": IDORProver,  # M4: Access control alias
    "broken_access_control": IDORProver,  # M4: OWASP naming
    "business_logic": BusinessLogicProver,
    "race_condition": BusinessLogicProver,  # M4: State manipulation
    "session_abuse": SessionProver,
    "session": SessionProver,
    "jwt": SessionProver,  # M4: JWT is session-related
    "jwt_vulnerability": SessionProver,  # M4: JWT alias
    # CORS
    "cors": CORSProver,  # M4: Base type
    "cors_wildcard": CORSProver,
    "cors_null": CORSProver,
    "cors_preflight": CORSProver,
    "cors_arbitrary": CORSProver,
    # Generic fallback types (M4: Common vulns without specialized provers)
    "open_redirect": GenericProver,
    "csrf": GenericProver,
    "clickjacking": GenericProver,
    "information_disclosure": GenericProver,
}


# =============================================================================
# Exploitation Proof Engine
# =============================================================================

class ExploitProofEngine:
    """Phase 4.2: Prove what each HIGH+ finding can actually DO.

    For every HIGH/CRITICAL finding, answers:
    - Can I repeat?  (deterministic)
    - Can I mutate?  (flexible payloads)
    - Can I escalate? (higher impact)
    - Can I chain?   (compound attack)
    """

    def __init__(
        self,
        settings: Any,
        auth_context: Any = None,
        rate_limiter: Any = None,
        endpoint_map: Any = None,
        exhaustion_tracker: Any = None,
        focus_lock: Any = None,
    ) -> None:
        self._settings = settings
        self._auth_context = auth_context
        self._rate_limiter = rate_limiter
        self._endpoint_map = endpoint_map
        self._exhaustion_tracker = exhaustion_tracker
        self._focus_lock = focus_lock

        # Determine safety limits
        mode = getattr(settings, 'safe_mode', SAFE_MODE)
        if isinstance(mode, str):
            mode = mode.lower()
        self._limits = PROOF_LIMITS.get(mode, PROOF_LIMITS["safe"])
        self._total_requests_used = 0

        # THEME-3: Track auth requirements for proof engine
        self._auth_requirements_log: list[str] = []

        # ISSUE-8 FIX 2026-02-11: Type-based cache of successful proof techniques
        # If SQLi extraction works on endpoint A, reuse technique on endpoint B
        self._type_cache: dict[str, dict[str, Any]] = {}
        # Cache structure: {
        #   "sqli": {"extraction_technique": "UNION SELECT", "extracted_tables": ["users", "orders"]},
        #   "xss": {"working_payload": "<img src=x onerror=alert(1)>", "context": "attribute"},
        # }

        # H2 FIX 2026-02-12: Metrics tracking (like Attack Chain Analyzer)
        self._metrics: dict[str, Any] = self._init_metrics()

    def _init_metrics(self) -> dict[str, Any]:
        """Initialize metrics structure."""
        return {
            "findings_processed": 0,
            "findings_proven": 0,
            "findings_skipped": 0,
            "findings_failed": 0,
            "requests_used": 0,
            "by_prover": {},
            "by_outcome": {
                "proven": 0,
                "attempted_partial": 0,
                "attempted_failed": 0,
                "not_attempted": 0,
            },
            "errors": [],
        }

    def get_metrics(self) -> dict[str, Any]:
        """Get current metrics snapshot."""
        return {
            **self._metrics,
            "requests_used": self._total_requests_used,
        }

    def reset_metrics(self) -> None:
        """Reset metrics counters."""
        self._metrics = self._init_metrics()
        self._total_requests_used = 0

    def _record_error(self, error: str, context: str = "") -> None:
        """Record an error for metrics tracking."""
        self._metrics["errors"].append({
            "error": error,
            "context": context,
        })

    def _check_and_record_auth_usage(self) -> None:
        """THEME-3: Check auth context and log usage/skip for proof engine."""
        if self._auth_context is None:
            logger.info("[ProofEngine] No auth context — some proofs may be limited")
            return

        # Record usage if auth context supports tracking
        if hasattr(self._auth_context, 'record_usage'):
            # Check if auth allows the operations we need
            if self._limits.get("allow_auth", False):
                self._auth_context.record_usage(
                    module_name="exploit_proof_engine",
                    auth_type_required="any"
                )
                logger.debug("[ProofEngine] Auth context recorded for proof operations")
            else:
                # Auth not allowed in this mode
                if hasattr(self._auth_context, 'record_skip'):
                    self._auth_context.record_skip(
                        "exploit_proof_engine",
                        f"auth_not_allowed_in_{SAFE_MODE}_mode"
                    )
                logger.info(f"[ProofEngine] Auth available but not allowed in {SAFE_MODE} mode")

        # Check if we need admin but only have user
        if hasattr(self._auth_context, 'role'):
            role = getattr(self._auth_context, 'role', 'user')
            if role != 'admin':
                self._auth_requirements_log.append(
                    f"proof_engine: has {role} role, admin would enable escalation proofs"
                )

    async def prove_all(self, result: Any) -> None:
        """Prove all HIGH+ findings in the scan result.

        Mutates result.findings in-place, adding metadata.proof to each.
        May also append new findings discovered during escalation/chaining.
        """
        if self._limits["max_requests"] == 0:
            logger.info("[ProofEngine] Skipped — safe mode (0 request budget)")
            return

        # THEME-3: Record auth context usage for proof engine
        self._check_and_record_auth_usage()

        findings = result.findings
        high_plus = [
            f for f in findings
            if (f.get("severity") or "").upper() in ("HIGH", "CRITICAL")
            and (f.get("metadata") or {}).get("proof_status") != "speculative"
            and f.get("discovered_via") != "vulnerability_chain"
        ]

        if not high_plus:
            logger.info("[ProofEngine] No HIGH+ findings to prove")
            return

        logger.info(f"[ProofEngine] Proving {len(high_plus)} HIGH+ findings "
                     f"(budget: {self._limits['max_requests']} requests)")

        # Sort: CRITICAL first, then by type (SQLi first for credential feedback)
        severity_order = {"CRITICAL": 0, "HIGH": 1}
        type_priority = {"sql_injection": 0, "session_abuse": 1}
        high_plus.sort(key=lambda f: (
            severity_order.get(f.get("severity", "").upper(), 9),
            type_priority.get(f.get("vuln_type", f.get("type", "")), 5),
        ))

        new_findings = []
        unproven_findings = []  # THEME-12: Track findings skipped due to budget
        budget_remaining = self._limits["max_requests"]
        proven_count = 0

        for idx, finding in enumerate(high_plus):
            if budget_remaining <= 0:
                # THEME-12: Track all remaining unproven findings
                unproven_findings = [
                    {"id": f.get("id", f"finding_{i}"), "name": f.get("name", "unknown"), "reason": "budget_exhausted"}
                    for i, f in enumerate(high_plus[idx:], start=idx)
                ]
                logger.info(
                    f"[AUDIT] Budget exhausted: {len(unproven_findings)} findings not proven "
                    f"({', '.join(f['name'][:30] for f in unproven_findings[:5])}...)"
                )
                break

            finding_type = finding.get("vuln_type", finding.get("type", ""))
            prover_class = PROVER_MAP.get(finding_type, GenericProver)

            # Create per-finding budget
            per_finding_budget = min(
                budget_remaining,
                max(5, self._limits["max_requests"] // max(len(high_plus), 1)),
            )
            finding_limits = dict(self._limits)
            finding_limits["max_requests"] = per_finding_budget

            # Get finding ID for exhaustion tracking (set by full_scanner)
            finding_id = (finding.get("metadata") or {}).get("exhaustion_id", "")

            # ISSUE-8 FIX 2026-02-11: Get cached insights for this vuln type
            type_insights = self._type_cache.get(finding_type, {})

            prover = prover_class(
                auth_context=self._auth_context,
                rate_limiter=self._rate_limiter,
                endpoint_map=self._endpoint_map,
                limits=finding_limits,
                all_findings=findings,
                exhaustion_tracker=self._exhaustion_tracker,
                focus_lock=self._focus_lock,
                current_finding_id=finding_id,
                type_cache=type_insights,  # ISSUE-8: Pass cached insights
            )

            try:
                proof = await prover.prove(finding)
                # H2 FIX: Track successful proof
                self._metrics["findings_processed"] += 1
            except Exception as e:
                logger.warning(f"[ProofEngine] Prover {prover_class.__name__} failed: {e}")
                # BUG-FIX 2026-02-08: Use not_attempted with reason instead of empty ProofResult
                proof = ProofResult.not_attempted(f"prover_crashed: {prover_class.__name__}")
                # H2 FIX: Track error
                self._record_error(str(e), prover_class.__name__)
                self._metrics["findings_failed"] += 1

            # ISSUE-8 FIX: Store successful insights back to cache for next finding
            if proof.can_repeat or proof.can_mutate:
                if finding_type not in self._type_cache:
                    self._type_cache[finding_type] = {}
                # Store any extraction techniques or working payloads
                if proof.data_extracted:
                    self._type_cache[finding_type]["has_extraction"] = True
                if hasattr(prover, '_working_technique'):
                    self._type_cache[finding_type]["working_technique"] = prover._working_technique
                logger.debug(f"[ProofEngine] Cached insights for {finding_type}: {list(self._type_cache.get(finding_type, {}).keys())}")

            # Build impact narrative
            proof.impact_narrative = self._build_narrative(finding, proof)

            # Store proof in finding metadata
            finding.setdefault("metadata", {})["proof"] = proof.to_dict()

            # BUG-FIX 2026-02-08: Apply confidence_modifier based on proof outcome
            # THEME-10: Uncertain outcomes should REDUCE confidence, proven should BOOST
            # LOGIC-V4 FIX 2026-02-11: proof_outcome is STRING, use get_outcome() to get ENUM
            if proof.proof_outcome:
                outcome = proof.get_outcome()  # Convert string to ProofOutcome enum
                modifier = outcome.confidence_modifier()
                current_conf = finding.get("confidence_score", finding.get("confidence", 50.0))
                if isinstance(current_conf, str):
                    current_conf = {"critical": 95, "high": 85, "medium": 65, "low": 40}.get(
                        current_conf.lower(), 50.0
                    )
                new_conf = max(0.0, min(100.0, current_conf + (modifier * 100)))
                finding["confidence_score"] = new_conf
                finding["confidence"] = new_conf
                if abs(modifier) > 0.01:
                    logger.debug(
                        f"[ProofEngine] Confidence adjusted: {current_conf:.0f}% → {new_conf:.0f}% "
                        f"(modifier: {modifier:+.0%} due to {outcome.name})"
                    )

                # H2 FIX: Track outcome metrics
                outcome_key = outcome.name.lower()
                if outcome_key in self._metrics["by_outcome"]:
                    self._metrics["by_outcome"][outcome_key] += 1
                if outcome == ProofOutcome.PROVEN:
                    self._metrics["findings_proven"] += 1

            # H2 FIX: Track by prover type
            prover_name = prover_class.__name__
            if prover_name not in self._metrics["by_prover"]:
                self._metrics["by_prover"][prover_name] = {"processed": 0, "proven": 0}
            self._metrics["by_prover"][prover_name]["processed"] += 1
            if proof.can_repeat or proof.can_mutate or proof.can_escalate or proof.can_chain:
                self._metrics["by_prover"][prover_name]["proven"] += 1

            # Track budget
            budget_remaining -= proof.requests_used
            self._total_requests_used += proof.requests_used

            # Collect new findings from escalation
            new_findings.extend(proof.new_findings)

            # Log proof summary
            proved = sum([proof.can_repeat, proof.can_mutate, proof.can_escalate, proof.can_chain])
            logger.info(
                f"[ProofEngine] {finding_type}: {proved}/4 proven "
                f"({proof.proven_impact}) [{proof.requests_used} reqs]"
            )

        # Append any new findings discovered during proofs
        for nf in new_findings:
            result.add_finding(nf)

        # THEME-12: Store unproven findings in result for auditability
        if hasattr(result, 'unproven_findings'):
            result.unproven_findings = [f["id"] for f in unproven_findings]
            result.proofs_skipped = len(unproven_findings)

        logger.info(
            f"[ProofEngine] Complete: {self._total_requests_used} total requests, "
            f"{len(new_findings)} new findings from escalation, "
            f"{len(unproven_findings)} unproven (budget)"
        )

    async def prove_all_parallel(self, result: Any, max_concurrent: int = 5) -> None:
        """
        Prove all HIGH+ findings with parallelization.

        PERFORMANCE IMPROVEMENT: Runs independent provers in parallel.
        SQLi provers run FIRST (they can extract credentials), then all others run in parallel.

        Args:
            result: ScanResult containing findings
            max_concurrent: Maximum concurrent provers (default 5)
        """
        if self._limits["max_requests"] == 0:
            logger.info("[ProofEngine] Skipped — safe mode (0 request budget)")
            return

        self._check_and_record_auth_usage()

        findings = result.findings
        high_plus = [
            f for f in findings
            if (f.get("severity") or "").upper() in ("HIGH", "CRITICAL")
            and (f.get("metadata") or {}).get("proof_status") != "speculative"
            and f.get("discovered_via") != "vulnerability_chain"
        ]

        if not high_plus:
            logger.info("[ProofEngine] No HIGH+ findings to prove")
            return

        logger.info(f"[ProofEngine] Parallel proving {len(high_plus)} HIGH+ findings "
                    f"(budget: {self._limits['max_requests']} requests, max_concurrent: {max_concurrent})")

        # Separate SQLi findings (run first for credential feedback) from others
        sqli_findings = [f for f in high_plus if f.get("vuln_type", f.get("type", "")) == "sql_injection"]
        other_findings = [f for f in high_plus if f.get("vuln_type", f.get("type", "")) != "sql_injection"]

        # Thread-safe budget tracking
        budget_lock = asyncio.Lock()
        budget_remaining = [self._limits["max_requests"]]  # Use list for mutability
        new_findings_all = []
        unproven_findings = []

        async def prove_single(finding: dict) -> tuple[dict, ProofResult | None]:
            """Prove a single finding with budget checking."""
            async with budget_lock:
                if budget_remaining[0] <= 0:
                    return finding, None
                per_finding_budget = min(
                    budget_remaining[0],
                    max(5, self._limits["max_requests"] // max(len(high_plus), 1)),
                )

            finding_type = finding.get("vuln_type", finding.get("type", ""))
            prover_class = PROVER_MAP.get(finding_type, GenericProver)

            finding_limits = dict(self._limits)
            finding_limits["max_requests"] = per_finding_budget

            finding_id = (finding.get("metadata") or {}).get("exhaustion_id", "")
            type_insights = self._type_cache.get(finding_type, {})

            prover = prover_class(
                auth_context=self._auth_context,
                rate_limiter=self._rate_limiter,
                endpoint_map=self._endpoint_map,
                limits=finding_limits,
                all_findings=findings,
                exhaustion_tracker=self._exhaustion_tracker,
                focus_lock=self._focus_lock,
                current_finding_id=finding_id,
                type_cache=type_insights,
            )

            try:
                proof = await prover.prove(finding)
                self._metrics["findings_processed"] += 1
            except Exception as e:
                logger.warning(f"[ProofEngine] Prover {prover_class.__name__} failed: {e}")
                proof = ProofResult.not_attempted(f"prover_crashed: {prover_class.__name__}")
                self._record_error(str(e), prover_class.__name__)
                self._metrics["findings_failed"] += 1

            # Update budget
            async with budget_lock:
                budget_remaining[0] -= proof.requests_used
                self._total_requests_used += proof.requests_used

            # Cache successful insights
            if proof.can_repeat or proof.can_mutate:
                if finding_type not in self._type_cache:
                    self._type_cache[finding_type] = {}
                if proof.data_extracted:
                    self._type_cache[finding_type]["has_extraction"] = True
                if hasattr(prover, '_working_technique'):
                    self._type_cache[finding_type]["working_technique"] = prover._working_technique

            return finding, proof

        def apply_proof(finding: dict, proof: ProofResult) -> list[dict]:
            """Apply proof result to finding and return new findings."""
            proof.impact_narrative = self._build_narrative(finding, proof)
            finding.setdefault("metadata", {})["proof"] = proof.to_dict()

            # Apply confidence modifier
            if proof.proof_outcome:
                outcome = proof.get_outcome()
                modifier = outcome.confidence_modifier()
                current_conf = finding.get("confidence_score", finding.get("confidence", 50.0))
                if isinstance(current_conf, str):
                    current_conf = {"critical": 95, "high": 85, "medium": 65, "low": 40}.get(
                        current_conf.lower(), 50.0
                    )
                new_conf = max(0.0, min(100.0, current_conf + (modifier * 100)))
                finding["confidence_score"] = new_conf
                finding["confidence"] = new_conf

                # Track metrics
                outcome_key = outcome.name.lower()
                if outcome_key in self._metrics["by_outcome"]:
                    self._metrics["by_outcome"][outcome_key] += 1
                if outcome == ProofOutcome.PROVEN:
                    self._metrics["findings_proven"] += 1

            # Track by prover type
            prover_name = PROVER_MAP.get(finding.get("vuln_type", finding.get("type", "")), GenericProver).__name__
            if prover_name not in self._metrics["by_prover"]:
                self._metrics["by_prover"][prover_name] = {"processed": 0, "proven": 0}
            self._metrics["by_prover"][prover_name]["processed"] += 1
            if proof.can_repeat or proof.can_mutate or proof.can_escalate or proof.can_chain:
                self._metrics["by_prover"][prover_name]["proven"] += 1

            proved = sum([proof.can_repeat, proof.can_mutate, proof.can_escalate, proof.can_chain])
            logger.info(
                f"[ProofEngine] {finding.get('vuln_type', finding.get('type', 'unknown'))}: {proved}/4 proven "
                f"({proof.proven_impact}) [{proof.requests_used} reqs]"
            )

            return proof.new_findings

        # Phase 1: Run SQLi provers SEQUENTIALLY (they extract credentials for later provers)
        if sqli_findings:
            logger.info(f"[ProofEngine] Phase 1: {len(sqli_findings)} SQLi findings (sequential for credential feedback)")
            for finding in sqli_findings:
                finding, proof = await prove_single(finding)
                if proof:
                    new_findings_all.extend(apply_proof(finding, proof))
                else:
                    unproven_findings.append({"id": finding.get("id", ""), "name": finding.get("name", ""), "reason": "budget_exhausted"})

        # Phase 2: Run other provers IN PARALLEL
        if other_findings and budget_remaining[0] > 0:
            logger.info(f"[ProofEngine] Phase 2: {len(other_findings)} other findings (parallel, max {max_concurrent})")
            semaphore = asyncio.Semaphore(max_concurrent)

            async def prove_with_semaphore(finding: dict):
                async with semaphore:
                    return await prove_single(finding)

            # Run in parallel
            tasks = [prove_with_semaphore(f) for f in other_findings]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, Exception):
                    logger.warning(f"[ProofEngine] Parallel prover failed: {r}")
                    continue
                finding, proof = r
                if proof:
                    new_findings_all.extend(apply_proof(finding, proof))
                else:
                    unproven_findings.append({"id": finding.get("id", ""), "name": finding.get("name", ""), "reason": "budget_exhausted"})

        # Append new findings
        for nf in new_findings_all:
            result.add_finding(nf)

        # Store unproven findings for auditability
        if hasattr(result, 'unproven_findings'):
            result.unproven_findings = [f["id"] for f in unproven_findings]
            result.proofs_skipped = len(unproven_findings)

        logger.info(
            f"[ProofEngine] Parallel complete: {self._total_requests_used} total requests, "
            f"{len(new_findings_all)} new findings from escalation, "
            f"{len(unproven_findings)} unproven (budget)"
        )

    def _build_narrative(self, finding: dict, proof: ProofResult) -> str:
        """Build a human-readable attack story from proof results."""
        parts = []
        matched = (
            finding.get("matched_at")
            or (finding.get("metadata") or {}).get("url")
            or finding.get("host")
            or "unknown endpoint"
        )

        if proof.can_repeat:
            parts.append(
                f"The vulnerability at {matched} is reliably reproducible "
                f"({proof.repeat_count}x confirmed)."
            )

        if proof.can_mutate:
            mut_summary = "; ".join(proof.mutations[:3])
            parts.append(f"An attacker can vary the payload: {mut_summary}.")

        if proof.can_escalate:
            parts.append(f"The impact escalates to: {proof.escalation}.")

        if proof.can_chain:
            chain_summary = "; ".join(proof.chain_targets[:3])
            parts.append(f"This finding unlocks further attacks: {chain_summary}.")

        # Assign proven impact label
        if proof.can_escalate and "admin" in str(proof.escalation).lower():
            proof.proven_impact = "Full Admin Takeover"
        elif proof.can_escalate and "write" in str(proof.escalation).lower():
            proof.proven_impact = "Read-to-Write Escalation"
        elif proof.can_escalate and ("credential" in str(proof.escalation).lower()
                                     or "financial" in str(proof.escalation).lower()):
            proof.proven_impact = "Data Exfiltration / Financial Manipulation"
        elif proof.can_chain and proof.can_mutate:
            proof.proven_impact = "Chainable Exploitation with Payload Flexibility"
        elif proof.can_repeat and proof.can_mutate:
            proof.proven_impact = "Reliable Exploitation with Payload Flexibility"
        elif proof.can_repeat:
            proof.proven_impact = "Confirmed Vulnerability"
        else:
            proof.proven_impact = "Unproven"

        return " ".join(parts)

    def get_feedback(self) -> dict[str, Any]:
        """
        Get feedback data from proof engine for cross-module amplification.

        Returns discoveries that should influence subsequent scanning:
        - auth_escalated: True if we obtained higher-privilege auth
        - escalated_auth: Updated auth context (if escalated)
        - chainable_findings: Findings that should trigger additional modules
        - discovered_endpoints: New endpoints found during probing
        - total_requests: Request budget consumed
        """
        feedback = {
            "auth_escalated": False,
            "escalated_auth": None,
            "chainable_findings": [],
            "discovered_endpoints": [],
            "total_requests": self._total_requests_used,
        }

        # Check if auth was escalated during proof (e.g., SQLi cred extraction)
        if self._auth_context:
            if getattr(self._auth_context, 'method', '') in (
                'sqli_credential_extraction', 'sqli_auth_bypass'
            ):
                feedback["auth_escalated"] = True
                feedback["escalated_auth"] = {
                    "token": getattr(self._auth_context, 'token', ''),
                    "method": getattr(self._auth_context, 'method', ''),
                    "email": getattr(self._auth_context, 'email', ''),
                }
                logger.info(
                    f"[ProofEngine] Auth escalated via {feedback['escalated_auth']['method']}"
                )

        return feedback
