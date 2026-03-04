"""
PHANTOM AI - Validation Pipeline Orchestrator
===============================================

Extracted from phantom/validation_pipeline.py (lines 2221-3207).

Contains:
- ValidationPipeline: Main 6-stage validation orchestrator
- create_raw_finding: Convenience function for creating RawFinding
- validate_findings: Convenience function for validating findings
"""

import asyncio
import re
import time
import logging
import uuid
from typing import Dict, List, Optional, Any

import httpx

from phantom.validation.models import (
    ValidationStage,
    ValidationResult,
    VulnerabilityType,
    FindingConfidence,
    RawFinding,
    StageResult,
    ValidatedFinding,
    ValidationConfig,
    is_static_asset_url,
    VULN_TYPES_IMPOSSIBLE_ON_STATIC,
    STATIC_ASSET_CONTENT_TYPES,
    DEFAULT_RAW_CONFIDENCE,
    CONFIDENCE_PENALTY_UNCERTAINTY,
    MAX_UNCERTAINTY_PENALTY,
    PROOF_BOOST_CAN_REPEAT,
    PROOF_BOOST_CAN_MUTATE,
    PROOF_BOOST_CAN_ESCALATE,
    PROOF_BOOST_CAN_CHAIN,
    PROOF_BOOST_DATA_EXTRACTION,
    PROOF_BOOST_STATE_CHANGE,
    PROOF_BOOST_PRIVILEGE_ESCALATION,
    PROOF_BOOST_DEMONSTRATED,
)
from phantom.validation.stages import (
    DeduplicationStage,
    PatternVerificationStage,
    SafeReplayStage,
    NegativeControlStage,
    ContextValidationStage,
    AIVerificationStage,
)

# Confidence normalization utility
from utils.confidence import normalize_confidence

# Feedback learning integration
try:
    from scanning.feedback_learning import (
        record_finding_outcome,
        apply_learned_confidence,
        get_learning_engine,
        ValidationOutcome,
    )
    FEEDBACK_LEARNING_AVAILABLE = True
except ImportError:
    FEEDBACK_LEARNING_AVAILABLE = False

# Impact Assessment Engine integration
try:
    from phantom.impact_assessment import (
        ImpactAssessmentEngine,
        get_impact_assessment_engine,
        ImpactAssessmentResult,
        CVSSVector,
        CIATriad,
        ImpactLevel,
        VULNERABILITY_PROFILES,
    )
    IMPACT_ASSESSMENT_AVAILABLE = True
except ImportError:
    IMPACT_ASSESSMENT_AVAILABLE = False

logger = logging.getLogger("phantom.validation.pipeline")


class ValidationPipeline:
    """
    PHANTOM AI 6-Stage Validation Pipeline.

    Validates findings through 6 progressive stages to achieve
    near-zero false positive rates.
    """

    VERSION = "3.0.0"

    def __init__(self, config: Optional[ValidationConfig] = None) -> None:
        """Initialize the validation pipeline."""
        self.config = config or ValidationConfig()

        # Initialize stages
        self.dedup_stage = DeduplicationStage(self.config)
        self.pattern_stage = PatternVerificationStage(self.config)
        self.replay_stage = SafeReplayStage(self.config)
        self.negative_stage = NegativeControlStage(self.config)
        self.context_stage = ContextValidationStage(self.config)
        self.ai_stage = AIVerificationStage(self.config)

        # HTTP client for replay/negative control
        self._http_client: Optional[httpx.AsyncClient] = None

        # Evidence Engine v3.0 integration for comprehensive proof collection
        self._evidence_engine = None
        try:
            from utils.evidence_engine import get_evidence_engine
            self._evidence_engine = get_evidence_engine()
        except ImportError:
            logger.debug("Evidence Engine not available")

        # Impact Assessment Engine for CVSS 3.1 scoring
        self._impact_engine = None
        if IMPACT_ASSESSMENT_AVAILABLE:
            try:
                self._impact_engine = get_impact_assessment_engine()
                logger.debug("Impact Assessment Engine initialized for CVSS scoring")
            except Exception as e:
                logger.debug(f"Impact Assessment Engine initialization failed: {e}")

        # Statistics and metrics
        self._init_metrics()

        logger.info(f"ValidationPipeline v{self.VERSION} initialized")

    def _init_metrics(self) -> None:
        """Initialize metrics dictionary."""
        self._metrics = {
            "findings_processed": 0,
            "findings_passed": 0,
            "findings_failed": 0,
            "findings_suppressed": 0,
            "by_stage": {
                stage.name: {"passed": 0, "failed": 0, "skipped": 0, "error": 0}
                for stage in ValidationStage
            },
            "by_vuln_type": {},
            "by_severity": {},
            "errors": 0,
            "total_validation_time_ms": 0.0,
        }
        # Keep legacy _stats for backwards compatibility
        self._stats = {
            "total_processed": 0,
            "passed": 0,
            "failed": 0,
            "by_stage": {stage.name: 0 for stage in ValidationStage},
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Get pipeline metrics."""
        return dict(self._metrics)

    def reset_metrics(self) -> None:
        """Reset metrics for new batch."""
        self._init_metrics()

    async def validate_finding(
        self,
        finding: RawFinding,
        all_findings: Optional[List[RawFinding]] = None,
        ai_client: Optional[Any] = None,
    ) -> ValidatedFinding:
        """
        Validate a single finding through all 6 stages.

        Args:
            finding: Raw finding to validate
            all_findings: All findings for deduplication
            ai_client: Optional AI client for stage 6

        Returns:
            ValidatedFinding with validation results
        """
        start_time = time.time()
        stage_results: List[StageResult] = []

        # AUDIT-6: Use centralized confidence normalization
        # Handles strings ("HIGH", "90%", "0.9") and numeric values (0.9, 90)
        confidence = normalize_confidence(finding.confidence)

        # ===================================================================
        # FEEDBACK LEARNING: Apply learned confidence adjustment
        # Based on historical TP/FP patterns for this module/vuln_type
        # ===================================================================
        original_confidence = confidence
        if FEEDBACK_LEARNING_AVAILABLE:
            try:
                finding_dict = finding.to_dict()
                finding_dict = apply_learned_confidence(finding_dict)
                learned_adjustment = finding_dict.get("metadata", {}).get("learning_adjustment", 0.0)
                if learned_adjustment != 0:
                    confidence = finding_dict.get("confidence", confidence)
                    logger.debug(
                        f"[FEEDBACK_LEARNING] Applied adjustment {learned_adjustment:+.3f} to {finding.module_name}"
                    )
            except Exception as e:
                logger.debug(f"[FEEDBACK_LEARNING] Error applying learned confidence: {e}")

        # Track which stages pass/fail for learning
        stages_passed: List[str] = []
        stages_failed: List[str] = []

        # ===================================================================
        # STAGE 0: STATIC ASSET FILTER (Early rejection for false positives)
        # Static assets (.jpg, .css, .js, etc.) cannot have server-side vulns
        # ISSUE-4 FIX 2026-02-11: Also check Content-Type, not just URL pattern
        # ===================================================================
        vuln_type_str = finding.vulnerability_type.value if hasattr(finding.vulnerability_type, 'value') else str(finding.vulnerability_type)

        # Check Content-Type from metadata (more reliable than URL pattern)
        metadata = finding.metadata or {}
        content_type = (
            metadata.get("response_content_type", "")
            or metadata.get("content_type", "")
            or ""
        ).lower()

        # Content-Type based rejection (most reliable)
        is_static_by_content_type = any(
            content_type.startswith(ct) for ct in STATIC_ASSET_CONTENT_TYPES
        )

        # URL pattern based rejection (fallback)
        is_static_by_url = is_static_asset_url(finding.url)

        # ISSUE-4 FIX: Don't reject API endpoints even if URL contains /static/, /public/, etc.
        # APIs return JSON/HTML, not static files
        url_lower = (finding.url or "").lower()
        is_api_endpoint = any(p in url_lower for p in ["/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/v3/"])

        # Only reject if definitely static AND not an API endpoint
        if vuln_type_str.lower() in VULN_TYPES_IMPOSSIBLE_ON_STATIC:
            if is_static_by_content_type:
                # THEME-12: Promote to INFO for auditability
                logger.info(f"[AUDIT] Finding suppressed: Content-Type {content_type} is static - {finding.url}")
                return self._create_result(
                    finding, False, 0.0, stage_results, start_time,
                    f"False positive: Content-Type {content_type} cannot have {vuln_type_str} vulnerability"
                )
            elif is_static_by_url and not is_api_endpoint:
                # URL pattern match but only if not an API
                logger.info(f"[AUDIT] Finding suppressed: URL pattern is static - {finding.url}")
                return self._create_result(
                    finding, False, 0.0, stage_results, start_time,
                    f"False positive: Static asset cannot have {vuln_type_str} vulnerability"
                )

        # Ensure HTTP client is available
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                verify=False,
            )

        # Stage 1: Deduplication
        # BUG-FIX 2026-02-11: Removed early exit on FAILED
        # Dedup should penalize confidence, not kill the finding
        # Let it go through all stages to get proper validation
        is_duplicate = False
        if self.config.enable_deduplication:
            result = self.dedup_stage.validate(finding, all_findings or [])
            stage_results.append(result)
            confidence += result.confidence_delta
            if result.result == ValidationResult.PASSED:
                stages_passed.append("deduplication")
            elif result.result == ValidationResult.FAILED:
                stages_failed.append("deduplication")
                is_duplicate = True
                # LOGIC-V4 FIX 2026-02-11: Removed duplicate -0.05 penalty
                # The -1.0 confidence_delta from StageResult is already sufficient

        # Stage 2: Pattern Verification
        if self.config.enable_pattern_verification:
            result = self.pattern_stage.validate(finding)
            stage_results.append(result)
            confidence += result.confidence_delta
            if result.result == ValidationResult.PASSED:
                stages_passed.append("pattern")
            elif result.result == ValidationResult.FAILED:
                stages_failed.append("pattern")

        # Stage 3: Safe Replay
        if self.config.enable_safe_replay:
            result = await self.replay_stage.validate(finding, self._http_client)
            stage_results.append(result)
            confidence += result.confidence_delta
            if result.result == ValidationResult.PASSED:
                stages_passed.append("safe_replay")
            elif result.result == ValidationResult.FAILED:
                stages_failed.append("safe_replay")

        # Stage 4: Negative Control
        if self.config.enable_negative_control:
            result = await self.negative_stage.validate(finding, self._http_client)
            stage_results.append(result)
            confidence += result.confidence_delta
            if result.result == ValidationResult.PASSED:
                stages_passed.append("negative_control")
            elif result.result == ValidationResult.FAILED:
                stages_failed.append("negative_control")

        # Stage 5: Context Validation
        if self.config.enable_context_validation:
            result = self.context_stage.validate(finding)
            stage_results.append(result)
            confidence += result.confidence_delta
            if result.result == ValidationResult.PASSED:
                stages_passed.append("context")
            elif result.result == ValidationResult.FAILED:
                stages_failed.append("context")

        # Stage 6: AI Verification (auditor, not blocker)
        if self.config.enable_ai_verification:
            result = await self.ai_stage.validate(finding, ai_client)
            stage_results.append(result)
            if result.result == ValidationResult.PASSED:
                stages_passed.append("ai")
            elif result.result == ValidationResult.FAILED:
                stages_failed.append("ai")

            # AI is auditor only - doesn't block, only adds info
            if not self.config.ai_verification_is_blocking:
                # Log AI result but don't affect confidence
                pass
            else:
                confidence += result.confidence_delta

        # ===================================================================
        # CONN-2 FIX: Proof Engine results boost validation confidence
        # If Proof Engine already demonstrated exploitability, trust that evidence
        # ===================================================================
        metadata = finding.metadata or {}
        proof = metadata.get("proof")
        if proof and isinstance(proof, dict):
            proof_boost = 0.0

            # Boost for each proven attribute
            if proof.get("can_repeat"):
                proof_boost += PROOF_BOOST_CAN_REPEAT
            if proof.get("can_mutate"):
                proof_boost += PROOF_BOOST_CAN_MUTATE
            if proof.get("can_escalate"):
                proof_boost += PROOF_BOOST_CAN_ESCALATE
            if proof.get("can_chain"):
                proof_boost += PROOF_BOOST_CAN_CHAIN

            # Additional boost for specific proven impacts
            proven_impact = proof.get("proven_impact", "")
            if "Data Extraction Confirmed" in proven_impact:
                proof_boost += PROOF_BOOST_DATA_EXTRACTION
            elif "State Change Confirmed" in proven_impact:
                proof_boost += PROOF_BOOST_STATE_CHANGE
            elif "Privilege Escalation Confirmed" in proven_impact:
                proof_boost += PROOF_BOOST_PRIVILEGE_ESCALATION
            elif "Demonstrated" in proven_impact or "Verified" in proven_impact:
                proof_boost += PROOF_BOOST_DEMONSTRATED

            if proof_boost > 0:
                confidence += proof_boost
                logger.debug(
                    f"[CONN-2] Proof boost +{proof_boost:.2f} for {finding.title}: "
                    f"repeat={proof.get('can_repeat')}, mutate={proof.get('can_mutate')}, "
                    f"escalate={proof.get('can_escalate')}, chain={proof.get('can_chain')}"
                )

        # FIX 2026-02-12: Cap cumulative uncertainty penalties
        # Without this, 4 SKIPPED stages = -0.08 penalty which is excessive
        original_confidence = normalize_confidence(finding.confidence)
        total_penalty = original_confidence - confidence
        if total_penalty > MAX_UNCERTAINTY_PENALTY:
            confidence = original_confidence - MAX_UNCERTAINTY_PENALTY
            logger.debug(f"[PENALTY_CAP] Capped penalty from {total_penalty:.2f} to {MAX_UNCERTAINTY_PENALTY}")

        # Clamp confidence
        confidence = max(0.0, min(1.0, confidence))

        # Determine threshold based on severity (CRITICAL needs higher confidence)
        severity = finding.severity.upper() if finding.severity else "MEDIUM"
        threshold = self.config.severity_confidence_thresholds.get(
            severity, self.config.min_confidence_to_report
        )

        # Determine if should report
        is_valid = confidence >= threshold
        suppression_reason = None if is_valid else f"Confidence {confidence:.2f} below {severity} threshold {threshold}"

        # Update stats and metrics
        self._stats["total_processed"] += 1
        self._metrics["findings_processed"] += 1
        if is_valid:
            self._stats["passed"] += 1
            self._metrics["findings_passed"] += 1
        else:
            self._stats["failed"] += 1
            self._metrics["findings_failed"] += 1
            if suppression_reason:
                self._metrics["findings_suppressed"] += 1

        # Track by vuln type
        vuln_type_str = finding.vulnerability_type.value if hasattr(finding.vulnerability_type, 'value') else str(finding.vulnerability_type)
        if vuln_type_str not in self._metrics["by_vuln_type"]:
            self._metrics["by_vuln_type"][vuln_type_str] = {"passed": 0, "failed": 0}
        self._metrics["by_vuln_type"][vuln_type_str]["passed" if is_valid else "failed"] += 1

        # Track by severity
        if severity not in self._metrics["by_severity"]:
            self._metrics["by_severity"][severity] = {"passed": 0, "failed": 0}
        self._metrics["by_severity"][severity]["passed" if is_valid else "failed"] += 1

        # Track stage results
        for sr in stage_results:
            stage_name = sr.stage.name
            result_key = sr.result.value if sr.result != ValidationResult.INCONCLUSIVE else "skipped"
            if result_key in self._metrics["by_stage"][stage_name]:
                self._metrics["by_stage"][stage_name][result_key] += 1

        # ===================================================================
        # FEEDBACK LEARNING: Record validation outcome for future learning
        # ===================================================================
        self._record_feedback(finding, is_valid, stages_passed, stages_failed)

        return self._create_result(
            finding, is_valid, confidence, stage_results, start_time,
            suppression_reason
        )

    # =========================================================================
    # TIME-BASED VALIDATION (GAP-2 FIX Sprint 1.3)
    # Proper validation for blind time-based vulnerabilities
    # =========================================================================

    async def validate_time_based_finding(
        self,
        finding: RawFinding,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> tuple[bool, float, str]:
        """
        Validate a time-based (blind) vulnerability finding.

        GAP-2 FIX Sprint 1.3: Verify timing difference is payload-dependent,
        not caused by network jitter or server load.

        Args:
            finding: The time-based finding to validate
            http_client: Optional HTTP client

        Returns:
            Tuple of (is_valid, confidence_delta, message)

        Process:
            1. Send payload with original delay (e.g., sleep(5))
            2. Send payload with delay=0 (e.g., sleep(0))
            3. Send benign payload (no sleep at all)
            4. Compare: t1 should be ~delay seconds longer than t2 and t3
        """
        if http_client is None:
            http_client = self._http_client or httpx.AsyncClient()

        try:
            # Extract timing info from metadata
            metadata = finding.metadata or {}
            original_delay = float(metadata.get("delay", metadata.get("sleep_time", 5)))
            payload = finding.payload or ""
            param = finding.parameter or ""
            url = finding.url or ""
            method = (finding.method or "GET").upper()

            if not payload or not param or not url:
                return False, -0.05, "Missing payload/param/url for time validation"

            # Measure original payload (should take ~delay seconds)
            t1 = await self._measure_request_time(
                http_client, url, param, payload, method
            )

            # Create zero-delay variant (replace delay value with 0)
            zero_payload = self._create_zero_delay_payload(payload, original_delay)
            t2 = await self._measure_request_time(
                http_client, url, param, zero_payload, method
            )

            # Benign payload (no injection at all)
            t3 = await self._measure_request_time(
                http_client, url, param, "harmless_test_value", method
            )

            # Validation logic:
            # t1 should be significantly longer than t2 and t3
            # t2 and t3 should be similar (within 1 second)
            min_expected_diff = original_delay * 0.7  # Allow 30% variance
            max_jitter = 1.5  # Max network jitter allowance

            timing_valid = (
                (t1 - t2) >= min_expected_diff and
                (t1 - t3) >= min_expected_diff and
                abs(t3 - t2) < max_jitter
            )

            if timing_valid:
                return True, 0.1, f"Time-based validated: t1={t1:.1f}s, t2={t2:.1f}s, t3={t3:.1f}s"
            else:
                return False, -0.15, f"Time validation failed: t1={t1:.1f}s, t2={t2:.1f}s, t3={t3:.1f}s (expected t1 > t2+{min_expected_diff:.1f}s)"

        except Exception as e:
            logger.debug(f"[TimeValidation] Error: {e}")
            return True, 0.0, f"Time validation skipped: {str(e)[:50]}"

    async def _measure_request_time(
        self,
        client: httpx.AsyncClient,
        url: str,
        param: str,
        value: str,
        method: str,
    ) -> float:
        """Measure time for a single request."""
        import time as time_module

        start = time_module.perf_counter()
        try:
            if method == "GET":
                await client.get(url, params={param: value}, timeout=30.0)
            else:
                await client.post(url, data={param: value}, timeout=30.0)
        except httpx.TimeoutException:
            return 30.0  # Return timeout duration
        except Exception:
            return 0.0

        return time_module.perf_counter() - start

    def _create_zero_delay_payload(self, payload: str, original_delay: float) -> str:
        """Create a variant of the payload with delay set to 0."""
        # Common patterns for time-based injection

        # Replace numeric delay values
        delay_str = str(int(original_delay))
        zero_payload = payload.replace(delay_str, "0")

        # Handle specific patterns
        patterns = [
            (r'sleep\s*\(\s*\d+\s*\)', 'sleep(0)'),
            (r'WAITFOR\s+DELAY\s+[\'"][\d:]+[\'"]', "WAITFOR DELAY '00:00:00'"),
            (r'pg_sleep\s*\(\s*\d+\s*\)', 'pg_sleep(0)'),
            (r'BENCHMARK\s*\(\s*\d+', 'BENCHMARK(1'),
            (r'dbms_pipe\.receive_message\s*\([^,]+,\s*\d+\)', "dbms_pipe.receive_message('a',0)"),
        ]

        for pattern, replacement in patterns:
            zero_payload = re.sub(pattern, replacement, zero_payload, flags=re.IGNORECASE)

        return zero_payload

    async def validate_findings(
        self,
        findings: List[RawFinding],
        ai_client: Optional[Any] = None,
    ) -> List[ValidatedFinding]:
        """
        Validate multiple findings.

        Args:
            findings: List of raw findings
            ai_client: Optional AI client

        Returns:
            List of validated findings
        """
        # Reset deduplication for new batch
        self.dedup_stage.reset()

        results = []
        for finding in findings:
            validated = await self.validate_finding(finding, findings, ai_client)
            results.append(validated)

        return results

    async def validate_findings_parallel(
        self,
        findings: List[RawFinding],
        ai_client: Optional[Any] = None,
        max_concurrent: int = 5,
    ) -> List[ValidatedFinding]:
        """
        Validate multiple findings with parallel processing.

        PERFORMANCE IMPROVEMENT: Runs synchronous stages (1-3) in parallel,
        then async stages (4-6) with controlled concurrency.

        Stages 1-3 (Dedup, Pattern, Context) are local operations - parallelizable.
        Stages 4-6 (Replay, Negative, AI) make HTTP requests - need rate limiting.

        Args:
            findings: List of raw findings
            ai_client: Optional AI client
            max_concurrent: Max concurrent validations for network stages

        Returns:
            List of validated findings
        """
        import concurrent.futures

        # Reset deduplication for new batch
        self.dedup_stage.reset()

        logger.info(f"[VALIDATION] Parallel validating {len(findings)} findings (max_concurrent: {max_concurrent})")

        # Phase 1: Run synchronous stages (1-3) in thread pool for CPU parallelism
        def run_sync_stages(finding: RawFinding) -> tuple[RawFinding, float, List[StageResult]]:
            """Run dedup, pattern, context stages (synchronous)."""
            stage_results: List[StageResult] = []
            confidence = normalize_confidence(finding.confidence)

            # Stage 1: Deduplication
            if self.config.enable_deduplication:
                result = self.dedup_stage.validate(finding, findings)
                stage_results.append(result)
                confidence += result.confidence_delta

            # Stage 2: Pattern Verification
            if self.config.enable_pattern_verification:
                result = self.pattern_stage.validate(finding)
                stage_results.append(result)
                confidence += result.confidence_delta

            # Stage 5: Context Validation (also synchronous)
            if self.config.enable_context_validation:
                result = self.context_stage.validate(finding)
                stage_results.append(result)
                confidence += result.confidence_delta

            return finding, confidence, stage_results

        # Run sync stages in parallel
        sync_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            futures = [executor.submit(run_sync_stages, f) for f in findings]
            for future in concurrent.futures.as_completed(futures):
                try:
                    sync_results.append(future.result())
                except Exception as e:
                    logger.warning(f"[VALIDATION] Sync stage failed: {e}")

        # Phase 2: Run async stages (3-4: Safe Replay, Negative Control) with semaphore
        semaphore = asyncio.Semaphore(max_concurrent)

        async def run_async_stages(
            finding: RawFinding,
            confidence: float,
            stage_results: List[StageResult],
        ) -> ValidatedFinding:
            """Run replay, negative control, AI stages (async)."""
            start_time = time.time()

            async with semaphore:
                # Stage 3: Safe Replay
                if self.config.enable_safe_replay:
                    result = await self.replay_stage.validate(finding, self._http_client)
                    stage_results.append(result)
                    confidence += result.confidence_delta

                # Stage 4: Negative Control
                if self.config.enable_negative_control:
                    result = await self.negative_stage.validate(finding, self._http_client)
                    stage_results.append(result)
                    confidence += result.confidence_delta

            # Stage 6: AI Verification (can run outside semaphore - different rate limits)
            if self.config.enable_ai_verification:
                result = await self.ai_stage.validate(finding, ai_client)
                stage_results.append(result)
                if self.config.ai_verification_is_blocking:
                    confidence += result.confidence_delta

            # Apply proof boosts and penalties
            metadata = finding.metadata or {}
            proof = metadata.get("proof")
            if proof and isinstance(proof, dict):
                proof_boost = 0.0
                if proof.get("can_repeat"):
                    proof_boost += PROOF_BOOST_CAN_REPEAT
                if proof.get("can_mutate"):
                    proof_boost += PROOF_BOOST_CAN_MUTATE
                if proof.get("can_escalate"):
                    proof_boost += PROOF_BOOST_CAN_ESCALATE
                if proof.get("can_chain"):
                    proof_boost += PROOF_BOOST_CAN_CHAIN
                if proof_boost > 0:
                    confidence += proof_boost

                # Penalize when proof engine couldn't verify the finding.
                # A finding with proof_outcome="not_attempted" or "unproven"
                # should not reach EXPLOITABLE tier (>=0.95).
                proof_outcome = proof.get("proof_outcome", "")
                proven_impact = proof.get("proven_impact", "")
                if proof_outcome in ("not_attempted", "") and proof_boost == 0:
                    # Proof engine didn't run or produced no evidence
                    # Cap below EXPLOITABLE threshold
                    confidence = min(confidence, 0.94)
                elif proven_impact in ("Unproven", "") and proof_boost == 0:
                    confidence = min(confidence, 0.94)

            # Cap penalty
            original_confidence = normalize_confidence(finding.confidence)
            total_penalty = original_confidence - confidence
            if total_penalty > MAX_UNCERTAINTY_PENALTY:
                confidence = original_confidence - MAX_UNCERTAINTY_PENALTY

            # Determine validity
            severity_str = finding.severity if hasattr(finding, 'severity') else "MEDIUM"
            threshold = self._get_threshold_for_severity(severity_str)
            is_valid = confidence >= threshold

            return self._create_result(
                finding, is_valid, confidence, stage_results, start_time, None
            )

        # Run async stages in parallel
        tasks = [
            run_async_stages(finding, conf, stages)
            for finding, conf, stages in sync_results
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions
        validated = []
        for r in results:
            if isinstance(r, Exception):
                logger.warning(f"[VALIDATION] Async stage failed: {r}")
            else:
                validated.append(r)

        logger.info(f"[VALIDATION] Parallel complete: {len(validated)} findings validated")
        return validated

    def _get_threshold_for_severity(self, severity: str) -> float:
        """Get confidence threshold for a given severity level."""
        severity_upper = severity.upper() if severity else "MEDIUM"
        return self.config.severity_confidence_thresholds.get(
            severity_upper, self.config.min_confidence_to_report
        )

    def _create_result(
        self,
        finding: RawFinding,
        is_valid: bool,
        confidence: float,
        stage_results: List[StageResult],
        start_time: float,
        suppression_reason: Optional[str],
    ) -> ValidatedFinding:
        """Create validated finding result."""
        # LOGIC-4 FIX: Clamp confidence to prevent negative/excessive values
        # Minimum 10% (finding was detected by scanner, deserves some credit)
        # Maximum 100% (can't be more than certain)
        confidence = max(0.10, min(1.0, confidence))

        # Determine confidence level
        if confidence >= 0.95:
            level = FindingConfidence.EXPLOITABLE
        elif confidence >= 0.75:
            level = FindingConfidence.CONFIRMED
        elif confidence >= 0.60:
            level = FindingConfidence.DETECTED
        else:
            level = FindingConfidence.SUSPECTED

        # Use severity-specific threshold for should_report (is_valid already checked threshold)
        should_report = is_valid

        # Evidence Engine v3.0: Add validation event to timeline for reportable findings
        if self._evidence_engine and should_report:
            try:
                self._evidence_engine.add_timeline_event(
                    event_type="validation_passed",
                    description=f"Finding validated: {finding.title} ({level.name})",
                    url=finding.url,
                    severity=finding.severity if hasattr(finding, 'severity') else "MEDIUM",
                    details={
                        "finding_id": finding.id,
                        "confidence": confidence,
                        "confidence_level": level.name,
                        "stages_passed": len([r for r in stage_results if r.result == ValidationResult.PASSED]),
                        "total_stages": len(stage_results),
                    }
                )
            except Exception as e:
                logger.debug(f"Evidence timeline event failed: {e}")

        validated = ValidatedFinding(
            raw_finding=finding,
            is_valid=is_valid,
            final_confidence=confidence,
            confidence_level=level,
            stage_results=stage_results,
            validation_time_ms=(time.time() - start_time) * 1000,
            should_report=should_report,
            suppression_reason=suppression_reason,
        )

        # ===================================================================
        # CVSS 3.1 IMPACT ASSESSMENT
        # Calculate professional CVSS scoring for valid findings
        # Uses ImpactAssessmentEngine for CIA triad and financial impact
        # ===================================================================
        if self._impact_engine and is_valid:
            try:
                # Get vulnerability type string — prefer original from metadata
                # over the ValidationVulnType enum (which may have lost specificity
                # by mapping to OTHER)
                original_vt = ""
                if finding.metadata and isinstance(finding.metadata, dict):
                    original_vt = finding.metadata.get("original_vuln_type", "")
                if not original_vt:
                    vuln_type_str = (
                        finding.vulnerability_type.value
                        if hasattr(finding.vulnerability_type, 'value')
                        else str(finding.vulnerability_type)
                    )
                else:
                    vuln_type_str = original_vt

                # Assess the vulnerability
                impact_result = self._impact_engine.assess_vulnerability(
                    vulnerability_id=finding.id,
                    vulnerability_type=vuln_type_str,
                    affected_records=finding.metadata.get("affected_records", 0) if finding.metadata else 0,
                )

                # Add CVSS data to finding metadata
                if finding.metadata is None:
                    finding.metadata = {}

                finding.metadata["cvss_score"] = impact_result.cvss.base_score
                finding.metadata["cvss_vector"] = impact_result.cvss.vector_string
                finding.metadata["cvss_severity"] = impact_result.cvss.severity.value
                finding.metadata["cia_impact"] = {
                    "confidentiality": impact_result.cvss.cia.confidentiality.name,
                    "integrity": impact_result.cvss.cia.integrity.name,
                    "availability": impact_result.cvss.cia.availability.name,
                    "impact_subscore": round(impact_result.cvss.cia.impact_subscore, 2),
                }
                finding.metadata["financial_impact"] = {
                    "total": impact_result.financial_impact.total_impact,
                    "direct_costs": impact_result.financial_impact.direct_costs,
                    "indirect_costs": impact_result.financial_impact.indirect_costs,
                    "range_estimate": {
                        "min": impact_result.financial_impact.range_estimate[0],
                        "max": impact_result.financial_impact.range_estimate[1],
                    },
                }
                finding.metadata["regulatory_impact"] = {
                    "applicable_regulations": impact_result.regulatory_impact.applicable_regulations,
                    "notification_required": impact_result.regulatory_impact.notification_required,
                    "max_fine_amount": impact_result.regulatory_impact.max_fine_amount,
                }
                finding.metadata["remediation_priority"] = impact_result.remediation_priority
                finding.metadata["recommendations"] = impact_result.recommendations

                logger.debug(
                    f"[CVSS] {finding.id}: score={impact_result.cvss.base_score} "
                    f"vector={impact_result.cvss.vector_string} "
                    f"priority={impact_result.remediation_priority}"
                )
            except Exception as e:
                logger.warning(f"[CVSS] Impact assessment failed for {finding.id}: {e}")

        # THEME-12: Audit log for suppressed findings
        if not is_valid and suppression_reason:
            # BUG-FIX 2026-02-08: Was r.stage_name, but StageResult has r.stage (enum)
            failed_stages = [r.stage.name for r in stage_results if r.result == ValidationResult.FAILED]
            logger.info(
                f"[AUDIT] Finding suppressed: {finding.id} | reason: {suppression_reason} | "
                f"failed_stages: {failed_stages} | confidence: {confidence:.2f}"
            )

        # THEME-10 FIX: Calculate uncertainty score for reporting
        validated.calculate_uncertainty()

        # Log high uncertainty findings for audit trail
        if validated.uncertainty_score > 0.5:
            logger.warning(
                f"[THEME-10] High uncertainty validation for {finding.id}: "
                f"score={validated.uncertainty_score:.2f}, "
                f"reasons={validated.uncertainty_reasons}"
            )

        return validated

    def _record_feedback(
        self,
        finding: RawFinding,
        is_valid: bool,
        stages_passed: List[str],
        stages_failed: List[str],
    ) -> None:
        """Record validation outcome for feedback learning."""
        if not FEEDBACK_LEARNING_AVAILABLE:
            return False

        try:
            finding_dict = finding.to_dict()
            record_finding_outcome(
                finding=finding_dict,
                is_valid=is_valid,
                validation_stages_passed=stages_passed,
                validation_stages_failed=stages_failed,
                user_override=False,
            )
            return True
        except Exception as e:
            logger.debug(f"[FEEDBACK_LEARNING] Error recording outcome: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get pipeline statistics (includes metrics)."""
        # Include learning stats if available
        learning_summary = {}
        if FEEDBACK_LEARNING_AVAILABLE:
            try:
                engine = get_learning_engine()
                learning_summary = engine.get_learning_summary()
            except Exception as e:
                logging.debug(f"Failed to get learning summary: {e}")

        return {
            "version": self.VERSION,
            "total_processed": self._stats["total_processed"],
            "passed": self._stats["passed"],
            "failed": self._stats["failed"],
            "suppressed": self._metrics.get("findings_suppressed", 0),
            "pass_rate": (
                self._stats["passed"] / self._stats["total_processed"]
                if self._stats["total_processed"] > 0 else 0
            ),
            "by_vuln_type": self._metrics.get("by_vuln_type", {}),
            "by_severity": self._metrics.get("by_severity", {}),
            "by_stage": self._metrics.get("by_stage", {}),
            "errors": self._metrics.get("errors", 0),
            "learning": learning_summary,
            "config": {
                "min_confidence": self.config.min_confidence_to_report,
                "ai_is_blocking": self.config.ai_verification_is_blocking,
            },
        }

    async def close(self) -> None:
        """Close resources."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_raw_finding(
    title: str,
    vuln_type: str,
    severity: str,
    url: str,
    **kwargs: Any,
) -> RawFinding:
    """Create a RawFinding with minimal parameters."""
    vuln_type_enum = VulnerabilityType(vuln_type) if vuln_type in [v.value for v in VulnerabilityType] else VulnerabilityType.OTHER

    return RawFinding(
        id=str(uuid.uuid4())[:8],
        title=title,
        vulnerability_type=vuln_type_enum,
        severity=severity,
        url=url,
        **kwargs,
    )


async def validate_findings(
    findings: List[RawFinding],
    config: Optional[ValidationConfig] = None,
) -> List[ValidatedFinding]:
    """Convenience function to validate findings."""
    pipeline = ValidationPipeline(config)
    try:
        return await pipeline.validate_findings(findings)
    finally:
        await pipeline.close()
