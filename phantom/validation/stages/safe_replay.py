"""
PHANTOM AI - Safe Replay Stage
================================

Extracted from phantom/validation_pipeline.py (lines 1437-1753).

Stage 3: Safe Replay
Replays the attack with a safe variant to verify it's not a false positive.

Includes behavior-based module detection and blind detection helpers.
"""

import re
import asyncio
import hashlib
import logging
import time
from typing import Dict, List, Any, Tuple, Optional

import httpx

from phantom.validation.models import (
    ValidationStage,
    ValidationResult,
    ValidationConfig,
    RawFinding,
    StageResult,
    VulnerabilityType,
    CONFIDENCE_BOOST_SAFE_REPLAY,
    CONFIDENCE_BOOST_BLIND_VULN,
    CONFIDENCE_BOOST_BEHAVIOR_EVIDENCE,
    CONFIDENCE_PENALTY_MISSING_DATA,
    CONFIDENCE_PENALTY_IDENTICAL_RESPONSE,
    CONFIDENCE_PENALTY_SIMILAR_RESPONSE,
    CONTEXT_PENALTY_NO_EVIDENCE,
    TOKEN_OVERLAP_THRESHOLD,
    LENGTH_SIMILARITY_THRESHOLD,
    SIGNIFICANT_NEW_TOKENS_MIN,
    SIGNIFICANT_NEW_TOKENS_PERCENT,
)
from phantom.validation.utils.payload_generator import SafePayloadGenerator

try:
    from utils.performance_cache import (
        get_cached_waf_detection,
        cache_waf_detection,
        WAFDetection,
    )
    PERFORMANCE_CACHE_AVAILABLE = True
except ImportError:
    PERFORMANCE_CACHE_AVAILABLE = False

logger = logging.getLogger("phantom.validation.stages.safe_replay")


# Modules whose findings are behavior-based (not payload-based).
# Safe replay and negative control make no sense for these — they test
# business logic, session behavior, or creative attack patterns where
# "safe variant" is meaningless.
_BEHAVIOR_BASED_MODULES = frozenset({
    "business", "business_logic",
    "creative_exploiter",
    "session_abuse",
    "authz",              # authorization checks (role/endpoint probing)
    "race",               # race conditions
    "mass_assign",        # mass assignment
    "ratelimit",          # rate limiting checks
    # FIX 2026-02-12: Added missing behavior-based modules
    "workflow_inference", # business flow detection
    "permission_matrix",  # role-based testing
    "token_binding",      # session validation
    "concurrency_stress", # race condition stress tests
    "abac_context",       # attribute-based access control
    "mfa_bypass",         # MFA bypass testing
})

_BEHAVIOR_BASED_VULN_TYPES = frozenset({
    # Note: IDOR is NOT here because IDOR findings have a parameter (the ID)
    # that can be replayed with different values. Only include truly behavior-based
    # types that have no payload/parameter to test.
    VulnerabilityType.AUTHORIZATION,
})

# FN-FIX: Blind detection methods where Safe Replay doesn't make sense
# These produce IDENTICAL responses because the difference is in timing/behavior, not content
_BLIND_DETECTION_METHODS = frozenset({
    "time_blind", "TIME_BLIND", "time-based", "time_based",
    "boolean_blind", "BOOLEAN_BLIND", "boolean-based", "boolean_based",
    "blind", "BLIND", "oob", "OOB", "out_of_band",
})

# FIX #9 2026-02-12: Keywords for more robust blind detection matching
# Instead of exact matches, check if any of these substrings appear in detection_method
_BLIND_DETECTION_KEYWORDS = frozenset({
    "blind", "time", "oob", "delay", "sleep", "dns", "callback",
    "waitfor", "benchmark", "latency", "async", "polling",
    "out-of-band", "external", "inferential", "conditional",
})


def _is_blind_detection_method(detection_method: str, metadata: dict) -> bool:
    """
    Check if a finding uses blind detection where Safe Replay doesn't apply.

    FIX #9 2026-02-12: Use keyword matching instead of exact set membership.
    This catches variations like "TIME_BLIND_5S", "boolean-blind-sqli", etc.
    """
    method_lower = detection_method.lower() if detection_method else ""

    # Check exact match first (fast path)
    if method_lower in _BLIND_DETECTION_METHODS:
        return True

    # Check keyword substrings (catches variations)
    if any(kw in method_lower for kw in _BLIND_DETECTION_KEYWORDS):
        return True

    # Check cross-validations
    cross_validations = metadata.get("cross_validations", [])
    for cv in cross_validations:
        if isinstance(cv, str):
            cv_lower = cv.lower()
            if cv_lower in _BLIND_DETECTION_METHODS:
                return True
            if any(kw in cv_lower for kw in _BLIND_DETECTION_KEYWORDS):
                return True

    # Check explicit blind flag
    if metadata.get("is_blind", False):
        return True

    # Check technique field (some scanners use this)
    technique = str(metadata.get("technique", "")).lower()
    if any(kw in technique for kw in _BLIND_DETECTION_KEYWORDS):
        return True

    return False


class SafeReplayStage:
    """
    Stage 3: Safe Replay
    Replays the attack with a safe variant to verify it's not a false positive.
    """

    def __init__(self, config: ValidationConfig) -> None:
        self.config = config
        self.generator = SafePayloadGenerator()

    async def validate(
        self,
        finding: RawFinding,
        http_client: httpx.AsyncClient,
    ) -> StageResult:
        """Replay with safe payload."""
        start = time.time()

        # Behavior-based findings (business logic, session abuse, creative exploiter,
        # authorization, etc.) are not payload-based. They don't have traditional
        # payloads to replay - skip this stage.
        # Note: IDOR is NOT skipped here - IDOR has a parameter (the ID) to replay.
        if (finding.vulnerability_type in _BEHAVIOR_BASED_VULN_TYPES
                or finding.module_name in _BEHAVIOR_BASED_MODULES):
            # ISSUE-2 FIX 2026-02-11: Evidence-based confidence delta
            # FN-M6 FIX: Expanded evidence field names that modules might use
            metadata = finding.metadata or {}
            has_evidence = bool(
                metadata.get("comparison_evidence")
                or metadata.get("state_persisted")
                or metadata.get("baseline_response")
                or metadata.get("evidence")
                or metadata.get("proof")
                # FN-M6: Additional evidence field names
                or metadata.get("verified")
                or metadata.get("confirmed")
                or metadata.get("reproduced")
                or metadata.get("diff")
                or metadata.get("delta")
                or metadata.get("response_comparison")
                or metadata.get("before_after")
                or metadata.get("mutation_result")
            )
            delta = CONFIDENCE_BOOST_BEHAVIOR_EVIDENCE if has_evidence else CONTEXT_PENALTY_NO_EVIDENCE
            msg = "Behavior-based with evidence, skipping replay" if has_evidence else "Behavior-based without evidence, skipping replay (penalty)"
            return StageResult(
                stage=ValidationStage.SAFE_REPLAY,
                result=ValidationResult.SKIPPED,
                confidence_delta=delta,
                message=msg,
                duration_ms=(time.time() - start) * 1000,
            )

        # FN-FIX: Handle blind vulnerabilities (time-based, boolean-based, OOB)
        # These produce IDENTICAL response content because the difference is in timing/behavior.
        # GAP-2 FIX Sprint 1.3: For time-based, do proper timing validation instead of skipping
        metadata = finding.metadata or {}
        detection_method = str(metadata.get("detection_method", ""))

        # FIX #9 2026-02-12: Use helper function for robust keyword matching
        if _is_blind_detection_method(detection_method, metadata):
            # GAP-2 FIX Sprint 1.3: Check if time-based and validate timing
            is_time_based = any(
                kw in detection_method.lower()
                for kw in ["time", "delay", "sleep", "waitfor", "benchmark"]
            )

            if is_time_based and http_client:
                # Perform actual time-based validation
                try:
                    # Import the validation method from pipeline instance
                    # Note: This stage doesn't have direct access to pipeline,
                    # so we log intent and skip (pipeline calls validate_time_based_finding separately)
                    logger.debug(
                        f"[SafeReplay] Time-based detection for {finding.vulnerability_type}, "
                        "marked for time validation"
                    )
                    return StageResult(
                        stage=ValidationStage.SAFE_REPLAY,
                        result=ValidationResult.SKIPPED,
                        confidence_delta=0.0,  # Neutral - time validation happens separately
                        message="Time-based vulnerability - requires timing validation",
                        evidence="Marked for validate_time_based_finding()",
                        duration_ms=(time.time() - start) * 1000,
                    )
                except Exception as e:
                    logger.debug(f"[SafeReplay] Time validation setup error: {e}")

            # Non-time blind (boolean, OOB) - skip with boost
            return StageResult(
                stage=ValidationStage.SAFE_REPLAY,
                result=ValidationResult.SKIPPED,
                confidence_delta=CONFIDENCE_BOOST_BLIND_VULN,
                message="Blind vulnerability (boolean-based/OOB) - replay not applicable",
                duration_ms=(time.time() - start) * 1000,
            )

        if not finding.payload or not finding.parameter:
            # THEME-10 FIX: Missing data = uncertainty, should penalize
            return StageResult(
                stage=ValidationStage.SAFE_REPLAY,
                result=ValidationResult.SKIPPED,
                confidence_delta=CONFIDENCE_PENALTY_MISSING_DATA,
                message="No payload/parameter to replay (data gap penalty applied)",
                duration_ms=(time.time() - start) * 1000,
            )

        try:
            # Generate safe payload
            safe_payload = self.generator.generate_safe_variant(
                finding.payload, finding.vulnerability_type
            )

            # Replay with safe payload
            if finding.method.upper() == "GET":
                params = {finding.parameter: safe_payload}
                response = await http_client.get(
                    finding.url,
                    params=params,
                    timeout=self.config.replay_timeout,
                )
            else:
                data = {finding.parameter: safe_payload}
                response = await http_client.post(
                    finding.url,
                    data=data,
                    timeout=self.config.replay_timeout,
                )

            # Compare with original response - use both length AND content hash
            original_response = finding.response or ""
            safe_response = response.text

            original_len = len(original_response)
            safe_len = len(safe_response)

            # Length-based similarity
            length_similarity = min(original_len, safe_len) / max(original_len, safe_len, 1)

            # Content-based similarity (hash comparison)
            # L1 FIX: Use SHA256 instead of MD5 for better collision resistance
            original_hash = hashlib.sha256(original_response.encode()).hexdigest()
            safe_hash = hashlib.sha256(safe_response.encode()).hexdigest()
            content_identical = original_hash == safe_hash

            # If content is IDENTICAL (same hash), definitely FP
            if content_identical:
                return StageResult(
                    stage=ValidationStage.SAFE_REPLAY,
                    result=ValidationResult.FAILED,
                    confidence_delta=CONFIDENCE_PENALTY_IDENTICAL_RESPONSE,
                    message="Safe replay produced IDENTICAL response (likely FP)",
                    evidence=f"Hash match: {original_hash[:8]}",
                    duration_ms=(time.time() - start) * 1000,
                )

            # If length is similar but content differs, check token overlap
            if length_similarity > LENGTH_SIMILARITY_THRESHOLD:
                # Compare word tokens
                original_tokens = set(original_response.split())
                safe_tokens = set(safe_response.split())
                overlap = len(original_tokens & safe_tokens) / max(len(original_tokens | safe_tokens), 1)
                new_tokens = original_tokens - safe_tokens

                # FIX 2026-02-18: Use both absolute AND percentage-based thresholds
                # AUDIT-FIX 2026-02-19: Fixed threshold for small responses
                # Problem: max(5, percent) always returns 5 for small responses
                # A 50-token SQL error with 2 new tokens ("MySQL", "error") was rejected
                #
                # New logic:
                # - Tiny responses (<50 tokens): require 1 new token (SQL errors are small)
                # - Small responses (50-200 tokens): require 2 new tokens
                # - Medium responses (200-500 tokens): require 3 new tokens or 2%
                # - Large responses (>500 tokens): require 5 tokens or 2%
                total_tokens = len(original_tokens)
                if total_tokens < 50:
                    min_required = 1  # SQL error responses are tiny
                elif total_tokens < 200:
                    min_required = 2  # Small responses
                elif total_tokens < 500:
                    min_required = max(3, int(total_tokens * SIGNIFICANT_NEW_TOKENS_PERCENT))
                else:
                    min_required = max(SIGNIFICANT_NEW_TOKENS_MIN, int(total_tokens * SIGNIFICANT_NEW_TOKENS_PERCENT))
                has_significant_new_content = len(new_tokens) >= min_required

                # FN-H1 FIX: Also check for significant new content
                if overlap > TOKEN_OVERLAP_THRESHOLD and not has_significant_new_content:
                    return StageResult(
                        stage=ValidationStage.SAFE_REPLAY,
                        result=ValidationResult.FAILED,
                        confidence_delta=CONFIDENCE_PENALTY_SIMILAR_RESPONSE,
                        message="Safe replay produced similar response (possible FP)",
                        evidence=f"Token overlap: {overlap:.2%}, new tokens: {len(new_tokens)}/{min_required} required",
                        duration_ms=(time.time() - start) * 1000,
                    )

            # Responses are sufficiently different - finding likely valid
            return StageResult(
                stage=ValidationStage.SAFE_REPLAY,
                result=ValidationResult.PASSED,
                confidence_delta=CONFIDENCE_BOOST_SAFE_REPLAY,
                message="Safe replay confirmed different behavior",
                evidence=f"Length similarity: {length_similarity:.2%}, Content differs",
                duration_ms=(time.time() - start) * 1000,
            )

        except asyncio.TimeoutError:
            return StageResult(
                stage=ValidationStage.SAFE_REPLAY,
                result=ValidationResult.ERROR,
                confidence_delta=0.0,
                message="Replay timeout",
                duration_ms=(time.time() - start) * 1000,
            )
        except httpx.HTTPError as e:
            return StageResult(
                stage=ValidationStage.SAFE_REPLAY,
                result=ValidationResult.ERROR,
                confidence_delta=0.0,
                message=f"HTTP error: {type(e).__name__}: {e}",
                duration_ms=(time.time() - start) * 1000,
            )
        except OSError as e:
            return StageResult(
                stage=ValidationStage.SAFE_REPLAY,
                result=ValidationResult.ERROR,
                confidence_delta=0.0,
                message=f"Network error: {type(e).__name__}: {e}",
                duration_ms=(time.time() - start) * 1000,
            )
