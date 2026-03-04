"""
SQL Injection Scanner - Boolean-Blind Strategy.

Detects SQL injection through differential analysis of true/false responses.
This method works when the application doesn't show errors but behaves
differently based on SQL condition results.

Extracted from sqli_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING
from urllib.parse import urlencode

from utils.logger import get_logger
from utils.scan_client import get_scan_client

from scanning.modules.sqli.sqli_base import (
    BOOLEAN_PAYLOADS, DetectionMethod, MAX_FALLBACK_PAYLOADS,
    ResponseFingerprint, SQLiEvidence,
)
from scanning.modules.sqli.strategies.base import BaseStrategy, StrategyContext, StrategyResult

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


class BooleanBlindStrategy(BaseStrategy):
    """Boolean-blind SQL injection detection strategy.

    Detects SQL injection by comparing responses to true/false conditions.
    Key detection methods:
    - Similarity-based: True condition matches baseline, false differs
    - Length-based: Significant content length difference between T/F
    - Inverse boolean: For LIKE/search contexts where true returns MORE data

    Requires stable baseline responses for reliable detection.
    """

    @property
    def name(self) -> str:
        return "boolean_blind"

    @property
    def detection_method(self) -> DetectionMethod:
        return DetectionMethod.BOOLEAN_BLIND

    async def test(self, ctx: StrategyContext) -> StrategyResult:
        """Test for boolean-blind SQL injection.

        Strategy:
        1. Verify baseline stability with negative control
        2. Test true/false payload pairs
        3. Compare responses using multiple detection methods
        4. Verify findings with secondary payload pair
        """
        attempts = 0
        errors: list[str] = []

        if not ctx.cluster or not ctx.cluster.fingerprints:
            return StrategyResult.not_found(0, ["No baseline cluster available"])

        async with get_scan_client(timeout=ctx.timeout, http2=True) as client:
            # Negative control check first
            baseline_fp = ctx.cluster.fingerprints[0] if ctx.cluster.fingerprints else None
            if baseline_fp:
                is_stable = await self._check_baseline_stability(ctx, client, baseline_fp)
                if not is_stable:
                    return StrategyResult.not_found(0, ["Baseline too variable for boolean detection"])

            # Test boolean payload pairs
            boolean_payloads = BOOLEAN_PAYLOADS[:MAX_FALLBACK_PAYLOADS]

            for true_payload, false_payload, name in boolean_payloads:
                attempts += 1

                try:
                    result = await self._test_boolean_pair(
                        ctx, client, true_payload, false_payload, name, baseline_fp
                    )
                    if result.found:
                        result.attempts = attempts
                        return result

                except Exception as e:
                    errors.append(str(e))
                    logger.debug(f"[SQLi] Boolean test {name} failed: {e}")

        return StrategyResult.not_found(attempts, errors)

    async def _check_baseline_stability(
        self,
        ctx: StrategyContext,
        client: "httpx.AsyncClient",  # type: ignore
        baseline_fp: ResponseFingerprint,
    ) -> bool:
        """Check if baseline is stable enough for boolean detection."""
        original = (ctx.params.get(ctx.param_name) or [""])[0]

        # Test with innocent (non-SQL) payloads
        innocent_values = [
            original + "xyztest123",  # Random suffix
            original + " AND ",       # Partial SQL but incomplete
        ]

        for innocent in innocent_values:
            neg_params = ctx.params.copy()
            neg_params[ctx.param_name] = [innocent]
            neg_url = f"{ctx.base_url}?{urlencode(neg_params, doseq=True)}"

            try:
                response = await client.get(neg_url, headers=ctx.auth_headers)
                neg_fp = ResponseFingerprint.from_response(response, 0.1)
                neg_similarity = neg_fp.similarity_score(baseline_fp)

                # If innocent payload causes large deviation, app is too variable
                if neg_similarity < 60:
                    logger.debug(
                        f"[SQLi] Negative control failed: innocent payload "
                        f"'{innocent[:30]}' caused {100-neg_similarity:.0f}% deviation"
                    )
                    return False
            except Exception:
                pass  # Negative control request failed, continue anyway

        return True

    async def _test_boolean_pair(
        self,
        ctx: StrategyContext,
        client: "httpx.AsyncClient",  # type: ignore
        true_payload: str,
        false_payload: str,
        name: str,
        baseline_fp: ResponseFingerprint | None,
    ) -> StrategyResult:
        """Test a single true/false payload pair."""
        if not baseline_fp:
            return StrategyResult.not_found()

        original = (ctx.params.get(ctx.param_name) or [""])[0]

        # Determine if numeric payload
        is_numeric = true_payload and (
            true_payload[0].isdigit() or
            (true_payload[0] == '-' and len(true_payload) > 1 and true_payload[1].isdigit())
        )

        # Build payload values
        if is_numeric and original.isdigit():
            true_value, false_value = self._build_numeric_payloads(
                original, true_payload, false_payload
            )
        else:
            true_value = original + true_payload
            false_value = original + false_payload

        # Build URLs
        true_params = ctx.params.copy()
        true_params[ctx.param_name] = [true_value]
        true_url = f"{ctx.base_url}?{urlencode(true_params, doseq=True)}"

        false_params = ctx.params.copy()
        false_params[ctx.param_name] = [false_value]
        false_url = f"{ctx.base_url}?{urlencode(false_params, doseq=True)}"

        logger.debug(f"Boolean test {name}: true_url={true_url}")
        logger.debug(f"Boolean test {name}: false_url={false_url}")

        # Get responses with rate limiting
        await ctx.acquire_rate_limit()
        start = time.time()
        true_response = await client.get(true_url, headers=ctx.auth_headers)
        true_elapsed = time.time() - start
        true_fp = ResponseFingerprint.from_response(true_response, true_elapsed)

        await ctx.acquire_rate_limit()
        start = time.time()
        false_response = await client.get(false_url, headers=ctx.auth_headers)
        false_elapsed = time.time() - start
        false_fp = ResponseFingerprint.from_response(false_response, false_elapsed)

        # Calculate similarities
        true_to_baseline = true_fp.similarity_score(baseline_fp)
        false_to_baseline = false_fp.similarity_score(baseline_fp)
        true_to_false = true_fp.similarity_score(false_fp)

        # Content length differences
        length_diff_tf = abs(true_fp.content_length - false_fp.content_length)
        length_ratio_tf = min(true_fp.content_length, false_fp.content_length) / max(
            true_fp.content_length, false_fp.content_length, 1
        )

        logger.debug(
            f"Boolean test {name}: true_sim={true_to_baseline:.1f}, "
            f"false_sim={false_to_baseline:.1f}, tf_sim={true_to_false:.1f}"
        )
        logger.debug(
            f"  Lengths: baseline={baseline_fp.content_length}, "
            f"true={true_fp.content_length}, false={false_fp.content_length}"
        )

        # Check detection criteria
        is_vulnerable = self._check_detection_criteria(
            true_to_baseline, false_to_baseline, true_to_false,
            length_diff_tf, length_ratio_tf,
            true_fp, false_fp, baseline_fp
        )

        if is_vulnerable:
            # Verify with second boolean pair
            verified = await self._verify_boolean_sqli(ctx, client, baseline_fp)

            if verified:
                evidence = SQLiEvidence(
                    detection_method=DetectionMethod.BOOLEAN_BLIND,
                    payload=true_payload,
                    original_value=original,
                    response_status=true_response.status_code,
                    response_length=true_fp.content_length,
                    response_time=true_elapsed,
                    baseline_status=baseline_fp.status_code,
                    baseline_length=baseline_fp.content_length,
                    differential_proof=f"true_sim={true_to_baseline:.1f}, false_sim={false_to_baseline:.1f}",
                )
                return StrategyResult.vulnerable(evidence)

        return StrategyResult.not_found()

    def _build_numeric_payloads(
        self,
        original: str,
        true_payload: str,
        false_payload: str,
    ) -> tuple[str, str]:
        """Build numeric-context payloads."""
        if " AND " in true_payload:
            true_value = f"{original} AND " + true_payload.split(" AND ", 1)[1]
            false_value = f"{original} AND " + false_payload.split(" AND ", 1)[1]
        elif " OR " in true_payload:
            true_value = f"{original} OR " + true_payload.split(" OR ", 1)[1]
            false_value = f"{original} OR " + false_payload.split(" OR ", 1)[1]
        else:
            true_value = original + " " + true_payload
            false_value = original + " " + false_payload
        return true_value, false_value

    def _check_detection_criteria(
        self,
        true_to_baseline: float,
        false_to_baseline: float,
        true_to_false: float,
        length_diff_tf: int,
        length_ratio_tf: float,
        true_fp: ResponseFingerprint,
        false_fp: ResponseFingerprint,
        baseline_fp: ResponseFingerprint,
    ) -> bool:
        """Check multiple detection criteria for boolean SQLi."""
        # Method 1: Traditional similarity based
        similarity_based = (
            true_to_baseline > 80 and  # True similar to baseline
            false_to_baseline < (true_to_baseline - 10) and  # False differs more
            true_to_false < 75  # True and false different
        )

        # Method 2: Content length based
        length_based = (
            length_diff_tf > 150 and  # Significant length difference
            length_ratio_tf < 0.9 and  # At least 10% size difference
            abs(true_fp.content_length - baseline_fp.content_length) <
            abs(false_fp.content_length - baseline_fp.content_length)  # True closer to baseline
        )

        # Method 3: Strong length difference
        strong_length = (
            length_diff_tf > 100 and
            length_ratio_tf < 0.85  # At least 15% difference
        )

        # Method 4: Inverse boolean for LIKE/search contexts
        # In search: TRUE (OR 1=1) returns ALL data (different from baseline)
        inverse_boolean = (
            true_to_baseline < 60 and  # True is DIFFERENT from baseline
            false_to_baseline > 70 and  # False is SIMILAR to baseline
            true_to_false < 60 and  # True and false are very different
            true_fp.content_length > baseline_fp.content_length * 1.5  # True has more data
        )

        if inverse_boolean:
            logger.info(
                f"[SQLi] Inverse boolean detected (LIKE context): "
                f"true_len={true_fp.content_length}, baseline_len={baseline_fp.content_length}"
            )

        return similarity_based or length_based or strong_length or inverse_boolean

    async def _verify_boolean_sqli(
        self,
        ctx: StrategyContext,
        client: "httpx.AsyncClient",  # type: ignore
        baseline_fp: ResponseFingerprint,
    ) -> bool:
        """Verify boolean SQLi with alternative payload pair."""
        verify_pairs = [
            # Standard SQL injection pairs
            ("' AND 1=1 AND 'x'='x", "' AND 1=2 AND 'x'='x"),
            ("' AND 'abc'='abc", "' AND 'abc'='def"),
            ("' OR 1=1 OR 'a'='a", "' OR 1=2 OR 'a'='a"),
            # LIKE-context pairs
            ("')) OR 1=1--", "')) AND 1=2--"),
            ("%')) OR 1=1--", "%')) AND 1=2--"),
            ("') OR 1=1--", "') AND 1=2--"),
        ]

        original = (ctx.params.get(ctx.param_name) or [""])[0]

        for true_p, false_p in verify_pairs:
            try:
                true_params = ctx.params.copy()
                true_params[ctx.param_name] = [original + true_p]
                true_url = f"{ctx.base_url}?{urlencode(true_params, doseq=True)}"

                false_params = ctx.params.copy()
                false_params[ctx.param_name] = [original + false_p]
                false_url = f"{ctx.base_url}?{urlencode(false_params, doseq=True)}"

                true_resp = await client.get(true_url, headers=ctx.auth_headers)
                false_resp = await client.get(false_url, headers=ctx.auth_headers)

                true_fp = ResponseFingerprint.from_response(true_resp, 0)
                false_fp = ResponseFingerprint.from_response(false_resp, 0)

                if true_fp.similarity_score(false_fp) < 75:
                    return True

            except Exception as e:
                logger.debug(f"[SQLi] Boolean verification failed: {e}")

        return False


__all__ = ["BooleanBlindStrategy"]
