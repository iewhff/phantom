"""
PHANTOM AI - Negative Control Stage
======================================

Extracted from phantom/validation_pipeline.py (lines 1754-2011).

Stage 4: Negative Control
Compares against baseline behavior to detect false positives.
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
    CONFIDENCE_BOOST_NEGATIVE_CONTROL,
    CONFIDENCE_BOOST_SQL_ERROR,
    CONFIDENCE_BOOST_BLIND_VULN,
    CONFIDENCE_BOOST_BEHAVIOR_EVIDENCE,
    CONFIDENCE_BOOST_IDOR_INDICATOR,
    CONFIDENCE_BOOST_USER_DATA,
    CONFIDENCE_BOOST_AUTHZ_DATA,
    CONFIDENCE_PENALTY_MISSING_DATA,
    CONFIDENCE_PENALTY_IDENTICAL_BASELINE,
    CONFIDENCE_PENALTY_UNCERTAINTY,
    TOKEN_OVERLAP_THRESHOLD,
    LENGTH_SIMILARITY_THRESHOLD,
    SIGNIFICANT_NEW_TOKENS_MIN,
    SIGNIFICANT_NEW_TOKENS_PERCENT,
    MAX_IDOR_BOOST,
)
from phantom.validation.utils.payload_generator import SafePayloadGenerator
from phantom.validation.stages.safe_replay import (
    _BEHAVIOR_BASED_MODULES,
    _BEHAVIOR_BASED_VULN_TYPES,
    _is_blind_detection_method,
)

try:
    from utils.performance_cache import (
        get_cached_baseline,
        cache_baseline,
        BaselineResult,
    )
    PERFORMANCE_CACHE_AVAILABLE = True
except ImportError:
    PERFORMANCE_CACHE_AVAILABLE = False

logger = logging.getLogger("phantom.validation.stages.negative_control")


class NegativeControlStage:
    """
    Stage 4: Negative Control
    Compares against baseline behavior to detect false positives.
    Thread-safe via asyncio.Lock for async operations.
    """

    def __init__(self, config: ValidationConfig) -> None:
        self.config = config
        self._baseline_cache: Dict[str, str] = {}
        self._cache_lock = asyncio.Lock()

    async def validate(
        self,
        finding: RawFinding,
        http_client: httpx.AsyncClient,
    ) -> StageResult:
        """Compare against baseline."""
        start = time.time()

        # Behavior-based findings (authorization, business logic, session abuse,
        # creative exploiter, etc.) are validated through behavior comparison,
        # not payload-vs-baseline. Only boost if they provide comparison evidence.
        # Note: IDOR is NOT included - IDOR has parameters that can be tested.
        if (finding.vulnerability_type in _BEHAVIOR_BASED_VULN_TYPES
                or finding.module_name in _BEHAVIOR_BASED_MODULES):
            # Check for comparison evidence in metadata
            # FN-M6 FIX: Expanded evidence field names that modules might use
            metadata = finding.metadata or {}
            has_comparison = any([
                metadata.get("comparison_evidence"),
                metadata.get("baseline_response"),
                metadata.get("attack_response"),
                metadata.get("response_diff"),
                metadata.get("behavior_difference"),
                # Business logic evidence
                metadata.get("original_value") and metadata.get("tampered_value"),
                metadata.get("expected_response") and metadata.get("actual_response"),
                # FN-M6: Additional evidence field names
                metadata.get("verified"),
                metadata.get("confirmed"),
                metadata.get("reproduced"),
                metadata.get("diff"),
                metadata.get("delta"),
                metadata.get("before_after"),
                metadata.get("state_persisted"),
                metadata.get("mutation_result"),
                metadata.get("proof"),
                metadata.get("evidence"),
            ])

            if has_comparison:
                return StageResult(
                    stage=ValidationStage.NEGATIVE_CONTROL,
                    result=ValidationResult.PASSED,
                    confidence_delta=CONFIDENCE_BOOST_BEHAVIOR_EVIDENCE,
                    message=f"Behavior-based finding with comparison evidence",
                    duration_ms=(time.time() - start) * 1000,
                )
            else:
                # ISSUE-2 FIX 2026-02-11: No evidence - apply penalty, not neutral
                return StageResult(
                    stage=ValidationStage.NEGATIVE_CONTROL,
                    result=ValidationResult.SKIPPED,
                    confidence_delta=CONFIDENCE_PENALTY_MISSING_DATA,
                    message=f"Behavior-based finding ({finding.module_name}) — no comparison evidence (penalty)",
                    duration_ms=(time.time() - start) * 1000,
                )

        # BUG-FIX 2026-02-08: Skip Negative Control for blind vulnerabilities
        metadata = finding.metadata or {}
        detection_method = str(metadata.get("detection_method", ""))

        # FIX #9 2026-02-12: Use helper function for robust keyword matching
        if _is_blind_detection_method(detection_method, metadata):
            return StageResult(
                stage=ValidationStage.NEGATIVE_CONTROL,
                result=ValidationResult.SKIPPED,
                confidence_delta=CONFIDENCE_BOOST_BLIND_VULN,
                message="Blind vulnerability (time/boolean-based) - baseline comparison not applicable",
                duration_ms=(time.time() - start) * 1000,
            )

        if not finding.parameter:
            # THEME-10 FIX: Missing data = uncertainty, should penalize
            return StageResult(
                stage=ValidationStage.NEGATIVE_CONTROL,
                result=ValidationResult.SKIPPED,
                confidence_delta=CONFIDENCE_PENALTY_MISSING_DATA,
                message="No parameter to test (data gap penalty applied)",
                duration_ms=(time.time() - start) * 1000,
            )

        try:
            # Get or fetch baseline (thread-safe cache access)
            baseline_key = f"{finding.url}|{finding.method}"
            baseline = None

            # PERFORMANCE: Check global cross-module cache first
            if PERFORMANCE_CACHE_AVAILABLE:
                cached = get_cached_baseline(finding.url, finding.method.upper())
                if cached:
                    baseline = str(cached.response_length)  # Use length as proxy
                    logger.debug(f"[PERF_CACHE] Baseline cache hit: {finding.url}")

            if baseline is None:
                async with self._cache_lock:
                    if baseline_key not in self._baseline_cache:
                        # Fetch baseline with benign input
                        benign = SafePayloadGenerator.generate_benign_payload(
                            finding.vulnerability_type
                        )

                        if finding.method.upper() == "GET":
                            params = {finding.parameter: benign}
                            response = await http_client.get(
                                finding.url,
                                params=params,
                                timeout=self.config.replay_timeout,
                            )
                        else:
                            data = {finding.parameter: benign}
                            response = await http_client.post(
                                finding.url,
                                data=data,
                                timeout=self.config.replay_timeout,
                            )

                        self._baseline_cache[baseline_key] = response.text

                        # PERFORMANCE: Store in global cache for other modules
                        if PERFORMANCE_CACHE_AVAILABLE:
                            import hashlib
                            content_hash = hashlib.md5(response.text.encode()[:1024]).hexdigest()
                            cache_baseline(
                                finding.url,
                                finding.method.upper(),
                                BaselineResult(
                                    endpoint=finding.url,
                                    method=finding.method.upper(),
                                    status_code=response.status_code,
                                    response_length=len(response.text),
                                    content_hash=content_hash,
                                    has_error_indicators=False,
                                )
                            )

                    baseline = self._baseline_cache[baseline_key]
            attack_response = finding.response or ""

            # Compare responses
            # AUDIT-FIX 2026-02-19: Check CONTENT equality, not just LENGTH
            # Two different responses can have the same length:
            # - Baseline: "<h1>Hello World</h1>" (20 chars)
            # - Attack:   "<p>SQLi Error!!!</p>" (20 chars)
            # Previous code would reject the second as "identical" when it's clearly different!
            if attack_response == baseline:
                # Actually identical content - this IS a false positive
                return StageResult(
                    stage=ValidationStage.NEGATIVE_CONTROL,
                    result=ValidationResult.FAILED,
                    confidence_delta=CONFIDENCE_PENALTY_IDENTICAL_BASELINE,
                    message="Attack response identical to baseline (exact content match)",
                    duration_ms=(time.time() - start) * 1000,
                )

            # Check for new content in attack response
            baseline_set = set(baseline.split())
            attack_set = set(attack_response.split())
            new_content = attack_set - baseline_set

            # ISSUE-7 FIX 2026-02-11: Detect SQL/DB error patterns even with few tokens
            # SQL errors can be 1-2 words ("syntax error", "mysql") that matter
            # FIX #5 2026-02-12: Added modern DB patterns (serverless, edge DBs)
            SQL_ERROR_PATTERNS = [
                # Classic databases
                "syntax error", "mysql", "sqlite", "postgresql", "mssql", "oracle",
                "mariadb", "sql syntax", "near \"", "at line", "query failed",
                "unknown column", "duplicate entry", "constraint violation",
                "foreign key", "deadlock", "lock wait", "connection refused",
                "access denied", "permission denied", "invalid identifier",
                # Modern serverless/edge databases (2025-2026)
                "cockroachdb", "crdb", "neon", "planetscale", "vitess",
                "turso", "libsql", "d1", "cloudflare d1", "tidb",
                "yugabytedb", "singlestore", "timescaledb", "questdb",
                "supabase", "fauna", "faunadb", "datomic",
                # ORM/Query builder errors
                "prisma", "drizzle", "typeorm", "sequelize", "knex",
                "sqlalchemy", "activerecord", "eloquent", "diesel",
                # Generic SQL error patterns
                "pg_", "pgsql", "psql", "sqlstate", "relation \"",
                "column \"", "table \"", "database \"", "schema \"",
                "unterminated", "unexpected token", "parse error",
            ]
            attack_lower = attack_response.lower()
            baseline_lower = baseline.lower()
            has_sql_error = any(
                p in attack_lower and p not in baseline_lower
                for p in SQL_ERROR_PATTERNS
            )

            # Strong pass if SQL error pattern detected
            if has_sql_error:
                return StageResult(
                    stage=ValidationStage.NEGATIVE_CONTROL,
                    result=ValidationResult.PASSED,
                    confidence_delta=CONFIDENCE_BOOST_SQL_ERROR,
                    message="Attack response contains SQL/DB error signature",
                    evidence="SQL error pattern detected in attack but not baseline",
                    duration_ms=(time.time() - start) * 1000,
                )

            # FN-H2 FIX: Lowered from 2 to 1 - SQL errors can be single word ("MySQL", "syntax")
            if len(new_content) >= 1:  # Any new content is significant for injection types
                return StageResult(
                    stage=ValidationStage.NEGATIVE_CONTROL,
                    result=ValidationResult.PASSED,
                    confidence_delta=CONFIDENCE_BOOST_NEGATIVE_CONTROL,
                    message="Attack response contains unique content",
                    evidence=f"New tokens: {len(new_content)}",
                    duration_ms=(time.time() - start) * 1000,
                )
            else:
                # THEME-10 FIX: INCONCLUSIVE should penalize confidence
                return StageResult(
                    stage=ValidationStage.NEGATIVE_CONTROL,
                    result=ValidationResult.INCONCLUSIVE,
                    confidence_delta=CONFIDENCE_PENALTY_UNCERTAINTY,
                    message="Minor differences from baseline (uncertainty penalty applied)",
                    duration_ms=(time.time() - start) * 1000,
                )

        except asyncio.TimeoutError:
            return StageResult(
                stage=ValidationStage.NEGATIVE_CONTROL,
                result=ValidationResult.ERROR,
                confidence_delta=0.0,
                message="Baseline fetch timeout",
                duration_ms=(time.time() - start) * 1000,
            )
        except httpx.HTTPError as e:
            return StageResult(
                stage=ValidationStage.NEGATIVE_CONTROL,
                result=ValidationResult.ERROR,
                confidence_delta=0.0,
                message=f"HTTP error: {type(e).__name__}: {e}",
                duration_ms=(time.time() - start) * 1000,
            )
        except OSError as e:
            return StageResult(
                stage=ValidationStage.NEGATIVE_CONTROL,
                result=ValidationResult.ERROR,
                confidence_delta=0.0,
                message=f"Network error: {type(e).__name__}: {e}",
                duration_ms=(time.time() - start) * 1000,
            )
