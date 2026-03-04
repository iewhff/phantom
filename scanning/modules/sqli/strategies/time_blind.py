"""
SQL Injection Scanner - Time-Blind Strategy.

Detects SQL injection through response time delays caused by SQL sleep/wait functions.
This method works when the application doesn't show errors or behavioral differences,
but the database supports time-delay functions.

Extracted from sqli_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import asyncio
import statistics
import time
from typing import TYPE_CHECKING
from urllib.parse import urlencode

from utils.logger import get_logger
from utils.scan_client import get_scan_client

from scanning.modules.sqli.sqli_base import (
    DatabaseType, DetectionMethod, TIME_PAYLOADS, SQLiEvidence,
)
from scanning.modules.sqli.strategies.base import BaseStrategy, StrategyContext, StrategyResult

if TYPE_CHECKING:
    from scanning.modules.sqli.utils.response_analysis import AnomalyDetector

logger = get_logger(__name__)


class TimeBlindStrategy(BaseStrategy):
    """Time-blind SQL injection detection strategy.

    Detects SQL injection by measuring response time delays caused by:
    - MySQL: SLEEP(), BENCHMARK()
    - PostgreSQL: pg_sleep()
    - MSSQL: WAITFOR DELAY
    - Oracle: DBMS_PIPE.RECEIVE_MESSAGE(), DBMS_LOCK.SLEEP()
    - SQLite: Heavy computation (RANDOMBLOB)

    Requires multiple measurements for reliability to avoid false positives
    from network latency variations.
    """

    # Default time delay in seconds
    DEFAULT_DELAY = 5
    # Number of measurements for reliability
    NUM_MEASUREMENTS = 3
    # Maximum mutations per payload
    MAX_TIME_MUTATIONS = 3

    @property
    def name(self) -> str:
        return "time_blind"

    @property
    def detection_method(self) -> DetectionMethod:
        return DetectionMethod.TIME_BLIND

    async def test(self, ctx: StrategyContext) -> StrategyResult:
        """Test for time-blind SQL injection.

        Strategy:
        1. Prioritize payloads for detected database type
        2. Apply WAF bypass mutations
        3. Measure response times with multiple samples
        4. Verify with anomaly detection
        """
        attempts = 0
        errors: list[str] = []

        delay = ctx.time_delay if ctx.time_delay > 0 else self.DEFAULT_DELAY

        # Prioritize payloads by detected DB type
        time_payloads = self._prioritize_payloads(ctx)

        async with get_scan_client(timeout=delay + 15, http2=True) as client:
            for payload_template, db_type, name in time_payloads:
                payload = payload_template.format(delay=delay)

                # Get mutations
                mutations = self._get_mutations(ctx, payload)

                for mutated_payload in mutations[:self.MAX_TIME_MUTATIONS]:
                    attempts += 1

                    try:
                        result = await self._test_time_payload(
                            ctx, client, payload, mutated_payload, db_type, delay
                        )
                        if result.found:
                            result.attempts = attempts
                            return result

                    except asyncio.TimeoutError:
                        # Timeout is strong evidence - verify
                        verified = await self._verify_timeout(ctx, client, delay)
                        if verified:
                            evidence = SQLiEvidence(
                                detection_method=DetectionMethod.TIME_BLIND,
                                payload=payload,
                                original_value=ctx.params.get(ctx.param_name, [""])[0],
                                response_status=0,
                                response_length=0,
                                response_time=delay + 15,  # Timeout
                                db_type=DatabaseType[db_type.upper()],
                            )
                            return StrategyResult.vulnerable(evidence, attempts)

                    except Exception as e:
                        errors.append(str(e))
                        logger.debug(f"[SQLi] Time-based test {name} failed: {e}")

        return StrategyResult.not_found(attempts, errors)

    def _prioritize_payloads(self, ctx: StrategyContext) -> list[tuple[str, str, str]]:
        """Prioritize payloads by detected database type."""
        detected_db = ctx.detected_db
        detected_db_str = detected_db.value.lower() if detected_db and detected_db != DatabaseType.UNKNOWN else None

        # Limit payloads (time-based is slow)
        max_payloads = ctx.max_payloads if ctx.max_payloads > 0 else 6

        if detected_db_str:
            # Filter payloads matching detected DB first
            matching = [p for p in TIME_PAYLOADS if p[1].lower() == detected_db_str]
            other = [p for p in TIME_PAYLOADS if p[1].lower() != detected_db_str]
            prioritized = matching[:max_payloads] or other[:max_payloads]
            logger.debug(f"[SQLi] Prioritized {len(prioritized)} time payloads for {detected_db_str}")
            return prioritized
        else:
            return TIME_PAYLOADS[:max_payloads]

    async def _test_time_payload(
        self,
        ctx: StrategyContext,
        client: "httpx.AsyncClient",  # type: ignore
        original_payload: str,
        mutated_payload: str,
        db_type: str,
        delay: int,
    ) -> StrategyResult:
        """Test a single time-based payload."""
        test_url = self._build_test_url(ctx, mutated_payload)

        # Triple test for reliability
        times: list[float] = []
        for _ in range(self.NUM_MEASUREMENTS):
            await ctx.acquire_rate_limit()
            start = time.time()
            await client.get(test_url, headers=ctx.auth_headers)
            elapsed = time.time() - start
            times.append(elapsed)

        # Calculate statistics
        avg_time = statistics.mean(times)
        time_variance = statistics.stdev(times) if len(times) > 1 else 0

        # Check anomaly using detector if available
        is_anomaly = False
        z_score = 0.0
        if ctx.detector:
            is_anomaly, z_score = ctx.detector.is_time_anomaly(avg_time)

        logger.debug(
            f"[SQLi] Time test: avg={avg_time:.2f}s, variance={time_variance:.2f}, "
            f"z_score={z_score:.2f}, is_anomaly={is_anomaly}"
        )

        # Strict detection criteria
        is_vulnerable = (
            all(t >= delay - 1 for t in times) and  # All measurements show delay
            time_variance < 2 and  # Consistent timing
            is_anomaly and  # Statistical anomaly
            z_score > 3  # Strong deviation
        )

        if is_vulnerable:
            evidence = SQLiEvidence(
                detection_method=DetectionMethod.TIME_BLIND,
                payload=original_payload,
                original_value=ctx.params.get(ctx.param_name, [""])[0],
                response_status=200,
                response_length=0,
                response_time=avg_time,
                db_type=DatabaseType[db_type.upper()],
                waf_bypassed=mutated_payload != original_payload,
                differential_proof=f"times={times}, z_score={z_score:.2f}",
            )
            return StrategyResult.vulnerable(evidence)

        return StrategyResult.not_found()

    async def _verify_timeout(
        self,
        ctx: StrategyContext,
        client: "httpx.AsyncClient",  # type: ignore
        delay: int,
    ) -> bool:
        """Verify timeout by checking normal response time."""
        try:
            normal_url = f"{ctx.base_url}?{urlencode(ctx.params, doseq=True)}"
            start = time.time()
            await client.get(normal_url, headers=ctx.auth_headers, timeout=10)
            normal_time = time.time() - start

            # If normal request is fast, timeout was likely due to SQLi
            return normal_time < 5

        except asyncio.TimeoutError:
            # Both timeout - inconclusive
            return False
        except Exception:
            return False


__all__ = ["TimeBlindStrategy"]
