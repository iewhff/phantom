"""
SQL Injection Scanner - Stacked Queries Strategy.

Detects SQL injection through multiple statement execution (semicolon-separated).
This is particularly dangerous as it allows INSERT, UPDATE, DELETE operations.

Extracted from sqli_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import re
import time
from typing import TYPE_CHECKING
from urllib.parse import urlencode

from utils.logger import get_logger
from utils.scan_client import get_scan_client

from scanning.modules.sqli.sqli_base import (
    DatabaseType, DetectionMethod, SQLiEvidence,
)
from scanning.modules.sqli.strategies.base import BaseStrategy, StrategyContext, StrategyResult

if TYPE_CHECKING:
    from scanning.modules.sqli.utils.response_analysis import AnomalyDetector

logger = get_logger(__name__)


# Stacked queries payloads - designed to trigger observable side effects
STACKED_PAYLOADS: list[tuple[str, str, str]] = [
    # Time-based stacked (most reliable)
    ("'; WAITFOR DELAY '0:0:{delay}'--", "mssql", "waitfor_delay"),
    ("'; SELECT pg_sleep({delay})--", "postgresql", "pg_sleep"),
    ("'; SELECT SLEEP({delay})--", "mysql", "sleep"),
    # Error-based stacked
    ("'; SELECT 1/0--", "generic", "div_zero"),
    ("'; SELECT * FROM nonexistent_table_xyzzy--", "generic", "bad_table"),
    ("'; EXEC xp_cmdshell 'ping 127.0.0.1'--", "mssql", "xp_cmdshell"),
    # Version fingerprinting (confirms stacked execution)
    ("'; SELECT @@version--", "mssql", "version_mssql"),
    ("'; SELECT version()--", "postgresql", "version_pg"),
    ("'; SELECT VERSION()--", "mysql", "version_mysql"),
    # Database enumeration stacked
    ("'; SELECT table_name FROM information_schema.tables LIMIT 1--", "generic", "info_schema"),
]


class StackedQueriesStrategy(BaseStrategy):
    """Stacked queries SQL injection detection strategy.

    Detects ability to execute multiple SQL statements via semicolon.
    This is particularly dangerous as it can:
    - INSERT, UPDATE, DELETE data
    - Execute stored procedures (xp_cmdshell)
    - Create/drop tables

    Detection methods:
    - Time-based: WAITFOR DELAY, pg_sleep, SLEEP
    - Error-based: Division by zero, invalid table
    - Version leak: SELECT version() in response
    """

    # Default time delay in seconds
    DEFAULT_DELAY = 5
    # Maximum mutations per payload
    MAX_STACKED_MUTATIONS = 4

    @property
    def name(self) -> str:
        return "stacked_queries"

    @property
    def detection_method(self) -> DetectionMethod:
        return DetectionMethod.STACKED_QUERIES

    async def test(self, ctx: StrategyContext) -> StrategyResult:
        """Test for stacked queries SQL injection.

        Strategy:
        1. Get baseline response for comparison
        2. Test time-based stacked payloads
        3. Test error-based stacked payloads
        4. Check for version information leaks
        """
        attempts = 0
        errors: list[str] = []

        delay = ctx.time_delay if ctx.time_delay > 0 else self.DEFAULT_DELAY

        async with get_scan_client(timeout=delay + 15, http2=True) as client:
            # Get baseline response
            baseline_url = f"{ctx.base_url}?{urlencode(ctx.params, doseq=True)}"
            try:
                baseline_resp = await client.get(baseline_url, headers=ctx.auth_headers)
                baseline_status = baseline_resp.status_code
                baseline_text = baseline_resp.text.lower()
            except Exception as e:
                return StrategyResult.not_found(0, [f"Baseline failed: {e}"])

            for payload_template, db_type, name in STACKED_PAYLOADS:
                payload = payload_template.format(delay=delay)

                # Get mutations
                mutations = self._get_mutations(ctx, payload)

                for mutated_payload in mutations[:self.MAX_STACKED_MUTATIONS]:
                    attempts += 1

                    try:
                        result = await self._test_stacked_payload(
                            ctx, client, payload, mutated_payload, db_type, name,
                            delay, baseline_status, baseline_text
                        )
                        if result.found:
                            result.attempts = attempts
                            return result

                    except Exception as e:
                        errors.append(str(e))
                        logger.debug(f"[SQLi] Stacked test {name} failed: {e}")

        return StrategyResult.not_found(attempts, errors)

    async def _test_stacked_payload(
        self,
        ctx: StrategyContext,
        client: "httpx.AsyncClient",  # type: ignore
        original_payload: str,
        mutated_payload: str,
        db_type: str,
        name: str,
        delay: int,
        baseline_status: int,
        baseline_text: str,
    ) -> StrategyResult:
        """Test a single stacked queries payload."""
        test_url = self._build_test_url(ctx, mutated_payload)

        await ctx.acquire_rate_limit()
        start = time.time()
        response = await client.get(test_url, headers=ctx.auth_headers)
        elapsed = time.time() - start
        resp_text = response.text.lower()

        is_vulnerable = False
        detection_type = ""

        # 1. Time-based detection (most reliable for stacked)
        if "delay" in original_payload or "sleep" in original_payload.lower():
            if ctx.detector:
                is_anomaly, z_score = ctx.detector.is_time_anomaly(elapsed)
                if elapsed >= delay - 1 and is_anomaly and z_score > 2:
                    is_vulnerable = True
                    detection_type = "time_delay"
            elif elapsed >= delay - 1:
                is_vulnerable = True
                detection_type = "time_delay"

        # 2. Error-based detection (for div_zero, bad_table)
        if not is_vulnerable:
            error_indicators = [
                "division by zero", "divide by zero",
                "does not exist", "doesn't exist",
                "unknown table", "no such table",
                "relation.*does not exist",
                "invalid object name",
            ]
            for indicator in error_indicators:
                if indicator in resp_text and indicator not in baseline_text:
                    is_vulnerable = True
                    detection_type = "error_triggered"
                    break

        # 3. Server error detection
        if not is_vulnerable and response.status_code == 500 and baseline_status != 500:
            is_vulnerable = True
            detection_type = "server_error"

        # 4. Version/info extraction (proves execution)
        if not is_vulnerable:
            version_patterns = [
                r"microsoft sql server.*\d+\.\d+",
                r"postgresql \d+\.\d+",
                r"\d+\.\d+\.\d+-.*mysql",
                r"mariadb",
            ]
            for pattern in version_patterns:
                if re.search(pattern, resp_text, re.I) and not re.search(pattern, baseline_text, re.I):
                    is_vulnerable = True
                    detection_type = "version_leak"
                    break

        if is_vulnerable:
            # Try to identify database type
            detected_db = DatabaseType.UNKNOWN
            if db_type != "generic":
                try:
                    detected_db = DatabaseType[db_type.upper()]
                except KeyError:
                    pass

            evidence = SQLiEvidence(
                detection_method=DetectionMethod.STACKED_QUERIES,
                payload=original_payload,
                original_value=ctx.params.get(ctx.param_name, [""])[0],
                response_status=response.status_code,
                response_length=len(response.text),
                response_time=elapsed,
                db_type=detected_db,
                waf_bypassed=mutated_payload != original_payload,
                differential_proof=f"detection_type={detection_type}",
            )
            return StrategyResult.vulnerable(evidence)

        return StrategyResult.not_found()


__all__ = ["StackedQueriesStrategy"]
