"""
SQL Injection Scanner - Error-Based Strategy.

Detects SQL injection through database error messages in responses.
This is the most reliable detection method when errors are verbose.

Extracted from sqli_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from utils.logger import get_logger
from utils.scan_client import get_scan_client

from scanning.modules.sqli.sqli_base import (
    DatabaseType, DetectionMethod, ERROR_PAYLOADS, MAX_FALLBACK_PAYLOADS,
    MAX_INTELLIGENT_PAYLOADS, ResponseFingerprint, SQLiEvidence,
)
from scanning.modules.sqli.utils.database_fingerprinter import DatabaseFingerprinter
from scanning.modules.sqli.strategies.base import BaseStrategy, StrategyContext, StrategyResult

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


class ErrorBasedStrategy(BaseStrategy):
    """Error-based SQL injection detection strategy.

    Detects SQL injection by triggering database error messages that
    appear in the response. This method works when:
    - Database errors are displayed (dev mode, verbose errors)
    - Error messages include SQL-specific keywords
    - Response differs from baseline when SQL syntax is injected

    Confidence is high when specific database error patterns are matched.
    """

    @property
    def name(self) -> str:
        return "error_based"

    @property
    def detection_method(self) -> DetectionMethod:
        return DetectionMethod.ERROR_BASED

    async def test(self, ctx: StrategyContext) -> StrategyResult:
        """Test for error-based SQL injection.

        Strategy:
        1. Try intelligent payloads first (from PayloadLibrary)
        2. Fall back to hardcoded payloads if needed
        3. Apply WAF bypass mutations to each payload
        4. Confirm findings with negative control
        5. Cross-validate with secondary payload
        """
        attempts = 0
        errors: list[str] = []

        # Try intelligent payloads first
        if ctx.get_intelligent_payloads:
            try:
                result = await self._test_intelligent_payloads(ctx)
                if result.found:
                    return result
                attempts += result.attempts
            except Exception as e:
                errors.append(f"Intelligent payload error: {e}")
                logger.debug(f"[SQLi] Error-based intelligent test failed: {e}")

        # Fall back to hardcoded payloads
        result = await self._test_hardcoded_payloads(ctx)
        result.attempts += attempts
        result.errors.extend(errors)
        return result

    async def _test_intelligent_payloads(self, ctx: StrategyContext) -> StrategyResult:
        """Test using intelligent payload selection from PayloadLibrary."""
        if not ctx.get_intelligent_payloads:
            return StrategyResult.not_found()

        attempts = 0

        # Get intelligent payloads
        intelligent_payloads = await ctx.get_intelligent_payloads(
            category="sqli",
            endpoint=ctx.base_url,
            param_name=ctx.param_name,
            max_payloads=MAX_INTELLIGENT_PAYLOADS,
            asset_data=ctx.asset_data,
        )

        if not intelligent_payloads:
            return StrategyResult.not_found()

        # Filter by detected DB if known
        detected_db = ctx.detected_db
        if detected_db and detected_db != DatabaseType.UNKNOWN:
            intelligent_payloads = self._filter_payloads_by_db(
                intelligent_payloads, detected_db.value
            )
            logger.debug(f"[SQLi] Filtered to {len(intelligent_payloads)} payloads for {detected_db.value}")

        async with get_scan_client(timeout=ctx.timeout, http2=True) as client:
            for payload, effectiveness in intelligent_payloads:
                attempts += 1
                test_url = self._build_test_url(ctx, payload)

                try:
                    await ctx.acquire_rate_limit()
                    start = time.time()
                    response = await client.get(test_url, headers=ctx.auth_headers)
                    elapsed = time.time() - start
                    content = response.text

                    if ctx.check_false_positive(content, response.status_code):
                        continue

                    db_type, error_conf, pattern = DatabaseFingerprinter.detect(content)

                    if db_type != DatabaseType.UNKNOWN and error_conf >= 60:
                        # Negative control check
                        if pattern and ctx.quick_negative_control:
                            is_valid = await ctx.quick_negative_control(
                                http_client=client,
                                url=ctx.base_url,
                                param=ctx.param_name,
                                indicator=pattern[:50] if len(pattern) > 50 else pattern,
                            )
                            if not is_valid:
                                continue

                        # Confirm with secondary payload
                        confirmed = await self._confirm_error_sqli(
                            client, ctx, db_type
                        )

                        if confirmed:
                            fp = ResponseFingerprint.from_response(response, elapsed)
                            version = DatabaseFingerprinter.extract_version(content, db_type)

                            evidence = SQLiEvidence(
                                detection_method=DetectionMethod.ERROR_BASED,
                                payload=payload,
                                original_value=ctx.params.get(ctx.param_name, [""])[0],
                                response_status=response.status_code,
                                response_length=len(content),
                                response_time=elapsed,
                                error_message=pattern,
                                db_type=db_type,
                                db_version=version,
                            )
                            return StrategyResult.vulnerable(evidence, attempts)

                except Exception as e:
                    logger.debug(f"[SQLi] Intelligent payload test failed: {e}")

        return StrategyResult.not_found(attempts)

    async def _test_hardcoded_payloads(self, ctx: StrategyContext) -> StrategyResult:
        """Test using hardcoded fallback payloads."""
        attempts = 0
        errors: list[str] = []

        # Get payloads - use ERROR_PAYLOADS constant
        error_payloads = ERROR_PAYLOADS[:MAX_FALLBACK_PAYLOADS]

        async with get_scan_client(timeout=ctx.timeout, http2=True) as client:
            for payload, name, base_confidence in error_payloads:
                # Generate mutations
                mutations = self._get_mutations(ctx, payload)

                for mutated_payload in mutations[:ctx.max_mutations]:
                    attempts += 1
                    test_url = self._build_test_url(ctx, mutated_payload)

                    try:
                        await ctx.acquire_rate_limit()
                        start = time.time()
                        response = await client.get(test_url, headers=ctx.auth_headers)
                        elapsed = time.time() - start
                        content = response.text

                        if ctx.check_false_positive(content, response.status_code):
                            continue

                        db_type, error_conf, pattern = DatabaseFingerprinter.detect(content)

                        if db_type != DatabaseType.UNKNOWN and error_conf >= 60:
                            # Negative control check
                            if pattern and ctx.quick_negative_control:
                                is_valid = await ctx.quick_negative_control(
                                    http_client=client,
                                    url=ctx.base_url,
                                    param=ctx.param_name,
                                    indicator=pattern[:50] if len(pattern) > 50 else pattern,
                                )
                                if not is_valid:
                                    logger.debug(f"[SQLi] Negative control failed for {ctx.param_name}")
                                    continue

                            # Confirm with secondary payload
                            confirmed = await self._confirm_error_sqli(
                                client, ctx, db_type
                            )

                            if confirmed:
                                fp = ResponseFingerprint.from_response(response, elapsed)
                                version = DatabaseFingerprinter.extract_version(content, db_type)

                                evidence = SQLiEvidence(
                                    detection_method=DetectionMethod.ERROR_BASED,
                                    payload=payload,
                                    original_value=ctx.params.get(ctx.param_name, [""])[0],
                                    response_status=response.status_code,
                                    response_length=len(content),
                                    response_time=elapsed,
                                    error_message=pattern,
                                    db_type=db_type,
                                    db_version=version,
                                    waf_bypassed=mutated_payload != payload,
                                )
                                return StrategyResult.vulnerable(evidence, attempts)

                    except Exception as e:
                        errors.append(str(e))
                        logger.debug(f"[SQLi] Error-based test failed: {e}")

        return StrategyResult.not_found(attempts, errors)

    async def _confirm_error_sqli(
        self,
        client: "httpx.AsyncClient",  # type: ignore
        ctx: StrategyContext,
        detected_db: DatabaseType,
    ) -> bool:
        """Confirm error-based SQLi with secondary payload."""
        # Confirmation payloads by database type
        confirm_payloads = {
            DatabaseType.MYSQL: [
                "' AND '1'='1",
                "' AND 1=1--",
                "' OR 'a'='a",
            ],
            DatabaseType.POSTGRESQL: [
                "' AND 1=cast('a' as int)--",
                "' AND 1::int=1/0--",
            ],
            DatabaseType.MSSQL: [
                "' AND 1=CONVERT(int,'a')--",
                "' AND 1=1/0--",
            ],
            DatabaseType.ORACLE: [
                "' AND 1=utl_inaddr.get_host_name('a')--",
            ],
            DatabaseType.SQLITE: [
                "' AND 1=load_extension('a')--",
            ],
        }

        payloads = confirm_payloads.get(detected_db, ["' AND '1'='1", "' OR '1'='2"])

        for payload in payloads:
            test_url = self._build_test_url(ctx, payload)

            try:
                await ctx.acquire_rate_limit()
                response = await client.get(test_url, headers=ctx.auth_headers)
                db_type, conf, _ = DatabaseFingerprinter.detect(response.text)
                if db_type == detected_db:
                    return True
            except Exception as e:
                logger.debug(f"[SQLi] Confirmation request failed: {e}")

        return False

    def _filter_payloads_by_db(
        self,
        payloads: list[tuple[str, float]],
        db_type: str,
    ) -> list[tuple[str, float]]:
        """Filter payloads by database type keywords."""
        db_keywords = {
            "mysql": ["mysql", "sleep", "benchmark"],
            "postgresql": ["pg_", "postgres"],
            "mssql": ["waitfor", "mssql", "sqlserver"],
            "oracle": ["ora-", "dbms_", "utl_"],
            "sqlite": ["sqlite", "randomblob"],
        }

        keywords = db_keywords.get(db_type.lower(), [])
        if not keywords:
            return payloads

        # Prioritize payloads matching DB keywords
        matching = []
        others = []
        for payload, effectiveness in payloads:
            payload_lower = payload.lower()
            if any(kw in payload_lower for kw in keywords):
                matching.append((payload, effectiveness))
            else:
                others.append((payload, effectiveness))

        return matching + others


__all__ = ["ErrorBasedStrategy"]
