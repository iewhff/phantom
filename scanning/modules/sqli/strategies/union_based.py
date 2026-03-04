"""
SQL Injection Scanner - Union-Based Strategy.

Detects SQL injection through UNION SELECT column enumeration.
This method works when results from injected queries can be included
in the application's response.

Extracted from sqli_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urlencode

from utils.logger import get_logger
from utils.scan_client import get_scan_client

from scanning.modules.sqli.sqli_base import (
    DetectionMethod, SQLiEvidence, UNION_TEMPLATES,
)
from scanning.modules.sqli.utils.database_fingerprinter import DatabaseFingerprinter
from scanning.modules.sqli.strategies.base import BaseStrategy, StrategyContext, StrategyResult

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


class UnionBasedStrategy(BaseStrategy):
    """Union-based SQL injection detection strategy.

    Detects SQL injection by:
    1. Binary search for column count using ORDER BY
    2. Testing UNION SELECT with enumerated columns
    3. Verifying successful union without SQL errors

    Most powerful for data extraction but requires specific conditions:
    - Query results must be displayed
    - Column types must be compatible
    """

    # Maximum columns to search for
    MAX_UNION_COLUMNS = 20
    # Maximum mutations per template
    MAX_UNION_MUTATIONS = 5

    @property
    def name(self) -> str:
        return "union_based"

    @property
    def detection_method(self) -> DetectionMethod:
        return DetectionMethod.UNION_BASED

    async def test(self, ctx: StrategyContext) -> StrategyResult:
        """Test for union-based SQL injection.

        Strategy:
        1. Binary search for column count using ORDER BY
        2. Build UNION SELECT with correct number of NULLs
        3. Test multiple UNION templates with WAF bypass mutations
        """
        attempts = 0
        errors: list[str] = []

        # Binary search for column count
        num_columns = await self._binary_search_columns(ctx)
        attempts += int(self.MAX_UNION_COLUMNS.bit_length())  # Approximate binary search attempts

        if num_columns == 0:
            return StrategyResult.not_found(attempts, ["Could not determine column count"])

        logger.debug(f"[SQLi] Found {num_columns} columns for UNION")

        # Build column list
        columns = ",".join(["NULL"] * num_columns)

        async with get_scan_client(timeout=ctx.timeout, http2=True) as client:
            for template in UNION_TEMPLATES[:8]:
                payload = template.format(columns=columns)

                # Get mutations
                mutations = self._get_mutations(ctx, payload)

                for mutated_payload in mutations[:self.MAX_UNION_MUTATIONS]:
                    attempts += 1

                    try:
                        result = await self._test_union_payload(
                            ctx, client, payload, mutated_payload, num_columns
                        )
                        if result.found:
                            result.attempts = attempts
                            return result

                    except Exception as e:
                        errors.append(str(e))
                        logger.debug(f"[SQLi] UNION test failed: {e}")

        return StrategyResult.not_found(attempts, errors)

    async def _binary_search_columns(self, ctx: StrategyContext) -> int:
        """Binary search for column count using ORDER BY."""
        async with get_scan_client(timeout=ctx.timeout) as client:
            low, high = 1, self.MAX_UNION_COLUMNS
            result = 0

            # Import ERROR_SIGNATURES from fingerprinter
            error_signatures = DatabaseFingerprinter.ERROR_SIGNATURES or {}
            # Ensure signatures are initialized
            DatabaseFingerprinter._init_signatures()
            error_signatures = DatabaseFingerprinter.ERROR_SIGNATURES

            while low <= high:
                mid = (low + high) // 2

                test_url = self._build_test_url(ctx, f"' ORDER BY {mid}--")

                try:
                    response = await client.get(test_url, headers=ctx.auth_headers)

                    # Check for error
                    has_error = response.status_code >= 500
                    if not has_error:
                        for patterns in error_signatures.values():
                            for pattern, _ in patterns:
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    has_error = True
                                    break
                            if has_error:
                                break

                    if has_error:
                        high = mid - 1
                    else:
                        result = mid
                        low = mid + 1

                except Exception:
                    high = mid - 1

            return result

    async def _test_union_payload(
        self,
        ctx: StrategyContext,
        client: "httpx.AsyncClient",  # type: ignore
        original_payload: str,
        mutated_payload: str,
        num_columns: int,
    ) -> StrategyResult:
        """Test a single UNION payload."""
        test_url = self._build_test_url(ctx, mutated_payload)

        response = await client.get(test_url, headers=ctx.auth_headers)

        # Success criteria: 200 status, no SQL error
        if response.status_code == 200:
            has_error = self._check_for_sql_error(response.text)

            if not has_error:
                evidence = SQLiEvidence(
                    detection_method=DetectionMethod.UNION_BASED,
                    payload=original_payload,
                    original_value=ctx.params.get(ctx.param_name, [""])[0],
                    response_status=response.status_code,
                    response_length=len(response.text),
                    response_time=0,
                    waf_bypassed=mutated_payload != original_payload,
                    differential_proof=f"columns={num_columns}",
                )
                return StrategyResult.vulnerable(evidence)

        return StrategyResult.not_found()

    def _check_for_sql_error(self, content: str) -> bool:
        """Check if content contains SQL error patterns."""
        # Initialize signatures if needed
        DatabaseFingerprinter._init_signatures()
        error_signatures = DatabaseFingerprinter.ERROR_SIGNATURES

        for patterns in error_signatures.values():
            for pattern, _ in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return True
        return False


__all__ = ["UnionBasedStrategy"]
