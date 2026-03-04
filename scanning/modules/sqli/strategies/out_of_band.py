"""
SQL Injection Scanner - Out-of-Band (OOB) Strategy.

Detects SQL injection through external DNS/HTTP callbacks.
This method works when no in-band response is visible but the database
can make external connections.

Extracted from sqli_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from utils.logger import get_logger
from utils.scan_client import get_scan_client

from scanning.modules.sqli.sqli_base import (
    DatabaseType, DetectionMethod, OOB_MANDATORY_PAYLOADS, SQLiEvidence,
)
from scanning.modules.sqli.strategies.base import BaseStrategy, StrategyContext, StrategyResult

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)

# Check OOB Engine availability
_OOB_AVAILABLE = True
try:
    from utils.oob_engine import OOBEngine, OOBProtocol, OOBPayloadGenerator
except ImportError:
    _OOB_AVAILABLE = False
    OOBEngine = None  # type: ignore
    OOBProtocol = None  # type: ignore


class OutOfBandStrategy(BaseStrategy):
    """Out-of-band SQL injection detection strategy.

    Detects SQL injection through external callbacks:
    - Oracle: UTL_HTTP.REQUEST, UTL_INADDR.GET_HOST_ADDRESS
    - MSSQL: xp_dirtree, xp_fileexist
    - PostgreSQL: COPY TO PROGRAM, dblink
    - MySQL: LOAD_FILE (limited, requires FILE privilege)

    Requires OOBEngine to be available for callback monitoring.
    Falls back to static payload testing if OOBEngine is unavailable.
    """

    @property
    def name(self) -> str:
        return "out_of_band"

    @property
    def detection_method(self) -> DetectionMethod:
        return DetectionMethod.OUT_OF_BAND

    async def test(self, ctx: StrategyContext) -> StrategyResult:
        """Test for out-of-band SQL injection.

        Strategy:
        1. If OOBEngine available, generate unique callback tokens
        2. Inject OOB payloads with tokens
        3. Monitor for callback hits
        4. Fallback to static testing if no OOB infrastructure
        """
        if _OOB_AVAILABLE:
            return await self._test_with_oob_engine(ctx)
        else:
            return await self._test_static_payloads(ctx)

    async def _test_with_oob_engine(self, ctx: StrategyContext) -> StrategyResult:
        """Test using OOBEngine for callback monitoring."""
        attempts = 0
        errors: list[str] = []

        try:
            oob_engine = OOBEngine.get_instance()

            # Generate unique callback domain/token
            callback_info = oob_engine.generate_callback("sqli", ctx.param_name)
            if not callback_info:
                logger.debug("[SQLi] OOB: Could not generate callback")
                return await self._test_static_payloads(ctx)

            callback_domain = callback_info.get("domain", "")
            token = callback_info.get("token", "")

            async with get_scan_client(timeout=ctx.timeout, http2=True) as client:
                for payload_template, db_type, name in OOB_MANDATORY_PAYLOADS:
                    attempts += 1

                    # Format payload with callback info
                    payload = payload_template.format(
                        callback=callback_domain,
                        domain=callback_domain,
                        token=token,
                    )

                    try:
                        result = await self._test_oob_payload(
                            ctx, client, oob_engine, payload, db_type, token
                        )
                        if result.found:
                            result.attempts = attempts
                            return result

                    except Exception as e:
                        errors.append(str(e))
                        logger.debug(f"[SQLi] OOB test {name} failed: {e}")

            return StrategyResult.not_found(attempts, errors)

        except Exception as e:
            logger.debug(f"[SQLi] OOB engine error: {e}")
            return await self._test_static_payloads(ctx)

    async def _test_oob_payload(
        self,
        ctx: StrategyContext,
        client: "httpx.AsyncClient",  # type: ignore
        oob_engine: Any,
        payload: str,
        db_type: str,
        token: str,
    ) -> StrategyResult:
        """Test a single OOB payload and wait for callback."""
        test_url = self._build_test_url(ctx, payload)

        # Send the injection request
        await ctx.acquire_rate_limit()
        response = await client.get(test_url, headers=ctx.auth_headers)

        # Wait for callback (OOB may be delayed)
        import asyncio
        await asyncio.sleep(2)  # Give time for callback

        # Check if callback was received
        callback_result = oob_engine.check_callback(token)

        if callback_result and callback_result.get("received"):
            # Determine database type
            detected_db = DatabaseType.UNKNOWN
            if db_type != "generic":
                try:
                    detected_db = DatabaseType[db_type.upper()]
                except KeyError:
                    pass

            evidence = SQLiEvidence(
                detection_method=DetectionMethod.OUT_OF_BAND,
                payload=payload,
                original_value=ctx.params.get(ctx.param_name, [""])[0],
                response_status=response.status_code,
                response_length=len(response.text),
                response_time=0,
                db_type=detected_db,
                differential_proof=f"oob_callback_received, token={token}",
            )
            return StrategyResult.vulnerable(evidence)

        return StrategyResult.not_found()

    async def _test_static_payloads(self, ctx: StrategyContext) -> StrategyResult:
        """Fallback static testing when OOB infrastructure unavailable.

        Without OOB monitoring, we can only detect if the payload causes
        observable side effects (errors, timeouts, etc.).
        """
        attempts = 0
        errors: list[str] = []

        logger.debug("[SQLi] OOB: Testing without callback monitoring (limited detection)")

        async with get_scan_client(timeout=ctx.timeout, http2=True) as client:
            # Get baseline
            from urllib.parse import urlencode
            baseline_url = f"{ctx.base_url}?{urlencode(ctx.params, doseq=True)}"
            try:
                baseline_resp = await client.get(baseline_url, headers=ctx.auth_headers)
                baseline_status = baseline_resp.status_code
            except Exception:
                baseline_status = 200

            for payload_template, db_type, name in OOB_MANDATORY_PAYLOADS[:6]:  # Limit tests
                attempts += 1

                # Use placeholder values since no real callback
                payload = payload_template.format(
                    callback="test.example.com",
                    domain="test.example.com",
                    token="test",
                )

                test_url = self._build_test_url(ctx, payload)

                try:
                    await ctx.acquire_rate_limit()
                    start = time.time()
                    response = await client.get(test_url, headers=ctx.auth_headers)
                    elapsed = time.time() - start

                    # Without callback, we can only detect:
                    # 1. Server errors (may indicate OOB attempted)
                    # 2. Significant delays (network call attempted)
                    # 3. Content changes

                    is_suspicious = False
                    reason = ""

                    if response.status_code == 500 and baseline_status != 500:
                        is_suspicious = True
                        reason = "server_error_after_oob"

                    if elapsed > 5 and ctx.detector:
                        is_anomaly, z_score = ctx.detector.is_time_anomaly(elapsed)
                        if is_anomaly and z_score > 3:
                            is_suspicious = True
                            reason = "network_delay"

                    if is_suspicious:
                        # Lower confidence without callback confirmation
                        evidence = SQLiEvidence(
                            detection_method=DetectionMethod.OUT_OF_BAND,
                            payload=payload,
                            original_value=ctx.params.get(ctx.param_name, [""])[0],
                            response_status=response.status_code,
                            response_length=len(response.text),
                            response_time=elapsed,
                            differential_proof=f"static_test_suspicious: {reason} (no callback verification)",
                        )
                        # Note: This is a weak signal without OOB callback
                        logger.warning(
                            f"[SQLi] OOB payload caused suspicious behavior ({reason}) "
                            "but no callback confirmation available"
                        )
                        # Don't return vulnerable without callback - too high FP risk
                        # return StrategyResult.vulnerable(evidence)

                except Exception as e:
                    errors.append(str(e))
                    logger.debug(f"[SQLi] OOB static test {name} failed: {e}")

        # Without OOB callback infrastructure, we can't reliably confirm OOB SQLi
        return StrategyResult.not_found(
            attempts,
            errors + ["OOB detection requires callback infrastructure (OOBEngine)"]
        )


__all__ = ["OutOfBandStrategy"]
