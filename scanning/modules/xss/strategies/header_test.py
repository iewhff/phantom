"""
XSS Scanner - HTTP Header Injection Strategy.

Tests XSS injection via HTTP headers that may be logged or reflected.
Common vectors include User-Agent, Referer, and X-Forwarded-For.

Extracted from xss_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from utils.logger import get_logger
from utils.scan_client import get_scan_client

from scanning.modules.xss.xss_base import XSSContext, XSSEvidence, WAFType
from scanning.modules.xss.strategies.base import (
    BaseXSSStrategy,
    XSSStrategyContext,
    XSSStrategyResult,
)

if TYPE_CHECKING:
    import httpx

logger = get_logger(__name__)


# XSS payloads optimized for header injection
HEADER_PAYLOADS: list[tuple[str, str]] = [
    ("<script>alert('XSS')</script>", "script_tag"),
    ("<img src=x onerror=alert('XSS')>", "img_onerror"),
    ("javascript:alert('XSS')", "javascript_proto"),
    ("'-alert('XSS')-'", "js_break"),
    ("\"><script>alert('XSS')</script>", "context_break"),
    ("{{constructor.constructor('alert(1)')()}}", "template_injection"),
]

# Headers commonly vulnerable to XSS injection
INJECTABLE_HEADERS: list[tuple[str, str]] = [
    ("User-Agent", "Mozilla/5.0 {payload}"),
    ("Referer", "{base}/{payload}"),
    ("X-Forwarded-For", "{payload}"),
    ("X-Real-IP", "{payload}"),
    ("X-Forwarded-Host", "{payload}"),
    ("Accept-Language", "{payload}"),
    ("X-Custom-Header", "{payload}"),
    ("X-Api-Key", "{payload}"),
]


class HeaderTestStrategy(BaseXSSStrategy):
    """HTTP header XSS injection strategy.

    Tests XSS injection via HTTP headers that may be:
    - Logged and viewed in admin panels
    - Reflected in error pages
    - Included in response headers
    - Stored in analytics systems
    """

    @property
    def name(self) -> str:
        return "header_test"

    async def test(self, ctx: XSSStrategyContext) -> XSSStrategyResult:
        """Test HTTP headers for XSS injection.

        Strategy:
        1. Send requests with XSS payloads in various headers
        2. Check if payload is reflected in response body or headers
        3. Track successful injections for stored XSS in logs
        """
        evidence_list: list[XSSEvidence] = []
        attempts = 0
        errors: list[str] = []
        tested_combinations: set[tuple[str, str]] = set()

        async with get_scan_client(timeout=ctx.timeout) as client:
            # Test against base URL and any provided endpoints
            endpoints = [ctx.base_url]

            for endpoint in endpoints[:5]:
                for header_name, header_template in INJECTABLE_HEADERS:
                    for payload, payload_type in HEADER_PAYLOADS[:4]:
                        # Dedup: (header, payload_type) per endpoint
                        combo_key = (header_name, payload_type)
                        if combo_key in tested_combinations:
                            continue
                        tested_combinations.add(combo_key)

                        await ctx.acquire_rate_limit()
                        attempts += 1

                        # Build test header
                        test_value = header_template.format(
                            payload=payload,
                            base=ctx.base_url,
                        )

                        # Build headers - keep auth but add malicious header
                        test_headers = dict(ctx.auth_headers)
                        test_headers[header_name] = test_value

                        try:
                            response = await client.get(endpoint, headers=test_headers)

                            # Check for reflection
                            is_reflected, reflection_context = self._check_header_reflection(
                                payload, response
                            )

                            if is_reflected:
                                evidence_list.append(XSSEvidence(
                                    payload=payload,
                                    context=XSSContext.HTML_TEXT,
                                    reflected_in=reflection_context,
                                    encoding_used="none",
                                    waf_bypassed=ctx.detected_waf is not None and ctx.detected_waf != WAFType.NONE,
                                    response_snippet=self._extract_snippet(payload, response.text),
                                    confirmation_count=1,
                                    metadata={
                                        "xss_type": "header_injection",
                                        "header_name": header_name,
                                        "payload_type": payload_type,
                                        "reflection_context": reflection_context,
                                    }
                                ))
                                logger.info(
                                    f"[XSS-Header] Injection found: {header_name} "
                                    f"reflected in {reflection_context}"
                                )
                                # Found for this header, try next
                                break

                        except asyncio.TimeoutError:
                            errors.append(f"Timeout testing {header_name}")
                        except Exception as e:
                            errors.append(f"Error testing {header_name}: {e}")
                            logger.debug(f"[XSS-Header] Test error ({header_name}): {e}")

        if evidence_list:
            return XSSStrategyResult.vulnerable(evidence_list, attempts)
        return XSSStrategyResult.not_found(attempts, errors)

    def _check_header_reflection(
        self,
        payload: str,
        response: "httpx.Response",
    ) -> tuple[bool, str]:
        """Check if payload is reflected in response.

        Returns:
            Tuple of (is_reflected, reflection_context)
        """
        # Check response body
        if payload in response.text:
            return True, "response_body"

        # Check for partial reflection (sanitized but present)
        if "alert" in response.text and "XSS" in response.text:
            return True, "partial_reflection"

        # Check response headers
        for header_name, header_value in response.headers.items():
            if payload in header_value:
                return True, f"header:{header_name}"

        return False, ""


__all__ = ["HeaderTestStrategy"]
