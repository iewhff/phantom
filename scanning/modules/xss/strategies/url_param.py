"""
XSS Scanner - URL Parameter Strategy.

Tests XSS injection via URL query parameters.
Handles both traditional query strings and SPA hash-based routes.

Extracted from xss_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlparse

from utils.logger import get_logger
from utils.scan_client import get_scan_client

from scanning.modules.xss.xss_base import (
    MIN_CONFIDENCE_THRESHOLD,
    CROSS_VALIDATION_REQUIRED,
    XSSContext,
    XSSEvidence,
    XSSResult,
    WAFType,
    POLYGLOT_PAYLOADS,
    PHP_LEGACY_BYPASS_PAYLOADS,
    PAYLOADS_BY_CONTEXT,
    WAF_BYPASS_PAYLOADS,
)
from scanning.modules.xss.strategies.base import (
    BaseXSSStrategy,
    XSSStrategyContext,
    XSSStrategyResult,
)

if TYPE_CHECKING:
    import httpx

logger = get_logger(__name__)


class URLParamStrategy(BaseXSSStrategy):
    """URL parameter XSS testing strategy.

    Tests XSS injection via query string parameters with:
    - SPA hash-route support (Angular, React, Vue routing)
    - Context detection (HTML, JS, attribute, etc.)
    - WAF bypass mutations
    - Cross-validation for confidence scoring
    """

    # Maximum requests per endpoint (rate limiting)
    MAX_REQUESTS_PER_ENDPOINT = 25
    # Maximum mutations per payload
    MAX_MUTATIONS = 15
    # Default max payloads per parameter
    DEFAULT_MAX_PAYLOADS = 30

    @property
    def name(self) -> str:
        return "url_param"

    async def test(self, ctx: XSSStrategyContext) -> XSSStrategyResult:
        """Test URL parameters for XSS.

        Strategy:
        1. Parse query string (including SPA hash routes)
        2. Test reflection with canary value
        3. Detect context (HTML, JS, attribute, etc.)
        4. Test context-specific payloads
        5. Cross-validate for confidence
        """
        evidence_list: list[XSSEvidence] = []
        attempts = 0
        errors: list[str] = []

        # Parse URL - handle SPA hash-based routes
        parsed = urlparse(ctx.base_url)
        query_string = parsed.query

        # Support SPA hash routes: /#/search?q=test
        if not query_string and parsed.fragment and '?' in parsed.fragment:
            fragment_parts = parsed.fragment.split('?', 1)
            if len(fragment_parts) == 2:
                query_string = fragment_parts[1]
                logger.debug(f"[XSS-URL] Detected hash-based route: {query_string}")

        if not query_string and not ctx.params:
            return XSSStrategyResult.not_found(0, ["No query parameters to test"])

        # Use provided params or parse from URL
        params = ctx.params if ctx.params else parse_qs(query_string)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Preserve fragment path for SPA routes
        if parsed.fragment and '?' in parsed.fragment:
            fragment_path = parsed.fragment.split('?')[0]
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}#{fragment_path}"

        async with get_scan_client(timeout=ctx.timeout, custom_headers=ctx.auth_headers) as client:
            for param_name in params:
                # Generate unique canary
                canary = f"XSS_CANARY_{hash(param_name) % 100000}"

                # Test reflection
                test_params = params.copy()
                test_params[param_name] = [canary]

                try:
                    await ctx.acquire_rate_limit()
                    attempts += 1

                    response = await client.get(
                        base_url,
                        params={k: v[0] for k, v in test_params.items()}
                    )

                    # Check if canary is reflected
                    if canary not in response.text:
                        continue  # Not reflected, skip

                    # Detect context
                    context = self._detect_context(response.text, canary)
                    logger.debug(f"[XSS-URL] Reflection in {context.name} for {param_name}")

                    # Get context-specific payloads
                    payloads = self._get_payloads_for_context(context, ctx)

                    # Test payloads with validation
                    max_payloads = ctx.max_payloads or self.DEFAULT_MAX_PAYLOADS
                    param_findings = 0

                    for payload in payloads[:max_payloads]:
                        if param_findings >= 3:  # Cap findings per param
                            break

                        attempts += 1
                        result = await self._test_payload_with_validation(
                            client, base_url, param_name, payload,
                            params, context, ctx
                        )

                        if result:
                            evidence_list.extend(result.evidence)
                            param_findings += 1

                except asyncio.TimeoutError:
                    errors.append(f"Timeout testing {param_name}")
                except Exception as e:
                    errors.append(f"Error testing {param_name}: {e}")
                    logger.debug(f"[XSS-URL] Test failed for {param_name}: {e}")

        if evidence_list:
            return XSSStrategyResult.vulnerable(evidence_list, attempts)
        return XSSStrategyResult.not_found(attempts, errors)

    async def _test_payload_with_validation(
        self,
        client: "httpx.AsyncClient",
        base_url: str,
        param_name: str,
        payload: str,
        original_params: dict,
        context: XSSContext,
        ctx: XSSStrategyContext,
    ) -> XSSStrategyResult | None:
        """Test payload with cross-validation for confidence scoring."""
        confirmations = 0
        evidence_list: list[XSSEvidence] = []

        # Get mutations
        mutations = self._get_mutations(ctx, payload)[:self.MAX_MUTATIONS]

        for mutation in mutations:
            await ctx.acquire_rate_limit()

            test_params = original_params.copy()
            test_params[param_name] = [mutation]

            try:
                response = await client.get(
                    base_url,
                    params={k: v[0] for k, v in test_params.items()}
                )

                # Check if reflected
                if self._check_reflection(mutation, response.text):
                    confirmations += 1

                    # Extract reflection details
                    snippet = self._extract_snippet(mutation, response.text)
                    encoding_used = "none" if mutation == payload else "mutated"

                    evidence_list.append(XSSEvidence(
                        payload=mutation,
                        context=context,
                        reflected_in="response_body",
                        encoding_used=encoding_used,
                        waf_bypassed=ctx.detected_waf is not None and ctx.detected_waf != WAFType.NONE,
                        response_snippet=snippet,
                        confirmation_count=confirmations,
                    ))

            except (asyncio.TimeoutError, Exception) as e:
                logger.debug(f"[XSS-URL] Request error: {e}")
                continue

        if confirmations >= CROSS_VALIDATION_REQUIRED:
            confidence = self._calculate_confidence(
                confirmations=confirmations,
                context=context,
                waf_detected=ctx.detected_waf is not None and ctx.detected_waf != WAFType.NONE,
                csp_present=ctx.csp_analysis.get("present", False),
            )

            if confidence >= MIN_CONFIDENCE_THRESHOLD:
                return XSSStrategyResult.vulnerable(evidence_list)

        return None

    def _detect_context(self, content: str, canary: str) -> XSSContext:
        """Detect XSS context from response content."""
        pos = content.find(canary)
        if pos == -1:
            return XSSContext.HTML_TEXT

        # Get surrounding context (200 chars before/after)
        start = max(0, pos - 200)
        end = min(len(content), pos + len(canary) + 200)
        context_str = content[start:end].lower()

        # Check various contexts
        if self._in_script_context(context_str, canary.lower()):
            return XSSContext.JS_STRING
        if self._in_attribute_context(context_str, canary.lower()):
            return XSSContext.HTML_ATTRIBUTE
        if self._in_url_context(context_str, canary.lower()):
            return XSSContext.URL_PARAM
        if '<style' in context_str or 'style=' in context_str:
            return XSSContext.CSS_VALUE
        if '<svg' in context_str:
            return XSSContext.SVG_CONTEXT

        # Check modern frameworks
        if any(ind in context_str for ind in ['x-data', 'x-bind', '@click']):
            return XSSContext.ALPINE_DIRECTIVE
        if any(ind in context_str for ind in ['hx-', 'data-hx-']):
            return XSSContext.HTMX_ATTRIBUTE
        if any(ind in context_str for ind in ['v-bind', 'v-on:', '@']):
            return XSSContext.VUE_DIRECTIVE
        if '{#' in context_str or 'bind:' in context_str:
            return XSSContext.SVELTE_BINDING
        if '{{' in context_str and '}}' in context_str:
            return XSSContext.ANGULAR_BINDING

        return XSSContext.HTML_TEXT

    def _in_script_context(self, context: str, canary: str) -> bool:
        """Check if canary is inside <script> block."""
        script_start = context.rfind('<script')
        script_end = context.find('</script>')
        canary_pos = context.find(canary)
        return script_start != -1 and (script_end == -1 or script_start < canary_pos < script_end)

    def _in_attribute_context(self, context: str, canary: str) -> bool:
        """Check if canary is inside an HTML attribute."""
        import re
        pattern = rf'[a-z]+\s*=\s*["\'][^"\']*{re.escape(canary)}'
        return bool(re.search(pattern, context, re.IGNORECASE))

    def _in_url_context(self, context: str, canary: str) -> bool:
        """Check if canary is in a URL context (href, src, action)."""
        import re
        pattern = rf'(?:href|src|action)\s*=\s*["\'][^"\']*{re.escape(canary)}'
        return bool(re.search(pattern, context, re.IGNORECASE))

    def _get_payloads_for_context(
        self,
        context: XSSContext,
        ctx: XSSStrategyContext,
    ) -> list[str]:
        """Get payloads optimized for detected context."""
        payloads: list[str] = []

        # Get context-specific payloads
        context_payloads = PAYLOADS_BY_CONTEXT.get(context, [])
        if context_payloads:
            payloads.extend(context_payloads)

        # Add WAF bypass payloads if WAF detected
        if ctx.detected_waf and ctx.detected_waf != WAFType.NONE:
            waf_payloads = WAF_BYPASS_PAYLOADS.get(ctx.detected_waf, [])
            payloads = list(waf_payloads) + payloads

        # Add polyglot payloads (work in multiple contexts)
        payloads = list(POLYGLOT_PAYLOADS) + payloads

        # Add PHP legacy bypass payloads
        payloads = payloads + list(PHP_LEGACY_BYPASS_PAYLOADS)

        # Deduplicate while preserving order
        seen = set()
        unique = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)

        return unique

    def _calculate_confidence(
        self,
        confirmations: int,
        context: XSSContext,
        waf_detected: bool,
        csp_present: bool,
    ) -> float:
        """Calculate confidence score based on evidence."""
        base_confidence = 60.0

        # Add for confirmations
        base_confidence += min(confirmations * 8, 25)

        # Context-specific adjustments
        high_risk_contexts = [
            XSSContext.HTML_TEXT,
            XSSContext.JS_STRING,
            XSSContext.HTML_ATTRIBUTE,
        ]
        if context in high_risk_contexts:
            base_confidence += 10

        # WAF bypass increases confidence (harder to exploit)
        if waf_detected:
            base_confidence += 5

        # CSP might reduce exploitability
        if csp_present:
            base_confidence -= 5

        return min(base_confidence, 100.0)


__all__ = ["URLParamStrategy"]
