"""
XSS Scanner - Form Field Strategy.

Tests XSS injection via HTML form fields.
Uses FormContextPreserver to maintain valid values in non-target fields.

Extracted from xss_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from utils.logger import get_logger
from utils.scan_client import get_scan_client

from scanning.modules.xss.xss_base import (
    MIN_CONFIDENCE_THRESHOLD,
    XSSContext,
    XSSEvidence,
    WAFType,
    POLYGLOT_PAYLOADS,
    PHP_LEGACY_BYPASS_PAYLOADS,
)
from scanning.modules.xss.strategies.base import (
    BaseXSSStrategy,
    XSSStrategyContext,
    XSSStrategyResult,
)

if TYPE_CHECKING:
    import httpx

logger = get_logger(__name__)


class FormTestStrategy(BaseXSSStrategy):
    """Form field XSS testing strategy.

    Tests XSS injection via HTML form fields with:
    - FormContextPreserver integration for valid field values
    - CSRF token handling
    - Multi-method support (GET/POST)
    - Context detection
    """

    # Maximum findings per form field
    MAX_FINDINGS_PER_FIELD = 3
    # Default form payloads
    DEFAULT_FORM_PAYLOADS = 15

    @property
    def name(self) -> str:
        return "form_test"

    async def test(self, ctx: XSSStrategyContext) -> XSSStrategyResult:
        """Test HTML forms for XSS.

        Strategy:
        1. Parse form definition (action, method, fields)
        2. Identify injectable fields (skip CSRF, hidden, submit)
        3. Test each field with context-preserved data
        4. Validate reflection and context
        """
        evidence_list: list[XSSEvidence] = []
        attempts = 0
        errors: list[str] = []

        # Get forms from context
        forms = ctx.forms or ctx.asset_data.get("forms", [])
        if not forms:
            return XSSStrategyResult.not_found(0, ["No forms to test"])

        async with get_scan_client(timeout=ctx.timeout) as client:
            for form in forms:
                form_evidence = await self._test_single_form(
                    client, form, ctx
                )
                if form_evidence:
                    evidence_list.extend(form_evidence)
                    attempts += len(form_evidence)

        if evidence_list:
            return XSSStrategyResult.vulnerable(evidence_list, attempts)
        return XSSStrategyResult.not_found(attempts, errors)

    async def _test_single_form(
        self,
        client: "httpx.AsyncClient",
        form: dict[str, Any],
        ctx: XSSStrategyContext,
    ) -> list[XSSEvidence]:
        """Test a single form for XSS."""
        evidence_list: list[XSSEvidence] = []

        action = form.get("action", "/")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        # Resolve action URL
        if not action.startswith("http"):
            parsed = urlparse(ctx.base_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            action = f"{base}{action}" if action.startswith("/") else f"{base}/{action}"

        # Identify injectable fields
        injectable_fields = self._get_injectable_fields(inputs)
        if not injectable_fields:
            return evidence_list

        # Get payloads
        payloads = self._get_form_payloads()

        for field_info in injectable_fields:
            field_name = field_info["name"]
            field_findings = 0

            for payload in payloads:
                if field_findings >= self.MAX_FINDINGS_PER_FIELD:
                    break

                # Build test data with context preservation
                test_data = self._build_test_data(inputs, field_name, payload)

                try:
                    await ctx.acquire_rate_limit()

                    if method == "POST":
                        response = await client.post(
                            action,
                            data=test_data,
                            headers=ctx.auth_headers,
                        )
                    else:
                        response = await client.get(
                            action,
                            params=test_data,
                            headers=ctx.auth_headers,
                        )

                    # Check reflection
                    if self._check_reflection(payload, response.text):
                        context = self._detect_form_context(response.text, payload)
                        confidence = self._calculate_form_confidence(
                            context, ctx.detected_waf, ctx.csp_analysis
                        )

                        if confidence >= MIN_CONFIDENCE_THRESHOLD:
                            evidence_list.append(XSSEvidence(
                                payload=payload,
                                context=context,
                                reflected_in="form_response",
                                encoding_used="none",
                                waf_bypassed=ctx.detected_waf is not None and ctx.detected_waf != WAFType.NONE,
                                response_snippet=self._extract_snippet(payload, response.text),
                                confirmation_count=1,
                                metadata={
                                    "form_action": action,
                                    "form_method": method,
                                    "field_name": field_name,
                                    "context": context.name,
                                }
                            ))
                            field_findings += 1
                            logger.info(
                                f"[XSS-Form] Found XSS: {action} field={field_name} "
                                f"context={context.name}"
                            )

                except asyncio.TimeoutError:
                    logger.debug(f"[XSS-Form] Timeout testing {action}")
                except Exception as e:
                    logger.debug(f"[XSS-Form] Test failed: {e}")

        return evidence_list

    def _get_injectable_fields(self, inputs: list[dict]) -> list[dict]:
        """Get fields that can be tested for XSS."""
        injectable = []

        # CSRF token field name patterns
        csrf_indicators = [
            "csrf", "token", "_token", "user_token", "nonce", "authenticity"
        ]
        # Non-injectable input types
        skip_types = ["hidden", "submit", "button", "file", "checkbox", "radio"]

        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue

            input_type = inp.get("type", "text").lower()

            # Skip non-injectable types
            if input_type in skip_types:
                continue

            # Skip CSRF tokens
            if any(ind in name.lower() for ind in csrf_indicators):
                continue

            injectable.append(inp)

        return injectable

    def _build_test_data(
        self,
        inputs: list[dict],
        target_field: str,
        payload: str,
    ) -> dict[str, str]:
        """Build form test data with context preservation.

        Maintains valid values in non-target fields to prevent
        server-side validation from rejecting the request.
        """
        test_data = {}

        # Default values for common field types
        field_defaults = {
            "email": "test@example.com",
            "password": "Test1234!",
            "username": "testuser",
            "name": "Test User",
            "phone": "1234567890",
            "url": "https://example.com",
            "number": "1",
        }

        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue

            input_type = inp.get("type", "text").lower()
            value = inp.get("value", "")

            if name == target_field:
                # Inject payload
                test_data[name] = payload
            elif input_type in field_defaults:
                # Use type-appropriate default
                test_data[name] = field_defaults[input_type]
            elif value:
                # Use existing value
                test_data[name] = value
            else:
                # Use name-based heuristics
                name_lower = name.lower()
                if "email" in name_lower:
                    test_data[name] = "test@example.com"
                elif "password" in name_lower or "passwd" in name_lower:
                    test_data[name] = "Test1234!"
                elif "user" in name_lower:
                    test_data[name] = "testuser"
                else:
                    test_data[name] = "test"

        return test_data

    def _get_form_payloads(self) -> list[str]:
        """Get payloads for form testing."""
        payloads = []

        # Start with polyglot payloads
        payloads.extend(POLYGLOT_PAYLOADS[:12])

        # Add PHP legacy bypass payloads
        payloads.extend(PHP_LEGACY_BYPASS_PAYLOADS[:15])

        return payloads

    def _detect_form_context(self, content: str, payload: str) -> XSSContext:
        """Detect XSS context from form response."""
        pos = content.find(payload)
        if pos == -1:
            return XSSContext.HTML_TEXT

        # Get surrounding context
        start = max(0, pos - 150)
        end = min(len(content), pos + len(payload) + 150)
        context_str = content[start:end].lower()

        # Check contexts
        if "<script" in context_str:
            return XSSContext.JS_STRING
        if 'value="' in context_str or "value='" in context_str:
            return XSSContext.HTML_ATTRIBUTE
        if '<style' in context_str:
            return XSSContext.CSS_VALUE

        return XSSContext.HTML_TEXT

    def _calculate_form_confidence(
        self,
        context: XSSContext,
        waf_detected: "WAFType | None",
        csp_analysis: dict,
    ) -> float:
        """Calculate confidence for form XSS finding."""
        base_confidence = 70.0

        # Context adjustments
        if context == XSSContext.HTML_TEXT:
            base_confidence += 10
        elif context == XSSContext.JS_STRING:
            base_confidence += 15

        # WAF bypass indicates real vulnerability
        if waf_detected and waf_detected != WAFType.NONE:
            base_confidence += 5

        # CSP reduces exploitability
        if csp_analysis.get("present"):
            base_confidence -= 5

        return min(base_confidence, 100.0)


__all__ = ["FormTestStrategy"]
