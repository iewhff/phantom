"""
XSS Scanner - JSON Body Strategy.

Tests XSS injection in JSON API request bodies.
Targets modern apps with JSON APIs that store user data.

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


# XSS payloads for JSON injection
JSON_XSS_PAYLOADS: list[tuple[str, str]] = [
    ("<script>alert('XSS')</script>", "script_tag"),
    ("<img src=x onerror=alert('XSS')>", "img_onerror"),
    ("<svg onload=alert('XSS')>", "svg_onload"),
    ("javascript:alert('XSS')", "javascript_proto"),
    ("<iframe src='javascript:alert(1)'>", "iframe_js"),
    ("{{constructor.constructor('alert(1)')()}}", "angular_csti"),
    ("${alert('XSS')}", "template_literal"),
]

# Common JSON endpoints and their typical field names
JSON_ENDPOINTS_PATTERNS: list[tuple[str, list[str]]] = [
    ("/api/user", ["name", "bio", "description", "displayName", "username"]),
    ("/api/profile", ["name", "bio", "about", "website", "location"]),
    ("/api/comment", ["text", "content", "message", "body"]),
    ("/api/post", ["title", "content", "body", "description"]),
    ("/api/message", ["text", "content", "subject", "body"]),
    ("/api/settings", ["name", "displayName", "title"]),
    ("/api/feedback", ["message", "comment", "text"]),
]


class JSONBodyStrategy(BaseXSSStrategy):
    """JSON body XSS injection strategy.

    Tests XSS injection in JSON API request bodies:
    - User profile updates (name, bio, description)
    - Comments/messages
    - Settings with display names
    - Search queries that get reflected
    """

    @property
    def name(self) -> str:
        return "json_body"

    async def test(self, ctx: XSSStrategyContext) -> XSSStrategyResult:
        """Test JSON API endpoints for XSS.

        Strategy:
        1. Identify JSON API endpoints
        2. Test fields with XSS payloads via POST/PUT
        3. Check for reflection in response
        """
        evidence_list: list[XSSEvidence] = []
        attempts = 0
        errors: list[str] = []

        # Identify JSON API endpoints
        json_api_endpoints = self._find_json_endpoints(ctx)
        if not json_api_endpoints:
            return XSSStrategyResult.not_found(0, ["No JSON API endpoints found"])

        async with get_scan_client(timeout=ctx.timeout) as client:
            for endpoint in json_api_endpoints[:10]:
                # Determine fields to test based on endpoint
                test_fields = self._get_fields_for_endpoint(endpoint)

                for payload, payload_type in JSON_XSS_PAYLOADS[:4]:
                    for field_name in test_fields[:3]:
                        await ctx.acquire_rate_limit()
                        attempts += 1

                        # Build JSON body with XSS payload
                        json_body = {field_name: payload}
                        if "id" not in json_body:
                            json_body["id"] = 1

                        headers = dict(ctx.auth_headers)
                        headers["Content-Type"] = "application/json"

                        try:
                            # Test POST (create)
                            response = await client.post(
                                endpoint,
                                json=json_body,
                                headers=headers,
                            )

                            # Check for reflection
                            is_vulnerable, reflection_type = self._check_json_reflection(
                                payload, response
                            )

                            # Also test PUT for update operations
                            if not is_vulnerable and response.status_code in (200, 201, 404):
                                response_put = await client.put(
                                    f"{endpoint}/1",
                                    json=json_body,
                                    headers=headers,
                                )
                                if payload in response_put.text:
                                    is_vulnerable = True
                                    reflection_type = "put_reflection"

                            if is_vulnerable:
                                evidence_list.append(XSSEvidence(
                                    payload=payload,
                                    context=XSSContext.HTML_TEXT,
                                    reflected_in=reflection_type,
                                    encoding_used="none",
                                    waf_bypassed=ctx.detected_waf is not None and ctx.detected_waf != WAFType.NONE,
                                    response_snippet=self._extract_snippet(payload, response.text),
                                    confirmation_count=1,
                                    metadata={
                                        "xss_type": "json_api",
                                        "field_name": field_name,
                                        "payload_type": payload_type,
                                        "reflection_type": reflection_type,
                                        "method": "POST/PUT",
                                    }
                                ))
                                logger.info(
                                    f"[XSS-JSON] Found XSS: {endpoint} field={field_name}"
                                )
                                # Found for this endpoint, try next
                                break

                        except asyncio.TimeoutError:
                            errors.append(f"Timeout testing {endpoint}")
                        except Exception as e:
                            errors.append(f"Error testing {endpoint}: {e}")
                            logger.debug(f"[XSS-JSON] Test error: {e}")

        if evidence_list:
            return XSSStrategyResult.vulnerable(evidence_list, attempts)
        return XSSStrategyResult.not_found(attempts, errors)

    def _find_json_endpoints(self, ctx: XSSStrategyContext) -> list[str]:
        """Find JSON API endpoints to test."""
        endpoints = []

        # Check asset_data for discovered endpoints
        if ctx.asset_data:
            discovered = ctx.asset_data.get("endpoints", [])
            for ep in discovered:
                ep_lower = ep.lower()
                # Match against known patterns
                if any(pattern in ep_lower for pattern, _ in JSON_ENDPOINTS_PATTERNS):
                    endpoints.append(ep)
                # Also include generic API paths
                elif any(api in ep_lower for api in ["/api/", "/rest/", "/v1/", "/v2/"]):
                    endpoints.append(ep)

        # Add common API paths if none found
        if not endpoints:
            parsed = urlparse(ctx.base_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            endpoints = [
                f"{base}/api/user",
                f"{base}/api/profile",
                f"{base}/api/comments",
            ]

        return endpoints

    def _get_fields_for_endpoint(self, endpoint: str) -> list[str]:
        """Get likely field names for an endpoint."""
        endpoint_lower = endpoint.lower()

        # Match against known patterns
        for pattern, fields in JSON_ENDPOINTS_PATTERNS:
            if pattern in endpoint_lower:
                return fields

        # Default fields
        return ["name", "text", "content", "message", "description"]

    def _check_json_reflection(
        self,
        payload: str,
        response: "httpx.Response",
    ) -> tuple[bool, str]:
        """Check if payload is reflected in response.

        Returns:
            Tuple of (is_vulnerable, reflection_type)
        """
        # Direct reflection in body
        if payload in response.text:
            return True, "direct_reflection"

        # Check for unescaped HTML in JSON response
        text_lower = response.text.lower()
        if "<script" in text_lower or "onerror=" in text_lower:
            # Verify not escaped
            if "\\u003c" not in response.text:
                return True, "unescaped_html"

        return False, ""


__all__ = ["JSONBodyStrategy"]
