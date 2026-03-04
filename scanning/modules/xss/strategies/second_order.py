"""
XSS Scanner - Second-Order XSS Strategy.

Tests for Second-Order XSS where payloads are submitted at endpoint A
but render at completely different endpoint B.

Extracted from xss_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import asyncio
import html
import random
import re
import string
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx

from utils.logger import get_logger
from utils.scan_client import get_scan_client

from scanning.modules.xss.xss_base import XSSContext, XSSEvidence, WAFType, TrackedInput
from scanning.modules.xss.strategies.base import (
    BaseXSSStrategy,
    XSSStrategyContext,
    XSSStrategyResult,
)

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


# Common input endpoint patterns
SECOND_ORDER_INPUT_PATTERNS: list[tuple[str, list[str]]] = [
    (r"/profile", ["bio", "name", "description"]),
    (r"/api/profile", ["bio", "name"]),
    (r"/feedback", ["comment", "message"]),
    (r"/api/feedback", ["comment"]),
    (r"/api/Feedbacks", ["comment"]),  # Juice Shop
    (r"/comment", ["text", "body"]),
    (r"/api/comments", ["text", "content"]),
    (r"/message", ["text", "body", "content"]),
    (r"/api/messages", ["text", "content"]),
    (r"/settings", ["display_name", "bio"]),
    (r"/api/settings", ["displayName", "bio"]),
]

# Locations where stored data might render
RENDER_LOCATIONS: list[str] = [
    "/admin",
    "/administration",
    "/dashboard",
    "/users",
    "/activity",
    "/logs",
    "/audit",
    "/reports",
    "/export",
    "/profile",
    "/profiles",
    "/members",
    "/customers",
    "/comments",
    "/reviews",
    "/feedback",
    "/api/admin/users",
    "/api/admin/logs",
]


class SecondOrderStrategy(BaseXSSStrategy):
    """Second-order XSS detection strategy.

    Second-order XSS is missed ~60% of the time because:
    - Payload submitted at endpoint A
    - Renders at completely different endpoint B
    - Traditional scanners only check immediate reflection

    Strategy:
    1. Submit payloads to input endpoints (profile, comments)
    2. Check render locations (admin panels, reports)
    3. Detect if payloads appear in different contexts
    """

    def __init__(self) -> None:
        self._tracked_inputs: list[TrackedInput] = []
        self._markers_sent: set[str] = set()

    @property
    def name(self) -> str:
        return "second_order"

    async def test(self, ctx: XSSStrategyContext) -> XSSStrategyResult:
        """Test for second-order XSS.

        Strategy:
        1. Discover input endpoints from asset_data
        2. Submit payloads with unique markers
        3. Wait for data propagation
        4. Check render locations for our markers
        """
        evidence_list: list[XSSEvidence] = []
        attempts = 0
        errors: list[str] = []
        markers_submitted = 0
        markers_found = 0

        logger.info("[XSS-SecondOrder] Starting second-order detection")

        # Reset tracking state
        self._tracked_inputs = []
        self._markers_sent = set()

        # Phase 1: Discover input endpoints
        input_endpoints = self._discover_input_endpoints(ctx)
        if not input_endpoints:
            logger.debug("[XSS-SecondOrder] No input endpoints discovered")
            return XSSStrategyResult.not_found(0, ["No input endpoints found"])

        async with get_scan_client(timeout=ctx.timeout, follow_redirects=True) as client:
            # Phase 2: Submit payloads
            for endpoint, fields in input_endpoints[:20]:
                for field in fields[:3]:
                    marker = self._generate_marker()
                    payload = self._get_payload(marker)

                    tracked = await self._submit_payload(
                        client, ctx, endpoint, field, payload, marker
                    )
                    if tracked:
                        self._tracked_inputs.append(tracked)
                        self._markers_sent.add(marker)
                        markers_submitted += 1
                        attempts += 1

            # Phase 3: Wait for data propagation
            if self._tracked_inputs:
                await asyncio.sleep(1.0)

            # Phase 4: Check render locations
            render_locations = self._get_render_locations(ctx)
            for location in render_locations[:30]:
                try:
                    await ctx.acquire_rate_limit()
                    url = self._build_url(ctx, location)
                    attempts += 1

                    response = await client.get(
                        url,
                        headers=ctx.auth_headers,
                        timeout=10.0,
                    )

                    if response.status_code == 200:
                        for tracked in self._tracked_inputs:
                            if self._is_executable(response.text, tracked.payload_marker):
                                markers_found += 1
                                evidence_list.append(self._create_evidence(
                                    tracked, url, response.text, ctx
                                ))
                                logger.info(
                                    f"[XSS-SecondOrder] CRITICAL: marker {tracked.payload_marker} "
                                    f"from {tracked.submit_endpoint} renders at {url}"
                                )

                except asyncio.TimeoutError:
                    errors.append(f"Timeout: {location}")
                except Exception as e:
                    errors.append(f"Error {location}: {e}")

        logger.info(
            f"[XSS-SecondOrder] Submitted {markers_submitted} markers, "
            f"found {markers_found} vulnerabilities"
        )

        if evidence_list:
            return XSSStrategyResult.vulnerable(evidence_list, attempts)
        return XSSStrategyResult.not_found(attempts, errors)

    def _discover_input_endpoints(
        self,
        ctx: XSSStrategyContext,
    ) -> list[tuple[str, list[str]]]:
        """Discover endpoints where user input is accepted."""
        discovered = []

        # Check forms from asset_data
        if ctx.asset_data:
            for form in ctx.asset_data.get("forms", []):
                action = form.get("action", "")
                method = form.get("method", "").upper()

                if method in ["POST", "PUT", "PATCH"]:
                    inputs = form.get("inputs", [])
                    text_fields = [
                        inp.get("name")
                        for inp in inputs
                        if inp.get("type") in ["text", "textarea", "email", None, ""]
                        and inp.get("name")
                    ]
                    if text_fields:
                        discovered.append((action, text_fields))

            # Check endpoints against patterns
            for endpoint in ctx.asset_data.get("endpoints", []):
                for pattern, fields in SECOND_ORDER_INPUT_PATTERNS:
                    if re.search(pattern, endpoint, re.IGNORECASE):
                        discovered.append((endpoint, fields))
                        break

        # Default endpoints if none found
        if not discovered:
            discovered = [
                ("/profile", ["bio", "name", "description"]),
                ("/api/profile", ["bio", "name"]),
                ("/feedback", ["comment", "message"]),
                ("/api/feedback", ["comment"]),
                ("/api/Feedbacks", ["comment"]),
                ("/comment", ["text", "body"]),
            ]

        return discovered

    def _get_render_locations(self, ctx: XSSStrategyContext) -> list[str]:
        """Get locations where stored data might render."""
        locations = list(RENDER_LOCATIONS)

        # Add from asset_data
        if ctx.asset_data:
            for endpoint in ctx.asset_data.get("endpoints", []):
                render_keywords = [
                    "admin", "users", "list", "view", "report",
                    "export", "dashboard", "activity", "log", "audit",
                    "profile", "member", "customer", "comment", "review",
                ]
                if any(kw in endpoint.lower() for kw in render_keywords):
                    if endpoint not in locations:
                        locations.append(endpoint)

        return locations

    def _generate_marker(self) -> str:
        """Generate unique marker for tracking."""
        random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"SECONDORDER_{random_part}"

    def _get_payload(self, marker: str) -> str:
        """Get XSS payload with marker."""
        payloads = [
            f'<script>/*{marker}*/alert(1)</script>',
            f'<img src=x onerror="/*{marker}*/alert(1)">',
            f'" onfocus="/*{marker}*/alert(1)" autofocus="',
        ]
        return random.choice(payloads)

    async def _submit_payload(
        self,
        client: httpx.AsyncClient,
        ctx: XSSStrategyContext,
        endpoint: str,
        field: str,
        payload: str,
        marker: str,
    ) -> TrackedInput | None:
        """Submit payload and track it."""
        url = self._build_url(ctx, endpoint)

        try:
            await ctx.acquire_rate_limit()
            data = {field: payload}

            # Try POST with JSON
            response = await client.post(
                url,
                json=data,
                headers=ctx.auth_headers,
                timeout=10.0,
            )

            # Fallback to form-encoded
            if response.status_code >= 400:
                response = await client.post(
                    url,
                    data=data,
                    headers=ctx.auth_headers,
                    timeout=10.0,
                )

            contains_marker = marker in response.text

            tracked = TrackedInput(
                submit_endpoint=url,
                submit_method="POST",
                field_name=field,
                payload=payload,
                payload_marker=marker,
                timestamp=time.time(),
                response_status=response.status_code,
                response_contains_marker=contains_marker,
            )

            logger.debug(
                f"[XSS-SecondOrder] Submitted {marker} to {url}/{field} "
                f"(status={response.status_code})"
            )

            return tracked

        except Exception as e:
            logger.debug(f"[XSS-SecondOrder] Submit failed: {e}")
            return None

    def _build_url(self, ctx: XSSStrategyContext, path: str) -> str:
        """Build full URL from path."""
        if path.startswith("http"):
            return path

        base = ctx.base_url
        if path.startswith("/"):
            from urllib.parse import urlparse
            parsed = urlparse(base)
            return f"{parsed.scheme}://{parsed.netloc}{path}"
        return f"{base}/{path}"

    def _is_executable(self, content: str, marker: str) -> bool:
        """Check if marker is in executable XSS context."""
        if marker not in content:
            return False

        pos = content.find(marker)
        context_start = max(0, pos - 100)
        context_end = min(len(content), pos + len(marker) + 100)
        context = content[context_start:context_end]

        # Executable patterns
        patterns = [
            r'<script[^>]*>.*' + re.escape(marker),
            r'onerror\s*=\s*["\']?[^"\']*' + re.escape(marker),
            r'onload\s*=\s*["\']?[^"\']*' + re.escape(marker),
            r'onfocus\s*=\s*["\']?[^"\']*' + re.escape(marker),
        ]

        for pattern in patterns:
            if re.search(pattern, context, re.IGNORECASE | re.DOTALL):
                # Verify not HTML-encoded
                escaped = html.escape(marker)
                if escaped in context and marker not in context.replace(escaped, ""):
                    continue
                return True

        return False

    def _create_evidence(
        self,
        tracked: TrackedInput,
        render_url: str,
        content: str,
        ctx: XSSStrategyContext,
    ) -> XSSEvidence:
        """Create evidence for second-order XSS."""
        return XSSEvidence(
            payload=tracked.payload,
            context=XSSContext.HTML_TEXT,
            reflected_in="second_order_render",
            encoding_used="none",
            waf_bypassed=ctx.detected_waf is not None and ctx.detected_waf != WAFType.NONE,
            response_snippet=self._extract_snippet(tracked.payload_marker, content),
            confirmation_count=1,
            metadata={
                "second_order_xss": True,
                "submit_endpoint": tracked.submit_endpoint,
                "submit_field": tracked.field_name,
                "render_location": render_url,
                "marker": tracked.payload_marker,
                "severity": "CRITICAL",
            }
        )


__all__ = ["SecondOrderStrategy"]
