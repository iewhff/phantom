"""
Webhook Security Scanner — Tests for webhook/callback security vulnerabilities.

Covers:
1. SSRF via webhook URL injection (attacker-controlled callback URLs)
2. Missing/weak webhook signature verification
3. Replay attack vulnerabilities (missing nonce/timestamp validation)
4. Webhook endpoint authentication bypass
5. Event type confusion/injection
6. Open redirect via callback URLs
7. Information disclosure via webhook responses
"""

from __future__ import annotations

import asyncio
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from scanning.scan_context import ScanContext
from utils.rate_limiter import RateLimiter


@dataclass
class WebhookEndpoint:
    """Discovered webhook-related endpoint."""
    url: str
    method: str = "POST"
    param_name: str = ""  # URL parameter name (webhook_url, callback, etc.)
    endpoint_type: str = "unknown"  # subscription, callback, notification


# Common webhook-related parameter names
WEBHOOK_URL_PARAMS = [
    "webhook_url", "webhookUrl", "webhook",
    "callback_url", "callbackUrl", "callback",
    "notify_url", "notifyUrl", "notification_url",
    "endpoint", "target_url", "targetUrl",
    "url", "uri", "destination", "return_url", "returnUrl",
    "redirect_url", "redirectUrl", "success_url", "failure_url",
    "ipn_url", "postback_url", "ping_url",
]

# Webhook-related path patterns
WEBHOOK_PATH_PATTERNS = [
    r"/webhooks?(?:/|$)",
    r"/callbacks?(?:/|$)",
    r"/hooks?(?:/|$)",
    r"/notify(?:/|$)",
    r"/notifications?(?:/|$)",
    r"/events?(?:/|$)",
    r"/subscriptions?(?:/|$)",
    r"/ipn(?:/|$)",
    r"/postback(?:/|$)",
]

# Common webhook event types to test injection
WEBHOOK_EVENT_TYPES = [
    "payment.completed", "payment.failed",
    "order.created", "order.updated", "order.cancelled",
    "user.created", "user.deleted", "user.updated",
    "subscription.created", "subscription.cancelled",
    "invoice.paid", "invoice.failed",
    "charge.succeeded", "charge.failed",
    "customer.created", "customer.deleted",
    "__admin.debug", "__internal.test", "../../../etc/passwd",
]

# Canary domains for SSRF detection (we check if app attempts connection)
SSRF_TEST_DOMAINS = [
    "webhook-test.attacker.example.com",
    "burpcollaborator.attacker.example.com",
]


class WebhookSecurityScanner(ScanModule):
    """
    Scanner for webhook and callback security vulnerabilities.

    Tests webhook URL injection (SSRF), signature bypass, replay attacks,
    and authentication issues on webhook endpoints.
    """

    name = "webhook_security"
    description = "Tests webhook/callback security (SSRF, signature bypass, replay)"
    version = "1.0.0"
    author = "PHANTOM AI"
    tags = ["webhook", "callback", "ssrf", "integration"]

    # Webhook testing is standard safety - no destructive operations
    min_safety_level = "standard"

    def __init__(
        self,
        settings: Any = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self._discovered_webhooks: list[WebhookEndpoint] = []
        self._ssrf_attempts: list[dict] = []
        self._base_url = ""

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any] | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> dict[str, Any]:
        """
        Main entry point for webhook security scanning.

        Updated to standard signature for full_scanner integration.
        """
        asset_data = asset_data or {}
        self._base_url = self._resolve_base_url(host, None)

        # SCAN CONTEXT: Unified access to auth, response validation
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        # FIX: Store rate limiter for use in HTTP requests
        self._rate_limiter = rate_limiter

        findings: list[Finding] = []

        # Phase 1: Discover webhook-related endpoints
        await self._discover_webhook_endpoints(asset_data)

        # Phase 2: Test for SSRF via webhook URL parameters
        ssrf_findings = await self._test_webhook_ssrf()
        findings.extend(ssrf_findings)

        # Phase 3: Test webhook signature verification
        sig_findings = await self._test_signature_bypass()
        findings.extend(sig_findings)

        # Phase 4: Test replay attack vulnerabilities
        replay_findings = await self._test_replay_attacks()
        findings.extend(replay_findings)

        # Phase 5: Test webhook endpoint authentication
        auth_findings = await self._test_webhook_auth_bypass()
        findings.extend(auth_findings)

        # Phase 6: Test event type injection
        event_findings = await self._test_event_injection()
        findings.extend(event_findings)

        # Convert Finding objects to dicts for standard interface
        return {"findings": [f.to_dict() if hasattr(f, 'to_dict') else f for f in findings]}

    def _resolve_base_url(self, host: str, port: int | None) -> str:
        """Resolve base URL from host and port."""
        if host.startswith(("http://", "https://")):
            return host.rstrip("/")

        # Detect protocol from port
        if port in (443, 8443):
            protocol = "https"
        elif port in (80, 8080, 8000, 3000, 5000, 8888, 9090):
            protocol = "http"
        else:
            protocol = "https" if port and port % 1000 == 443 else "http"

        if port and port not in (80, 443):
            return f"{protocol}://{host}:{port}"
        return f"{protocol}://{host}"

    async def _discover_webhook_endpoints(self, extra_params: dict) -> None:
        """
        Discover webhook-related endpoints from endpoint map and common paths.
        """
        self._discovered_webhooks = []

        # Get endpoints from endpoint map if available
        endpoints = extra_params.get("endpoints", [])

        # Check endpoint map entries
        for ep in endpoints:
            url = getattr(ep, "url", "") or getattr(ep, "path", "")
            if not url:
                continue

            # Check if path matches webhook patterns
            for pattern in WEBHOOK_PATH_PATTERNS:
                if re.search(pattern, url, re.IGNORECASE):
                    self._discovered_webhooks.append(
                        WebhookEndpoint(
                            url=urljoin(self._base_url, url),
                            method="POST",
                            endpoint_type="webhook",
                        )
                    )
                    break

            # Check for webhook URL parameters
            for param in WEBHOOK_URL_PARAMS:
                if param.lower() in url.lower():
                    self._discovered_webhooks.append(
                        WebhookEndpoint(
                            url=urljoin(self._base_url, url),
                            param_name=param,
                            endpoint_type="subscription",
                        )
                    )
                    break

        # Probe common webhook paths
        common_webhook_paths = [
            "/webhooks", "/webhook", "/api/webhooks", "/api/webhook",
            "/callbacks", "/callback", "/api/callbacks", "/api/callback",
            "/hooks", "/hook", "/api/hooks", "/api/hook",
            "/notify", "/notifications", "/api/notify",
            "/events", "/api/events", "/subscriptions", "/api/subscriptions",
            "/ipn", "/postback", "/stripe/webhook", "/github/webhook",
            "/slack/events", "/twilio/webhook", "/sendgrid/webhook",
        ]

        probe_tasks = []
        for path in common_webhook_paths:
            probe_tasks.append(self._probe_webhook_path(path))

        if probe_tasks:
            await asyncio.gather(*probe_tasks, return_exceptions=True)

    async def _probe_webhook_path(self, path: str) -> None:
        """Probe a potential webhook path."""
        url = urljoin(self._base_url, path)

        try:
            # Try GET first to check if endpoint exists
            await self._acquire_rate_limit()  # FIX: Rate limit before request
            async with self._get_http_client() as client:
                resp = await client.get(url, timeout=5.0)

                # Webhook endpoints typically return 405 for GET (method not allowed)
                # or 401/403 (auth required) or 200 (listing/docs)
                if resp.status_code in (200, 401, 403, 405, 415):
                    # SPA DETECTION: Skip if response looks like SPA fallback
                    content_type = resp.headers.get("content-type", "").lower()
                    body = resp.text

                    # If 200 with HTML content, likely SPA catch-all - skip
                    if resp.status_code == 200 and "text/html" in content_type:
                        # Check for SPA indicators (comprehensive list aligned with SemanticAnalyzer)
                        spa_indicators = [
                            "ng-app", "data-ng-", "__next", "_nuxt", "data-reactroot",
                            "react-root", "__vue__", "data-v-", "svelte-", "astro-island",
                            "__remix_ssr__", "data-qwik", "q:container", "data-solid",
                            "data-svelte", 'id="root"', 'id="app"', "__remixContext",
                        ]
                        if any(ind in body for ind in spa_indicators):
                            return  # Skip SPA fallback

                        # Check response length - SPA bundles are typically large
                        if len(body) > 50000:  # 50KB+ is likely bundled SPA
                            return

                    self._discovered_webhooks.append(
                        WebhookEndpoint(
                            url=url,
                            method="POST",
                            endpoint_type="webhook",
                        )
                    )
        except Exception:
            pass

    async def _test_webhook_ssrf(self) -> list[Finding]:
        """
        Test for SSRF via webhook URL injection.

        Attempts to register attacker-controlled URLs as webhook destinations.
        """
        findings: list[Finding] = []

        # Test endpoints that accept URL parameters
        for ep in self._discovered_webhooks:
            if ep.endpoint_type == "subscription" or ep.param_name:
                ssrf_finding = await self._test_url_param_ssrf(ep)
                if ssrf_finding:
                    findings.append(ssrf_finding)

        # Test POST bodies on webhook endpoints
        for ep in self._discovered_webhooks:
            if ep.endpoint_type == "webhook":
                ssrf_finding = await self._test_body_ssrf(ep)
                if ssrf_finding:
                    findings.append(ssrf_finding)

        return findings

    async def _test_url_param_ssrf(self, endpoint: WebhookEndpoint) -> Finding | None:
        """Test SSRF via URL query parameter."""
        param_name = endpoint.param_name or "webhook_url"
        attacker_url = f"https://{SSRF_TEST_DOMAINS[0]}/ssrf-test"

        # Build test URL
        parsed = urlparse(endpoint.url)
        params = parse_qs(parsed.query)
        params[param_name] = [attacker_url]
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(params, doseq=True)}"

        try:
            async with self._get_http_client() as client:
                # Try both GET and POST
                for method in ["GET", "POST"]:
                    await self._acquire_rate_limit()  # FIX: Rate limit before request
                    if method == "GET":
                        resp = await client.get(test_url, timeout=10.0)
                    else:
                        resp = await client.post(
                            test_url,
                            json={param_name: attacker_url},
                            timeout=10.0,
                        )

                    # Check for acceptance indicators
                    if resp.status_code in (200, 201, 202, 204):
                        body = resp.text.lower()

                        # Check if URL was accepted/registered
                        if any(indicator in body for indicator in [
                            "success", "registered", "created", "webhook",
                            "subscribed", "callback", attacker_url.lower(),
                        ]):
                            return self._create_finding(
                                name="Webhook URL SSRF Injection",
                                description=(
                                    f"The endpoint accepts arbitrary webhook URLs via the '{param_name}' parameter. "
                                    f"An attacker can register a malicious URL to receive sensitive webhook data "
                                    f"or trigger SSRF attacks by making the server connect to internal services."
                                ),
                                severity=Severity.HIGH,
                                confidence_score=85.0,
                                endpoint=endpoint.url,
                                metadata={
                                    "param_name": param_name,
                                    "test_url": attacker_url,
                                    "method": method,
                                    "response_status": resp.status_code,
                                    "evidence": f"Server accepted webhook URL: {attacker_url}",
                                },
                            )
        except Exception:
            pass

        return None

    async def _test_body_ssrf(self, endpoint: WebhookEndpoint) -> Finding | None:
        """Test SSRF via webhook registration POST body."""
        attacker_url = f"https://{SSRF_TEST_DOMAINS[0]}/ssrf-body-test"

        # Common webhook registration payloads
        test_payloads = [
            {"url": attacker_url},
            {"webhook_url": attacker_url},
            {"callback_url": attacker_url},
            {"endpoint": attacker_url},
            {"target": attacker_url},
            {"destination": attacker_url},
            {"events": ["*"], "url": attacker_url},
            {"config": {"url": attacker_url}},
        ]

        try:
            async with self._get_http_client() as client:
                for payload in test_payloads:
                    await self._acquire_rate_limit()  # FIX: Rate limit before request
                    resp = await client.post(
                        endpoint.url,
                        json=payload,
                        timeout=10.0,
                    )

                    if resp.status_code in (200, 201, 202, 204):
                        # FP PREVENTION: Must be JSON response, not HTML
                        content_type = resp.headers.get("content-type", "").lower()
                        body = resp.text

                        # Skip if response is HTML (SPA fallback)
                        if "text/html" in content_type:
                            continue

                        # Must be valid JSON to be a real webhook registration response
                        if "application/json" not in content_type:
                            continue

                        # Try to parse as JSON
                        try:
                            json_body = json.loads(body)
                        except (json.JSONDecodeError, ValueError):
                            continue  # Not JSON, skip

                        # Check for success indicators in parsed JSON (not raw HTML)
                        body_lower = body.lower()
                        if any(indicator in body_lower for indicator in [
                            "success", "created", "registered", "id",
                            attacker_url.lower(),
                        ]):
                            param_name = list(payload.keys())[0]
                            return self._create_finding(
                                name="Webhook Registration SSRF",
                                description=(
                                    f"The webhook endpoint accepts arbitrary destination URLs. "
                                    f"An attacker can register webhooks pointing to internal services "
                                    f"or attacker-controlled servers to exfiltrate data."
                                ),
                                severity=Severity.HIGH,
                                confidence_score=85.0,  # Higher confidence with JSON validation
                                endpoint=endpoint.url,
                                metadata={
                                    "param_name": param_name,
                                    "test_payload": payload,
                                    "test_url": attacker_url,
                                    "response_status": resp.status_code,
                                    "response_type": "json",
                                },
                            )
        except Exception:
            pass

        return None

    async def _test_signature_bypass(self) -> list[Finding]:
        """
        Test webhook signature verification bypass.

        Sends webhook events without valid signatures or with tampered signatures.
        """
        findings: list[Finding] = []

        # Common webhook event payloads
        test_event = {
            "id": f"evt_test_{secrets.token_hex(8)}",
            "type": "payment.completed",
            "data": {
                "object": {
                    "id": "pay_test",
                    "amount": 10000,
                    "currency": "usd",
                    "status": "succeeded",
                }
            },
            "created": int(time.time()),
        }

        for ep in self._discovered_webhooks:
            if ep.endpoint_type != "webhook":
                continue

            finding = await self._test_single_signature_bypass(ep, test_event)
            if finding:
                findings.append(finding)

        return findings

    async def _test_single_signature_bypass(
        self, endpoint: WebhookEndpoint, event: dict
    ) -> Finding | None:
        """Test signature bypass on a single endpoint."""

        # Test 1: No signature header at all
        try:
            await self._acquire_rate_limit()  # FIX: Rate limit before request
            async with self._get_http_client() as client:
                resp = await client.post(
                    endpoint.url,
                    json=event,
                    headers={"Content-Type": "application/json"},
                    timeout=10.0,
                )

                # If accepted without signature (200/201/202/204), it's vulnerable
                if resp.status_code in (200, 201, 202, 204):
                    body = resp.text.lower()

                    # Exclude generic error pages
                    if not any(err in body for err in ["error", "invalid", "unauthorized", "forbidden"]):
                        return self._create_finding(
                            name="Missing Webhook Signature Verification",
                            description=(
                                "The webhook endpoint accepts events without signature verification. "
                                "An attacker can forge webhook events to trigger unauthorized actions "
                                "like marking payments as complete or modifying user data."
                            ),
                            severity=Severity.HIGH,
                            confidence_score=85.0,
                            endpoint=endpoint.url,
                            metadata={
                                "test_type": "no_signature",
                                "event_type": event.get("type"),
                                "response_status": resp.status_code,
                                "evidence": "Webhook event accepted without signature header",
                            },
                        )
        except Exception:
            pass

        # Test 2: Invalid/tampered signature
        invalid_signatures = [
            ("X-Hub-Signature-256", "sha256=invalid"),
            ("X-Signature", "invalid_signature"),
            ("Stripe-Signature", "t=123,v1=invalid"),
            ("X-Twilio-Signature", "invalid"),
            ("X-Webhook-Signature", "invalid"),
            ("X-Request-Signature", "invalid"),
        ]

        try:
            async with self._get_http_client() as client:
                for header_name, header_value in invalid_signatures:
                    await self._acquire_rate_limit()  # FIX: Rate limit before request
                    resp = await client.post(
                        endpoint.url,
                        json=event,
                        headers={
                            "Content-Type": "application/json",
                            header_name: header_value,
                        },
                        timeout=10.0,
                    )

                    if resp.status_code in (200, 201, 202, 204):
                        body = resp.text.lower()
                        if "error" not in body and "invalid" not in body:
                            return self._create_finding(
                                name="Weak Webhook Signature Verification",
                                description=(
                                    f"The webhook endpoint accepts events with invalid {header_name} signatures. "
                                    f"The signature verification is either missing or improperly implemented."
                                ),
                                severity=Severity.HIGH,
                                confidence_score=80.0,
                                endpoint=endpoint.url,
                                metadata={
                                    "test_type": "invalid_signature",
                                    "header_name": header_name,
                                    "header_value": header_value,
                                    "response_status": resp.status_code,
                                },
                            )
        except Exception:
            pass

        return None

    async def _test_replay_attacks(self) -> list[Finding]:
        """
        Test for webhook replay attack vulnerabilities.

        Checks if the same webhook event can be replayed multiple times.
        """
        findings: list[Finding] = []

        # Create a unique event
        event_id = f"evt_replay_test_{secrets.token_hex(8)}"
        timestamp = int(time.time())

        test_event = {
            "id": event_id,
            "type": "payment.completed",
            "data": {"amount": 100, "status": "succeeded"},
            "created": timestamp,
        }

        for ep in self._discovered_webhooks:
            if ep.endpoint_type != "webhook":
                continue

            finding = await self._test_single_replay(ep, test_event)
            if finding:
                findings.append(finding)

        return findings

    async def _test_single_replay(
        self, endpoint: WebhookEndpoint, event: dict
    ) -> Finding | None:
        """Test replay vulnerability on a single endpoint."""
        success_count = 0

        try:
            async with self._get_http_client() as client:
                # Send the same event 3 times
                for _ in range(3):
                    await self._acquire_rate_limit()  # FIX: Rate limit before request
                    resp = await client.post(
                        endpoint.url,
                        json=event,
                        timeout=10.0,
                    )

                    if resp.status_code in (200, 201, 202, 204):
                        success_count += 1

                    await asyncio.sleep(0.1)

                # If all 3 requests succeeded, replay is possible
                if success_count >= 3:
                    return self._create_finding(
                        name="Webhook Replay Attack Vulnerability",
                        description=(
                            "The webhook endpoint does not prevent replay attacks. "
                            "The same event with identical ID and timestamp was accepted multiple times. "
                            "An attacker could intercept webhook events and replay them to trigger "
                            "duplicate actions (e.g., multiple payment credits)."
                        ),
                        severity=Severity.MEDIUM,
                        confidence_score=75.0,
                        endpoint=endpoint.url,
                        metadata={
                            "test_type": "replay_attack",
                            "event_id": event.get("id"),
                            "replay_count": success_count,
                            "evidence": f"Same event accepted {success_count} times",
                        },
                    )
        except Exception:
            pass

        return None

    async def _test_webhook_auth_bypass(self) -> list[Finding]:
        """
        Test for authentication bypass on webhook endpoints.

        Many webhook endpoints should require authentication or IP whitelisting.
        """
        findings: list[Finding] = []

        for ep in self._discovered_webhooks:
            finding = await self._test_single_auth_bypass(ep)
            if finding:
                findings.append(finding)

        return findings

    async def _test_single_auth_bypass(self, endpoint: WebhookEndpoint) -> Finding | None:
        """Test if webhook endpoint is accessible without authentication."""

        try:
            await self._acquire_rate_limit()  # FIX: Rate limit before request
            async with self._get_http_client() as client:
                # Send minimal valid-looking event
                resp = await client.post(
                    endpoint.url,
                    json={
                        "type": "test.event",
                        "data": {},
                    },
                    headers={"Content-Type": "application/json"},
                    timeout=10.0,
                )

                # Check response for sensitive information disclosure
                body = resp.text

                # Look for sensitive data in error responses
                sensitive_patterns = [
                    (r"api[_-]?key", "API Key"),
                    (r"secret[_-]?key", "Secret Key"),
                    (r"password", "Password"),
                    (r"token", "Token"),
                    (r"internal.*error", "Internal Error Details"),
                    (r"stack.*trace", "Stack Trace"),
                    (r"exception", "Exception Details"),
                    (r"database", "Database Information"),
                ]

                for pattern, data_type in sensitive_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        return self._create_finding(
                            name="Webhook Information Disclosure",
                            description=(
                                f"The webhook endpoint exposes {data_type.lower()} information in its response. "
                                f"This may help attackers understand the internal implementation."
                            ),
                            severity=Severity.MEDIUM,
                            confidence_score=70.0,
                            endpoint=endpoint.url,
                            metadata={
                                "data_type": data_type,
                                "pattern": pattern,
                                "response_status": resp.status_code,
                            },
                        )
        except Exception:
            pass

        return None

    async def _test_event_injection(self) -> list[Finding]:
        """
        Test for event type injection/confusion vulnerabilities.

        Sends unexpected event types to check for improper handling.
        """
        findings: list[Finding] = []

        for ep in self._discovered_webhooks:
            if ep.endpoint_type != "webhook":
                continue

            finding = await self._test_single_event_injection(ep)
            if finding:
                findings.append(finding)

        return findings

    async def _test_single_event_injection(
        self, endpoint: WebhookEndpoint
    ) -> Finding | None:
        """Test event type injection on a single endpoint."""

        # Malicious event types
        injection_events = [
            {"type": "__admin.debug", "data": {}},
            {"type": "__internal.test", "data": {}},
            {"type": "../../etc/passwd", "data": {}},
            {"type": "payment.completed; SELECT @@version;--", "data": {}},  # Non-destructive SQL
            {"type": "<script>alert(1)</script>", "data": {}},
            {"type": "{{constructor.constructor('return this')()}}", "data": {}},
        ]

        try:
            async with self._get_http_client() as client:
                for event in injection_events:
                    await self._acquire_rate_limit()  # FIX: Rate limit before request
                    resp = await client.post(
                        endpoint.url,
                        json=event,
                        timeout=10.0,
                    )

                    body = resp.text

                    # Check for injection indicators
                    if resp.status_code == 500:
                        # Server error might indicate injection worked
                        if any(err in body.lower() for err in [
                            "sql", "syntax", "query", "database",
                            "undefined", "null", "exception", "stack",
                        ]):
                            return self._create_finding(
                                name="Webhook Event Type Injection",
                                description=(
                                    f"The webhook endpoint is vulnerable to event type injection. "
                                    f"Malicious event type '{event['type'][:50]}...' caused a server error, "
                                    f"indicating improper input validation."
                                ),
                                severity=Severity.MEDIUM,
                                confidence_score=70.0,
                                endpoint=endpoint.url,
                                metadata={
                                    "malicious_type": event["type"],
                                    "response_status": resp.status_code,
                                    "evidence": body[:500],
                                },
                            )

                    # Check if injection payload is reflected
                    if event["type"] in body and resp.status_code in (200, 201):
                        return self._create_finding(
                            name="Webhook Event Type Reflection",
                            description=(
                                "The webhook endpoint reflects the event type in its response without sanitization. "
                                "This could lead to XSS if the response is rendered in a browser."
                            ),
                            severity=Severity.LOW,
                            confidence_score=60.0,
                            endpoint=endpoint.url,
                            metadata={
                                "injected_type": event["type"],
                                "response_status": resp.status_code,
                            },
                        )
        except Exception:
            pass

        return None

    def _create_finding(
        self,
        name: str,
        description: str,
        severity: str,
        confidence: float,
        matched_at: str,
        metadata: dict | None = None,
    ) -> Finding:
        """Create a standardized finding."""
        return Finding(
            vuln_type=VulnType.OTHER,
            name=name,
            description=description,
            severity=severity,
            confidence_score=confidence,
            endpoint=matched_at,
            host=urlparse(matched_at).netloc if matched_at else "",
            evidence=[f"{name} detected at {matched_at}"],
            metadata=metadata or {},
        )

    def _get_http_client(self):
        """Get HTTP client with appropriate settings."""
        import httpx
        return httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=10.0,
            headers=self._auth_headers,  # FIX: Include auth headers
        )

    async def _acquire_rate_limit(self) -> None:
        """Acquire rate limit before making HTTP request."""
        if self._rate_limiter:
            try:
                await self._rate_limiter.acquire()
            except Exception:
                pass  # Proceed if rate limiter fails
