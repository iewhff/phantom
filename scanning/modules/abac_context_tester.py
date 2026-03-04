"""
PHANTOM AI - ABAC Context Tester

Tests Attribute-Based Access Control (ABAC) by systematically varying
request context attributes to find access control bypasses.

Tests for bypass via:
1. Time-based access control (business hours, time windows)
2. IP/Location-based restrictions (geo-blocking, IP whitelisting)
3. Device/User-Agent restrictions
4. Request origin/referer restrictions
5. Custom header requirements
6. Rate limit bypass via context variation

Works generically for ALL web applications by detecting and testing
context-dependent access decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.scan_client import get_scan_client
from utils.logger import get_logger
from scanning.scan_context import ScanContext

logger = get_logger(__name__)


# Common internal/admin IP ranges
INTERNAL_IPS = [
    "127.0.0.1",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "192.168.0.1",
    "localhost",
    "::1",
]

# IP spoofing headers to test
IP_SPOOF_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Client-IP",
    "Client-IP",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Fastly-Client-IP",
    "X-Cluster-Client-IP",
    "X-Azure-ClientIP",
    "X-Appengine-User-IP",
]

# User agents for different contexts
USER_AGENTS = {
    "desktop_chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "desktop_firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "mobile_android": "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "mobile_ios": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "bot_google": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "bot_bing": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "curl": "curl/8.4.0",
    "python": "python-requests/2.31.0",
    "admin_tool": "PHANTOM-AdminTool/1.0",
    "internal_service": "InternalServiceClient/1.0",
}

# Origin/Referer values for context testing
ORIGIN_VALUES = [
    "",  # Empty
    "null",
    "http://localhost",
    "http://127.0.0.1",
    "http://internal.local",
    "http://admin.internal",
    "file://",
]

# Time-based bypass headers
TIME_HEADERS = {
    "X-Request-Time": None,  # Will be set dynamically
    "X-Timestamp": None,
    "Date": None,
    "X-Date": None,
}


@dataclass
class ContextTestResult:
    """Result of a context test."""
    context_type: str
    header_name: str
    header_value: str
    baseline_status: int
    test_status: int
    baseline_size: int
    test_size: int
    access_granted: bool = False
    new_data_exposed: bool = False


class ABACContextTester(ScanModule):
    """
    Tests ABAC (Attribute-Based Access Control) by varying request context.

    Detects access control bypass via:
    - IP spoofing headers
    - User-Agent manipulation
    - Origin/Referer bypasses
    - Time-based access windows
    - Custom header injection
    """

    name = "abac_context"
    description = "Tests attribute-based access control via context manipulation"
    version = "1.0.0"
    author = "PHANTOM AI"
    tags = ["abac", "access_control", "context", "bypass"]

    # Standard safety - tests headers only, no destructive operations
    min_safety_level = "standard"

    def __init__(
        self,
        settings: Any = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self._base_url = ""
        self._auth_headers: dict[str, str] = {}
        self._discovered_endpoints: list[dict] = []

    async def scan(
        self,
        host: str,
        port: int | None = None,
        extra_params: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Main entry point for ABAC context testing."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(extra_params)
        self._auth_headers = self._ctx.auth_headers

        extra_params = extra_params or {}
        self._base_url = self._resolve_base_url(host, port)

        # Get auth context if available
        auth_context = extra_params.get("auth_context")
        if auth_context and hasattr(auth_context, "auth_headers"):
            self._auth_headers = auth_context.auth_headers

        # Get discovered endpoints
        endpoints = extra_params.get("endpoints", [])
        self._discovered_endpoints = [
            {"url": getattr(ep, "url", "") or getattr(ep, "path", ""),
             "method": getattr(ep, "method", "GET")}
            for ep in endpoints
        ]

        findings: list[Finding] = []

        # Phase 1: Test IP spoofing bypass
        ip_findings = await self._test_ip_spoofing()
        findings.extend(ip_findings)

        # Phase 2: Test User-Agent context bypass
        ua_findings = await self._test_user_agent_context()
        findings.extend(ua_findings)

        # Phase 3: Test Origin/Referer bypass
        origin_findings = await self._test_origin_bypass()
        findings.extend(origin_findings)

        # Phase 4: Test time-based access
        time_findings = await self._test_time_based_access()
        findings.extend(time_findings)

        # Phase 5: Test custom header requirements
        header_findings = await self._test_custom_headers()
        findings.extend(header_findings)

        return findings

    def _resolve_base_url(self, host: str, port: int | None) -> str:
        """Resolve base URL from host and port."""
        if host.startswith(("http://", "https://")):
            return host.rstrip("/")

        if port in (443, 8443):
            protocol = "https"
        else:
            protocol = "http"

        if port and port not in (80, 443):
            return f"{protocol}://{host}:{port}"
        return f"{protocol}://{host}"

    async def _get_baseline(self, url: str, method: str = "GET") -> tuple[int, int, str]:
        """Get baseline response without context manipulation."""
        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                if method.upper() == "POST":
                    resp = await client.post(url, json={}, headers=self._auth_headers)
                else:
                    resp = await client.get(url, headers=self._auth_headers)
                return resp.status_code, len(resp.content), resp.text
        except (httpx.RequestError, httpx.TimeoutException):
            return 0, 0, ""

    async def _test_ip_spoofing(self) -> list[Finding]:
        """Test for IP spoofing header bypass."""
        findings: list[Finding] = []

        # Find restricted endpoints (those returning 401/403)
        restricted_endpoints = await self._find_restricted_endpoints()

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                # FN-H4 FIX: Increased endpoint limit (was [:10])
                for ep_url in restricted_endpoints[:25]:
                    url = urljoin(self._base_url, ep_url)
                    baseline_status, baseline_size, _ = await self._get_baseline(url)

                    if baseline_status not in (401, 403):
                        continue

                    # Test each IP spoofing header with internal IPs
                    for header_name in IP_SPOOF_HEADERS:
                        for ip_value in INTERNAL_IPS:
                            test_headers = {**self._auth_headers, header_name: ip_value}

                            try:
                                resp = await client.get(url, headers=test_headers)

                                # Check if access was granted
                                if resp.status_code == 200 and baseline_status in (401, 403):
                                    findings.append(Finding(
                                        vuln_type=VulnType.AUTH_BYPASS,
                                        name="IP-Based Access Control Bypass",
                                        description=(
                                            f"The endpoint at `{url}` restricts access based on IP address, "
                                            f"but this can be bypassed using the `{header_name}` header.\n\n"
                                            f"**Header:** `{header_name}: {ip_value}`\n"
                                            f"**Baseline status:** {baseline_status}\n"
                                            f"**Bypass status:** {resp.status_code}\n\n"
                                            f"An attacker can spoof their IP address to bypass IP-based "
                                            f"access controls and access restricted resources."
                                        ),
                                        severity=Severity.HIGH,
                                        confidence_score=90.0,
                                        host=urlparse(url).netloc,
                                        endpoint=url,
                                        metadata={
                                            "header_name": header_name,
                                            "header_value": ip_value,
                                            "baseline_status": baseline_status,
                                            "bypass_status": resp.status_code,
                                            "context_type": "ip_spoofing",
                                        },
                                    ))
                                    break  # Found bypass for this endpoint
                            except (httpx.RequestError, httpx.TimeoutException):
                                pass

        except (httpx.RequestError, httpx.TimeoutException) as e:
            logger.debug(f"[ABAC] Error testing IP spoofing: {e}")

        return findings

    async def _test_user_agent_context(self) -> list[Finding]:
        """Test for User-Agent based access control bypass."""
        findings: list[Finding] = []

        # Find admin/internal endpoints
        admin_patterns = [r"admin", r"internal", r"management", r"debug", r"api/v\d+/internal"]
        admin_endpoints = [
            ep.get("url", "") for ep in self._discovered_endpoints
            if any(p in ep.get("url", "").lower() for p in ["admin", "internal", "manage", "debug"])
        ]

        # Also add common admin paths
        admin_endpoints.extend([
            "/admin", "/api/admin", "/internal", "/debug", "/management",
            "/_admin", "/api/internal", "/system", "/backend",
        ])

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                for ep_url in admin_endpoints[:25]:
                    url = urljoin(self._base_url, ep_url)
                    baseline_status, baseline_size, _ = await self._get_baseline(url)

                    if baseline_status not in (401, 403, 404):
                        continue

                    # Test each User-Agent
                    for ua_name, ua_value in USER_AGENTS.items():
                        test_headers = {**self._auth_headers, "User-Agent": ua_value}

                        try:
                            resp = await client.get(url, headers=test_headers)

                            # Check if access pattern changed
                            if resp.status_code == 200 and baseline_status in (401, 403, 404):
                                # Verify it's not just a different error page
                                if len(resp.content) > baseline_size + 100:
                                    findings.append(Finding(
                                        vuln_type=VulnType.AUTH_BYPASS,
                                        name="User-Agent Based Access Control Bypass",
                                        description=(
                                            f"The endpoint at `{url}` grants different access based on "
                                            f"User-Agent header.\n\n"
                                            f"**User-Agent type:** {ua_name}\n"
                                            f"**User-Agent:** `{ua_value[:50]}...`\n"
                                            f"**Baseline status:** {baseline_status}\n"
                                            f"**Bypass status:** {resp.status_code}\n\n"
                                            f"This could allow attackers to bypass access controls by "
                                            f"changing their User-Agent header."
                                        ),
                                        severity=Severity.MEDIUM,
                                        confidence_score=75.0,
                                        host=urlparse(url).netloc,
                                        endpoint=url,
                                        metadata={
                                            "ua_type": ua_name,
                                            "user_agent": ua_value,
                                            "baseline_status": baseline_status,
                                            "bypass_status": resp.status_code,
                                            "context_type": "user_agent",
                                        },
                                    ))
                                    break
                        except (httpx.RequestError, httpx.TimeoutException):
                            pass

        except (httpx.RequestError, httpx.TimeoutException) as e:
            logger.debug(f"[ABAC] Error testing User-Agent context: {e}")

        return findings

    async def _test_origin_bypass(self) -> list[Finding]:
        """Test for Origin/Referer based access control bypass."""
        findings: list[Finding] = []

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                for ep in self._discovered_endpoints[:30]:
                    url = urljoin(self._base_url, ep.get("url", ""))
                    method = ep.get("method", "GET").upper()

                    baseline_status, baseline_size, _ = await self._get_baseline(url, method)

                    if baseline_status not in (401, 403):
                        continue

                    # Test Origin bypass
                    for origin_value in ORIGIN_VALUES:
                        test_headers = {
                            **self._auth_headers,
                            "Origin": origin_value,
                            "Referer": f"{origin_value}/" if origin_value else "",
                        }

                        try:
                            if method == "POST":
                                resp = await client.post(url, json={}, headers=test_headers)
                            else:
                                resp = await client.get(url, headers=test_headers)

                            if resp.status_code == 200 and baseline_status in (401, 403):
                                findings.append(Finding(
                                    vuln_type=VulnType.AUTH_BYPASS,
                                    name="Origin-Based Access Control Bypass",
                                    description=(
                                        f"The endpoint at `{url}` can be accessed by manipulating "
                                        f"the Origin/Referer headers.\n\n"
                                        f"**Origin:** `{origin_value or '(empty)'}`\n"
                                        f"**Baseline status:** {baseline_status}\n"
                                        f"**Bypass status:** {resp.status_code}\n\n"
                                        f"This indicates weak origin validation that could be "
                                        f"exploited via CSRF or direct API access."
                                    ),
                                    severity=Severity.MEDIUM,
                                    confidence_score=80.0,
                                    host=urlparse(url).netloc,
                                    endpoint=url,
                                    metadata={
                                        "origin_value": origin_value,
                                        "baseline_status": baseline_status,
                                        "bypass_status": resp.status_code,
                                        "context_type": "origin",
                                    },
                                ))
                                break
                        except (httpx.RequestError, httpx.TimeoutException):
                            pass

        except (httpx.RequestError, httpx.TimeoutException) as e:
            logger.debug(f"[ABAC] Error testing Origin bypass: {e}")

        return findings

    async def _test_time_based_access(self) -> list[Finding]:
        """Test for time-based access control issues."""
        findings: list[Finding] = []

        # Test time manipulation headers
        test_times = [
            datetime.utcnow() - timedelta(days=30),  # Past
            datetime.utcnow() + timedelta(days=30),  # Future
            datetime.utcnow().replace(hour=3),       # Off-hours
            datetime.utcnow().replace(hour=14),      # Business hours
        ]

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                for ep in self._discovered_endpoints[:25]:
                    url = urljoin(self._base_url, ep.get("url", ""))
                    baseline_status, baseline_size, _ = await self._get_baseline(url)

                    if baseline_status not in (401, 403):
                        continue

                    for test_time in test_times:
                        time_str = test_time.strftime("%a, %d %b %Y %H:%M:%S GMT")

                        for header_name in ["Date", "X-Request-Time", "X-Timestamp"]:
                            test_headers = {**self._auth_headers, header_name: time_str}

                            try:
                                resp = await client.get(url, headers=test_headers)

                                if resp.status_code == 200 and baseline_status in (401, 403):
                                    findings.append(Finding(
                                        vuln_type=VulnType.AUTH_BYPASS,
                                        name="Time-Based Access Control Bypass",
                                        description=(
                                            f"The endpoint at `{url}` may be using time-based access "
                                            f"control that can be bypassed via header manipulation.\n\n"
                                            f"**Header:** `{header_name}: {time_str}`\n"
                                            f"**Baseline status:** {baseline_status}\n"
                                            f"**Bypass status:** {resp.status_code}\n\n"
                                            f"If the application trusts client-provided timestamps, "
                                            f"attackers can bypass time-restricted access."
                                        ),
                                        severity=Severity.MEDIUM,
                                        confidence_score=70.0,
                                        host=urlparse(url).netloc,
                                        endpoint=url,
                                        metadata={
                                            "header_name": header_name,
                                            "time_value": time_str,
                                            "context_type": "time",
                                        },
                                    ))
                                    break
                            except (httpx.RequestError, httpx.TimeoutException):
                                pass

        except (httpx.RequestError, httpx.TimeoutException) as e:
            logger.debug(f"[ABAC] Error testing time-based access: {e}")

        return findings

    async def _test_custom_headers(self) -> list[Finding]:
        """Test for custom header-based access control."""
        findings: list[Finding]= []

        # Common internal/admin headers
        internal_headers = {
            "X-Internal-Request": "true",
            "X-Admin-Request": "true",
            "X-Bypass-Auth": "true",
            "X-Debug": "true",
            "X-Test-Mode": "true",
            "X-Backend-Request": "true",
            "X-Service-Request": "true",
            "X-Skip-Auth": "true",
            "X-Trust": "true",
            "X-Internal": "1",
            "X-Local-Request": "true",
            "X-Authenticated": "true",
            "X-API-Internal": "true",
        }

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                for ep in self._discovered_endpoints[:30]:
                    url = urljoin(self._base_url, ep.get("url", ""))
                    baseline_status, baseline_size, _ = await self._get_baseline(url)

                    if baseline_status not in (401, 403):
                        continue

                    for header_name, header_value in internal_headers.items():
                        test_headers = {**self._auth_headers, header_name: header_value}

                        try:
                            resp = await client.get(url, headers=test_headers)

                            if resp.status_code == 200 and baseline_status in (401, 403):
                                findings.append(Finding(
                                    vuln_type=VulnType.AUTH_BYPASS,
                                    name="Custom Header Access Control Bypass",
                                    description=(
                                        f"The endpoint at `{url}` grants access when a custom "
                                        f"internal header is provided.\n\n"
                                        f"**Header:** `{header_name}: {header_value}`\n"
                                        f"**Baseline status:** {baseline_status}\n"
                                        f"**Bypass status:** {resp.status_code}\n\n"
                                        f"This indicates that internal headers are trusted without "
                                        f"proper validation, allowing attackers to bypass access controls."
                                    ),
                                    severity=Severity.CRITICAL,
                                    confidence_score=95.0,
                                    host=urlparse(url).netloc,
                                    endpoint=url,
                                    metadata={
                                        "header_name": header_name,
                                        "header_value": header_value,
                                        "baseline_status": baseline_status,
                                        "bypass_status": resp.status_code,
                                        "context_type": "custom_header",
                                    },
                                ))
                                break
                        except (httpx.RequestError, httpx.TimeoutException):
                            pass

        except (httpx.RequestError, httpx.TimeoutException) as e:
            logger.debug(f"[ABAC] Error testing custom headers: {e}")

        return findings

    async def _find_restricted_endpoints(self) -> list[str]:
        """Find endpoints that return 401/403."""
        restricted = []

        try:
            async with get_scan_client(verify_ssl=False, timeout=5.0) as client:
                # Check discovered endpoints
                for ep in self._discovered_endpoints[:30]:
                    url = urljoin(self._base_url, ep.get("url", ""))
                    try:
                        resp = await client.get(url, headers=self._auth_headers)
                        if resp.status_code in (401, 403):
                            restricted.append(ep.get("url", ""))
                    except (httpx.RequestError, httpx.TimeoutException):
                        pass

                # Also check common admin/internal paths
                common_restricted = [
                    "/admin", "/api/admin", "/internal", "/debug",
                    "/management", "/metrics", "/actuator", "/health",
                    "/api/internal", "/api/v1/admin", "/system",
                ]
                for path in common_restricted:
                    url = urljoin(self._base_url, path)
                    try:
                        resp = await client.get(url, headers=self._auth_headers)
                        if resp.status_code in (401, 403):
                            restricted.append(path)
                    except (httpx.RequestError, httpx.TimeoutException):
                        pass

        except (httpx.RequestError, httpx.TimeoutException):
            pass

        return list(set(restricted))
