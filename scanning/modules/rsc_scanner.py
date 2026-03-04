"""
React Server Components (RSC) Security Scanner v1.0

Detects security vulnerabilities in Next.js 13+/14+ Server Components
and Server Actions. RSC introduces new attack surfaces unique to the
server-first React rendering model.

Vulnerability Types Covered:
1. Server Action CSRF - Actions without CSRF protection
2. Server Action Auth Bypass - Actions accessible without auth
3. Action ID Tampering - Modified action identifiers
4. Mass Assignment - Extra fields in formData
5. RSC Stream Data Leakage - Sensitive data in RSC payloads
6. Server-Only Data Exposure - Client-side data leak
7. Parallel Route Exploitation - Unauthorized route access
8. RSC Serialization Injection - Injection via RSC format

Bug Bounty Value: $2,000 - $10,000 for critical RSC vulns
Reference: Next.js Server Actions are new attack surfaces in 2024-2026

CWE Coverage:
- CWE-352: Cross-Site Request Forgery (CSRF)
- CWE-284: Improper Access Control
- CWE-200: Exposure of Sensitive Information
- CWE-915: Mass Assignment
- CWE-502: Deserialization of Untrusted Data

Author: PetNTester AI
Version: 1.0.0 (2026-02-19)
"""

from __future__ import annotations

import re
import hashlib
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import httpx

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.http_client import create_protected_client, get_configured_ssl_verify
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)

# Version
RSC_SCANNER_VERSION = "1.0.0"


class RSCVulnType(Enum):
    """Types of RSC/Server Action vulnerabilities."""
    CSRF_BYPASS = auto()           # Server Action without CSRF protection
    AUTH_BYPASS = auto()           # Action accessible without auth
    ACTION_ID_TAMPERING = auto()   # Manipulated action identifiers
    MASS_ASSIGNMENT = auto()       # Extra fields accepted in formData
    DATA_LEAKAGE = auto()          # Sensitive data in RSC stream
    SERVER_ONLY_EXPOSURE = auto()  # Server-only data on client
    PARALLEL_ROUTE_EXPLOIT = auto()  # Unauthorized parallel route
    SERIALIZATION_INJECTION = auto()  # Injection via RSC format


class NextJSRouter(Enum):
    """Next.js router types."""
    APP_ROUTER = "app"       # app/ directory (Next.js 13+)
    PAGES_ROUTER = "pages"   # pages/ directory (legacy)
    UNKNOWN = "unknown"


@dataclass
class RSCEndpoint:
    """Represents a discovered RSC-enabled endpoint."""
    url: str
    router_type: NextJSRouter
    nextjs_version: str = "unknown"
    has_server_actions: bool = False
    action_ids: list[str] = field(default_factory=list)
    parallel_routes: list[str] = field(default_factory=list)


@dataclass
class RSCTestResult:
    """Result of an RSC security test."""
    vulnerable: bool
    vuln_type: RSCVulnType
    confidence: int  # 0-100
    payload: str
    response_data: str = ""
    evidence: list[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    data_leaked: bool = False


class RSCScanner(ScanModule):
    """
    React Server Components Security Scanner.

    Detects vulnerabilities in Next.js 13+/14+ applications:
    - Server Action security issues
    - RSC stream data leakage
    - Parallel route exploitation
    - Mass assignment in formData

    Focus: Server Components introduce server-first rendering with
    unique security implications not found in traditional React SPAs.
    """

    name = "rsc_scanner"
    version = RSC_SCANNER_VERSION

    # Next.js detection patterns
    NEXTJS_INDICATORS = {
        "headers": [
            ("x-nextjs-cache", r".*"),
            ("x-nextjs-matched-path", r".*"),
            ("x-middleware-rewrite", r".*"),
            ("x-middleware-redirect", r".*"),
            ("x-vercel-cache", r".*"),
        ],
        "body": [
            r"/_next/static",
            r"__NEXT_DATA__",
            r"next/dist",
            r"__next",
            r"data-nextjs",
            r"NextRouter",
        ],
    }

    # App router (RSC) specific patterns
    APP_ROUTER_PATTERNS = [
        r"__next_f",              # RSC flight data
        r"\$ACTION_ID",          # Server Action markers
        r"__next_action_id",     # Action ID in forms
        r'type="hidden"\s+name="\$ACTION',
        r"0:[^\]]+\]",           # RSC payload format
        r"1:[^\]]+\]",           # RSC payload format
        r"/_not-found",          # App router 404
        r"@[a-z]+/",             # Parallel routes (@modal, @sidebar)
    ]

    # Server Action detection patterns
    SERVER_ACTION_PATTERNS = [
        r'action="[^"]*\$ACTION',
        r"formAction.*\$ACTION",
        r"__next_action_id=[a-f0-9]+",
        r'name="\$ACTION_REF_\d+"',
        r'name="\$ACTION_\d+:\d+"',
    ]

    # Sensitive data patterns in RSC streams
    SENSITIVE_PATTERNS = [
        r"password[\"']?\s*[:=]\s*[\"'][^\"']+",
        r"api[_-]?key[\"']?\s*[:=]\s*[\"'][^\"']+",
        r"secret[\"']?\s*[:=]\s*[\"'][^\"']+",
        r"token[\"']?\s*[:=]\s*[\"'][^\"']+",
        r"private[_-]?key[\"']?\s*[:=]\s*[\"'][^\"']+",
        r"database[_-]?url[\"']?\s*[:=]\s*[\"'][^\"']+",
        r"connection[_-]?string[\"']?\s*[:=]\s*[\"'][^\"']+",
        r'"email":\s*"[^"]+@[^"]+"',
        r'"ssn":\s*"\d{3}-\d{2}-\d{4}"',
        r'"credit[_-]?card":\s*"\d{13,19}"',
    ]

    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
        self.findings: list[dict[str, Any]] = []
        self.rsc_endpoints: list[RSCEndpoint] = []
        self._ssl_verify = get_configured_ssl_verify()

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Execute RSC security scan."""

        # SCAN CONTEXT: Unified access to auth, response validation
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        self.findings = []
        self.rsc_endpoints = []

        base_url = f"https://{host}" if not host.startswith("http") else host
        urls = asset_data.get("urls", []) if isinstance(asset_data, dict) else []

        logger.info(f"RSC Scanner v{self.version} starting on {host}")

        client = create_protected_client(
            timeout=self.timeout,
            verify_ssl=self._ssl_verify,
            follow_redirects=True,
            custom_headers=self._auth_headers,
        )

        async with client:
            # Phase 1: Detect Next.js and RSC support
            await self._detect_nextjs_rsc(client, base_url, urls, rate_limiter)

            if not self.rsc_endpoints:
                logger.info("No Next.js RSC endpoints detected")
                return {
                    "module": self.name,
                    "version": self.version,
                    "findings": [],
                    "rsc_endpoints": [],
                }

            logger.info(f"Found {len(self.rsc_endpoints)} RSC-enabled endpoints")

            # Phase 2: Test Server Action CSRF
            await self._test_server_action_csrf(client, rate_limiter)

            # Phase 3: Test Server Action Auth Bypass
            await self._test_action_auth_bypass(client, rate_limiter)

            # Phase 4: Test Action ID Tampering
            await self._test_action_id_tampering(client, rate_limiter)

            # Phase 5: Test Mass Assignment
            await self._test_mass_assignment(client, rate_limiter)

            # Phase 6: Test RSC Data Leakage
            await self._test_rsc_data_leakage(client, rate_limiter)

            # Phase 7: Test Parallel Route Exploitation
            await self._test_parallel_routes(client, rate_limiter)

            # Phase 8: Test RSC Serialization Injection
            await self._test_serialization_injection(client, rate_limiter)

        logger.info(f"RSC scan complete. Found {len(self.findings)} vulnerabilities")

        return {
            "module": self.name,
            "version": self.version,
            "findings": self.findings,
            "rsc_endpoints": [
                {"url": ep.url, "router": ep.router_type.value, "version": ep.nextjs_version}
                for ep in self.rsc_endpoints
            ],
        }

    async def _detect_nextjs_rsc(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Detect Next.js with RSC support."""
        await rate_limiter.acquire()

        try:
            # Fetch homepage
            response = await client.get(base_url)
            headers_str = str(response.headers).lower()
            body = response.text

            # Check for Next.js indicators
            is_nextjs = False
            nextjs_version = "unknown"

            # Header checks
            for header_name, pattern in self.NEXTJS_INDICATORS["headers"]:
                if header_name.lower() in headers_str:
                    is_nextjs = True
                    break

            # Body checks
            for pattern in self.NEXTJS_INDICATORS["body"]:
                if re.search(pattern, body, re.IGNORECASE):
                    is_nextjs = True
                    # Try to extract version from build manifest
                    version_match = re.search(r'"version"\s*:\s*"([\d.]+)"', body)
                    if version_match:
                        nextjs_version = version_match.group(1)
                    break

            if not is_nextjs:
                return

            # Determine router type
            router_type = NextJSRouter.PAGES_ROUTER
            has_server_actions = False
            action_ids = []
            parallel_routes = []

            # Check for App Router (RSC) patterns
            for pattern in self.APP_ROUTER_PATTERNS:
                if re.search(pattern, body):
                    router_type = NextJSRouter.APP_ROUTER
                    break

            # Check for Server Actions
            for pattern in self.SERVER_ACTION_PATTERNS:
                matches = re.findall(pattern, body)
                if matches:
                    has_server_actions = True
                    # Extract action IDs
                    id_matches = re.findall(r'__next_action_id[=:]"?([a-f0-9]+)', body)
                    action_ids.extend(id_matches)

            # Check for parallel routes
            parallel_matches = re.findall(r'@([a-z_-]+)/', body, re.IGNORECASE)
            parallel_routes.extend(list(set(parallel_matches)))

            endpoint = RSCEndpoint(
                url=base_url,
                router_type=router_type,
                nextjs_version=nextjs_version,
                has_server_actions=has_server_actions,
                action_ids=list(set(action_ids)),
                parallel_routes=parallel_routes,
            )
            self.rsc_endpoints.append(endpoint)

            logger.info(
                f"Detected Next.js {nextjs_version} ({router_type.value} router) "
                f"| Server Actions: {has_server_actions} | Actions: {len(action_ids)}"
            )

            # Also check provided URLs for additional RSC endpoints
            for url in urls[:30]:
                await rate_limiter.acquire()

                try:
                    resp = await client.get(url)
                    if resp.status_code == 200:
                        body = resp.text
                        if any(re.search(p, body) for p in self.APP_ROUTER_PATTERNS):
                            # Additional action IDs
                            ids = re.findall(r'__next_action_id[=:]"?([a-f0-9]+)', body)
                            for action_id in ids:
                                if action_id not in endpoint.action_ids:
                                    endpoint.action_ids.append(action_id)

                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"Next.js detection error: {e}")

    async def _test_server_action_csrf(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for CSRF vulnerabilities in Server Actions."""
        for endpoint in self.rsc_endpoints:
            if not endpoint.has_server_actions:
                continue

            for action_id in endpoint.action_ids[:10]:
                await rate_limiter.acquire()

                # Test Server Action without CSRF token
                try:
                    # Typical Server Action request format
                    action_url = urljoin(endpoint.url, "/_next/action")

                    # Create form data without CSRF token
                    form_data = {
                        "__next_action_id": action_id,
                        "0": "test_input",  # RSC closure format
                    }

                    # Try cross-origin request (no cookies/credentials)
                    headers = {
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Origin": "https://evil.com",  # Cross-origin
                        "Referer": "https://evil.com/",
                    }

                    response = await client.post(
                        action_url,
                        data=form_data,
                        headers=headers,
                    )

                    # Check if action was processed (no CSRF rejection)
                    if response.status_code in [200, 303]:
                        # Check response for action success indicators
                        if "error" not in response.text.lower() and response.status_code == 200:
                            result = RSCTestResult(
                                vulnerable=True,
                                vuln_type=RSCVulnType.CSRF_BYPASS,
                                confidence_score=75,
                                payload=f"Action ID: {action_id}",
                                response_data=response.text[:300],
                                evidence=[
                                    "Server Action accepted cross-origin request",
                                    f"Action ID: {action_id}",
                                    "No CSRF token validation detected",
                                    f"Response status: {response.status_code}",
                                ],
                                severity=Severity.HIGH,
                            )

                            self._add_finding(
                                name="Server Action CSRF Vulnerability",
                                description=(
                                    "Next.js Server Action accepts requests from cross-origin "
                                    "sources without CSRF token validation. Attackers can craft "
                                    "malicious pages that trigger actions on behalf of users."
                                ),
                                endpoint=action_url,
                                result=result,
                            )
                            break

                except Exception as e:
                    logger.debug(f"Server Action CSRF test error: {e}")

    async def _test_action_auth_bypass(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for authentication bypass in Server Actions."""
        for endpoint in self.rsc_endpoints:
            if not endpoint.has_server_actions:
                continue

            for action_id in endpoint.action_ids[:10]:
                await rate_limiter.acquire()

                try:
                    action_url = urljoin(endpoint.url, "/_next/action")

                    # Test without any auth headers
                    form_data = {
                        "__next_action_id": action_id,
                        "0": "test",
                    }

                    # Create fresh client without auth
                    async with create_protected_client(
                        timeout=self.timeout,
                        verify_ssl=self._ssl_verify,
                    ) as unauth_client:
                        response = await unauth_client.post(
                            action_url,
                            data=form_data,
                        )

                        # Check if action succeeded without auth
                        if response.status_code == 200:
                            body = response.text.lower()
                            # Look for success indicators (not auth errors)
                            if all(x not in body for x in ["unauthorized", "forbidden", "login", "sign in"]):
                                result = RSCTestResult(
                                    vulnerable=True,
                                    vuln_type=RSCVulnType.AUTH_BYPASS,
                                    confidence_score=70,
                                    payload=f"Action ID: {action_id} (no auth)",
                                    response_data=response.text[:300],
                                    evidence=[
                                        "Server Action executed without authentication",
                                        f"Action ID: {action_id}",
                                        "No auth challenge received",
                                    ],
                                    severity=Severity.HIGH,
                                )

                                self._add_finding(
                                    name="Server Action Authentication Bypass",
                                    description=(
                                        "Next.js Server Action can be invoked without proper "
                                        "authentication. Attackers can execute privileged actions "
                                        "without logging in."
                                    ),
                                    endpoint=action_url,
                                    result=result,
                                )
                                break

                except Exception as e:
                    logger.debug(f"Action auth bypass test error: {e}")

    async def _test_action_id_tampering(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for action ID tampering vulnerabilities."""
        for endpoint in self.rsc_endpoints:
            if not endpoint.has_server_actions:
                continue

            await rate_limiter.acquire()

            try:
                action_url = urljoin(endpoint.url, "/_next/action")

                # Generate tampered action IDs
                if endpoint.action_ids:
                    base_id = endpoint.action_ids[0]

                    # Tampering strategies
                    tampered_ids = [
                        # Increment/decrement
                        hex(int(base_id, 16) + 1)[2:] if len(base_id) <= 16 else base_id,
                        hex(int(base_id, 16) - 1)[2:] if len(base_id) <= 16 else base_id,
                        # Replace last characters
                        base_id[:-2] + "ff",
                        base_id[:-2] + "00",
                        # Known dangerous action name hashes
                        hashlib.md5(b"deleteUser").hexdigest()[:len(base_id)],
                        hashlib.md5(b"adminAction").hexdigest()[:len(base_id)],
                        hashlib.md5(b"updateRole").hexdigest()[:len(base_id)],
                    ]

                    for tampered_id in tampered_ids:
                        await rate_limiter.acquire()

                        form_data = {
                            "__next_action_id": tampered_id,
                            "0": "admin",
                        }

                        response = await client.post(action_url, data=form_data)

                        if response.status_code == 200:
                            body = response.text.lower()
                            # Check if a different action was triggered
                            if "success" in body or "updated" in body or "deleted" in body:
                                result = RSCTestResult(
                                    vulnerable=True,
                                    vuln_type=RSCVulnType.ACTION_ID_TAMPERING,
                                    confidence_score=65,
                                    payload=f"Tampered ID: {tampered_id} (from {base_id})",
                                    response_data=response.text[:300],
                                    evidence=[
                                        "Server accepted tampered action ID",
                                        f"Original: {base_id}",
                                        f"Tampered: {tampered_id}",
                                        "Possible unauthorized action execution",
                                    ],
                                    severity=Severity.HIGH,
                                )

                                self._add_finding(
                                    name="Server Action ID Tampering",
                                    description=(
                                        "Server Action IDs can be tampered to invoke different "
                                        "actions. This could allow attackers to call admin-only "
                                        "or privileged actions by guessing/manipulating IDs."
                                    ),
                                    endpoint=action_url,
                                    result=result,
                                )
                                break

            except Exception as e:
                logger.debug(f"Action ID tampering test error: {e}")

    async def _test_mass_assignment(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for mass assignment in Server Action formData."""
        for endpoint in self.rsc_endpoints:
            if not endpoint.has_server_actions:
                continue

            for action_id in endpoint.action_ids[:5]:
                await rate_limiter.acquire()

                try:
                    action_url = urljoin(endpoint.url, "/_next/action")

                    # Mass assignment payloads
                    mass_assignment_fields = {
                        "__next_action_id": action_id,
                        "0": "test",  # Normal field
                        # Potential privileged fields
                        "role": "admin",
                        "isAdmin": "true",
                        "is_admin": "true",
                        "admin": "1",
                        "verified": "true",
                        "emailVerified": "true",
                        "permissions": "all",
                        "userId": "1",
                        "user_id": "1",
                    }

                    response = await client.post(action_url, data=mass_assignment_fields)

                    if response.status_code == 200:
                        body = response.text.lower()
                        # Check for success indicators with privilege fields
                        if any(x in body for x in ["admin", "verified", "success", "updated"]):
                            result = RSCTestResult(
                                vulnerable=True,
                                vuln_type=RSCVulnType.MASS_ASSIGNMENT,
                                confidence_score=60,
                                payload=f"Fields: role=admin, isAdmin=true, etc.",
                                response_data=response.text[:300],
                                evidence=[
                                    "Server Action accepted extra form fields",
                                    "Privilege-related fields may have been processed",
                                    "Response indicates possible assignment",
                                ],
                                severity=Severity.HIGH,
                            )

                            self._add_finding(
                                name="Mass Assignment in Server Action",
                                description=(
                                    "Server Action accepts and processes arbitrary form fields. "
                                    "Attackers can inject fields like 'role=admin' or 'isAdmin=true' "
                                    "to escalate privileges."
                                ),
                                endpoint=action_url,
                                result=result,
                            )
                            break

                except Exception as e:
                    logger.debug(f"Mass assignment test error: {e}")

    async def _test_rsc_data_leakage(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for sensitive data leakage in RSC payloads."""
        for endpoint in self.rsc_endpoints:
            if endpoint.router_type != NextJSRouter.APP_ROUTER:
                continue

            await rate_limiter.acquire()

            try:
                # Fetch with RSC headers to get flight data
                rsc_headers = {
                    "Accept": "text/x-component",
                    "RSC": "1",
                    "Next-Router-State-Tree": '["",{},"","","",null]',
                }

                # Test main page
                response = await client.get(endpoint.url, headers=rsc_headers)

                if response.status_code == 200:
                    body = response.text

                    # Check for sensitive data patterns
                    leaked_data = []
                    for pattern in self.SENSITIVE_PATTERNS:
                        matches = re.findall(pattern, body, re.IGNORECASE)
                        if matches:
                            leaked_data.extend(matches[:3])  # Limit matches

                    if leaked_data:
                        result = RSCTestResult(
                            vulnerable=True,
                            vuln_type=RSCVulnType.DATA_LEAKAGE,
                            confidence_score=85,
                            payload="RSC stream request",
                            response_data=body[:500],
                            evidence=[
                                "Sensitive data found in RSC payload",
                                f"Patterns matched: {leaked_data[:5]}",
                                "Data may be visible to client",
                            ],
                            severity=Severity.HIGH,
                            data_leaked=True,
                        )

                        self._add_finding(
                            name="RSC Stream Data Leakage",
                            description=(
                                "React Server Components stream contains sensitive data "
                                "(credentials, API keys, PII). This data is sent to the client "
                                "and can be extracted by inspecting network traffic."
                            ),
                            endpoint=endpoint.url,
                            result=result,
                        )

                # Test additional paths for data leakage
                sensitive_paths = [
                    "/api/auth/session",
                    "/api/user",
                    "/api/me",
                    "/dashboard",
                    "/admin",
                    "/profile",
                    "/account",
                    "/settings",
                ]

                for path in sensitive_paths:
                    await rate_limiter.acquire()

                    url = urljoin(endpoint.url, path)
                    resp = await client.get(url, headers=rsc_headers)

                    if resp.status_code == 200:
                        for pattern in self.SENSITIVE_PATTERNS:
                            if re.search(pattern, resp.text, re.IGNORECASE):
                                result = RSCTestResult(
                                    vulnerable=True,
                                    vuln_type=RSCVulnType.DATA_LEAKAGE,
                                    confidence_score=80,
                                    payload=f"RSC request to {path}",
                                    response_data=resp.text[:300],
                                    evidence=[
                                        f"Sensitive data in RSC payload at {path}",
                                        "Data exposed via Server Components",
                                    ],
                                    severity=Severity.HIGH,
                                    data_leaked=True,
                                )

                                self._add_finding(
                                    name=f"RSC Data Leakage at {path}",
                                    description=(
                                        f"Sensitive data found in RSC stream for {path}. "
                                        "Server Components may be exposing server-only data "
                                        "to the client."
                                    ),
                                    endpoint=url,
                                    result=result,
                                )
                                break

            except Exception as e:
                logger.debug(f"RSC data leakage test error: {e}")

    async def _test_parallel_routes(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for parallel route exploitation."""
        for endpoint in self.rsc_endpoints:
            if not endpoint.parallel_routes:
                continue

            for route in endpoint.parallel_routes:
                await rate_limiter.acquire()

                try:
                    # Common parallel route patterns
                    test_paths = [
                        f"/@{route}/",
                        f"/@{route}/default",
                        f"/(.)@{route}/",
                        f"/(..)@{route}/",
                    ]

                    # Also try sensitive route names
                    sensitive_routes = ["admin", "modal", "sidebar", "auth", "dashboard"]

                    for test_path in test_paths:
                        url = urljoin(endpoint.url, test_path)
                        response = await client.get(url)

                        if response.status_code == 200:
                            body = response.text.lower()

                            # Check for unauthorized content access
                            if any(x in body for x in ["admin", "secret", "private", "restricted"]):
                                result = RSCTestResult(
                                    vulnerable=True,
                                    vuln_type=RSCVulnType.PARALLEL_ROUTE_EXPLOIT,
                                    confidence_score=65,
                                    payload=test_path,
                                    response_data=response.text[:300],
                                    evidence=[
                                        f"Parallel route accessible: {test_path}",
                                        "May expose content intended for specific contexts",
                                    ],
                                    severity=Severity.MEDIUM,
                                )

                                self._add_finding(
                                    name="Parallel Route Exploitation",
                                    description=(
                                        f"Next.js parallel route @{route} is directly accessible. "
                                        "Parallel routes may expose content intended for modals, "
                                        "sidebars, or specific UI contexts."
                                    ),
                                    endpoint=url,
                                    result=result,
                                )
                                break

                except Exception as e:
                    logger.debug(f"Parallel route test error: {e}")

    async def _test_serialization_injection(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for RSC serialization injection."""
        for endpoint in self.rsc_endpoints:
            if endpoint.router_type != NextJSRouter.APP_ROUTER:
                continue

            await rate_limiter.acquire()

            try:
                # RSC uses a specific serialization format
                # Test injection via _rsc parameter
                injection_payloads = [
                    # RSC format injection
                    '0:["$","div",null,{"children":"INJECTED"}]',
                    '1:{"type":"component","props":{"dangerouslySetInnerHTML":{"__html":"<script>alert(1)</script>"}}}',
                    # JSON injection in RSC
                    '{"__proto__":{"admin":true}}',
                    '{"constructor":{"prototype":{"admin":true}}}',
                ]

                for payload in injection_payloads:
                    await rate_limiter.acquire()

                    # Try injection via _rsc query param
                    url = f"{endpoint.url}?_rsc={payload}"
                    response = await client.get(url)

                    # Try injection via POST body
                    post_response = await client.post(
                        endpoint.url,
                        json={"_rsc": payload},
                        headers={"Content-Type": "application/json"},
                    )

                    for resp in [response, post_response]:
                        if resp.status_code == 200:
                            body = resp.text

                            # Check for injection indicators
                            if "INJECTED" in body or "admin" in body.lower():
                                result = RSCTestResult(
                                    vulnerable=True,
                                    vuln_type=RSCVulnType.SERIALIZATION_INJECTION,
                                    confidence_score=60,
                                    payload=payload[:100],
                                    response_data=body[:300],
                                    evidence=[
                                        "RSC serialization may accept injected data",
                                        f"Payload reflected or processed",
                                    ],
                                    severity=Severity.HIGH,
                                )

                                self._add_finding(
                                    name="RSC Serialization Injection",
                                    description=(
                                        "RSC serialization format may be injectable. "
                                        "Attackers could manipulate the component tree or "
                                        "inject malicious properties via RSC payload manipulation."
                                    ),
                                    endpoint=endpoint.url,
                                    result=result,
                                )
                                break

            except Exception as e:
                logger.debug(f"Serialization injection test error: {e}")

    def _add_finding(
        self,
        name: str,
        description: str,
        endpoint: str,
        result: RSCTestResult,
    ) -> None:
        """Add a finding to the results."""
        cvss_scores = {
            "CRITICAL": 9.5,
            "HIGH": 8.0,
            "MEDIUM": 5.5,
            "LOW": 3.0,
        }

        cwe_mapping = {
            RSCVulnType.CSRF_BYPASS: "CWE-352",
            RSCVulnType.AUTH_BYPASS: "CWE-306",
            RSCVulnType.ACTION_ID_TAMPERING: "CWE-639",
            RSCVulnType.MASS_ASSIGNMENT: "CWE-915",
            RSCVulnType.DATA_LEAKAGE: "CWE-200",
            RSCVulnType.SERVER_ONLY_EXPOSURE: "CWE-200",
            RSCVulnType.PARALLEL_ROUTE_EXPLOIT: "CWE-284",
            RSCVulnType.SERIALIZATION_INJECTION: "CWE-502",
        }

        finding = Finding(
            vuln_type=VulnType.OTHER,
            name=name,
            severity=result.severity,
            description=description,
            host=endpoint,
            endpoint=endpoint,
            evidence=[
                f"Payload: {result.payload[:100]}",
                f"Confidence: {result.confidence}%",
                f"Vulnerability Type: {result.vuln_type.name}",
                f"Data Leaked: {result.data_leaked}",
            ] + result.evidence,
            cvss_score=cvss_scores.get(result.severity, 5.5),
            cwe_id=cwe_mapping.get(result.vuln_type, "CWE-284"),
            remediation=self._get_remediation(result.vuln_type),
            references=[
                "https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations",
                "https://nextjs.org/docs/app/building-your-application/routing/parallel-routes",
                "https://react.dev/reference/rsc/server-components",
                "https://owasp.org/www-project-web-security-testing-guide/",
            ],
        )

        self.findings.append(finding.to_dict())

        logger.info(
            f"RSC Vulnerability [{result.severity}]: {name} "
            f"| Confidence: {result.confidence}%"
        )

    def _get_remediation(self, vuln_type: RSCVulnType) -> str:
        """Get remediation advice for RSC vulnerabilities."""
        base = (
            "1. Implement server-side authentication checks in all Server Actions.\n"
            "2. Use Next.js built-in CSRF protection for forms.\n"
            "3. Validate and sanitize all Server Action inputs.\n"
            "4. Avoid passing sensitive data through RSC props.\n"
            "5. Use 'use server' directive only for necessary actions.\n"
        )

        if vuln_type == RSCVulnType.CSRF_BYPASS:
            base += (
                "\n\nCSRF SPECIFIC:\n"
                "6. Enable Next.js experimental.serverActions.allowedOrigins config.\n"
                "7. Implement SameSite cookie policy.\n"
                "8. Use CSRF tokens for state-changing actions.\n"
                "9. Verify Origin/Referer headers on server.\n"
            )

        elif vuln_type == RSCVulnType.AUTH_BYPASS:
            base += (
                "\n\nAUTH BYPASS SPECIFIC:\n"
                "6. Always check authentication at the start of Server Actions.\n"
                "7. Use Next.js middleware for auth checks.\n"
                "8. Don't rely on client-side auth state.\n"
                "9. Implement session validation for each action.\n"
            )

        elif vuln_type == RSCVulnType.MASS_ASSIGNMENT:
            base += (
                "\n\nMASS ASSIGNMENT SPECIFIC:\n"
                "6. Use explicit parameter destructuring in actions.\n"
                "7. Define strict TypeScript types for action parameters.\n"
                "8. Validate all fields against allowlist.\n"
                "9. Never trust client-provided role/permission fields.\n"
            )

        elif vuln_type == RSCVulnType.DATA_LEAKAGE:
            base += (
                "\n\nDATA LEAKAGE SPECIFIC:\n"
                "6. Use 'server-only' package for sensitive modules.\n"
                "7. Don't pass secrets through component props.\n"
                "8. Use environment variables on server only.\n"
                "9. Audit RSC payloads in production for leaks.\n"
            )

        elif vuln_type == RSCVulnType.PARALLEL_ROUTE_EXPLOIT:
            base += (
                "\n\nPARALLEL ROUTES SPECIFIC:\n"
                "6. Implement auth checks in parallel route components.\n"
                "7. Use layout-level authentication.\n"
                "8. Don't expose sensitive content in parallel routes.\n"
                "9. Consider if parallel routes need direct access protection.\n"
            )

        return base


# Export
__all__ = ["RSCScanner", "RSC_SCANNER_VERSION"]
