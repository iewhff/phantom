"""
Edge Functions Security Scanner v1.0

Detects security vulnerabilities in edge computing platforms:
- Vercel Edge Functions
- Cloudflare Workers
- Netlify Edge Functions
- Deno Deploy
- AWS Lambda@Edge

Edge functions run at CDN edge locations with unique security
considerations: limited runtime, environment isolation, and
different attack surfaces than traditional servers.

Vulnerability Types Covered:
1. Environment Variable Exposure - Secrets leaked at edge
2. KV/Storage Binding Exposure - Cloudflare KV, R2, D1 access
3. Origin Bypass - Direct edge access bypassing origin controls
4. Timeout Exploitation - Long-running operations abuse
5. Memory Exhaustion - DoS via memory limits
6. Runtime Object Leakage - process, Deno, globalThis exposure
7. SSRF via Edge - Edge-to-origin SSRF
8. Cache Poisoning - Edge cache manipulation

Bug Bounty Value: $1,000 - $8,000 for critical edge vulns
Reference: Edge security is often overlooked, lower competition

CWE Coverage:
- CWE-200: Exposure of Sensitive Information
- CWE-918: Server-Side Request Forgery
- CWE-400: Uncontrolled Resource Consumption
- CWE-284: Improper Access Control

Author: PetNTester AI
Version: 1.0.0 (2026-02-19)
"""

from __future__ import annotations

import asyncio
import re
import time
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
EDGE_SCANNER_VERSION = "1.0.0"


class EdgeVulnType(Enum):
    """Types of edge function vulnerabilities."""
    ENV_EXPOSURE = auto()          # Environment variables leaked
    STORAGE_EXPOSURE = auto()      # KV/R2/D1/Blob bindings exposed
    ORIGIN_BYPASS = auto()         # Bypass origin server controls
    TIMEOUT_EXPLOIT = auto()       # CPU/timeout limit abuse
    MEMORY_EXHAUST = auto()        # Memory limit DoS
    RUNTIME_LEAK = auto()          # process/Deno object leakage
    EDGE_SSRF = auto()             # SSRF from edge to origin/internal
    CACHE_POISON = auto()          # Edge cache manipulation


class EdgePlatform(Enum):
    """Edge computing platforms."""
    VERCEL = "vercel"
    CLOUDFLARE = "cloudflare"
    NETLIFY = "netlify"
    DENO_DEPLOY = "deno_deploy"
    LAMBDA_EDGE = "lambda_edge"
    FASTLY = "fastly"
    UNKNOWN = "unknown"


@dataclass
class EdgeEndpoint:
    """Represents a discovered edge function endpoint."""
    url: str
    platform: EdgePlatform
    response_time_ms: float = 0.0
    is_edge: bool = False
    region: str = ""
    features: list[str] = field(default_factory=list)


@dataclass
class EdgeTestResult:
    """Result of an edge security test."""
    vulnerable: bool
    vuln_type: EdgeVulnType
    confidence: int  # 0-100
    payload: str
    response_data: str = ""
    evidence: list[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    data_leaked: bool = False


class EdgeFunctionScanner(ScanModule):
    """
    Edge Functions Security Scanner.

    Detects vulnerabilities in edge computing platforms:
    - Environment variable exposure
    - Storage binding leakage (KV, R2, D1, Blob)
    - Origin bypass attacks
    - Resource exhaustion (timeout, memory)
    - Runtime object leakage

    Focus: Edge functions are high-value targets due to:
    - Often contain secrets for external APIs
    - Run in isolated but powerful environments
    - May have access to storage bindings
    - Can bypass origin-level protections
    """

    name = "edge_function_scanner"
    version = EDGE_SCANNER_VERSION

    # Platform detection patterns
    PLATFORM_HEADERS = {
        EdgePlatform.VERCEL: [
            ("x-vercel-cache", r".*"),
            ("x-vercel-id", r".*"),
            ("x-vercel-deployment-url", r".*"),
            ("x-matched-path", r".*"),
            ("server", r"vercel"),
        ],
        EdgePlatform.CLOUDFLARE: [
            ("cf-ray", r".*"),
            ("cf-cache-status", r".*"),
            ("cf-request-id", r".*"),
            ("server", r"cloudflare"),
            ("cf-worker", r".*"),
        ],
        EdgePlatform.NETLIFY: [
            ("x-nf-request-id", r".*"),
            ("x-nf-site-id", r".*"),
            ("x-nf-account-id", r".*"),
            ("netlify-cdn-cache-control", r".*"),
        ],
        EdgePlatform.DENO_DEPLOY: [
            ("x-deno-region", r".*"),
            ("server", r"deno"),
            ("x-deploy-id", r".*"),
        ],
        EdgePlatform.LAMBDA_EDGE: [
            ("x-amz-cf-id", r".*"),
            ("x-amz-cf-pop", r".*"),
            ("x-cache", r".*from cloudfront"),
        ],
        EdgePlatform.FASTLY: [
            ("x-served-by", r"cache-.*"),
            ("x-cache", r".*"),
            ("fastly-.*", r".*"),
        ],
    }

    # Edge-specific API endpoints to probe
    EDGE_ENDPOINTS = [
        "/api/", "/edge/", "/_edge/",
        "/api/edge/", "/functions/",
        "/.netlify/functions/",
        "/.vercel/functions/",
        "/api/hello", "/api/test",
    ]

    # Environment variable patterns to detect
    ENV_PATTERNS = [
        r"VERCEL_[A-Z_]+",
        r"CF_[A-Z_]+",
        r"CLOUDFLARE_[A-Z_]+",
        r"NETLIFY_[A-Z_]+",
        r"DENO_[A-Z_]+",
        r"AWS_[A-Z_]+",
        r"DATABASE_URL",
        r"API_KEY",
        r"SECRET_KEY",
        r"AUTH_SECRET",
        r"NEXT_PUBLIC_[A-Z_]+",
        r"PRIVATE_[A-Z_]+",
    ]

    # Storage binding patterns
    STORAGE_PATTERNS = {
        "cloudflare_kv": [r"KV\.", r"env\.KV", r"NAMESPACE\.get", r"NAMESPACE\.put"],
        "cloudflare_r2": [r"R2\.", r"env\.R2", r"BUCKET\.get", r"BUCKET\.put"],
        "cloudflare_d1": [r"D1\.", r"env\.D1", r"DB\.prepare", r"DB\.exec"],
        "netlify_blob": [r"getStore", r"Blob\.set", r"Blob\.get"],
        "vercel_kv": [r"@vercel/kv", r"kv\.get", r"kv\.set"],
        "vercel_postgres": [r"@vercel/postgres", r"sql`", r"db\.query"],
    }

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
        self.edge_endpoints: list[EdgeEndpoint] = []
        self._ssl_verify = get_configured_ssl_verify()

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Execute edge function security scan."""

        # SCAN CONTEXT
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        self.findings = []
        self.edge_endpoints = []

        base_url = f"https://{host}" if not host.startswith("http") else host
        urls = asset_data.get("urls", []) if isinstance(asset_data, dict) else []

        logger.info(f"Edge Function Scanner v{self.version} starting on {host}")

        client = create_protected_client(
            timeout=self.timeout,
            verify_ssl=self._ssl_verify,
            follow_redirects=True,
            custom_headers=self._auth_headers,
        )

        async with client:
            # Phase 1: Detect edge platform and endpoints
            await self._detect_edge_platform(client, base_url, urls, rate_limiter)

            if not self.edge_endpoints:
                logger.info("No edge function endpoints detected")
                return {
                    "module": self.name,
                    "version": self.version,
                    "findings": [],
                    "edge_endpoints": [],
                }

            logger.info(f"Found {len(self.edge_endpoints)} edge endpoints")

            # Phase 2: Test environment variable exposure
            await self._test_env_exposure(client, rate_limiter)

            # Phase 3: Test storage binding exposure
            await self._test_storage_exposure(client, rate_limiter)

            # Phase 4: Test origin bypass
            await self._test_origin_bypass(client, rate_limiter)

            # Phase 5: Test timeout exploitation
            await self._test_timeout_exploit(client, rate_limiter)

            # Phase 6: Test memory exhaustion
            await self._test_memory_exhaust(client, rate_limiter)

            # Phase 7: Test runtime object leakage
            await self._test_runtime_leak(client, rate_limiter)

            # Phase 8: Test edge SSRF
            await self._test_edge_ssrf(client, rate_limiter)

            # Phase 9: Test cache poisoning
            await self._test_cache_poison(client, rate_limiter)

        logger.info(f"Edge scan complete. Found {len(self.findings)} vulnerabilities")

        return {
            "module": self.name,
            "version": self.version,
            "findings": self.findings,
            "edge_endpoints": [
                {
                    "url": ep.url,
                    "platform": ep.platform.value,
                    "response_time_ms": ep.response_time_ms,
                    "region": ep.region,
                }
                for ep in self.edge_endpoints
            ],
        }

    async def _detect_edge_platform(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Detect edge computing platform and endpoints."""
        # Test base URL first
        await rate_limiter.acquire()

        try:
            start = time.time()
            response = await client.get(base_url)
            response_time = (time.time() - start) * 1000  # ms

            platform = self._identify_platform(response)
            region = self._extract_region(response)

            if platform != EdgePlatform.UNKNOWN:
                endpoint = EdgeEndpoint(
                    url=base_url,
                    platform=platform,
                    response_time_ms=response_time,
                    is_edge=response_time < 100,  # Fast response suggests edge
                    region=region,
                )
                self.edge_endpoints.append(endpoint)

                logger.info(
                    f"Detected {platform.value} edge platform "
                    f"| Response: {response_time:.0f}ms | Region: {region or 'unknown'}"
                )

        except Exception as e:
            logger.debug(f"Edge platform detection error: {e}")

        # Probe edge-specific endpoints
        for endpoint_path in self.EDGE_ENDPOINTS:
            await rate_limiter.acquire()

            url = urljoin(base_url, endpoint_path)
            try:
                start = time.time()
                response = await client.get(url)
                response_time = (time.time() - start) * 1000

                if response.status_code in [200, 401, 403, 405]:
                    platform = self._identify_platform(response)

                    if platform != EdgePlatform.UNKNOWN:
                        endpoint = EdgeEndpoint(
                            url=url,
                            platform=platform,
                            response_time_ms=response_time,
                            is_edge=response_time < 100,
                            region=self._extract_region(response),
                        )

                        if not any(ep.url == url for ep in self.edge_endpoints):
                            self.edge_endpoints.append(endpoint)

            except Exception:
                pass

        # Check crawled URLs
        for url in urls[:30]:
            if any(p in url.lower() for p in ["/api/", "/edge/", "/functions/"]):
                await rate_limiter.acquire()

                try:
                    start = time.time()
                    response = await client.get(url)
                    response_time = (time.time() - start) * 1000

                    platform = self._identify_platform(response)
                    if platform != EdgePlatform.UNKNOWN:
                        if not any(ep.url == url for ep in self.edge_endpoints):
                            self.edge_endpoints.append(EdgeEndpoint(
                                url=url,
                                platform=platform,
                                response_time_ms=response_time,
                                is_edge=response_time < 100,
                            ))

                except Exception:
                    pass

    def _identify_platform(self, response: httpx.Response) -> EdgePlatform:
        """Identify edge platform from response headers."""
        headers = {k.lower(): v for k, v in response.headers.items()}

        for platform, patterns in self.PLATFORM_HEADERS.items():
            for header_name, pattern in patterns:
                header_name = header_name.lower()
                if header_name in headers:
                    if re.search(pattern, headers[header_name], re.IGNORECASE):
                        return platform

        return EdgePlatform.UNKNOWN

    def _extract_region(self, response: httpx.Response) -> str:
        """Extract edge region from response headers."""
        headers = {k.lower(): v for k, v in response.headers.items()}

        # Vercel
        if "x-vercel-id" in headers:
            # Format: xxx1::xxxxx-1234567890123-xxx
            parts = headers["x-vercel-id"].split("::")
            if parts:
                return parts[0]

        # Cloudflare
        if "cf-ray" in headers:
            # Format: xxxxxxxxxxxxxxxx-XXX (XXX is region code)
            parts = headers["cf-ray"].split("-")
            if len(parts) > 1:
                return parts[-1]

        # Deno Deploy
        if "x-deno-region" in headers:
            return headers["x-deno-region"]

        # Lambda@Edge
        if "x-amz-cf-pop" in headers:
            return headers["x-amz-cf-pop"]

        return ""

    async def _test_env_exposure(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for environment variable exposure."""
        for endpoint in self.edge_endpoints[:10]:
            await rate_limiter.acquire()

            # Payloads designed to trigger env leakage
            test_payloads = [
                # Query params
                ("?debug=true", {}),
                ("?env=1", {}),
                ("?showEnv=true", {}),
                ("?__debug", {}),
                # Headers
                ("", {"X-Debug": "true"}),
                ("", {"X-Show-Env": "1"}),
                # Error triggering
                ("?error=1", {}),
                ("?undefined", {}),
            ]

            for path_suffix, extra_headers in test_payloads:
                try:
                    url = endpoint.url + path_suffix
                    response = await client.get(url, headers=extra_headers)

                    if response.status_code in [200, 500]:
                        body = response.text

                        # Check for env variable patterns
                        leaked_vars = []
                        for pattern in self.ENV_PATTERNS:
                            matches = re.findall(pattern, body)
                            if matches:
                                leaked_vars.extend(matches)

                        if leaked_vars:
                            result = EdgeTestResult(
                                vulnerable=True,
                                vuln_type=EdgeVulnType.ENV_EXPOSURE,
                                confidence_score=85,
                                payload=path_suffix or str(extra_headers),
                                response_data=body[:500],
                                evidence=[
                                    f"Environment variables exposed: {leaked_vars[:5]}",
                                    f"Platform: {endpoint.platform.value}",
                                ],
                                severity=Severity.HIGH,
                                data_leaked=True,
                            )

                            self._add_finding(
                                name="Edge Environment Variable Exposure",
                                description=(
                                    "Edge function exposes environment variables in responses. "
                                    "This may leak API keys, database URLs, secrets, and other "
                                    "sensitive configuration data."
                                ),
                                endpoint=endpoint.url,
                                result=result,
                            )
                            break

                except Exception as e:
                    logger.debug(f"Env exposure test error: {e}")

    async def _test_storage_exposure(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for storage binding exposure (KV, R2, D1, etc.)."""
        for endpoint in self.edge_endpoints[:10]:
            await rate_limiter.acquire()

            # Platform-specific storage probes
            storage_probes = []

            if endpoint.platform == EdgePlatform.CLOUDFLARE:
                storage_probes = [
                    "?kv=list",
                    "?r2=list",
                    "?d1=tables",
                    "?__cf_kv",
                    "?bindings",
                ]
            elif endpoint.platform == EdgePlatform.NETLIFY:
                storage_probes = [
                    "?blob=list",
                    "?store=list",
                    "?__nf_blob",
                ]
            elif endpoint.platform == EdgePlatform.VERCEL:
                storage_probes = [
                    "?kv=list",
                    "?postgres=tables",
                    "?__vercel_kv",
                ]

            for probe in storage_probes:
                try:
                    url = endpoint.url + probe
                    response = await client.get(url)

                    if response.status_code == 200:
                        body = response.text.lower()

                        # Check for storage patterns
                        storage_found = []
                        for storage_type, patterns in self.STORAGE_PATTERNS.items():
                            for pattern in patterns:
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    storage_found.append(storage_type)
                                    break

                        # Check for data indicators
                        if storage_found or any(
                            x in body for x in ["keys", "bucket", "namespace", "database", "table"]
                        ):
                            result = EdgeTestResult(
                                vulnerable=True,
                                vuln_type=EdgeVulnType.STORAGE_EXPOSURE,
                                confidence_score=75,
                                payload=probe,
                                response_data=response.text[:500],
                                evidence=[
                                    f"Storage bindings exposed: {storage_found or 'detected'}",
                                    f"Platform: {endpoint.platform.value}",
                                    "May allow reading/writing edge storage",
                                ],
                                severity=Severity.HIGH,
                                data_leaked=True,
                            )

                            self._add_finding(
                                name="Edge Storage Binding Exposure",
                                description=(
                                    f"Edge function exposes {endpoint.platform.value} storage "
                                    "bindings (KV, R2, D1, Blob). Attackers may be able to "
                                    "read, modify, or delete data in edge storage."
                                ),
                                endpoint=endpoint.url,
                                result=result,
                            )
                            break

                except Exception as e:
                    logger.debug(f"Storage exposure test error: {e}")

    async def _test_origin_bypass(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for origin bypass via edge functions."""
        for endpoint in self.edge_endpoints[:5]:
            await rate_limiter.acquire()

            try:
                # Test accessing protected paths through edge
                protected_paths = [
                    "/admin",
                    "/api/admin",
                    "/internal",
                    "/api/internal",
                    "/.env",
                    "/config",
                ]

                for path in protected_paths:
                    # Try with edge-specific headers
                    bypass_headers = [
                        {"X-Forwarded-Host": "internal.local"},
                        {"X-Original-URL": path},
                        {"X-Rewrite-URL": path},
                        {"Host": "internal"},
                    ]

                    for headers in bypass_headers:
                        await rate_limiter.acquire()

                        url = urljoin(endpoint.url, path)
                        response = await client.get(url, headers=headers)

                        if response.status_code == 200:
                            body = response.text.lower()

                            # Check for admin/internal content
                            if any(x in body for x in ["admin", "internal", "config", "secret"]):
                                result = EdgeTestResult(
                                    vulnerable=True,
                                    vuln_type=EdgeVulnType.ORIGIN_BYPASS,
                                    confidence_score=70,
                                    payload=f"{path} with {headers}",
                                    response_data=response.text[:300],
                                    evidence=[
                                        f"Protected path accessible via edge: {path}",
                                        "Origin-level controls may be bypassed",
                                    ],
                                    severity=Severity.HIGH,
                                )

                                self._add_finding(
                                    name="Edge Origin Bypass",
                                    description=(
                                        "Edge function allows bypassing origin server access "
                                        "controls. Attackers can access protected paths by "
                                        "manipulating headers at the edge layer."
                                    ),
                                    endpoint=endpoint.url,
                                    result=result,
                                )
                                break

            except Exception as e:
                logger.debug(f"Origin bypass test error: {e}")

    async def _test_timeout_exploit(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for timeout/CPU limit exploitation."""
        for endpoint in self.edge_endpoints[:5]:
            await rate_limiter.acquire()

            try:
                # Payloads designed to consume CPU time
                timeout_payloads = [
                    # Regex DoS
                    {"input": "a" * 100 + "!"},
                    {"regex": "(a+)+$", "input": "a" * 30 + "!"},
                    # JSON parsing
                    {"data": '{"a":' * 100 + '1' + '}' * 100},
                    # Loop triggers
                    {"iterations": "999999"},
                    {"depth": "1000"},
                ]

                for payload in timeout_payloads:
                    await rate_limiter.acquire()

                    start = time.time()
                    response = await client.post(
                        endpoint.url,
                        json=payload,
                        timeout=15.0,  # Extended timeout for this test
                    )
                    elapsed = time.time() - start

                    # Check if we got close to typical edge timeout (10-30s)
                    if elapsed > 8.0 or response.status_code == 504:
                        result = EdgeTestResult(
                            vulnerable=True,
                            vuln_type=EdgeVulnType.TIMEOUT_EXPLOIT,
                            confidence_score=65,
                            payload=str(payload)[:100],
                            evidence=[
                                f"Request took {elapsed:.2f}s (edge timeout ~10-30s)",
                                "CPU-intensive operations possible",
                                "Potential for DoS via timeout abuse",
                            ],
                            severity=Severity.MEDIUM,
                        )

                        self._add_finding(
                            name="Edge Timeout Exploitation",
                            description=(
                                "Edge function can be made to consume excessive CPU time. "
                                "Attackers can trigger expensive computations approaching "
                                "the edge timeout limit, causing resource exhaustion."
                            ),
                            endpoint=endpoint.url,
                            result=result,
                        )
                        break

            except asyncio.TimeoutError:
                # Timeout itself is evidence
                result = EdgeTestResult(
                    vulnerable=True,
                    vuln_type=EdgeVulnType.TIMEOUT_EXPLOIT,
                    confidence_score=60,
                    payload="Timeout triggered",
                    evidence=["Request exceeded timeout", "Edge function can be stalled"],
                    severity=Severity.MEDIUM,
                )

                self._add_finding(
                    name="Edge Timeout Exploitation",
                    description="Edge function can be stalled to timeout.",
                    endpoint=endpoint.url,
                    result=result,
                )

            except Exception as e:
                logger.debug(f"Timeout exploit test error: {e}")

    async def _test_memory_exhaust(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for memory exhaustion attacks."""
        for endpoint in self.edge_endpoints[:5]:
            await rate_limiter.acquire()

            try:
                # Memory exhaustion payloads
                memory_payloads = [
                    # Large array
                    {"array": list(range(100000))},
                    # Deep nesting
                    {"nested": self._create_nested_dict(50)},
                    # Large string
                    {"data": "A" * 1000000},  # 1MB string
                ]

                for payload in memory_payloads:
                    await rate_limiter.acquire()

                    try:
                        response = await client.post(
                            endpoint.url,
                            json=payload,
                            timeout=10.0,
                        )

                        # Check for memory-related errors
                        if response.status_code in [500, 502, 503]:
                            body = response.text.lower()
                            if any(x in body for x in [
                                "memory", "heap", "allocation", "oom",
                                "limit exceeded", "resource"
                            ]):
                                result = EdgeTestResult(
                                    vulnerable=True,
                                    vuln_type=EdgeVulnType.MEMORY_EXHAUST,
                                    confidence_score=70,
                                    payload=f"Payload size: {len(str(payload))}",
                                    response_data=body[:300],
                                    evidence=[
                                        "Memory exhaustion error triggered",
                                        f"Status: {response.status_code}",
                                    ],
                                    severity=Severity.MEDIUM,
                                )

                                self._add_finding(
                                    name="Edge Memory Exhaustion",
                                    description=(
                                        "Edge function vulnerable to memory exhaustion. "
                                        "Large payloads can crash the function or cause "
                                        "service degradation."
                                    ),
                                    endpoint=endpoint.url,
                                    result=result,
                                )
                                break

                    except Exception:
                        pass

            except Exception as e:
                logger.debug(f"Memory exhaust test error: {e}")

    def _create_nested_dict(self, depth: int) -> dict:
        """Create deeply nested dictionary for testing."""
        result = {"leaf": "value"}
        for _ in range(depth):
            result = {"nested": result}
        return result

    async def _test_runtime_leak(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for runtime object leakage (process, Deno, globalThis)."""
        for endpoint in self.edge_endpoints[:10]:
            await rate_limiter.acquire()

            try:
                # Probes for runtime objects
                runtime_probes = [
                    "?eval=process.env",
                    "?eval=globalThis",
                    "?eval=Deno.env",
                    "?debug=runtime",
                    "?__proto__",
                    "?constructor",
                ]

                for probe in runtime_probes:
                    url = endpoint.url + probe
                    response = await client.get(url)

                    if response.status_code == 200:
                        body = response.text

                        # Check for runtime object indicators
                        runtime_indicators = [
                            ("process.env", r"process\.env"),
                            ("Deno.env", r"Deno\.env"),
                            ("globalThis", r"globalThis"),
                            ("__proto__", r"__proto__"),
                            ("constructor", r'"constructor"'),
                            ("NODE_ENV", r"NODE_ENV"),
                        ]

                        for name, pattern in runtime_indicators:
                            if re.search(pattern, body):
                                result = EdgeTestResult(
                                    vulnerable=True,
                                    vuln_type=EdgeVulnType.RUNTIME_LEAK,
                                    confidence_score=75,
                                    payload=probe,
                                    response_data=body[:500],
                                    evidence=[
                                        f"Runtime object exposed: {name}",
                                        "May allow code execution or env access",
                                    ],
                                    severity=Severity.HIGH,
                                    data_leaked=True,
                                )

                                self._add_finding(
                                    name="Edge Runtime Object Leakage",
                                    description=(
                                        "Edge function exposes runtime objects (process, Deno, "
                                        "globalThis). This can leak environment variables, enable "
                                        "prototype pollution, or allow arbitrary code execution."
                                    ),
                                    endpoint=endpoint.url,
                                    result=result,
                                )
                                break

            except Exception as e:
                logger.debug(f"Runtime leak test error: {e}")

    async def _test_edge_ssrf(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for SSRF from edge to origin/internal."""
        for endpoint in self.edge_endpoints[:5]:
            await rate_limiter.acquire()

            try:
                # SSRF payloads
                ssrf_payloads = [
                    {"url": "http://169.254.169.254/latest/meta-data/"},
                    {"url": "http://localhost:8080/"},
                    {"url": "http://127.0.0.1/admin"},
                    {"fetch": "http://internal.service/"},
                    {"proxy": "http://origin.internal/"},
                ]

                for payload in ssrf_payloads:
                    await rate_limiter.acquire()

                    response = await client.post(endpoint.url, json=payload)

                    if response.status_code == 200:
                        body = response.text.lower()

                        # Check for SSRF success indicators
                        ssrf_indicators = [
                            "ami-id", "instance-id",  # AWS metadata
                            "localhost", "127.0.0.1", "internal",
                            "admin", "root", "config",
                        ]

                        if any(ind in body for ind in ssrf_indicators):
                            result = EdgeTestResult(
                                vulnerable=True,
                                vuln_type=EdgeVulnType.EDGE_SSRF,
                                confidence_score=80,
                                payload=str(payload),
                                response_data=body[:500],
                                evidence=[
                                    "SSRF successful from edge function",
                                    "Internal services may be accessible",
                                ],
                                severity=Severity.HIGH,
                                data_leaked=True,
                            )

                            self._add_finding(
                                name="Edge SSRF Vulnerability",
                                description=(
                                    "Edge function can make requests to internal services. "
                                    "Attackers can access cloud metadata, internal APIs, or "
                                    "origin servers that should not be publicly accessible."
                                ),
                                endpoint=endpoint.url,
                                result=result,
                            )
                            break

            except Exception as e:
                logger.debug(f"Edge SSRF test error: {e}")

    async def _test_cache_poison(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for edge cache poisoning."""
        for endpoint in self.edge_endpoints[:5]:
            await rate_limiter.acquire()

            try:
                # Cache poisoning vectors
                poison_tests = [
                    # Host header injection
                    ({"Host": "evil.com"}, "host"),
                    # X-Forwarded headers
                    ({"X-Forwarded-Host": "evil.com"}, "forwarded"),
                    ({"X-Forwarded-Scheme": "http"}, "scheme"),
                    # Cache key manipulation
                    ({"X-Original-URL": "/admin"}, "original-url"),
                ]

                for headers, vector_name in poison_tests:
                    await rate_limiter.acquire()

                    response = await client.get(endpoint.url, headers=headers)

                    if response.status_code == 200:
                        # Check if our injection appears in cacheable response
                        cache_headers = response.headers.get("cache-control", "")
                        is_cached = response.headers.get("x-cache", "").lower()

                        if "evil.com" in response.text or "evil" in response.text.lower():
                            # Check if response is cacheable
                            if "public" in cache_headers or "hit" in is_cached:
                                result = EdgeTestResult(
                                    vulnerable=True,
                                    vuln_type=EdgeVulnType.CACHE_POISON,
                                    confidence_score=75,
                                    payload=f"Header: {vector_name}",
                                    evidence=[
                                        f"Injection via {vector_name} header reflected",
                                        f"Cache-Control: {cache_headers}",
                                        "Poisoned response may be cached",
                                    ],
                                    severity=Severity.HIGH,
                                )

                                self._add_finding(
                                    name="Edge Cache Poisoning",
                                    description=(
                                        "Edge cache can be poisoned via header manipulation. "
                                        "Attackers can inject malicious content that gets cached "
                                        "and served to other users."
                                    ),
                                    endpoint=endpoint.url,
                                    result=result,
                                )
                                break

            except Exception as e:
                logger.debug(f"Cache poison test error: {e}")

    def _add_finding(
        self,
        name: str,
        description: str,
        endpoint: str,
        result: EdgeTestResult,
    ) -> None:
        """Add a finding to the results."""
        cvss_scores = {
            "CRITICAL": 9.5,
            "HIGH": 8.0,
            "MEDIUM": 5.5,
            "LOW": 3.0,
        }

        cwe_mapping = {
            EdgeVulnType.ENV_EXPOSURE: "CWE-200",
            EdgeVulnType.STORAGE_EXPOSURE: "CWE-200",
            EdgeVulnType.ORIGIN_BYPASS: "CWE-284",
            EdgeVulnType.TIMEOUT_EXPLOIT: "CWE-400",
            EdgeVulnType.MEMORY_EXHAUST: "CWE-400",
            EdgeVulnType.RUNTIME_LEAK: "CWE-200",
            EdgeVulnType.EDGE_SSRF: "CWE-918",
            EdgeVulnType.CACHE_POISON: "CWE-444",
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
                "https://developers.cloudflare.com/workers/platform/security/",
                "https://vercel.com/docs/functions/edge-functions",
                "https://docs.netlify.com/edge-functions/overview/",
                "https://deno.com/deploy/docs",
            ],
        )

        self.findings.append(finding.to_dict())

        logger.info(
            f"Edge Vulnerability [{result.severity}]: {name} "
            f"| Confidence: {result.confidence}%"
        )

    def _get_remediation(self, vuln_type: EdgeVulnType) -> str:
        """Get remediation advice for edge vulnerabilities."""
        base = (
            "1. Never expose environment variables in responses.\n"
            "2. Implement proper input validation at the edge.\n"
            "3. Use edge-specific security headers.\n"
            "4. Monitor edge function logs for anomalies.\n"
            "5. Set appropriate CPU and memory limits.\n"
        )

        if vuln_type == EdgeVulnType.ENV_EXPOSURE:
            base += (
                "\n\nENV EXPOSURE SPECIFIC:\n"
                "6. Use secret management (not env vars) for sensitive data.\n"
                "7. Never log or return env vars in responses.\n"
                "8. Disable debug modes in production.\n"
                "9. Use edge-specific secret stores when available.\n"
            )

        elif vuln_type == EdgeVulnType.STORAGE_EXPOSURE:
            base += (
                "\n\nSTORAGE EXPOSURE SPECIFIC:\n"
                "6. Implement authentication for storage access.\n"
                "7. Use namespace isolation for multi-tenant data.\n"
                "8. Validate all storage operation parameters.\n"
                "9. Audit storage access patterns.\n"
            )

        elif vuln_type == EdgeVulnType.EDGE_SSRF:
            base += (
                "\n\nEDGE SSRF SPECIFIC:\n"
                "6. Validate and allowlist outbound URLs.\n"
                "7. Block requests to internal IPs (169.254.x.x, 127.x.x.x).\n"
                "8. Use edge-specific URL validation.\n"
                "9. Consider network isolation for edge functions.\n"
            )

        elif vuln_type == EdgeVulnType.CACHE_POISON:
            base += (
                "\n\nCACHE POISONING SPECIFIC:\n"
                "6. Normalize cache keys to exclude injectable headers.\n"
                "7. Validate Host and X-Forwarded-* headers.\n"
                "8. Use Vary header appropriately.\n"
                "9. Implement cache key sanitization at edge.\n"
            )

        return base


# Export
__all__ = ["EdgeFunctionScanner", "EDGE_SCANNER_VERSION"]
