"""
Bun/Deno Runtime Fingerprinter v1.0

Specialized fingerprinting for modern JavaScript/TypeScript runtimes:
- Bun (fast all-in-one toolkit)
- Deno (secure runtime)
- Node.js (with version detection)
- Cloudflare Workers
- Edge runtimes

Detects runtime-specific vulnerabilities and misconfigurations:
- Deno permission gaps
- Bun-specific APIs
- Runtime version vulnerabilities
- Unsafe runtime configurations

LOW Priority - 1 day effort

CWE Coverage:
- CWE-200: Exposure of Sensitive Information
- CWE-250: Execution with Unnecessary Privileges
- CWE-693: Protection Mechanism Failure

Bug Bounty Value: $200 - $2,000 for runtime-specific issues
"""

from __future__ import annotations

import re
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

BUN_DENO_FINGERPRINTER_VERSION = "1.0.0"


class JSRuntime(Enum):
    """JavaScript/TypeScript runtimes."""
    BUN = "bun"
    DENO = "deno"
    NODE = "node"
    DENO_DEPLOY = "deno_deploy"
    CLOUDFLARE_WORKERS = "cloudflare_workers"
    VERCEL_EDGE = "vercel_edge"
    NETLIFY_EDGE = "netlify_edge"
    UNKNOWN = "unknown"


class RuntimeVulnType(Enum):
    """Types of runtime-specific vulnerabilities."""
    RUNTIME_VERSION_LEAK = auto()       # Version information disclosed
    PERMISSION_MISCONFIGURATION = auto() # Deno permissions too broad
    UNSAFE_API_EXPOSED = auto()          # Dangerous runtime APIs exposed
    DEBUG_MODE_ENABLED = auto()          # Debug/development mode
    OUTDATED_RUNTIME = auto()            # Known vulnerable version
    CONFIG_EXPOSURE = auto()             # Runtime config exposed
    IMPORT_MAP_EXPOSURE = auto()         # Deno import maps exposed
    PERMISSION_BYPASS = auto()           # Permission system bypass


@dataclass
class RuntimeInfo:
    """Detected runtime information."""
    runtime: JSRuntime
    version: str = ""
    detected_via: str = ""
    permissions: list[str] = field(default_factory=list)
    features: list[str] = field(default_factory=list)
    confidence: int = 0


@dataclass
class RuntimeTestResult:
    """Result of a runtime security test."""
    vulnerable: bool
    vuln_type: RuntimeVulnType
    confidence: int
    runtime: JSRuntime
    evidence: list[str] = field(default_factory=list)
    severity: str = "INFO"
    cwe: str = "CWE-200"


# Runtime fingerprints
RUNTIME_FINGERPRINTS = {
    JSRuntime.BUN: {
        "headers": [
            ("server", r"bun(/[\d.]+)?", 90),
            ("x-powered-by", r"bun", 85),
            ("x-bun-version", r"[\d.]+", 95),
        ],
        "errors": [
            (r"Bun\.serve", 80),
            (r"bun:ffi", 85),
            (r"BunFile", 80),
            (r"Bun\.file", 75),
            (r"import\.meta\.dir", 70),  # Bun-specific
            (r"Bun\.password", 85),
            (r"Bun\.write", 80),
        ],
        "apis": [
            "/bun:test",
            "/bun:sqlite",
            "/bun:ffi",
        ],
        "known_vulns": {
            "1.0.0": ["CVE-2023-XXXXX"],  # Placeholder for real CVEs
            "1.0.1": [],
        },
    },
    JSRuntime.DENO: {
        "headers": [
            ("server", r"deno(/[\d.]+)?", 90),
            ("x-powered-by", r"deno", 85),
            ("x-deno-version", r"[\d.]+", 95),
            ("x-deno-region", r".*", 80),  # Deno Deploy
        ],
        "errors": [
            (r"Deno\.(read|write|open)", 85),
            (r"PermissionDenied", 90),
            (r"deno\.land", 70),
            (r"Deno\.permissions", 85),
            (r"import\.meta\.url.*deno", 75),
            (r"Deno\.serve", 80),
            (r"Deno\.env", 85),
        ],
        "apis": [
            "/deno.json",
            "/deno.jsonc",
            "/deno.lock",
            "/import_map.json",
        ],
        "permissions": [
            "--allow-read",
            "--allow-write",
            "--allow-net",
            "--allow-env",
            "--allow-run",
            "--allow-ffi",
            "--allow-hrtime",
            "--allow-all",
        ],
        "known_vulns": {
            "1.0.0": ["CVE-2020-XXXXX"],  # Placeholder
            "1.30.0": [],
        },
    },
    JSRuntime.NODE: {
        "headers": [
            ("x-powered-by", r"express", 70),
            ("x-powered-by", r"node", 80),
            ("server", r"node(/[\d.]+)?", 85),
        ],
        "errors": [
            (r"node:.*Error", 75),
            (r"require\(.*\)", 65),
            (r"__dirname", 70),
            (r"process\.env", 75),
            (r"module\.exports", 65),
        ],
        "apis": [
            "/package.json",
            "/node_modules/",
        ],
        "known_vulns": {
            "14.0.0": ["CVE-2021-22930", "CVE-2021-22931"],
            "16.0.0": ["CVE-2022-32212"],
            "18.0.0": [],
            "20.0.0": [],
        },
    },
    JSRuntime.DENO_DEPLOY: {
        "headers": [
            ("server", r"deno.*deploy", 95),
            ("x-deno-region", r".*", 90),
            ("x-deploy-id", r".*", 95),
        ],
        "errors": [
            (r"Deno Deploy", 95),
            (r"deployctl", 80),
        ],
        "apis": [],
    },
    JSRuntime.CLOUDFLARE_WORKERS: {
        "headers": [
            ("cf-ray", r".*", 70),
            ("cf-worker", r".*", 95),
            ("server", r"cloudflare", 60),
        ],
        "errors": [
            (r"WorkerGlobalScope", 85),
            (r"cf-connecting-ip", 70),
        ],
        "apis": [],
    },
}

# Deno permission indicators
DENO_PERMISSION_INDICATORS = {
    "allow-read": [
        r"Deno\.read",
        r"Deno\.open",
        r"Deno\.stat",
        r"Deno\.readFile",
        r"Deno\.readDir",
    ],
    "allow-write": [
        r"Deno\.write",
        r"Deno\.writeFile",
        r"Deno\.mkdir",
        r"Deno\.remove",
        r"Deno\.rename",
    ],
    "allow-net": [
        r"Deno\.connect",
        r"Deno\.listen",
        r"fetch\(",
        r"WebSocket",
    ],
    "allow-env": [
        r"Deno\.env",
    ],
    "allow-run": [
        r"Deno\.run",
        r"Deno\.Command",
    ],
    "allow-ffi": [
        r"Deno\.dlopen",
        r"Deno\.UnsafePointer",
    ],
}

# Bun-specific dangerous APIs
BUN_DANGEROUS_APIS = {
    "Bun.spawn": {
        "description": "Process spawning",
        "severity": "HIGH",
    },
    "Bun.file": {
        "description": "File system access",
        "severity": "MEDIUM",
    },
    "Bun.write": {
        "description": "File writing",
        "severity": "HIGH",
    },
    "bun:ffi": {
        "description": "Foreign function interface",
        "severity": "CRITICAL",
    },
    "Bun.password": {
        "description": "Password hashing (may expose algo info)",
        "severity": "LOW",
    },
    "Bun.sql": {
        "description": "SQL interface",
        "severity": "MEDIUM",
    },
}


class BunDenoFingerprinter(ScanModule):
    """
    Bun/Deno Runtime Fingerprinter.

    Detects and analyzes modern JavaScript/TypeScript runtimes:
    - Runtime type and version detection
    - Permission analysis (Deno)
    - Dangerous API exposure
    - Configuration exposure
    - Known vulnerability matching
    """

    name = "bun_deno_fingerprinter"
    version = BUN_DENO_FINGERPRINTER_VERSION
    category = "fingerprint"

    def __init__(
        self,
        settings: Any = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.findings: list[dict[str, Any]] = []
        self.detected_runtimes: list[RuntimeInfo] = []
        self._ssl_verify = get_configured_ssl_verify()

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any] | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> dict[str, Any]:
        """Execute runtime fingerprinting scan."""
        asset_data = asset_data or {}

        # SCAN CONTEXT
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        self.findings = []
        self.detected_runtimes = []

        base_url = f"https://{host}" if not host.startswith("http") else host
        urls = asset_data.get("urls", [])

        logger.info(f"Bun/Deno Fingerprinter v{self.version} starting on {host}")

        client = create_protected_client(
            timeout=30.0,
            verify_ssl=self._ssl_verify,
            follow_redirects=True,
            custom_headers=self._auth_headers,
        )

        async with client:
            # Phase 1: Detect runtime via headers and errors
            await self._detect_runtime(client, base_url, rate_limiter)

            if not self.detected_runtimes:
                logger.info("No Bun/Deno/modern runtime detected")
                return {
                    "module": self.name,
                    "version": self.version,
                    "findings": [],
                    "runtime_detected": False,
                }

            primary_runtime = self.detected_runtimes[0]
            logger.info(f"Detected runtime: {primary_runtime.runtime.value} v{primary_runtime.version or 'unknown'}")

            # Phase 2: Check for config/import map exposure
            await self._check_config_exposure(client, base_url, rate_limiter)

            # Phase 3: Analyze Deno permissions (if Deno)
            if primary_runtime.runtime in [JSRuntime.DENO, JSRuntime.DENO_DEPLOY]:
                await self._analyze_deno_permissions(client, base_url, rate_limiter)

            # Phase 4: Check for dangerous API exposure (Bun)
            if primary_runtime.runtime == JSRuntime.BUN:
                await self._check_bun_dangerous_apis(client, base_url, rate_limiter)

            # Phase 5: Check for known vulnerable versions
            await self._check_known_vulnerabilities()

            # Phase 6: Check for debug/development mode
            await self._check_debug_mode(client, base_url, rate_limiter)

        logger.info(f"Fingerprinting complete. Found {len(self.findings)} issues")

        return {
            "module": self.name,
            "version": self.version,
            "findings": self.findings,
            "runtime_detected": True,
            "runtimes": [
                {
                    "runtime": r.runtime.value,
                    "version": r.version,
                    "detected_via": r.detected_via,
                    "permissions": r.permissions,
                    "features": r.features,
                    "confidence": r.confidence,
                }
                for r in self.detected_runtimes
            ],
        }

    async def _detect_runtime(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Detect runtime via headers and error messages."""
        logger.debug("Phase 1: Detecting runtime")

        # Test main URL
        if rate_limiter:
            await rate_limiter.acquire()

        try:
            response = await client.get(base_url)
            self._analyze_response_for_runtime(response, base_url)

        except Exception as e:
            logger.debug(f"Main URL detection error: {e}")

        # Trigger error responses for more fingerprinting
        error_endpoints = [
            "/nonexistent-endpoint-12345",
            "/__debug__",
            "/error",
            "/?__error=true",
        ]

        for ep_path in error_endpoints:
            if rate_limiter:
                await rate_limiter.acquire()

            url = urljoin(base_url, ep_path)
            try:
                response = await client.get(url)
                self._analyze_response_for_runtime(response, url)

            except Exception:
                pass

        # Check runtime-specific endpoints
        for runtime, fingerprint in RUNTIME_FINGERPRINTS.items():
            for api_endpoint in fingerprint.get("apis", []):
                if rate_limiter:
                    await rate_limiter.acquire()

                url = urljoin(base_url, api_endpoint)
                try:
                    response = await client.get(url)

                    if response.status_code == 200:
                        # Found runtime-specific file
                        existing = [r for r in self.detected_runtimes if r.runtime == runtime]
                        if existing:
                            existing[0].features.append(api_endpoint)
                        else:
                            self.detected_runtimes.append(RuntimeInfo(
                                runtime=runtime,
                                detected_via=f"api_endpoint:{api_endpoint}",
                                confidence_score=75,
                                features=[api_endpoint],
                            ))

                except Exception:
                    pass

    def _analyze_response_for_runtime(
        self,
        response: httpx.Response,
        url: str,
    ) -> None:
        """Analyze response headers and body for runtime fingerprints."""
        headers = {k.lower(): v for k, v in response.headers.items()}
        body = response.text

        for runtime, fingerprint in RUNTIME_FINGERPRINTS.items():
            best_match_confidence = 0
            detected_via = ""
            version = ""

            # Check headers
            for header_name, pattern, confidence in fingerprint.get("headers", []):
                if header_name in headers:
                    match = re.search(pattern, headers[header_name], re.IGNORECASE)
                    if match:
                        if confidence > best_match_confidence:
                            best_match_confidence = confidence
                            detected_via = f"header:{header_name}"

                            # Extract version if present
                            version_match = re.search(r'[\d.]+', headers[header_name])
                            if version_match:
                                version = version_match.group()

            # Check error patterns in body
            for error_pattern, confidence in fingerprint.get("errors", []):
                if re.search(error_pattern, body, re.IGNORECASE):
                    if confidence > best_match_confidence:
                        best_match_confidence = confidence
                        detected_via = f"error_pattern:{error_pattern[:30]}"

            # Add runtime if confidence threshold met
            if best_match_confidence >= 70:
                # Check if already detected
                existing = [r for r in self.detected_runtimes if r.runtime == runtime]
                if existing:
                    if best_match_confidence > existing[0].confidence:
                        existing[0].confidence = best_match_confidence
                        existing[0].detected_via = detected_via
                        if version:
                            existing[0].version = version
                else:
                    self.detected_runtimes.append(RuntimeInfo(
                        runtime=runtime,
                        version=version,
                        detected_via=detected_via,
                        confidence_score=best_match_confidence,
                    ))

    async def _check_config_exposure(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Check for exposed configuration files."""
        logger.debug("Phase 2: Checking config exposure")

        config_files = [
            # Deno
            ("/deno.json", "Deno configuration"),
            ("/deno.jsonc", "Deno configuration (JSONC)"),
            ("/deno.lock", "Deno lock file"),
            ("/import_map.json", "Deno import map"),

            # Bun
            ("/bunfig.toml", "Bun configuration"),
            ("/bun.lockb", "Bun lock file"),

            # Node (for comparison)
            ("/package.json", "Node.js package manifest"),
            ("/package-lock.json", "Node.js lock file"),

            # Generic
            ("/.env", "Environment variables"),
            ("/.env.local", "Local environment variables"),
        ]

        for path, description in config_files:
            if rate_limiter:
                await rate_limiter.acquire()

            url = urljoin(base_url, path)
            try:
                response = await client.get(url)

                if response.status_code == 200:
                    body = response.text

                    # Determine severity based on content
                    severity = "LOW"
                    sensitive_patterns = [
                        (r'"(api_?key|apikey|secret|password|token)"', "HIGH"),
                        (r"(API_KEY|SECRET|PASSWORD|TOKEN)=", "HIGH"),
                        (r'"private":\s*true', "MEDIUM"),
                        (r'"allow-(read|write|net|run|all)"', "MEDIUM"),
                    ]

                    evidence = [f"Config file exposed: {path}"]

                    for pattern, sev in sensitive_patterns:
                        if re.search(pattern, body, re.IGNORECASE):
                            if sev == "HIGH":
                                severity = "HIGH"
                            elif sev == "MEDIUM" and severity != "HIGH":
                                severity = "MEDIUM"
                            evidence.append(f"Contains sensitive pattern: {pattern[:30]}")

                    # Determine runtime from config type
                    runtime = JSRuntime.UNKNOWN
                    if "deno" in path.lower():
                        runtime = JSRuntime.DENO
                    elif "bun" in path.lower():
                        runtime = JSRuntime.BUN
                    elif "package" in path.lower():
                        runtime = JSRuntime.NODE

                    result = RuntimeTestResult(
                        vulnerable=True,
                        vuln_type=RuntimeVulnType.CONFIG_EXPOSURE,
                        confidence_score=85,
                        runtime=runtime,
                        evidence=evidence,
                        severity=severity,
                        cwe_id="CWE-200",
                    )

                    self._add_finding(
                        name=f"Runtime Configuration Exposed ({description})",
                        description=(
                            f"Runtime configuration file '{path}' is publicly accessible. "
                            "This may reveal dependencies, scripts, or sensitive configuration."
                        ),
                        endpoint=url,
                        result=result,
                    )

            except Exception as e:
                logger.debug(f"Config check error for {path}: {e}")

    async def _analyze_deno_permissions(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Analyze Deno permission configuration."""
        logger.debug("Phase 3: Analyzing Deno permissions")

        # Try to trigger permission errors to understand config
        permission_tests = [
            # Test read permission
            ({"path": "/etc/passwd"}, "allow-read", "File read attempted"),
            ({"file": "file:///etc/passwd"}, "allow-read", "File URL read attempted"),

            # Test write permission
            ({"write_path": "/tmp/test"}, "allow-write", "File write attempted"),

            # Test net permission
            ({"url": "http://internal/"}, "allow-net", "Network access attempted"),

            # Test env permission
            ({"env": "PATH"}, "allow-env", "Env access attempted"),

            # Test run permission
            ({"cmd": "ls"}, "allow-run", "Command execution attempted"),
        ]

        detected_permissions = set()
        permission_issues = []

        for payload, permission, description in permission_tests:
            if rate_limiter:
                await rate_limiter.acquire()

            try:
                response = await client.post(base_url, json=payload)
                body = response.text.lower()

                # Check if permission was denied (good) or allowed (bad)
                if "permissiondenied" in body or "permission" in body:
                    # Permission is properly restricted
                    pass
                elif response.status_code == 200 and any(
                    indicator in body for indicator in ["success", "ok", "result", "data"]
                ):
                    # Permission might be granted
                    detected_permissions.add(permission)
                    permission_issues.append(f"{permission}: {description}")

            except Exception:
                pass

        # Check for --allow-all
        deno_runtimes = [r for r in self.detected_runtimes if r.runtime in [JSRuntime.DENO, JSRuntime.DENO_DEPLOY]]
        for runtime_info in deno_runtimes:
            runtime_info.permissions = list(detected_permissions)

        if detected_permissions:
            severity = "CRITICAL" if "allow-run" in detected_permissions else "HIGH"

            result = RuntimeTestResult(
                vulnerable=True,
                vuln_type=RuntimeVulnType.PERMISSION_MISCONFIGURATION,
                confidence_score=70,
                runtime=JSRuntime.DENO,
                evidence=[
                    f"Detected permissions: {list(detected_permissions)}",
                    "Broad permissions may allow unintended access",
                ] + permission_issues,
                severity=severity,
                cwe_id="CWE-250",
            )

            self._add_finding(
                name="Deno Overly Permissive Configuration",
                description=(
                    "Deno runtime appears to have broad permissions enabled. "
                    f"Detected: {', '.join(detected_permissions)}. "
                    "Consider using more restrictive permissions."
                ),
                endpoint=base_url,
                result=result,
            )

    async def _check_bun_dangerous_apis(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Check for dangerous Bun API exposure."""
        logger.debug("Phase 4: Checking Bun dangerous APIs")

        # Try to trigger error messages that reveal API usage
        api_probes = [
            {"spawn": True},
            {"file": "/etc/passwd"},
            {"ffi": "test"},
            {"sql": "SELECT 1"},
        ]

        exposed_apis = []

        for probe in api_probes:
            if rate_limiter:
                await rate_limiter.acquire()

            try:
                response = await client.post(base_url, json=probe)
                body = response.text

                # Check for Bun API indicators in response/error
                for api_name, api_info in BUN_DANGEROUS_APIS.items():
                    if api_name.lower() in body.lower():
                        exposed_apis.append((api_name, api_info))

            except Exception:
                pass

        if exposed_apis:
            most_severe = max(exposed_apis, key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[x[1]["severity"]])
            severity = most_severe[1]["severity"]

            result = RuntimeTestResult(
                vulnerable=True,
                vuln_type=RuntimeVulnType.UNSAFE_API_EXPOSED,
                confidence_score=65,
                runtime=JSRuntime.BUN,
                evidence=[
                    f"Exposed Bun APIs: {[a[0] for a in exposed_apis]}",
                ] + [f"{a[0]}: {a[1]['description']}" for a in exposed_apis],
                severity=severity,
                cwe_id="CWE-250",
            )

            self._add_finding(
                name="Bun Dangerous API Exposure",
                description=(
                    "Bun runtime exposes potentially dangerous APIs. "
                    f"Detected: {', '.join(a[0] for a in exposed_apis)}"
                ),
                endpoint=base_url,
                result=result,
            )

    async def _check_known_vulnerabilities(self) -> None:
        """Check detected runtime versions for known vulnerabilities."""
        logger.debug("Phase 5: Checking known vulnerabilities")

        for runtime_info in self.detected_runtimes:
            if not runtime_info.version:
                continue

            fingerprint = RUNTIME_FINGERPRINTS.get(runtime_info.runtime, {})
            known_vulns = fingerprint.get("known_vulns", {})

            for vuln_version, cves in known_vulns.items():
                if cves and self._version_affected(runtime_info.version, vuln_version):
                    result = RuntimeTestResult(
                        vulnerable=True,
                        vuln_type=RuntimeVulnType.OUTDATED_RUNTIME,
                        confidence_score=90,
                        runtime=runtime_info.runtime,
                        evidence=[
                            f"Runtime: {runtime_info.runtime.value} v{runtime_info.version}",
                            f"Known CVEs: {', '.join(cves)}",
                            "Update to latest version recommended",
                        ],
                        severity=Severity.HIGH,
                        cwe_id="CWE-1104",
                    )

                    self._add_finding(
                        name=f"Outdated {runtime_info.runtime.value.title()} Version",
                        description=(
                            f"{runtime_info.runtime.value.title()} version {runtime_info.version} "
                            f"has known vulnerabilities: {', '.join(cves)}"
                        ),
                        endpoint="",
                        result=result,
                    )

    def _version_affected(self, current: str, vulnerable: str) -> bool:
        """Check if current version is affected by vulnerable version."""
        try:
            current_parts = [int(x) for x in current.split(".")[:3]]
            vuln_parts = [int(x) for x in vulnerable.split(".")[:3]]

            # Simple comparison - current <= vulnerable
            for c, v in zip(current_parts, vuln_parts):
                if c < v:
                    return True
                elif c > v:
                    return False

            return True  # Equal versions

        except Exception:
            return False

    async def _check_debug_mode(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Check for debug/development mode indicators."""
        logger.debug("Phase 6: Checking debug mode")

        debug_endpoints = [
            "/__debug__",
            "/debug",
            "/_debug",
            "/?debug=true",
            "/?dev=true",
        ]

        debug_indicators = [
            r"stack\s*trace",
            r"error\s*at\s*",
            r"file://",
            r"line\s*\d+",
            r"column\s*\d+",
            r"debugger",
            r"development\s*mode",
            r"hot\s*reload",
            r"hmr",
        ]

        for ep_path in debug_endpoints:
            if rate_limiter:
                await rate_limiter.acquire()

            url = urljoin(base_url, ep_path)
            try:
                response = await client.get(url)
                body = response.text.lower()

                found_indicators = []
                for pattern in debug_indicators:
                    if re.search(pattern, body, re.IGNORECASE):
                        found_indicators.append(pattern)

                if found_indicators:
                    result = RuntimeTestResult(
                        vulnerable=True,
                        vuln_type=RuntimeVulnType.DEBUG_MODE_ENABLED,
                        confidence_score=70,
                        runtime=self.detected_runtimes[0].runtime if self.detected_runtimes else JSRuntime.UNKNOWN,
                        evidence=[
                            f"Debug endpoint: {ep_path}",
                            f"Debug indicators: {found_indicators[:5]}",
                        ],
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-215",
                    )

                    self._add_finding(
                        name="Runtime Debug Mode Enabled",
                        description=(
                            f"Debug mode appears to be enabled. "
                            f"Endpoint {ep_path} reveals debug information."
                        ),
                        endpoint=url,
                        result=result,
                    )
                    break  # One finding is enough

            except Exception:
                pass

    def _add_finding(
        self,
        name: str,
        description: str,
        endpoint: str,
        result: RuntimeTestResult,
    ) -> None:
        """Add a finding to the results."""
        finding = Finding(
            vuln_type=VulnType.INFO_DISCLOSURE,
            name=name,
            severity=result.severity,
            confidence_score=float(result.confidence),
            description=description,
            url=endpoint or "N/A",
            endpoint=endpoint or "N/A",
            evidence=result.evidence,
            metadata={
                "runtime_vuln_type": result.vuln_type.name,
                "runtime": result.runtime.value,
                "cwe": result.cwe,
            },
        )

        self.findings.append(finding.to_dict())

        logger.info(
            f"Runtime issue [{result.severity}]: {name} "
            f"| Runtime: {result.runtime.value} | Confidence: {result.confidence}%"
        )


# Export
__all__ = [
    "BunDenoFingerprinter",
    "JSRuntime",
    "RuntimeVulnType",
    "BUN_DENO_FINGERPRINTER_VERSION",
]
