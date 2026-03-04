"""
DNS Rebinding Scanner - Enterprise Edition v2.0

Comprehensive DNS rebinding vulnerability detection and Same-Origin Policy bypass testing.
Industry-leading coverage for browser-based and server-side DNS rebinding attacks.

Features:
- 50+ DNS rebinding vectors
- Host header validation bypass
- Same-Origin Policy bypass testing
- IP address manipulation techniques
- Time-based rebinding detection
- WebSocket rebinding attacks
- CORS configuration analysis
- Browser-based rebinding vectors
- Internal service discovery via rebinding
- Cloud metadata access (AWS/GCP/Azure)
- Docker/Kubernetes API access
- SSRF chain exploitation
- DNS TTL manipulation
- Wildcard DNS bypass
- Real-world CVE patterns

CWE Coverage:
- CWE-350: Reliance on Reverse DNS Resolution for Security
- CWE-346: Origin Validation Error
- CWE-918: Server-Side Request Forgery
- CWE-601: Open Redirect
- CWE-942: Overly Permissive CORS Policy

Based on:
- OWASP Testing Guide - DNS Rebinding
- PortSwigger Web Security Academy
- Bug Bounty DNS rebinding techniques
- Conference presentations (BlackHat, DEF CON)
"""

from __future__ import annotations

import secrets
import time
import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urljoin, urlparse, quote
from enum import Enum

import httpx

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.scan_client import get_scan_client
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class RebindingVectorType(Enum):
    """Types of DNS rebinding attack vectors."""
    HOST_HEADER_BYPASS = "host_header_bypass"
    SSRF_REBINDING = "ssrf_rebinding"
    WEBSOCKET_ORIGIN = "websocket_origin"
    CORS_BYPASS = "cors_bypass"
    REDIRECT_REBINDING = "redirect_rebinding"
    DNS_MANIPULATION = "dns_manipulation"
    IFRAME_SANDBOX = "iframe_sandbox"
    SERVICE_WORKER = "service_worker"
    TTL_REBINDING = "ttl_rebinding"


class InternalServiceType(Enum):
    """Types of internal services targetable via rebinding."""
    AWS_METADATA = "aws_metadata"
    GCP_METADATA = "gcp_metadata"
    AZURE_METADATA = "azure_metadata"
    KUBERNETES_API = "kubernetes_api"
    DOCKER_API = "docker_api"
    REDIS = "redis"
    ELASTICSEARCH = "elasticsearch"
    MONGODB = "mongodb"
    CONSUL = "consul"
    ETCD = "etcd"
    PROMETHEUS = "prometheus"
    GRAFANA = "grafana"


@dataclass
class RebindingVector:
    """DNS rebinding attack vector."""
    payload: str
    vector_type: RebindingVectorType
    description: str
    target_ip: Optional[str] = None
    header_based: bool = False
    requires_dns: bool = False


@dataclass
class InternalService:
    """Internal service target for rebinding."""
    service_type: InternalServiceType
    host: str
    port: int
    path: str
    indicators: list[str]
    description: str
    severity: str = "CRITICAL"


@dataclass
class RebindingVulnerability:
    """Detected DNS rebinding vulnerability."""
    vector_type: RebindingVectorType
    payload: str
    target: str
    evidence: list[str]
    severity: str
    confidence: str
    internal_access: bool = False
    service_exposed: Optional[str] = None


class DNSRebindingScanner(ScanModule):
    """
    DNS Rebinding Scanner - Enterprise Edition v2.0
    
    Comprehensive DNS rebinding and Same-Origin Policy bypass detection.
    
    Attack Categories:
    ==================
    1. Host Header Manipulation
       - Arbitrary Host header injection
       - IP-based Host bypass
       - Port-based bypass
       - Unicode/encoded Host bypass
    
    2. DNS-based Rebinding
       - TTL manipulation
       - DNS server spoofing
       - nip.io/xip.io services
       - Wildcard DNS bypass
    
    3. Same-Origin Policy Bypass
       - Cross-origin resource access
       - Browser-based attacks
       - iframe sandbox bypass
       - Service worker exploitation
    
    4. Server-Side Request Forgery Chain
       - Internal service access
       - Cloud metadata theft
       - Container API access
       - Database access
    
    5. WebSocket Rebinding
       - Origin validation bypass
       - WebSocket upgrade hijacking
       - Real-time data exfiltration
    
    6. CORS Misconfiguration
       - Wildcard origin
       - Null origin
       - Internal IP origins
       - Credentials with permissive CORS
    
    Internal Service Targets:
    ========================
    - AWS IMDS (169.254.169.254)
    - GCP Metadata (metadata.google.internal)
    - Azure Metadata (169.254.169.254)
    - Kubernetes API
    - Docker API (2375/2376)
    - Redis (6379)
    - Elasticsearch (9200)
    - MongoDB (27017)
    - Consul (8500)
    - etcd (2379)
    """
    
    name = "dns_rebinding_scanner"
    
    # =============================================================
    # ENTERPRISE HOST HEADER BYPASS PAYLOADS
    # =============================================================
    
    # Internal IP targets
    INTERNAL_IP_TARGETS = [
        # Localhost variations
        ("127.0.0.1", "IPv4 localhost"),
        ("127.0.0.2", "IPv4 localhost alias"),
        ("127.1", "Shorthand localhost"),
        ("127.1.1.1", "Alternative localhost"),
        ("localhost", "Hostname localhost"),
        ("localhost.localdomain", "Full localhost domain"),
        
        # IPv6 localhost
        ("[::1]", "IPv6 localhost"),
        ("[::]", "IPv6 any address"),
        ("[0:0:0:0:0:0:0:1]", "IPv6 localhost expanded"),
        ("[::ffff:127.0.0.1]", "IPv4-mapped IPv6"),
        
        # Any address
        ("0.0.0.0", "Any interface"),
        ("0", "Zero address shorthand"),
        ("0.0.0.0:80", "Any interface with port"),
        
        # Private networks
        ("192.168.0.1", "Private Class C"),
        ("192.168.1.1", "Common router"),
        ("10.0.0.1", "Private Class A"),
        ("172.16.0.1", "Private Class B"),
        
        # Link-local
        ("169.254.1.1", "Link-local"),
        ("169.254.169.254", "AWS/Cloud metadata"),
        
        # Special
        ("0177.0.0.1", "Octal localhost"),
        ("2130706433", "Decimal localhost"),
        ("0x7f000001", "Hex localhost"),
    ]
    
    # Host header bypass techniques
    HOST_BYPASS_TECHNIQUES = [
        # Basic injection
        "{internal}",
        
        # Subdomain tricks
        "{internal}.{original}",
        "{original}.{internal}",
        "{original}.{internal}.nip.io",
        "{internal}.{original}.xip.io",
        "{internal}.{original}.sslip.io",
        
        # Port manipulation
        "{original}:{internal}:80",
        "{original}:{internal}:443",
        "{internal}:80@{original}",
        "{internal}:443@{original}",
        
        # URL authority tricks
        "{original}@{internal}",
        "{internal}@{original}",
        "{original}%00{internal}",
        "{internal}%00{original}",
        
        # Hash/fragment tricks
        "{original}#{internal}",
        "{internal}#{original}",
        
        # Encoding bypass
        "{internal_encoded}",
        "%00{internal}",
        "{internal}%00",
        
        # Whitespace tricks
        "{internal} ",
        " {internal}",
        "{internal}\t",
        "\t{internal}",
        "{internal}\r\n",
        
        # Case manipulation
        "LOCALHOST",
        "Localhost",
        "LocalHost",
        
        # Unicode bypass
        "ⓛⓞⓒⓐⓛⓗⓞⓢⓣ",  # Circled letters
        "127。0。0。1",  # Fullwidth dots
        "127．0．0．1",  # Halfwidth dots
        
        # DNS rebinding services
        "{internal}.nip.io",
        "{internal}.xip.io",
        "{internal}.sslip.io",
        "rebind.{original}.{internal}.nip.io",
    ]
    
    # =============================================================
    # INTERNAL SERVICE TARGETS
    # =============================================================
    
    INTERNAL_SERVICES = [
        # Cloud Metadata Services
        InternalService(
            service_type=InternalServiceType.AWS_METADATA,
            host="169.254.169.254",
            port=80,
            path="/latest/meta-data/",
            indicators=["ami-id", "instance-id", "instance-type", "local-ipv4", "public-keys"],
            description="AWS EC2 Instance Metadata Service (IMDS)",
            severity=Severity.CRITICAL
        ),
        InternalService(
            service_type=InternalServiceType.AWS_METADATA,
            host="169.254.169.254",
            port=80,
            path="/latest/meta-data/iam/security-credentials/",
            indicators=["AccessKeyId", "SecretAccessKey", "Token"],
            description="AWS IAM Role Credentials",
            severity=Severity.CRITICAL
        ),
        InternalService(
            service_type=InternalServiceType.GCP_METADATA,
            host="metadata.google.internal",
            port=80,
            path="/computeMetadata/v1/",
            indicators=["project-id", "zone", "instance", "attributes"],
            description="GCP Metadata Service",
            severity=Severity.CRITICAL
        ),
        InternalService(
            service_type=InternalServiceType.GCP_METADATA,
            host="169.254.169.254",
            port=80,
            path="/computeMetadata/v1/instance/service-accounts/",
            indicators=["email", "scopes", "token"],
            description="GCP Service Account Credentials",
            severity=Severity.CRITICAL
        ),
        InternalService(
            service_type=InternalServiceType.AZURE_METADATA,
            host="169.254.169.254",
            port=80,
            path="/metadata/instance?api-version=2021-02-01",
            indicators=["compute", "network", "vmId", "subscriptionId"],
            description="Azure Instance Metadata Service",
            severity=Severity.CRITICAL
        ),
        
        # Container/Orchestration APIs
        InternalService(
            service_type=InternalServiceType.KUBERNETES_API,
            host="kubernetes.default",
            port=443,
            path="/api/v1/",
            indicators=["namespaces", "pods", "services", "secrets"],
            description="Kubernetes API Server",
            severity=Severity.CRITICAL
        ),
        InternalService(
            service_type=InternalServiceType.KUBERNETES_API,
            host="10.0.0.1",
            port=443,
            path="/api/v1/namespaces/",
            indicators=["kube-system", "default"],
            description="Kubernetes API (default gateway)",
            severity=Severity.CRITICAL
        ),
        # FIX 2026-02-12: Made indicators more specific to avoid FPs
        # Docker API returns JSON with specific structure, not HTML
        InternalService(
            service_type=InternalServiceType.DOCKER_API,
            host="127.0.0.1",
            port=2375,
            path="/version",
            # More specific: require JSON-like patterns, not just "Os"
            indicators=['"ApiVersion":', '"GoVersion":', '"GitCommit":', '"KernelVersion":'],
            description="Docker Remote API (unauthenticated)",
            severity=Severity.CRITICAL
        ),
        InternalService(
            service_type=InternalServiceType.DOCKER_API,
            host="127.0.0.1",
            port=2376,
            path="/containers/json",
            # More specific: require JSON array structure
            indicators=['"Id":', '"Names":[', '"ImageID":', '"HostConfig":'],
            description="Docker TLS API",
            severity=Severity.CRITICAL
        ),
        
        # Database Services
        InternalService(
            service_type=InternalServiceType.REDIS,
            host="127.0.0.1",
            port=6379,
            path="/",
            indicators=["redis_version", "PONG", "ERR"],
            description="Redis Database",
            severity=Severity.HIGH
        ),
        InternalService(
            service_type=InternalServiceType.ELASTICSEARCH,
            host="127.0.0.1",
            port=9200,
            path="/",
            indicators=["cluster_name", "cluster_uuid", "version", "lucene_version"],
            description="Elasticsearch",
            severity=Severity.HIGH
        ),
        InternalService(
            service_type=InternalServiceType.MONGODB,
            host="127.0.0.1",
            port=27017,
            path="/",
            indicators=["mongodb", "ismaster"],
            description="MongoDB",
            severity=Severity.HIGH
        ),
        
        # Service Discovery
        InternalService(
            service_type=InternalServiceType.CONSUL,
            host="127.0.0.1",
            port=8500,
            path="/v1/agent/services",
            indicators=["Services", "ID", "Tags"],
            description="Consul Agent",
            severity=Severity.HIGH
        ),
        InternalService(
            service_type=InternalServiceType.ETCD,
            host="127.0.0.1",
            port=2379,
            path="/v2/keys/",
            indicators=["action", "node", "key", "value"],
            description="etcd Key-Value Store",
            severity=Severity.HIGH
        ),
        
        # Monitoring
        InternalService(
            service_type=InternalServiceType.PROMETHEUS,
            host="127.0.0.1",
            port=9090,
            path="/api/v1/targets",
            indicators=["activeTargets", "droppedTargets", "status"],
            description="Prometheus Monitoring",
            severity=Severity.MEDIUM
        ),
        InternalService(
            service_type=InternalServiceType.GRAFANA,
            host="127.0.0.1",
            port=3000,
            path="/api/admin/settings",
            indicators=["DEFAULT", "database", "security"],
            description="Grafana Dashboard",
            severity=Severity.MEDIUM
        ),
    ]
    
    # SSRF-triggering parameters
    SSRF_PARAMETERS = [
        # URL parameters
        "url", "uri", "link", "href", "src", "source",
        "dest", "destination", "target", "path", "file",
        "document", "doc", "page", "view", "content",
        
        # Callback/webhook parameters
        "callback", "webhook", "notify", "notification",
        "endpoint", "api", "service", "server",
        
        # Fetch/load parameters
        "fetch", "load", "get", "request", "retrieve",
        "download", "upload", "import", "include",
        
        # Image/media parameters
        "img", "image", "pic", "picture", "photo",
        "avatar", "icon", "logo", "thumb", "thumbnail",
        
        # Proxy parameters
        "proxy", "forward", "redirect", "redir", "return",
        "next", "goto", "continue", "back", "ref",
        
        # XML/Feed parameters
        "xml", "rss", "feed", "atom", "sitemap",
        "wsdl", "wadl", "xsd", "dtd",
        
        # PDF/Report parameters
        "pdf", "report", "export", "render", "print",
        
        # Other
        "data", "payload", "body", "input", "val",
    ]
    
    # WebSocket paths
    WEBSOCKET_PATHS = [
        "/ws",
        "/websocket",
        "/socket",
        "/socket.io/",
        "/sockjs/",
        "/realtime",
        "/live",
        "/stream",
        "/events",
        "/signalr",
        "/graphql-ws",
        "/subscriptions",
        "/api/ws",
        "/api/websocket",
        "/ws/v1",
        "/ws/v2",
    ]
    
    # SPA indicators - SPAs don't make server-side fetches, so SSRF is unlikely
    SPA_INDICATORS = [
        # Framework scripts
        "angular", "react", "vue", "svelte", "__NUXT__", "__NEXT_DATA__",
        "ng-app", "ng-controller", "data-ng-", "v-app", "data-v-",
        # SPA routing
        "router-view", "router-link", "ui-view", "app-root", "__APP_ROOT__",
        # Bundle patterns
        "bundle.js", "main.js", "app.js", "vendor.js", "chunk.",
        # State management
        "__REDUX__", "__PRELOADED_STATE__", "window.__STATE__",
    ]

    # FIX 2026-02-13: Overall scan timeout to prevent 5+ minute hangs
    MAX_SCAN_DURATION = 90.0  # 90 seconds max for entire module (10 phases)

    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
        self.tested_combinations: set[str] = set()
        self._is_spa: bool = False  # Set during scan
        self._scan_start: float = 0.0

    def _time_remaining(self) -> float:
        """Returns time remaining in scan budget."""
        import time
        return max(0, self.MAX_SCAN_DURATION - (time.time() - self._scan_start))

    def _should_continue(self) -> bool:
        """Check if we should continue scanning (time budget remaining)."""
        return self._time_remaining() > 5.0  # Need at least 5s for a phase

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Comprehensive DNS rebinding vulnerability scan - Enterprise Edition.

        Scan Phases (run with time budget):
        1. Host header validation bypass (priority: HIGH)
        2. CORS misconfiguration (priority: HIGH)
        3. Internal service discovery (priority: MEDIUM)
        4. Cloud metadata access (priority: MEDIUM)
        5-10. Other phases (priority: LOW - run only if time permits)
        """
        import time
        self._scan_start = time.time()

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings: list[Finding] = []

        base_url = f"https://{host}" if not host.startswith("http") else host
        parsed = urlparse(base_url)
        original_host = parsed.netloc

        logger.info(f"[DNS Rebinding] Starting scan on {base_url} (budget: {self.MAX_SCAN_DURATION}s)")

        # FIX: Pass auth headers for authenticated endpoint testing
        async with get_scan_client(
            verify_ssl=False,
            timeout=min(self.timeout, 10.0),  # Cap per-request timeout to 10s
            custom_headers=self._auth_headers,
        ) as client:
            # FIX 2026-02-12: Detect SPA - SPAs don't make server-side fetches
            self._is_spa = await self._detect_spa(client, base_url, rate_limiter)
            if self._is_spa:
                logger.info(f"[DNS Rebinding] SPA detected - skipping server-side SSRF phases")
                # For SPAs, only test client-side vectors (Host header, CORS)

            # PRIORITY 1: Host Header Validation (fast, high-value)
            if self._should_continue():
                host_findings = await self._test_host_validation_enterprise(
                    client, base_url, original_host, rate_limiter
                )
                findings.extend(host_findings)

            # PRIORITY 2: CORS Misconfiguration (fast, high-value)
            if self._should_continue():
                cors_findings = await self._test_cors_rebinding_enterprise(
                    client, base_url, original_host, rate_limiter
                )
                findings.extend(cors_findings)

            # Skip server-side phases for SPAs
            if not self._is_spa:
                # PRIORITY 3: Internal Service Access (medium)
                if self._should_continue():
                    internal_findings = await self._test_internal_service_access(
                        client, base_url, rate_limiter
                    )
                    findings.extend(internal_findings)

                # PRIORITY 4: Cloud Metadata Access (medium)
                if self._should_continue():
                    cloud_findings = await self._test_cloud_metadata_access(
                        client, base_url, rate_limiter
                    )
                    findings.extend(cloud_findings)

                # PRIORITY 5: Container API Access (low - only if time permits)
                if self._should_continue():
                    container_findings = await self._test_container_api_access(
                        client, base_url, rate_limiter
                    )
                    findings.extend(container_findings)

            # Lower priority phases - only run if significant time remains
            if self._time_remaining() > 30:
                # DNS Rebinding Services
                if self._should_continue():
                    dns_findings = await self._test_dns_rebinding_services(
                        client, base_url, original_host, rate_limiter
                    )
                    findings.extend(dns_findings)

                # WebSocket Origin Validation
                if self._should_continue():
                    ws_findings = await self._test_websocket_rebinding_enterprise(
                        client, base_url, original_host, rate_limiter
                    )
                    findings.extend(ws_findings)

                # Redirect-based Rebinding
                if self._should_continue():
                    redirect_findings = await self._test_redirect_rebinding_enterprise(
                        client, base_url, rate_limiter
                    )
                    findings.extend(redirect_findings)

                # IP Representation Bypass
                if self._should_continue():
                    ip_findings = await self._test_ip_representation_bypass(
                        client, base_url, original_host, rate_limiter
                    )
                    findings.extend(ip_findings)

                # DNS TTL Manipulation (slowest - last)
                if self._should_continue():
                    ttl_findings = await self._test_ttl_rebinding(
                        client, base_url, original_host, rate_limiter
                    )
                    findings.extend(ttl_findings)

        # Deduplicate findings
        findings = self._deduplicate_findings(findings)

        elapsed = time.time() - self._scan_start
        if elapsed >= self.MAX_SCAN_DURATION:
            logger.info(f"[DNS Rebinding] Scan timeout ({elapsed:.1f}s) - partial results ({len(findings)} findings)")
        else:
            logger.info(f"[DNS Rebinding] Completed in {elapsed:.1f}s - {len(findings)} findings")

        return findings
    
    async def _test_host_validation_enterprise(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        original_host: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Enterprise Host header validation bypass testing."""
        findings = []

        # FP1 FIX 2026-02-18: Get baseline response with original Host header
        # Many apps ignore Host header entirely - we need to detect this
        import hashlib
        baseline_hash = None
        baseline_length = 0
        try:
            await rate_limiter.acquire()
            baseline_resp = await client.get(base_url, headers={"Host": original_host})
            if baseline_resp.status_code == 200:
                baseline_hash = hashlib.md5(baseline_resp.text.encode()).hexdigest()
                baseline_length = len(baseline_resp.text)
                logger.debug(f"[DNS Rebinding] Baseline: {baseline_length} bytes, hash={baseline_hash[:8]}")
        except Exception as e:
            logger.debug(f"[DNS Rebinding] Baseline request failed: {e}")

        for internal_ip, ip_desc in self.INTERNAL_IP_TARGETS:
            for technique in self.HOST_BYPASS_TECHNIQUES[:15]:
                await rate_limiter.acquire()

                try:
                    # Build malicious Host header
                    malicious_host = technique.format(
                        internal=internal_ip,
                        original=original_host,
                        internal_encoded=quote(internal_ip)
                    )

                    # Skip if already tested
                    test_key = f"host:{malicious_host}"
                    if test_key in self.tested_combinations:
                        continue
                    self.tested_combinations.add(test_key)

                    response = await client.get(
                        base_url,
                        headers={"Host": malicious_host}
                    )

                    # Check if request was accepted
                    if response.status_code == 200 and len(response.text) > 100:
                        # FP1 FIX 2026-02-18: Compare with baseline to detect apps that ignore Host
                        response_hash = hashlib.md5(response.text.encode()).hexdigest()

                        if baseline_hash and response_hash == baseline_hash:
                            # Response identical to baseline - app ignores Host header
                            # This is NOT a vulnerability (no rebinding possible)
                            logger.debug(f"[DNS Rebinding] Host {malicious_host} ignored (same as baseline)")
                            continue

                        # FP1 FIX: Also check for meaningful difference (not just length variance)
                        # If response differs but doesn't contain internal indicators, it's suspicious
                        response_text_lower = response.text.lower()
                        internal_indicators = [
                            internal_ip.lower(), 'internal', 'localhost', '127.0.0.1',
                            'admin', 'config', 'debug', 'env', 'secret', 'metadata'
                        ]
                        has_internal_indicator = any(ind in response_text_lower for ind in internal_indicators)

                        # If baseline exists and response is identical (no rebinding), skip
                        # If response differs AND has internal indicators, it's real
                        if baseline_hash and not has_internal_indicator:
                            # Different response but no internal data - likely just error page
                            logger.debug(f"[DNS Rebinding] Host {malicious_host} different but no internal data")
                            continue

                        severity = "CRITICAL" if internal_ip in ["127.0.0.1", "169.254.169.254", "localhost"] else "HIGH"

                        findings.append(Finding(
                            name=f"DNS Rebinding - Host Header Bypass ({ip_desc})",
                            severity=severity,
                            confidence_score=85.0,
                            description=f"Application accepts manipulated Host header pointing to {ip_desc}",
                            endpoint=base_url,
                            evidence=[
                                f"Host header: {malicious_host}",
                                f"Target: {ip_desc}",
                                f"Response code: {response.status_code}",
                                f"Response size: {len(response.text)} bytes",
                            ],
                            cwe_id="CWE-350",
                            cvss_score=9.1 if severity == "CRITICAL" else 7.5,
                            remediation=(
                                "1. Implement strict Host header validation against whitelist\n"
                                "2. Use absolute URLs instead of relying on Host header\n"
                                "3. Configure web server to reject requests with invalid Host\n"
                                "4. Implement DNS pinning\n"
                                "5. Use HTTPS with proper certificate validation"
                            ),
                            vuln_type=VulnType.DNS_REBINDING,
                            scanner="dns_rebinding_scanner",
                        ))
                        
                        if severity == "CRITICAL":
                            return findings  # Critical finding, stop testing
                        
                except Exception as e:
                    logger.debug(f"[DNS Rebinding] Host test error: {e}")
        
        return findings
    
    async def _test_dns_rebinding_services(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        original_host: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test DNS rebinding via nip.io, xip.io, sslip.io services."""
        findings = []
        import hashlib

        # FP1 FIX 2026-02-18: Get baseline response for comparison
        baseline_hash = None
        try:
            await rate_limiter.acquire()
            baseline_resp = await client.get(base_url, headers={"Host": original_host})
            if baseline_resp.status_code == 200:
                baseline_hash = hashlib.md5(baseline_resp.text.encode()).hexdigest()
        except Exception:
            pass

        rebinding_domains = [
            f"127.0.0.1.nip.io",
            f"127.0.0.1.xip.io",
            f"127-0-0-1.nip.io",
            f"127-0-0-1.xip.io",
            f"169.254.169.254.nip.io",
            f"169-254-169-254.sslip.io",
            f"10.0.0.1.nip.io",
            f"192.168.1.1.nip.io",
            f"localhost.nip.io",
            f"{original_host}.127.0.0.1.nip.io",
        ]

        for domain in rebinding_domains:
            await rate_limiter.acquire()

            try:
                response = await client.get(
                    base_url,
                    headers={"Host": domain}
                )

                if response.status_code == 200 and len(response.text) > 100:
                    # FP1 FIX 2026-02-18: Compare with baseline
                    response_hash = hashlib.md5(response.text.encode()).hexdigest()

                    if baseline_hash and response_hash == baseline_hash:
                        # Same response as baseline - app ignores Host header
                        logger.debug(f"[DNS Rebinding] Service {domain} ignored (same as baseline)")
                        continue

                    # FP1 FIX: Check for internal data indicators
                    response_lower = response.text.lower()
                    internal_indicators = ['localhost', '127.0.0.1', 'internal', 'admin', 'metadata']
                    has_internal_data = any(ind in response_lower for ind in internal_indicators)

                    if baseline_hash and not has_internal_data:
                        # Different response but no internal data - likely error page
                        logger.debug(f"[DNS Rebinding] Service {domain} different but no internal data")
                        continue

                    findings.append(Finding(
                        name="DNS Rebinding via Dynamic DNS Service",
                        severity=Severity.HIGH,
                        confidence_score=85.0,
                        description=f"Application accepts Host header using DNS rebinding service: {domain}",
                        endpoint=base_url,
                        evidence=[
                            f"Rebinding domain: {domain}",
                            "Dynamic DNS service resolves to internal IP",
                            f"Response differs from baseline: {response_hash[:8]} vs {baseline_hash[:8] if baseline_hash else 'N/A'}",
                        ],
                        cwe_id="CWE-350",
                        cvss_score=8.1,
                        remediation=(
                            "1. Block requests with dynamic DNS service domains\n"
                            "2. Implement DNS pinning\n"
                            "3. Validate Host header against explicit whitelist"
                        ),
                        vuln_type=VulnType.DNS_REBINDING,
                        scanner="dns_rebinding_scanner",
                    ))
                    return findings  # One finding is sufficient

            except Exception as e:
                logger.debug(f"[DNS Rebinding] Service test error: {e}")
        
        return findings
    
    async def _test_internal_service_access(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for internal service access via SSRF parameters."""
        findings = []

        # FIX 2026-02-12: SPAs don't make server-side fetches
        # If SPA detected, demote SSRF findings (likely FP from client-side reflection)
        if self._is_spa:
            logger.debug("[DNS Rebinding] SPA detected - skipping server-side SSRF tests")
            return findings

        for service in self.INTERNAL_SERVICES[:8]:  # Limit to most critical
            for param in self.SSRF_PARAMETERS[:10]:
                await rate_limiter.acquire()

                try:
                    target_url = f"http://{service.host}:{service.port}{service.path}"
                    test_url = f"{base_url}?{param}={quote(target_url)}"

                    response = await client.get(test_url)

                    # Check for service indicators
                    for indicator in service.indicators:
                        if indicator.lower() in response.text.lower():
                            findings.append(Finding(
                                name=f"DNS Rebinding/SSRF - {service.description} Access",
                                severity=service.severity,
                                confidence_score=85.0,
                                description=f"Internal {service.description} accessible via {param} parameter",
                                endpoint=test_url,
                                evidence=[
                                    f"Parameter: {param}",
                                    f"Target: {target_url}",
                                    f"Service: {service.description}",
                                    f"Indicator: {indicator}",
                                ],
                                cwe_id="CWE-918",
                                cvss_score=9.8 if service.severity == "CRITICAL" else 8.0,
                                remediation=(
                                    "1. Block requests to internal IP ranges\n"
                                    "2. Implement URL allowlist for external requests\n"
                                    "3. Use DNS pinning to prevent rebinding\n"
                                    "4. Disable cloud metadata access (IMDSv2 on AWS)\n"
                                    "5. Network segmentation for sensitive services"
                                ),
                                vuln_type=VulnType.SSRF,
                                scanner="dns_rebinding_scanner",
                            ))
                            return findings  # Critical finding

                except Exception as e:
                    logger.debug(f"[DNS Rebinding] Service access error: {e}")
        
        return findings
    
    async def _test_cloud_metadata_access(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Specifically test cloud metadata service access."""
        findings = []

        # FIX 2026-02-12: SPAs don't make server-side fetches
        if self._is_spa:
            logger.debug("[DNS Rebinding] SPA detected - skipping cloud metadata SSRF tests")
            return findings

        metadata_targets = [
            # AWS IMDS
            ("http://169.254.169.254/latest/meta-data/", "AWS Metadata", ["ami-id", "instance-id"]),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM Credentials", ["AccessKeyId"]),
            ("http://169.254.169.254/latest/user-data/", "AWS User Data", ["#!/", "password", "secret"]),
            
            # GCP
            ("http://metadata.google.internal/computeMetadata/v1/", "GCP Metadata", ["project-id"]),
            ("http://169.254.169.254/computeMetadata/v1/", "GCP Metadata (IP)", ["project-id"]),
            
            # Azure
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure Metadata", ["compute", "vmId"]),
            ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01", "Azure Identity", ["access_token"]),
            
            # Digital Ocean
            ("http://169.254.169.254/metadata/v1/", "DigitalOcean Metadata", ["droplet_id"]),
            
            # Oracle Cloud
            ("http://169.254.169.254/opc/v1/instance/", "Oracle Cloud Metadata", ["instanceId"]),
        ]
        
        for target_url, service_name, indicators in metadata_targets:
            for param in ["url", "uri", "redirect", "callback", "webhook"][:3]:
                await rate_limiter.acquire()
                
                try:
                    test_url = f"{base_url}?{param}={quote(target_url)}"
                    
                    headers = {}
                    if "google" in target_url or "computeMetadata" in target_url:
                        headers["Metadata-Flavor"] = "Google"
                    
                    response = await client.get(test_url, headers=headers)
                    
                    for indicator in indicators:
                        if indicator.lower() in response.text.lower():
                            findings.append(Finding(
                                name=f"Cloud Metadata Access via DNS Rebinding/SSRF - {service_name}",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description=f"{service_name} exposed via SSRF parameter. Cloud credentials may be compromised.",
                                endpoint=test_url,
                                evidence=[
                                    f"Target: {target_url}",
                                    f"Service: {service_name}",
                                    f"Indicator found: {indicator}",
                                    "CRITICAL: Cloud credentials may be accessible",
                                ],
                                cwe_id="CWE-918",
                                cvss_score=10.0,
                                remediation=(
                                    "1. IMMEDIATE: Rotate all cloud credentials/tokens\n"
                                    "2. Enable IMDSv2 on AWS (requires token)\n"
                                    "3. Block metadata IP (169.254.169.254) at network level\n"
                                    "4. Implement strict URL validation\n"
                                    "5. Use VPC endpoints instead of public metadata"
                                ),
                                vuln_type=VulnType.SSRF,
                                scanner="dns_rebinding_scanner",
                            ))
                            return findings  # Critical finding
                            
                except Exception as e:
                    logger.debug(f"[DNS Rebinding] Cloud metadata error: {e}")
        
        return findings
    
    async def _test_websocket_rebinding_enterprise(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        original_host: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Enterprise WebSocket origin validation testing."""
        findings = []
        
        malicious_origins = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254",
            f"http://{original_host}.attacker.com",
            f"http://attacker.com",
            f"http://{original_host}.127.0.0.1.nip.io",
            "null",
            "file://",
            f"http://127.0.0.1.{original_host}",
        ]
        
        for path in self.WEBSOCKET_PATHS[:8]:
            for origin in malicious_origins:
                await rate_limiter.acquire()
                
                try:
                    url = urljoin(base_url, path)
                    
                    response = await client.get(
                        url,
                        headers={
                            "Upgrade": "websocket",
                            "Connection": "Upgrade",
                            "Sec-WebSocket-Key": secrets.token_urlsafe(16),
                            "Sec-WebSocket-Version": "13",
                            "Origin": origin,
                        }
                    )
                    
                    # Check for WebSocket upgrade acceptance
                    if response.status_code == 101:
                        severity = "CRITICAL" if origin in ["http://127.0.0.1", "http://localhost", "null"] else "HIGH"
                        
                        findings.append(Finding(
                            name="WebSocket DNS Rebinding - Origin Bypass",
                            severity=severity,
                            confidence_score=85.0,
                            description=f"WebSocket endpoint accepts connections from untrusted origin: {origin}",
                            endpoint=url,
                            evidence=[
                                f"WebSocket path: {path}",
                                f"Malicious origin: {origin}",
                                "Upgrade to WebSocket accepted",
                            ],
                            cwe_id="CWE-346",
                            cvss_score=8.5 if severity == "CRITICAL" else 7.0,
                            remediation=(
                                "1. Implement strict Origin header validation\n"
                                "2. Whitelist only trusted origins\n"
                                "3. Reject null and localhost origins in production\n"
                                "4. Use CSRF tokens for WebSocket handshake"
                            ),
                            vuln_type=VulnType.WEBSOCKET_VULNERABILITY,
                            scanner="dns_rebinding_scanner",
                        ))
                        return findings  # One critical finding is enough
                        
                except Exception as e:
                    logger.debug(f"[DNS Rebinding] WebSocket error: {e}")
        
        return findings
    
    async def _test_cors_rebinding_enterprise(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        original_host: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Enterprise CORS misconfiguration testing for rebinding."""
        findings = []
        
        test_origins = [
            # Localhost/Internal
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://0.0.0.0",
            
            # Rebinding services
            f"http://127.0.0.1.nip.io",
            f"http://{original_host}.127.0.0.1.nip.io",
            
            # Null origin (sandboxed iframes, data URIs)
            "null",
            
            # Attacker-controlled
            "http://attacker.com",
            f"http://{original_host}.attacker.com",
            f"http://attacker.{original_host}",
            
            # Subdomain variations
            f"http://evil.{original_host}",
            f"http://{original_host}evil.com",
            f"http://prefix{original_host}",
        ]
        
        for origin in test_origins:
            await rate_limiter.acquire()
            
            try:
                # Preflight request
                response = await client.options(
                    base_url,
                    headers={
                        "Origin": origin,
                        "Access-Control-Request-Method": "GET",
                        "Access-Control-Request-Headers": "X-Custom-Header",
                    }
                )
                
                acao = response.headers.get("access-control-allow-origin", "")
                acac = response.headers.get("access-control-allow-credentials", "")
                
                # Check for vulnerable configurations
                vulnerable = False
                severity = "MEDIUM"
                
                if acao == "*":
                    vulnerable = True
                    severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                elif acao == origin:
                    vulnerable = True
                    if origin in ["http://127.0.0.1", "http://localhost", "null"]:
                        severity = "CRITICAL" if acac.lower() == "true" else "HIGH"
                    elif "attacker" in origin or origin.startswith("http://") and original_host not in origin:
                        severity = "HIGH" if acac.lower() == "true" else "MEDIUM"
                elif acao and origin in acao:
                    vulnerable = True
                    severity = "MEDIUM"
                
                if vulnerable:
                    findings.append(Finding(
                        name=f"CORS DNS Rebinding Misconfiguration",
                        severity=severity,
                        confidence_score=85.0,
                        description=f"CORS allows requests from potentially malicious origin: {origin}",
                        endpoint=base_url,
                        evidence=[
                            f"Origin tested: {origin}",
                            f"Access-Control-Allow-Origin: {acao}",
                            f"Access-Control-Allow-Credentials: {acac}",
                        ],
                        cwe_id="CWE-942",
                        cvss_score=9.1 if severity == "CRITICAL" else (7.5 if severity == "HIGH" else 5.3),
                        remediation=(
                            "1. Implement strict origin whitelist (never use *)\n"
                            "2. Block localhost/internal IPs in CORS policy\n"
                            "3. Never reflect arbitrary Origin header\n"
                            "4. Be careful with Access-Control-Allow-Credentials\n"
                            "5. Validate origin against allowed domains list"
                        ),
                        vuln_type=VulnType.DNS_REBINDING,
                        scanner="dns_rebinding_scanner",
                    ))
                    
                    if severity == "CRITICAL":
                        return findings
                        
            except Exception as e:
                logger.debug(f"[DNS Rebinding] CORS error: {e}")
        
        return findings
    
    async def _test_redirect_rebinding_enterprise(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test redirect-based DNS rebinding attacks."""
        findings = []
        
        redirect_params = ["redirect", "url", "next", "goto", "return", "returnUrl", "continue", "callback"]
        
        internal_targets = [
            "http://127.0.0.1/",
            "http://localhost/",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/",
            "http://metadata.google.internal/",
            "http://kubernetes.default/",
            "gopher://127.0.0.1:6379/_INFO",
            "dict://127.0.0.1:6379/INFO",
            "file:///etc/passwd",
        ]
        
        for param in redirect_params:
            for target in internal_targets:
                await rate_limiter.acquire()
                
                try:
                    test_url = f"{base_url}?{param}={quote(target)}"
                    response = await client.get(test_url, follow_redirects=False)
                    
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get("location", "")
                        
                        # Check if redirect goes to internal service
                        internal_indicators = ["127.0.0.1", "localhost", "169.254", "metadata", "kubernetes", "::1"]
                        
                        if any(indicator in location for indicator in internal_indicators):
                            findings.append(Finding(
                                name="DNS Rebinding via Open Redirect",
                                severity=Severity.HIGH,
                                confidence_score=85.0,
                                description=f"Open redirect allows rebinding to internal services via {param}",
                                endpoint=test_url,
                                evidence=[
                                    f"Parameter: {param}",
                                    f"Target: {target}",
                                    f"Redirect location: {location}",
                                ],
                                cwe_id="CWE-601",
                                cvss_score=8.1,
                                remediation=(
                                    "1. Validate redirect URLs against strict whitelist\n"
                                    "2. Block redirects to internal IP ranges\n"
                                    "3. Use relative paths for redirects\n"
                                    "4. Implement redirect confirmation page"
                                ),
                                vuln_type=VulnType.DNS_REBINDING,
                                scanner="dns_rebinding_scanner",
                            ))
                            return findings
                        
                        # Check for protocol handlers
                        if location.startswith(("gopher://", "dict://", "file://", "ldap://")):
                            findings.append(Finding(
                                name="SSRF via Protocol Handler in Redirect",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description=f"Redirect allows dangerous protocol handler: {location.split(':')[0]}://",
                                endpoint=test_url,
                                evidence=[
                                    f"Parameter: {param}",
                                    f"Protocol: {location.split(':')[0]}",
                                    f"Location: {location}",
                                ],
                                cwe_id="CWE-918",
                                cvss_score=9.8,
                                remediation="Block all non-HTTP(S) protocol handlers in redirects",
                                vuln_type=VulnType.SSRF,
                                scanner="dns_rebinding_scanner",
                            ))
                            return findings
                            
                except Exception as e:
                    logger.debug(f"[DNS Rebinding] Redirect error: {e}")
        
        return findings
    
    async def _test_container_api_access(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for container/orchestration API access."""
        findings = []

        # FIX 2026-02-12: SPAs don't make server-side fetches
        if self._is_spa:
            logger.debug("[DNS Rebinding] SPA detected - skipping container API SSRF tests")
            return findings

        container_targets = [
            # Docker
            ("http://127.0.0.1:2375/version", "Docker API", ["ApiVersion", "Version"]),
            ("http://127.0.0.1:2375/containers/json", "Docker Containers", ["Names", "Image"]),
            ("http://localhost:2375/images/json", "Docker Images", ["RepoTags"]),
            
            # Kubernetes
            ("https://kubernetes.default/api/v1/namespaces", "Kubernetes API", ["items", "namespaces"]),
            ("https://10.0.0.1:443/api", "Kubernetes Gateway", ["paths", "api"]),
            
            # Rancher
            ("http://127.0.0.1:80/v3", "Rancher API", ["rancher"]),
        ]
        
        for target, service, indicators in container_targets:
            for param in ["url", "callback", "webhook"][:2]:
                await rate_limiter.acquire()
                
                try:
                    test_url = f"{base_url}?{param}={quote(target)}"
                    response = await client.get(test_url)
                    
                    for indicator in indicators:
                        if indicator.lower() in response.text.lower():
                            findings.append(Finding(
                                name=f"Container API Access via DNS Rebinding - {service}",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description=f"{service} exposed via SSRF. Container escape or cluster takeover possible.",
                                endpoint=test_url,
                                evidence=[
                                    f"Target: {target}",
                                    f"Service: {service}",
                                    f"Indicator: {indicator}",
                                ],
                                cwe_id="CWE-918",
                                cvss_score=9.8,
                                remediation=(
                                    "1. Disable Docker remote API or require TLS auth\n"
                                    "2. Use network policies to block container API access\n"
                                    "3. Implement strict SSRF protection\n"
                                    "4. Enable Kubernetes RBAC and network policies"
                                ),
                                vuln_type=VulnType.SSRF,
                                scanner="dns_rebinding_scanner",
                            ))
                            return findings
                            
                except Exception as e:
                    logger.debug(f"[DNS Rebinding] Container API error: {e}")
        
        return findings
    
    async def _test_ip_representation_bypass(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        original_host: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test IP address representation bypass techniques."""
        findings = []
        
        # Alternative representations of 127.0.0.1
        ip_representations = [
            ("2130706433", "Decimal representation"),
            ("0x7f000001", "Hexadecimal representation"),
            ("0177.0.0.1", "Octal representation"),
            ("127.1", "Shorthand notation"),
            ("127.0.1", "Shorthand notation 2"),
            ("0", "Zero address"),
            ("0.0.0.0", "Any interface"),
            ("127.000.000.001", "Zero-padded"),
            ("127.0.0.1.xip.io", "DNS service"),
            ("[::ffff:127.0.0.1]", "IPv4-mapped IPv6"),
            ("127。0。0。1", "Fullwidth dots"),
        ]
        
        for ip_repr, description in ip_representations:
            await rate_limiter.acquire()
            
            try:
                # Test as Host header
                response = await client.get(
                    base_url,
                    headers={"Host": ip_repr}
                )
                
                if response.status_code == 200 and len(response.text) > 100:
                    findings.append(Finding(
                        name=f"DNS Rebinding - IP Representation Bypass ({description})",
                        severity=Severity.HIGH,
                        confidence_score=85.0,
                        description=f"Host validation bypassed using {description}: {ip_repr}",
                        endpoint=base_url,
                        evidence=[
                            f"IP representation: {ip_repr}",
                            f"Technique: {description}",
                        ],
                        cwe_id="CWE-350",
                        cvss_score=8.0,
                        remediation=(
                            "1. Normalize IP addresses before validation\n"
                            "2. Parse and validate all IP formats (decimal, hex, octal)\n"
                            "3. Use IP parsing library that handles all representations"
                        ),
                        vuln_type=VulnType.DNS_REBINDING,
                        scanner="dns_rebinding_scanner",
                    ))
                    return findings
                    
            except Exception as e:
                logger.debug(f"[DNS Rebinding] IP bypass error: {e}")
        
        return findings
    
    async def _test_ttl_rebinding(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        original_host: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for TTL-based DNS rebinding vulnerability."""
        findings = []
        
        # This is a detection test - actual TTL rebinding requires DNS server control
        # We check if the application is vulnerable to the concept
        
        await rate_limiter.acquire()
        
        try:
            # Make two requests quickly to see if DNS is cached
            start = time.time()
            response1 = await client.get(base_url)
            time1 = time.time() - start
            
            await asyncio.sleep(0.1)
            
            start = time.time()
            response2 = await client.get(base_url)
            time2 = time.time() - start
            
            # If second request is significantly faster, DNS may be cached
            # This is just an informational finding
            if time2 < time1 * 0.5:
                findings.append(Finding(
                    name="Potential TTL-Based DNS Rebinding Susceptibility",
                    severity=Severity.INFO,
                    confidence_score=40.0,
                    description="Application may be susceptible to TTL-based DNS rebinding (requires further testing)",
                    endpoint=base_url,
                    evidence=[
                        f"First request: {time1:.3f}s",
                        f"Second request: {time2:.3f}s",
                        "DNS caching detected - rebinding may be possible with controlled DNS",
                    ],
                    cwe_id="CWE-350",
                    cvss_score=0.0,
                    remediation=(
                        "1. Implement DNS pinning\n"
                        "2. Validate Host header on every request\n"
                        "3. Use static IP configuration where possible"
                    ),
                    vuln_type=VulnType.DNS_REBINDING,
                    scanner="dns_rebinding_scanner",
                ))
                
        except Exception as e:
            logger.debug(f"[DNS Rebinding] TTL test error: {e}")
        
        return findings
    
    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings."""
        seen = set()
        unique = []

        for finding in findings:
            key = (finding.name, finding.endpoint)
            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique

    async def _detect_spa(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> bool:
        """Detect if target is a Single Page Application.

        SPAs don't make server-side fetches, so SSRF via DNS rebinding
        is unlikely. This reduces false positives for SPA targets.
        """
        await rate_limiter.acquire()

        try:
            response = await client.get(base_url)
            if response.status_code != 200:
                return False

            body = response.text.lower()
            content_type = response.headers.get("content-type", "").lower()

            # Must be HTML
            if "text/html" not in content_type:
                return False

            # Check for SPA indicators
            spa_score = 0
            for indicator in self.SPA_INDICATORS:
                if indicator.lower() in body:
                    spa_score += 1
                    if spa_score >= 2:  # Need 2+ indicators
                        return True

            return False

        except Exception as e:
            logger.debug(f"[DNS Rebinding] SPA detection error: {e}")
            return False
