"""
gRPC-Web Security Scanner v1.0

Detects security vulnerabilities in gRPC-Web endpoints.
gRPC-Web enables browser clients to communicate with gRPC services,
introducing unique security considerations.

Vulnerability Types Covered:
1. Authentication Bypass - Requests without metadata auth
2. Field Manipulation - Modifying protobuf message fields
3. Type Confusion - Sending incorrect field types
4. Reflection Abuse - Exploiting gRPC Server Reflection
5. Streaming Abuse - DoS via stream manipulation
6. Metadata Injection - Injecting malicious headers
7. Service Enumeration - Discovering hidden services
8. Message Tampering - Modifying serialized messages

Bug Bounty Value: $2,000 - $12,000 for critical gRPC vulns
Reference: gRPC security is often overlooked in web applications

CWE Coverage:
- CWE-284: Improper Access Control
- CWE-287: Improper Authentication
- CWE-20: Improper Input Validation
- CWE-400: Uncontrolled Resource Consumption
- CWE-200: Exposure of Sensitive Information

Author: PetNTester AI
Version: 1.0.0 (2026-02-19)
"""

from __future__ import annotations

import asyncio
import base64
import struct
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
GRPC_WEB_SCANNER_VERSION = "1.0.0"


class GRPCWebVulnType(Enum):
    """Types of gRPC-Web vulnerabilities."""
    AUTH_BYPASS = auto()           # Missing authentication
    FIELD_MANIPULATION = auto()    # Modifying protobuf fields
    TYPE_CONFUSION = auto()        # Wrong field types
    REFLECTION_ABUSE = auto()      # Server reflection exploitation
    STREAMING_ABUSE = auto()       # Stream-based DoS
    METADATA_INJECTION = auto()    # Header/metadata injection
    SERVICE_ENUM = auto()          # Service discovery
    MESSAGE_TAMPERING = auto()     # Message modification


class GRPCWebMode(Enum):
    """gRPC-Web transport modes."""
    TEXT = "text"      # Base64-encoded, application/grpc-web-text
    BINARY = "binary"  # Binary, application/grpc-web+proto


@dataclass
class GRPCEndpoint:
    """Represents a discovered gRPC-Web endpoint."""
    url: str
    mode: GRPCWebMode
    services: list[str] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    has_reflection: bool = False
    proxy_type: str = ""  # envoy, grpc-gateway, etc.


@dataclass
class GRPCTestResult:
    """Result of a gRPC-Web security test."""
    vulnerable: bool
    vuln_type: GRPCWebVulnType
    confidence: int  # 0-100
    payload: str
    response_data: str = ""
    evidence: list[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    data_leaked: bool = False


class GRPCWebMessage:
    """
    Simple gRPC-Web message encoder/decoder.

    gRPC-Web frame format:
    - 1 byte: flags (0 = data, 128 = trailers)
    - 4 bytes: message length (big-endian)
    - N bytes: message data
    """

    @staticmethod
    def encode_frame(data: bytes, is_trailer: bool = False) -> bytes:
        """Encode data into gRPC-Web frame format."""
        flags = 128 if is_trailer else 0
        length = len(data)
        header = struct.pack(">BI", flags, length)
        return header + data

    @staticmethod
    def decode_frame(frame: bytes) -> tuple[bool, bytes]:
        """Decode gRPC-Web frame, returns (is_trailer, data)."""
        if len(frame) < 5:
            return False, b""

        flags = frame[0]
        length = struct.unpack(">I", frame[1:5])[0]
        is_trailer = (flags & 128) != 0
        data = frame[5:5+length]
        return is_trailer, data

    @staticmethod
    def encode_text(data: bytes) -> str:
        """Encode binary data to base64 for gRPC-Web-Text."""
        frame = GRPCWebMessage.encode_frame(data)
        return base64.b64encode(frame).decode('ascii')

    @staticmethod
    def decode_text(text: str) -> bytes:
        """Decode base64 gRPC-Web-Text to binary."""
        try:
            frame = base64.b64decode(text)
            _, data = GRPCWebMessage.decode_frame(frame)
            return data
        except Exception:
            return b""

    @staticmethod
    def create_simple_message(field_values: dict[int, Any]) -> bytes:
        """
        Create a simple protobuf message (wire format).

        field_values: {field_number: value}
        Supports: strings (wire type 2), ints (wire type 0)
        """
        result = b""

        for field_num, value in field_values.items():
            if isinstance(value, str):
                # Wire type 2 (length-delimited) for strings
                wire_type = 2
                tag = (field_num << 3) | wire_type
                data = value.encode('utf-8')
                result += GRPCWebMessage._encode_varint(tag)
                result += GRPCWebMessage._encode_varint(len(data))
                result += data
            elif isinstance(value, int):
                # Wire type 0 (varint) for integers
                wire_type = 0
                tag = (field_num << 3) | wire_type
                result += GRPCWebMessage._encode_varint(tag)
                result += GRPCWebMessage._encode_varint(value)
            elif isinstance(value, bytes):
                # Wire type 2 for bytes
                wire_type = 2
                tag = (field_num << 3) | wire_type
                result += GRPCWebMessage._encode_varint(tag)
                result += GRPCWebMessage._encode_varint(len(value))
                result += value

        return result

    @staticmethod
    def _encode_varint(value: int) -> bytes:
        """Encode an integer as a protobuf varint."""
        result = []
        while value > 127:
            result.append((value & 0x7F) | 0x80)
            value >>= 7
        result.append(value)
        return bytes(result)


class GRPCWebScanner(ScanModule):
    """
    gRPC-Web Security Scanner.

    Detects vulnerabilities in gRPC-Web enabled services:
    - Authentication bypass
    - Field manipulation attacks
    - Type confusion attacks
    - Server reflection abuse
    - Streaming DoS

    Focus: gRPC-Web bridges browser clients to gRPC backends,
    creating attack surfaces at the protocol translation layer.
    """

    name = "grpc_web_scanner"
    version = GRPC_WEB_SCANNER_VERSION

    # Common gRPC-Web endpoint patterns
    GRPC_ENDPOINTS = [
        "/grpc/", "/api/grpc/", "/grpc-web/",
        "/rpc/", "/api/rpc/",
        "/proto/", "/api/proto/",
        "/twirp/",  # Twirp (gRPC-like)
    ]

    # Common gRPC service patterns
    COMMON_SERVICES = [
        "grpc.reflection.v1alpha.ServerReflection",
        "grpc.health.v1.Health",
        "google.protobuf.Empty",
        "UserService", "AuthService", "AdminService",
        "PaymentService", "OrderService", "AccountService",
    ]

    # gRPC-Web Content-Type patterns
    CONTENT_TYPES = {
        GRPCWebMode.TEXT: [
            "application/grpc-web-text",
            "application/grpc-web-text+proto",
        ],
        GRPCWebMode.BINARY: [
            "application/grpc-web",
            "application/grpc-web+proto",
        ],
    }

    # Proxy detection patterns
    PROXY_PATTERNS = {
        "envoy": ["envoy", "x-envoy-", "server: envoy"],
        "grpc-gateway": ["grpc-gateway", "x-grpc-web"],
        "improbable": ["improbable-eng", "@improbable-eng"],
        "connect": ["connect-protocol", "connect-rpc"],
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
        self.grpc_endpoints: list[GRPCEndpoint] = []
        self._ssl_verify = get_configured_ssl_verify()

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Execute gRPC-Web security scan."""

        # SCAN CONTEXT
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        self.findings = []
        self.grpc_endpoints = []

        base_url = f"https://{host}" if not host.startswith("http") else host
        urls = asset_data.get("urls", []) if isinstance(asset_data, dict) else []

        logger.info(f"gRPC-Web Scanner v{self.version} starting on {host}")

        client = create_protected_client(
            timeout=self.timeout,
            verify_ssl=self._ssl_verify,
            follow_redirects=True,
            custom_headers=self._auth_headers,
        )

        async with client:
            # Phase 1: Discover gRPC-Web endpoints
            await self._discover_grpc_endpoints(client, base_url, urls, rate_limiter)

            if not self.grpc_endpoints:
                logger.info("No gRPC-Web endpoints discovered")
                return {
                    "module": self.name,
                    "version": self.version,
                    "findings": [],
                    "grpc_endpoints": [],
                }

            logger.info(f"Found {len(self.grpc_endpoints)} gRPC-Web endpoints")

            # Phase 2: Test authentication bypass
            await self._test_auth_bypass(client, rate_limiter)

            # Phase 3: Test reflection abuse
            await self._test_reflection_abuse(client, rate_limiter)

            # Phase 4: Test field manipulation
            await self._test_field_manipulation(client, rate_limiter)

            # Phase 5: Test type confusion
            await self._test_type_confusion(client, rate_limiter)

            # Phase 6: Test metadata injection
            await self._test_metadata_injection(client, rate_limiter)

            # Phase 7: Test service enumeration
            await self._test_service_enumeration(client, rate_limiter)

            # Phase 8: Test streaming abuse
            await self._test_streaming_abuse(client, rate_limiter)

        logger.info(f"gRPC-Web scan complete. Found {len(self.findings)} vulnerabilities")

        return {
            "module": self.name,
            "version": self.version,
            "findings": self.findings,
            "grpc_endpoints": [
                {
                    "url": ep.url,
                    "mode": ep.mode.value,
                    "services": ep.services,
                    "has_reflection": ep.has_reflection,
                    "proxy": ep.proxy_type,
                }
                for ep in self.grpc_endpoints
            ],
        }

    async def _discover_grpc_endpoints(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Discover gRPC-Web enabled endpoints."""
        # Test known gRPC endpoint patterns
        for endpoint_path in self.GRPC_ENDPOINTS:
            await rate_limiter.acquire()

            url = urljoin(base_url, endpoint_path)
            try:
                # Send OPTIONS to check CORS/gRPC headers
                response = await client.options(url)

                if self._is_grpc_endpoint(response):
                    mode = self._detect_mode(response)
                    proxy = self._detect_proxy(response)

                    endpoint = GRPCEndpoint(
                        url=url,
                        mode=mode,
                        proxy_type=proxy,
                    )
                    self.grpc_endpoints.append(endpoint)
                    continue

                # Try POST with gRPC-Web content type
                for content_type in self.CONTENT_TYPES[GRPCWebMode.TEXT]:
                    response = await client.post(
                        url,
                        content=b"",
                        headers={"Content-Type": content_type},
                    )

                    if response.status_code in [200, 400, 415, 500]:
                        # Any response suggests gRPC is understood
                        if self._is_grpc_response(response):
                            mode = self._detect_mode(response)
                            endpoint = GRPCEndpoint(
                                url=url,
                                mode=mode,
                                proxy_type=self._detect_proxy(response),
                            )
                            self.grpc_endpoints.append(endpoint)
                            break

            except Exception as e:
                logger.debug(f"gRPC endpoint discovery error at {url}: {e}")

        # Test common service paths
        for service in self.COMMON_SERVICES[:5]:
            await rate_limiter.acquire()

            # Common path patterns: /package.Service/Method
            test_paths = [
                f"/{service}/Check",
                f"/{service}/List",
                f"/{service.replace('.', '/')}/",
            ]

            for path in test_paths:
                url = urljoin(base_url, path)
                try:
                    response = await client.post(
                        url,
                        content=b"",
                        headers={"Content-Type": "application/grpc-web-text"},
                    )

                    if self._is_grpc_response(response):
                        if not any(ep.url == url for ep in self.grpc_endpoints):
                            endpoint = GRPCEndpoint(
                                url=url,
                                mode=GRPCWebMode.TEXT,
                                services=[service],
                            )
                            self.grpc_endpoints.append(endpoint)

                except Exception:
                    pass

        # Check crawled URLs
        for url in urls[:30]:
            if any(p in url.lower() for p in ["/grpc", "/rpc/", "/proto/", "/twirp/"]):
                await rate_limiter.acquire()

                try:
                    response = await client.post(
                        url,
                        content=b"",
                        headers={"Content-Type": "application/grpc-web-text"},
                    )

                    if self._is_grpc_response(response):
                        if not any(ep.url == url for ep in self.grpc_endpoints):
                            self.grpc_endpoints.append(GRPCEndpoint(
                                url=url,
                                mode=GRPCWebMode.TEXT,
                            ))

                except Exception:
                    pass

    def _is_grpc_endpoint(self, response: httpx.Response) -> bool:
        """Check if response indicates gRPC-Web support."""
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}

        # Check for gRPC-specific headers
        grpc_indicators = [
            "grpc" in headers.get("content-type", ""),
            "grpc" in headers.get("access-control-allow-headers", ""),
            "grpc" in headers.get("access-control-expose-headers", ""),
            "x-grpc" in " ".join(headers.keys()),
        ]

        return any(grpc_indicators)

    def _is_grpc_response(self, response: httpx.Response) -> bool:
        """Check if response is a gRPC-Web response."""
        content_type = response.headers.get("content-type", "").lower()

        # Check content type
        if "grpc" in content_type:
            return True

        # Check for gRPC status headers
        if "grpc-status" in response.headers:
            return True

        # Check body for gRPC-Web frame format
        if len(response.content) >= 5:
            # First byte should be 0 or 128
            if response.content[0] in [0, 128]:
                return True

        return False

    def _detect_mode(self, response: httpx.Response) -> GRPCWebMode:
        """Detect gRPC-Web transport mode."""
        content_type = response.headers.get("content-type", "").lower()

        if "text" in content_type:
            return GRPCWebMode.TEXT

        return GRPCWebMode.BINARY

    def _detect_proxy(self, response: httpx.Response) -> str:
        """Detect gRPC proxy/gateway type."""
        headers_str = str(response.headers).lower()

        for proxy_name, patterns in self.PROXY_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in headers_str:
                    return proxy_name

        return ""

    async def _test_auth_bypass(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for authentication bypass in gRPC-Web calls."""
        for endpoint in self.grpc_endpoints[:10]:
            await rate_limiter.acquire()

            try:
                # Create test messages without auth
                test_methods = [
                    ("GetUser", {1: "1"}),  # field 1 = user_id
                    ("ListUsers", {}),
                    ("GetProfile", {1: "admin"}),
                    ("Check", {}),  # Health check
                ]

                for method_name, fields in test_methods:
                    # Build URL with method
                    method_url = endpoint.url.rstrip("/") + "/" + method_name

                    # Create protobuf message
                    message = GRPCWebMessage.create_simple_message(fields)

                    # Send without auth headers
                    headers = {
                        "Content-Type": "application/grpc-web-text",
                        "Accept": "application/grpc-web-text",
                        "X-Grpc-Web": "1",
                    }

                    if endpoint.mode == GRPCWebMode.TEXT:
                        body = GRPCWebMessage.encode_text(message)
                    else:
                        body = GRPCWebMessage.encode_frame(message)

                    response = await client.post(
                        method_url,
                        content=body,
                        headers=headers,
                    )

                    # Check for success without auth
                    grpc_status = response.headers.get("grpc-status", "")

                    if response.status_code == 200 and grpc_status != "16":  # 16 = UNAUTHENTICATED
                        # Check if we got data back
                        if len(response.content) > 5:
                            result = GRPCTestResult(
                                vulnerable=True,
                                vuln_type=GRPCWebVulnType.AUTH_BYPASS,
                                confidence_score=75,
                                payload=f"{method_name} without auth",
                                response_data=response.content[:200].hex(),
                                evidence=[
                                    f"Method {method_name} accessible without authentication",
                                    f"gRPC status: {grpc_status or 'OK'}",
                                    "No auth metadata required",
                                ],
                                severity=Severity.HIGH,
                            )

                            self._add_finding(
                                name="gRPC-Web Authentication Bypass",
                                description=(
                                    f"gRPC method '{method_name}' can be called without "
                                    "authentication metadata. Attackers can invoke sensitive "
                                    "operations without proper authorization."
                                ),
                                endpoint=method_url,
                                result=result,
                            )
                            break

            except Exception as e:
                logger.debug(f"gRPC auth bypass test error: {e}")

    async def _test_reflection_abuse(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for gRPC Server Reflection abuse."""
        for endpoint in self.grpc_endpoints[:5]:
            await rate_limiter.acquire()

            try:
                # gRPC Reflection service endpoint
                reflection_url = urljoin(
                    endpoint.url,
                    "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
                )

                # Create ListServices request
                # Message: ServerReflectionRequest with list_services field
                reflection_request = GRPCWebMessage.create_simple_message({
                    3: "",  # field 3 = list_services (empty string = list all)
                })

                headers = {
                    "Content-Type": "application/grpc-web-text",
                    "Accept": "application/grpc-web-text",
                    "X-Grpc-Web": "1",
                }

                body = GRPCWebMessage.encode_text(reflection_request)

                response = await client.post(
                    reflection_url,
                    content=body,
                    headers=headers,
                )

                if response.status_code == 200:
                    # Check if we got service list
                    response_text = response.text.lower()

                    if any(s.lower() in response_text for s in [
                        "service", "method", "proto", "message", "field"
                    ]):
                        endpoint.has_reflection = True

                        result = GRPCTestResult(
                            vulnerable=True,
                            vuln_type=GRPCWebVulnType.REFLECTION_ABUSE,
                            confidence_score=85,
                            payload="ServerReflection/ServerReflectionInfo",
                            response_data=response.text[:500],
                            evidence=[
                                "gRPC Server Reflection is enabled",
                                "Service and method enumeration possible",
                                "Proto schema may be exposed",
                            ],
                            severity=Severity.MEDIUM,
                            data_leaked=True,
                        )

                        self._add_finding(
                            name="gRPC Server Reflection Enabled",
                            description=(
                                "gRPC Server Reflection allows enumeration of all "
                                "services, methods, and message types. Attackers can "
                                "discover internal APIs and their schemas."
                            ),
                            endpoint=reflection_url,
                            result=result,
                        )

            except Exception as e:
                logger.debug(f"gRPC reflection test error: {e}")

    async def _test_field_manipulation(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for field manipulation vulnerabilities."""
        for endpoint in self.grpc_endpoints[:5]:
            await rate_limiter.acquire()

            try:
                # Test with manipulated field values
                manipulation_tests = [
                    # IDOR - access other users
                    ("GetUser", {1: "1"}, "Normal request"),
                    ("GetUser", {1: "0"}, "ID zero"),
                    ("GetUser", {1: "-1"}, "Negative ID"),
                    ("GetUser", {1: "admin"}, "Admin string"),

                    # Privilege escalation
                    ("UpdateUser", {1: "1", 2: "admin", 3: 1}, "Set role to admin"),

                    # Mass assignment
                    ("CreateUser", {1: "test", 2: "test@test.com", 99: "admin"}, "Extra field"),
                ]

                for method_name, fields, description in manipulation_tests:
                    await rate_limiter.acquire()

                    method_url = endpoint.url.rstrip("/") + "/" + method_name
                    message = GRPCWebMessage.create_simple_message(fields)

                    headers = {
                        "Content-Type": "application/grpc-web-text",
                        "Accept": "application/grpc-web-text",
                    }

                    body = GRPCWebMessage.encode_text(message)

                    response = await client.post(
                        method_url,
                        content=body,
                        headers=headers,
                    )

                    grpc_status = response.headers.get("grpc-status", "")

                    # Check for unexpected success
                    if response.status_code == 200 and grpc_status in ["", "0"]:
                        if len(response.content) > 5:
                            result = GRPCTestResult(
                                vulnerable=True,
                                vuln_type=GRPCWebVulnType.FIELD_MANIPULATION,
                                confidence_score=70,
                                payload=f"{method_name}: {description}",
                                response_data=response.content[:200].hex(),
                                evidence=[
                                    f"Field manipulation accepted: {description}",
                                    f"Fields: {fields}",
                                    "Server processed manipulated message",
                                ],
                                severity=Severity.HIGH,
                            )

                            self._add_finding(
                                name="gRPC Field Manipulation",
                                description=(
                                    f"gRPC method accepts manipulated field values. "
                                    f"Test: {description}. This may allow IDOR, "
                                    "privilege escalation, or data tampering."
                                ),
                                endpoint=method_url,
                                result=result,
                            )
                            break

            except Exception as e:
                logger.debug(f"gRPC field manipulation test error: {e}")

    async def _test_type_confusion(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for type confusion vulnerabilities."""
        for endpoint in self.grpc_endpoints[:5]:
            await rate_limiter.acquire()

            try:
                # Send wrong types for fields
                confusion_tests = [
                    # String where int expected
                    ({1: "'; DROP TABLE users; --"}, "SQL in string field"),
                    ({1: "<script>alert(1)</script>"}, "XSS in string field"),

                    # Very large numbers
                    ({1: 2**31 - 1}, "Max int32"),
                    ({1: 2**63 - 1}, "Max int64"),

                    # Negative values
                    ({1: -2**31}, "Min int32"),

                    # Mixed types (string as bytes)
                    ({1: b"\x00\xff\x00\xff"}, "Binary data"),
                ]

                for fields, description in confusion_tests:
                    await rate_limiter.acquire()

                    # Try common method names
                    for method in ["Process", "Handle", "Execute", "Query"]:
                        method_url = endpoint.url.rstrip("/") + "/" + method

                        try:
                            message = GRPCWebMessage.create_simple_message(fields)
                            body = GRPCWebMessage.encode_text(message)

                            headers = {
                                "Content-Type": "application/grpc-web-text",
                                "Accept": "application/grpc-web-text",
                            }

                            response = await client.post(
                                method_url,
                                content=body,
                                headers=headers,
                            )

                            # Check for interesting error responses
                            if response.status_code == 500:
                                response_text = response.text.lower()

                                error_indicators = [
                                    "sql", "syntax", "query", "database",
                                    "overflow", "type", "parse", "error",
                                ]

                                if any(ind in response_text for ind in error_indicators):
                                    result = GRPCTestResult(
                                        vulnerable=True,
                                        vuln_type=GRPCWebVulnType.TYPE_CONFUSION,
                                        confidence_score=65,
                                        payload=description,
                                        response_data=response.text[:300],
                                        evidence=[
                                            f"Type confusion triggered: {description}",
                                            "Error message reveals backend details",
                                        ],
                                        severity=Severity.MEDIUM,
                                    )

                                    self._add_finding(
                                        name="gRPC Type Confusion",
                                        description=(
                                            f"gRPC method vulnerable to type confusion. "
                                            f"Payload: {description}. May indicate "
                                            "improper input validation or injection."
                                        ),
                                        endpoint=method_url,
                                        result=result,
                                    )
                                    break
                        except Exception:
                            pass

            except Exception as e:
                logger.debug(f"gRPC type confusion test error: {e}")

    async def _test_metadata_injection(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for metadata/header injection vulnerabilities."""
        for endpoint in self.grpc_endpoints[:5]:
            await rate_limiter.acquire()

            try:
                # Metadata injection payloads
                injection_tests = [
                    # Auth bypass via metadata
                    ({"x-user-id": "admin"}, "User ID injection"),
                    ({"x-role": "administrator"}, "Role injection"),
                    ({"authorization": "Bearer admin"}, "Auth injection"),

                    # Internal header injection
                    ({"x-forwarded-for": "127.0.0.1"}, "IP spoofing"),
                    ({"x-real-ip": "internal"}, "Internal IP"),

                    # gRPC metadata manipulation
                    ({"grpc-metadata-user": "admin"}, "gRPC metadata"),
                    ({"grpc-metadata-admin": "true"}, "Admin metadata"),
                ]

                for inject_headers, description in injection_tests:
                    await rate_limiter.acquire()

                    method_url = endpoint.url
                    message = GRPCWebMessage.create_simple_message({1: "test"})

                    headers = {
                        "Content-Type": "application/grpc-web-text",
                        "Accept": "application/grpc-web-text",
                        **inject_headers,
                    }

                    body = GRPCWebMessage.encode_text(message)

                    response = await client.post(
                        method_url,
                        content=body,
                        headers=headers,
                    )

                    if response.status_code == 200:
                        response_text = response.text.lower()

                        # Check for privilege indicators
                        if any(x in response_text for x in [
                            "admin", "root", "internal", "elevated", "authorized"
                        ]):
                            result = GRPCTestResult(
                                vulnerable=True,
                                vuln_type=GRPCWebVulnType.METADATA_INJECTION,
                                confidence_score=70,
                                payload=description,
                                response_data=response.text[:300],
                                evidence=[
                                    f"Metadata injection successful: {description}",
                                    f"Injected headers: {inject_headers}",
                                ],
                                severity=Severity.HIGH,
                            )

                            self._add_finding(
                                name="gRPC Metadata Injection",
                                description=(
                                    f"gRPC accepts injected metadata headers. "
                                    f"Attack: {description}. This may allow "
                                    "authentication bypass or privilege escalation."
                                ),
                                endpoint=method_url,
                                result=result,
                            )
                            break

            except Exception as e:
                logger.debug(f"gRPC metadata injection test error: {e}")

    async def _test_service_enumeration(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for service enumeration vulnerabilities."""
        for endpoint in self.grpc_endpoints[:5]:
            await rate_limiter.acquire()

            try:
                discovered_services = []

                # Try common service/method names
                test_services = [
                    "UserService", "AuthService", "AdminService",
                    "PaymentService", "OrderService", "InternalService",
                    "DebugService", "HealthService", "MetricsService",
                ]

                test_methods = [
                    "Get", "List", "Create", "Update", "Delete",
                    "Check", "Verify", "Process", "Execute",
                ]

                for service in test_services:
                    for method in test_methods[:3]:
                        await rate_limiter.acquire()

                        method_url = f"{endpoint.url.rstrip('/')}/{service}/{method}"

                        message = GRPCWebMessage.create_simple_message({})
                        body = GRPCWebMessage.encode_text(message)

                        headers = {
                            "Content-Type": "application/grpc-web-text",
                        }

                        response = await client.post(
                            method_url,
                            content=body,
                            headers=headers,
                        )

                        grpc_status = response.headers.get("grpc-status", "")

                        # Status 12 = UNIMPLEMENTED (method exists but not this one)
                        # Status 0/empty = OK
                        if grpc_status in ["0", "", "12"]:
                            discovered_services.append(f"{service}/{method}")

                if discovered_services:
                    endpoint.services = list(set(discovered_services))

                    result = GRPCTestResult(
                        vulnerable=True,
                        vuln_type=GRPCWebVulnType.SERVICE_ENUM,
                        confidence_score=75,
                        payload=f"Discovered {len(discovered_services)} services/methods",
                        evidence=[
                            f"Services found: {discovered_services[:10]}",
                            "Internal API surface exposed",
                        ],
                        severity=Severity.LOW,
                        data_leaked=True,
                    )

                    self._add_finding(
                        name="gRPC Service Enumeration",
                        description=(
                            f"Discovered {len(discovered_services)} gRPC services/methods. "
                            "Attackers can enumerate the API surface to find "
                            "sensitive or administrative endpoints."
                        ),
                        endpoint=endpoint.url,
                        result=result,
                    )

            except Exception as e:
                logger.debug(f"gRPC service enumeration error: {e}")

    async def _test_streaming_abuse(
        self,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> None:
        """Test for streaming abuse (DoS potential)."""
        for endpoint in self.grpc_endpoints[:3]:
            await rate_limiter.acquire()

            try:
                # Test sending multiple frames rapidly
                frames = []
                for i in range(100):  # 100 small messages
                    message = GRPCWebMessage.create_simple_message({1: f"test{i}"})
                    frames.append(GRPCWebMessage.encode_frame(message))

                combined = b"".join(frames)

                headers = {
                    "Content-Type": "application/grpc-web",
                    "Accept": "application/grpc-web",
                }

                response = await client.post(
                    endpoint.url,
                    content=combined,
                    headers=headers,
                    timeout=10.0,
                )

                # Check if server processed many messages
                if response.status_code == 200:
                    # Large response might indicate processing
                    if len(response.content) > 1000:
                        result = GRPCTestResult(
                            vulnerable=True,
                            vuln_type=GRPCWebVulnType.STREAMING_ABUSE,
                            confidence_score=60,
                            payload="100 rapid messages",
                            evidence=[
                                "Server processed many messages without rate limiting",
                                f"Response size: {len(response.content)} bytes",
                                "Potential for DoS via stream flooding",
                            ],
                            severity=Severity.MEDIUM,
                        )

                        self._add_finding(
                            name="gRPC Streaming Abuse",
                            description=(
                                "gRPC endpoint accepts many messages without rate "
                                "limiting. Attackers can flood the service with "
                                "requests causing resource exhaustion."
                            ),
                            endpoint=endpoint.url,
                            result=result,
                        )

            except asyncio.TimeoutError:
                # Timeout might indicate we caused stress
                result = GRPCTestResult(
                    vulnerable=True,
                    vuln_type=GRPCWebVulnType.STREAMING_ABUSE,
                    confidence_score=55,
                    payload="100 messages caused timeout",
                    evidence=["Server timeout under load", "DoS potential confirmed"],
                    severity=Severity.MEDIUM,
                )

                self._add_finding(
                    name="gRPC Streaming DoS",
                    description="gRPC endpoint vulnerable to stream flooding DoS.",
                    endpoint=endpoint.url,
                    result=result,
                )

            except Exception as e:
                logger.debug(f"gRPC streaming abuse test error: {e}")

    def _add_finding(
        self,
        name: str,
        description: str,
        endpoint: str,
        result: GRPCTestResult,
    ) -> None:
        """Add a finding to the results."""
        cvss_scores = {
            "CRITICAL": 9.5,
            "HIGH": 8.0,
            "MEDIUM": 5.5,
            "LOW": 3.0,
        }

        cwe_mapping = {
            GRPCWebVulnType.AUTH_BYPASS: "CWE-287",
            GRPCWebVulnType.FIELD_MANIPULATION: "CWE-20",
            GRPCWebVulnType.TYPE_CONFUSION: "CWE-843",
            GRPCWebVulnType.REFLECTION_ABUSE: "CWE-200",
            GRPCWebVulnType.STREAMING_ABUSE: "CWE-400",
            GRPCWebVulnType.METADATA_INJECTION: "CWE-74",
            GRPCWebVulnType.SERVICE_ENUM: "CWE-200",
            GRPCWebVulnType.MESSAGE_TAMPERING: "CWE-345",
        }

        finding = Finding(
            vuln_type=VulnType.GRPC_VULNERABILITY,
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
                "https://grpc.io/docs/guides/security/",
                "https://github.com/grpc/grpc-web",
                "https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/grpc_web_filter",
                "https://owasp.org/www-project-web-security-testing-guide/",
            ],
        )

        self.findings.append(finding.to_dict())

        logger.info(
            f"gRPC-Web Vulnerability [{result.severity}]: {name} "
            f"| Confidence: {result.confidence}%"
        )

    def _get_remediation(self, vuln_type: GRPCWebVulnType) -> str:
        """Get remediation advice for gRPC-Web vulnerabilities."""
        base = (
            "1. Implement authentication for all gRPC methods.\n"
            "2. Use TLS for all gRPC-Web connections.\n"
            "3. Validate all message fields on the server.\n"
            "4. Implement rate limiting for gRPC calls.\n"
            "5. Disable server reflection in production.\n"
        )

        if vuln_type == GRPCWebVulnType.AUTH_BYPASS:
            base += (
                "\n\nAUTH BYPASS SPECIFIC:\n"
                "6. Require authentication metadata for all methods.\n"
                "7. Use gRPC interceptors for auth validation.\n"
                "8. Implement method-level authorization checks.\n"
                "9. Consider using mTLS for service-to-service auth.\n"
            )

        elif vuln_type == GRPCWebVulnType.REFLECTION_ABUSE:
            base += (
                "\n\nREFLECTION ABUSE SPECIFIC:\n"
                "6. Disable ServerReflection in production.\n"
                "7. If needed, restrict reflection to internal networks.\n"
                "8. Use authentication for reflection endpoint.\n"
                "9. Consider using proto descriptor sets instead.\n"
            )

        elif vuln_type == GRPCWebVulnType.FIELD_MANIPULATION:
            base += (
                "\n\nFIELD MANIPULATION SPECIFIC:\n"
                "6. Validate all field values against expected types.\n"
                "7. Implement business logic validation in services.\n"
                "8. Use protobuf validation libraries.\n"
                "9. Check authorization for all resource access.\n"
            )

        elif vuln_type == GRPCWebVulnType.STREAMING_ABUSE:
            base += (
                "\n\nSTREAMING ABUSE SPECIFIC:\n"
                "6. Implement per-connection rate limiting.\n"
                "7. Set maximum message count per stream.\n"
                "8. Configure timeout for streaming calls.\n"
                "9. Monitor and alert on unusual traffic patterns.\n"
            )

        return base


# Export
__all__ = ["GRPCWebScanner", "GRPC_WEB_SCANNER_VERSION"]
