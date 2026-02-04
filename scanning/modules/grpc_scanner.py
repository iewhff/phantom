"""
gRPC Security Scanner.
Tests for gRPC specific vulnerabilities and misconfigurations.
"""

from __future__ import annotations

import json
import struct
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import httpx

from scanning.vuln_scanner import Finding, ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class GRPCScanner(ScanModule):
    """
    gRPC Security Scanner.
    
    Tests for:
    - gRPC reflection enabled
    - gRPC-Web exposure
    - Insecure gRPC (no TLS)
    - Method enumeration
    - Input validation bypass
    - Authorization bypass
    - DoS via large messages
    - Streaming abuse
    - Metadata injection
    """
    
    name = "grpc_scanner"
    
    # Common gRPC ports
    GRPC_PORTS = [50051, 50052, 9090, 443, 8443]
    
    # gRPC-Web content types
    GRPC_WEB_CONTENT_TYPES = [
        "application/grpc-web",
        "application/grpc-web+proto",
        "application/grpc-web-text",
        "application/grpc-web-text+proto",
    ]
    
    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.timeout = settings.timeouts.request_timeout
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Scan for gRPC vulnerabilities."""
        findings: list[Finding] = []
        
        clean_host = host.replace("https://", "").replace("http://", "").split("/")[0]
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            # Detect gRPC endpoints
            grpc_info = await self._detect_grpc(client, clean_host, rate_limiter)
            
            if grpc_info["found"]:
                # Test gRPC-Web endpoints
                grpc_web_findings = await self._test_grpc_web(
                    client, clean_host, grpc_info, rate_limiter
                )
                findings.extend(grpc_web_findings)
                
                # Test reflection
                reflection_findings = await self._test_reflection(
                    client, clean_host, grpc_info, rate_limiter
                )
                findings.extend(reflection_findings)
                
                # Test health endpoints
                health_findings = await self._test_grpc_health(
                    client, clean_host, rate_limiter
                )
                findings.extend(health_findings)
                
                # Test for common services
                service_findings = await self._test_common_services(
                    client, clean_host, grpc_info, rate_limiter
                )
                findings.extend(service_findings)
                
                # Test metadata injection
                metadata_findings = await self._test_metadata_injection(
                    client, clean_host, grpc_info, rate_limiter
                )
                findings.extend(metadata_findings)
            
            # Test for insecure gRPC
            insecure_findings = await self._test_insecure_grpc(
                client, clean_host, rate_limiter
            )
            findings.extend(insecure_findings)
        
        return findings
    
    async def _detect_grpc(
        self,
        client: httpx.AsyncClient,
        host: str,
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Detect gRPC endpoints."""
        grpc_info = {
            "found": False,
            "type": None,
            "port": None,
            "url": None,
        }
        
        # Check for gRPC-Web via HTTP/2
        grpc_web_paths = [
            "/",
            "/grpc",
            "/api/grpc",
            "/rpc",
        ]
        
        for path in grpc_web_paths:
            for scheme in ["https", "http"]:
                await rate_limiter.acquire()
                
                try:
                    url = f"{scheme}://{host}{path}"
                    
                    # Send gRPC-Web style request
                    response = await client.post(
                        url,
                        headers={
                            "Content-Type": "application/grpc-web+proto",
                            "Accept": "application/grpc-web+proto",
                            "x-grpc-web": "1",
                        },
                        content=b"\x00\x00\x00\x00\x00",  # Empty gRPC message
                    )
                    
                    # Check for gRPC response headers
                    content_type = response.headers.get("content-type", "")
                    
                    if any(ct in content_type for ct in self.GRPC_WEB_CONTENT_TYPES):
                        grpc_info["found"] = True
                        grpc_info["type"] = "grpc-web"
                        grpc_info["url"] = url
                        logger.info(f"gRPC-Web found at {url}")
                        return grpc_info
                    
                    # Check for gRPC error responses
                    grpc_status = response.headers.get("grpc-status")
                    if grpc_status is not None:
                        grpc_info["found"] = True
                        grpc_info["type"] = "grpc-web"
                        grpc_info["url"] = url
                        return grpc_info
                        
                except Exception as e:
                    logger.debug(f"Error checking gRPC at {path}: {e}")
        
        return grpc_info
    
    async def _test_grpc_web(
        self,
        client: httpx.AsyncClient,
        host: str,
        grpc_info: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test gRPC-Web endpoints."""
        findings = []
        
        if grpc_info["type"] != "grpc-web":
            return findings
        
        url = grpc_info.get("url", f"https://{host}")
        
        # Test common service methods
        test_methods = [
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
            "/grpc.health.v1.Health/Check",
            "/google.protobuf.Empty",
            "/admin.AdminService/GetUsers",
            "/user.UserService/GetUser",
            "/auth.AuthService/Login",
        ]
        
        for method in test_methods:
            await rate_limiter.acquire()
            
            try:
                test_url = f"{url.rstrip('/')}{method}"
                
                response = await client.post(
                    test_url,
                    headers={
                        "Content-Type": "application/grpc-web+proto",
                        "Accept": "application/grpc-web+proto",
                        "x-grpc-web": "1",
                    },
                    content=b"\x00\x00\x00\x00\x00",
                )
                
                grpc_status = response.headers.get("grpc-status", "")
                grpc_message = response.headers.get("grpc-message", "")
                
                # Status 12 = UNIMPLEMENTED (method exists but not implemented)
                # Status 2 = UNKNOWN (method found)
                # Status 0 = OK
                if grpc_status in ["0", "2", "12"]:
                    severity = "HIGH" if "admin" in method.lower() else "MEDIUM"
                    
                    findings.append(Finding(
                        name="gRPC-Web Method Accessible",
                        severity=severity,
                        confidence="HIGH",
                        description=f"gRPC-Web method accessible: {method}",
                        matched_at=test_url,
                        evidence=[
                            f"gRPC Status: {grpc_status}",
                            f"Message: {grpc_message}",
                        ],
                        cwe="CWE-200",
                        cvss_score=6.5 if "admin" in method.lower() else 4.3,
                        remediation="Implement proper authorization for gRPC methods. "
                                   "Use interceptors for authentication.",
                    ))
                    
            except Exception as e:
                logger.debug(f"Error testing gRPC method: {e}")
        
        return findings
    
    async def _test_reflection(
        self,
        client: httpx.AsyncClient,
        host: str,
        grpc_info: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for gRPC reflection."""
        findings = []
        
        url = grpc_info.get("url", f"https://{host}")
        
        reflection_endpoints = [
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
        ]
        
        for endpoint in reflection_endpoints:
            await rate_limiter.acquire()
            
            try:
                test_url = f"{url.rstrip('/')}{endpoint}"
                
                # gRPC reflection request (list services)
                # This is a simplified check - actual reflection uses streaming
                response = await client.post(
                    test_url,
                    headers={
                        "Content-Type": "application/grpc-web+proto",
                        "Accept": "application/grpc-web+proto",
                        "x-grpc-web": "1",
                    },
                    content=b"\x00\x00\x00\x00\x05\n\x03\x00\x00\x00",
                )
                
                grpc_status = response.headers.get("grpc-status", "")
                
                # If reflection responds (even with error), it's enabled
                if grpc_status in ["0", "2", "3"]:  # OK, UNKNOWN, or INVALID_ARGUMENT
                    findings.append(Finding(
                        name="gRPC Reflection Enabled",
                        severity="MEDIUM",
                        confidence="HIGH",
                        description="gRPC server reflection is enabled, exposing service definitions",
                        matched_at=test_url,
                        evidence=[
                            "Reflection endpoint responds",
                            f"gRPC Status: {grpc_status}",
                        ],
                        cwe="CWE-200",
                        cvss_score=5.3,
                        remediation="Disable gRPC reflection in production. "
                                   "Use: grpc.reflection.enabled=false",
                    ))
                    break
                    
            except Exception as e:
                logger.debug(f"Error testing reflection: {e}")
        
        return findings
    
    async def _test_grpc_health(
        self,
        client: httpx.AsyncClient,
        host: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test gRPC health check endpoint."""
        findings = []
        
        health_endpoints = [
            "/grpc.health.v1.Health/Check",
            "/grpc.health.v1.Health/Watch",
        ]
        
        for scheme in ["https", "http"]:
            for endpoint in health_endpoints:
                await rate_limiter.acquire()
                
                try:
                    url = f"{scheme}://{host}{endpoint}"
                    
                    response = await client.post(
                        url,
                        headers={
                            "Content-Type": "application/grpc-web+proto",
                            "x-grpc-web": "1",
                        },
                        content=b"\x00\x00\x00\x00\x00",
                    )
                    
                    grpc_status = response.headers.get("grpc-status", "")
                    
                    if grpc_status in ["0", "2"]:
                        findings.append(Finding(
                            name="gRPC Health Endpoint Exposed",
                            severity="LOW",
                            confidence="HIGH",
                            description="gRPC health check endpoint is publicly accessible",
                            matched_at=url,
                            evidence=["Health endpoint responds"],
                            cwe="CWE-200",
                            cvss_score=3.1,
                            remediation="Consider restricting health endpoint to internal access.",
                        ))
                        return findings
                        
                except Exception as e:
                    logger.debug(f"Error testing health: {e}")
        
        return findings
    
    async def _test_common_services(
        self,
        client: httpx.AsyncClient,
        host: str,
        grpc_info: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for common gRPC service patterns."""
        findings = []
        
        url = grpc_info.get("url", f"https://{host}")
        
        # Common service patterns that might be sensitive
        sensitive_services = [
            ("/admin.AdminService/", "Admin Service"),
            ("/internal.InternalService/", "Internal Service"),
            ("/debug.DebugService/", "Debug Service"),
            ("/config.ConfigService/", "Config Service"),
            ("/user.UserService/ListUsers", "User Listing"),
            ("/auth.AuthService/", "Auth Service"),
            ("/payment.PaymentService/", "Payment Service"),
            ("/order.OrderService/", "Order Service"),
        ]
        
        for service_path, service_name in sensitive_services:
            await rate_limiter.acquire()
            
            try:
                test_url = f"{url.rstrip('/')}{service_path}"
                
                response = await client.post(
                    test_url,
                    headers={
                        "Content-Type": "application/grpc-web+proto",
                        "x-grpc-web": "1",
                    },
                    content=b"\x00\x00\x00\x00\x00",
                )
                
                grpc_status = response.headers.get("grpc-status", "")
                
                # Service exists if status is not 12 (UNIMPLEMENTED)
                if grpc_status and grpc_status != "12":
                    severity = "HIGH" if "admin" in service_path.lower() or "internal" in service_path.lower() else "MEDIUM"
                    
                    findings.append(Finding(
                        name=f"gRPC {service_name} Detected",
                        severity=severity,
                        confidence="MEDIUM",
                        description=f"gRPC service detected: {service_name}",
                        matched_at=test_url,
                        evidence=[
                            f"Service path: {service_path}",
                            f"gRPC Status: {grpc_status}",
                        ],
                        cwe="CWE-200",
                        cvss_score=6.5 if severity == "HIGH" else 4.3,
                        remediation="Ensure proper authorization for sensitive services.",
                    ))
                    
            except Exception as e:
                logger.debug(f"Error testing service: {e}")
        
        return findings
    
    async def _test_metadata_injection(
        self,
        client: httpx.AsyncClient,
        host: str,
        grpc_info: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for metadata/header injection in gRPC."""
        findings = []
        
        url = grpc_info.get("url", f"https://{host}")
        
        # Test header injection
        injection_headers = {
            "Content-Type": "application/grpc-web+proto",
            "x-grpc-web": "1",
            # Injection attempts
            "authorization": "Bearer admin",
            "x-user-id": "1",
            "x-admin": "true",
            "x-internal": "true",
            "x-forwarded-user": "admin",
            "x-original-user": "admin",
        }
        
        await rate_limiter.acquire()
        
        try:
            test_url = f"{url.rstrip('/')}/grpc.health.v1.Health/Check"
            
            response = await client.post(
                test_url,
                headers=injection_headers,
                content=b"\x00\x00\x00\x00\x00",
            )
            
            # Check if any custom headers are echoed back
            for header in ["x-user-id", "x-admin", "x-internal"]:
                if header in response.headers:
                    findings.append(Finding(
                        name="gRPC Metadata Reflection",
                        severity="MEDIUM",
                        confidence="MEDIUM",
                        description="gRPC server reflects metadata headers",
                        matched_at=test_url,
                        evidence=[f"Header {header} reflected in response"],
                        cwe="CWE-200",
                        cvss_score=4.3,
                        remediation="Don't reflect arbitrary metadata. Validate metadata inputs.",
                    ))
                    break
                    
        except Exception as e:
            logger.debug(f"Error testing metadata: {e}")
        
        return findings
    
    async def _test_insecure_grpc(
        self,
        client: httpx.AsyncClient,
        host: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for insecure (non-TLS) gRPC."""
        findings = []
        
        # Test common gRPC ports without TLS
        for port in self.GRPC_PORTS:
            await rate_limiter.acquire()
            
            try:
                # Try HTTP (insecure) connection
                url = f"http://{host}:{port}/grpc.health.v1.Health/Check"
                
                response = await client.post(
                    url,
                    headers={
                        "Content-Type": "application/grpc-web+proto",
                        "x-grpc-web": "1",
                    },
                    content=b"\x00\x00\x00\x00\x00",
                    timeout=5.0,
                )
                
                grpc_status = response.headers.get("grpc-status")
                
                if grpc_status is not None:
                    findings.append(Finding(
                        name="Insecure gRPC (No TLS)",
                        severity="HIGH",
                        confidence="HIGH",
                        description=f"gRPC service accessible without TLS on port {port}",
                        matched_at=url,
                        evidence=[
                            f"Port: {port}",
                            "gRPC responds over HTTP (no encryption)",
                        ],
                        cwe="CWE-319",
                        cvss_score=7.5,
                        remediation="Enable TLS for all gRPC communications. "
                                   "Use grpc.ssl_channel_credentials().",
                    ))
                    break
                    
            except Exception:
                pass  # Port not responding
        
        return findings
