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

                    # Test path manipulation bypass
                    path_variants = [
                        path + "/",
                        path + "//",
                        path + "/./",
                        path + "/%2e/",
                        path.upper(),
                        path + "?",
                        path + "#",
                        path + ";",
                        path + "%00",
                        path + ".json",
                        path + ".html",
                    ]

                    for variant in path_variants:
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

                except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                    logger.debug(f"Auth bypass check failed for {url}: {e}")

        return findings
