"""
OAuth 2.0 / OpenID Connect Security Scanner

Enterprise-grade OAuth/OIDC security testing including:
- OpenID Configuration analysis
- Implicit flow detection
- PKCE support verification
- Redirect URI validation
- State parameter checking

CWE Coverage:
- CWE-287: Improper Authentication
- CWE-319: Cleartext Transmission of Sensitive Information
- CWE-601: URL Redirection to Untrusted Site

Author: PetNTester AI Enterprise
Version: 2.0.0
"""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

import httpx

from scanning.findings import Finding, Severity, VulnType
from utils.scan_client import get_scan_client
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

from .auth_base import OAuthConfig, OAUTH_PATHS

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class OAuthScanner:
    """
    OAuth 2.0 / OpenID Connect Security Scanner

    Tests for common OAuth/OIDC security issues including
    implicit flow, missing PKCE, and redirect vulnerabilities.
    """

    def __init__(self, settings: Settings) -> None:
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
        self.oauth_config: OAuthConfig | None = None

    async def scan(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Comprehensive OAuth 2.0 / OpenID Connect security scan.
        """
        findings = []

        try:
            async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
                # Check for OpenID configuration
                await rate_limiter.acquire()

                for path in ["/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"]:
                    url = urljoin(base_url, path)
                    try:
                        resp = await client.get(url)
                        if resp.status_code == 200:
                            try:
                                config = resp.json()
                                self.oauth_config = OAuthConfig(
                                    authorization_endpoint=config.get("authorization_endpoint", ""),
                                    token_endpoint=config.get("token_endpoint", ""),
                                )

                                # Check for insecure response types
                                response_types = config.get("response_types_supported", [])
                                if "token" in response_types:
                                    findings.append(Finding(
                                        vuln_type=VulnType.AUTH_BYPASS,
                                        name="OAuth Implicit Flow Supported",
                                        severity=Severity.MEDIUM,
                                        description="OAuth server supports implicit flow (response_type=token). "
                                                   "This is deprecated and can leak tokens via browser history.",
                                        host=base_url,
                                        endpoint=url,
                                        evidence=[f"response_types_supported: {response_types}"],
                                        cvss_score=5.3,
                                        cwe_id="CWE-319",
                                        remediation="Disable implicit flow. Use authorization code flow with PKCE.",
                                    ).to_dict())

                                # Check for PKCE support
                                pkce_methods = config.get("code_challenge_methods_supported", [])
                                if not pkce_methods or "S256" not in pkce_methods:
                                    findings.append(Finding(
                                        vuln_type=VulnType.AUTH_BYPASS,
                                        name="OAuth Missing PKCE Support",
                                        severity=Severity.LOW,
                                        description="OAuth server does not advertise PKCE support. "
                                                   "Authorization code flow may be vulnerable to interception.",
                                        host=base_url,
                                        endpoint=url,
                                        evidence=[f"code_challenge_methods_supported: {pkce_methods}"],
                                        cvss_score=3.7,
                                        cwe_id="CWE-287",
                                        remediation="Enable PKCE with S256 method for all clients.",
                                    ).to_dict())

                                # Check grant types
                                grant_types = config.get("grant_types_supported", [])
                                if "password" in grant_types:
                                    findings.append(Finding(
                                        vuln_type=VulnType.AUTH_BYPASS,
                                        name="OAuth Resource Owner Password Grant Supported",
                                        severity=Severity.LOW,
                                        description="OAuth server supports password grant. "
                                                   "This exposes user credentials to the client application.",
                                        host=base_url,
                                        endpoint=url,
                                        evidence=[f"grant_types_supported: {grant_types}"],
                                        cvss_score=4.0,
                                        cwe_id="CWE-287",
                                        remediation="Disable password grant for public clients. "
                                                   "Use authorization code flow instead.",
                                    ).to_dict())

                            except json.JSONDecodeError:
                                pass
                    except (httpx.HTTPError, httpx.TimeoutException, OSError):
                        continue

                # Check for OAuth redirect vulnerabilities in page content
                await rate_limiter.acquire()
                resp = await client.get(base_url)

                oauth_patterns = [
                    r'redirect_uri=([^&\s"\']+)',
                    r'callback_url=([^&\s"\']+)',
                    r'return_url=([^&\s"\']+)',
                ]

                for pattern in oauth_patterns:
                    matches = re.findall(pattern, resp.text)
                    for match in matches[:3]:
                        parsed = urlparse(match)
                        if parsed.scheme and parsed.netloc:
                            if parsed.netloc != urlparse(base_url).netloc:
                                findings.append(Finding(
                                    vuln_type=VulnType.AUTH_BYPASS,
                                    name="OAuth Open Redirect Risk",
                                    severity=Severity.MEDIUM,
                                    description="OAuth redirect_uri may be vulnerable to open redirect. "
                                               "Attackers could steal authorization codes.",
                                    host=base_url,
                                    endpoint=base_url,
                                    evidence=[f"Redirect found: {match[:100]}"],
                                    cvss_score=6.1,
                                    cwe_id="CWE-601",
                                    remediation="Whitelist redirect URIs. "
                                               "Do not allow arbitrary redirect destinations.",
                                ).to_dict())
                                break

                # Check OAuth endpoints directly
                oauth_findings = await self._check_oauth_endpoints(
                    base_url, client, rate_limiter
                )
                findings.extend(oauth_findings)

        except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
            logger.debug(f"OAuth security check failed: {e}")

        return findings

    async def _check_oauth_endpoints(
        self,
        base_url: str,
        client: httpx.AsyncClient,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Check OAuth endpoints for security issues."""
        findings = []

        for path in OAUTH_PATHS:
            await rate_limiter.acquire()

            url = urljoin(base_url, path)

            try:
                resp = await client.get(url)

                if resp.status_code == 200:
                    content = resp.text.lower()

                    # Check for exposed client secrets
                    secret_patterns = [
                        r'client_secret["\s:=]+([a-zA-Z0-9_-]{20,})',
                        r'secret["\s:=]+([a-zA-Z0-9_-]{20,})',
                    ]

                    for pattern in secret_patterns:
                        if re.search(pattern, resp.text, re.I):
                            findings.append(Finding(
                                vuln_type=VulnType.AUTH_BYPASS,
                                name="OAuth Client Secret Exposed",
                                severity=Severity.HIGH,
                                description="OAuth client secret found in response. "
                                           "This allows attackers to impersonate the client.",
                                host=base_url,
                                endpoint=url,
                                evidence=[f"Secret pattern found at: {url}"],
                                cvss_score=7.5,
                                cwe_id="CWE-798",
                                remediation="Remove client secrets from public responses. "
                                           "Use PKCE for public clients instead of secrets.",
                            ).to_dict())
                            break

                    # Check for missing state parameter
                    if "authorize" in path and "state" not in content:
                        findings.append(Finding(
                            vuln_type=VulnType.AUTH_BYPASS,
                            name="OAuth State Parameter Missing",
                            severity=Severity.MEDIUM,
                            description="OAuth authorization endpoint may not require state parameter. "
                                       "This enables CSRF attacks on OAuth flow.",
                            host=base_url,
                            endpoint=url,
                            evidence=[f"No state parameter found at: {url}"],
                            cvss_score=5.3,
                            cwe_id="CWE-352",
                            remediation="Require and validate state parameter on all OAuth requests.",
                        ).to_dict())

            except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
                logger.debug(f"OAuth endpoint check failed for {url}: {e}")

        return findings

    def get_oauth_config(self) -> OAuthConfig | None:
        """Return detected OAuth configuration."""
        return self.oauth_config
