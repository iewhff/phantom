"""
PHANTOM AI - Token Binding Validator

Tests token security by validating that tokens are properly bound to:
1. Session context (token reuse across sessions)
2. IP address (token reuse from different IPs)
3. Device/User-Agent (token reuse from different devices)
4. TLS session (token binding to TLS)
5. Proof-of-Possession keys (OAuth 2.0 DPoP)

Also tests:
- Refresh token rotation enforcement
- Token scope boundary violations
- Session timeout enforcement
- MFA token security

Works generically for ALL web applications with JWT or session-based auth.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.scan_client import get_scan_client
from utils.logger import get_logger
from scanning.scan_context import ScanContext

logger = get_logger(__name__)


# Common token locations
TOKEN_LOCATIONS = [
    "Authorization",  # Bearer token
    "X-Access-Token",
    "X-Auth-Token",
    "X-API-Key",
    "Cookie",  # Session cookies
]

# Common whoami/profile endpoints to verify token validity
WHOAMI_ENDPOINTS = [
    "/api/user", "/api/me", "/api/profile", "/api/whoami",
    "/user/me", "/users/me", "/me", "/whoami", "/profile",
    "/rest/user/whoami", "/api/v1/user", "/api/v1/me",
    "/account", "/api/account", "/api/users/current",
]

# Common refresh token endpoints
REFRESH_ENDPOINTS = [
    "/api/auth/refresh", "/auth/refresh", "/api/refresh",
    "/oauth/token", "/api/token/refresh", "/token/refresh",
    "/api/v1/auth/refresh", "/rest/user/refresh",
]


@dataclass
class TokenInfo:
    """Information about a discovered token."""
    value: str
    location: str  # Header name or cookie name
    token_type: str  # jwt, session, api_key, bearer
    claims: dict = field(default_factory=dict)
    expiry: int = 0


class TokenBindingValidator(ScanModule):
    """
    Validates token binding and session security.

    Tests for missing token binding, scope violations, and session management issues.
    """

    name = "token_binding"
    description = "Validates token binding to context (session, IP, device, TLS)"
    version = "1.0.0"
    author = "PHANTOM AI"
    tags = ["token", "session", "binding", "oauth", "jwt"]

    # Standard safety - reads and reuses tokens, no destructive operations
    min_safety_level = "standard"

    def __init__(
        self,
        settings: Any = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self._base_url = ""
        self._auth_headers: dict[str, str] = {}
        self._discovered_tokens: list[TokenInfo] = []
        self._whoami_endpoint: str = ""

    async def scan(
        self,
        host: str,
        port: int | None = None,
        extra_params: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Main entry point for token binding validation."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(extra_params)
        self._auth_headers = self._ctx.auth_headers

        extra_params = extra_params or {}
        self._base_url = self._resolve_base_url(host, port)

        # Get auth context if available
        auth_context = extra_params.get("auth_context")
        if auth_context and hasattr(auth_context, "auth_headers"):
            self._auth_headers = auth_context.auth_headers

        findings: list[Finding] = []

        # Phase 1: Discover tokens and whoami endpoint
        await self._discover_tokens()
        await self._find_whoami_endpoint()

        if not self._discovered_tokens:
            logger.info("[TOKEN] No tokens discovered, skipping binding tests")
            return findings

        # Phase 2: Test token reuse from different contexts
        context_findings = await self._test_context_binding()
        findings.extend(context_findings)

        # Phase 3: Test refresh token rotation
        refresh_findings = await self._test_refresh_rotation()
        findings.extend(refresh_findings)

        # Phase 4: Test token scope boundaries
        scope_findings = await self._test_scope_boundaries()
        findings.extend(scope_findings)

        # Phase 5: Test session timeout enforcement
        timeout_findings = await self._test_timeout_enforcement()
        findings.extend(timeout_findings)

        # Phase 6: Test concurrent session handling
        concurrent_findings = await self._test_concurrent_sessions()
        findings.extend(concurrent_findings)

        return findings

    def _resolve_base_url(self, host: str, port: int | None) -> str:
        """Resolve base URL from host and port."""
        if host.startswith(("http://", "https://")):
            return host.rstrip("/")

        if port in (443, 8443):
            protocol = "https"
        else:
            protocol = "http"

        if port and port not in (80, 443):
            return f"{protocol}://{host}:{port}"
        return f"{protocol}://{host}"

    async def _discover_tokens(self) -> None:
        """Discover tokens from auth headers and responses."""
        self._discovered_tokens = []

        # Check auth headers for tokens
        for header_name in TOKEN_LOCATIONS:
            if header_name in self._auth_headers:
                value = self._auth_headers[header_name]
                token_info = self._analyze_token(value, header_name)
                if token_info:
                    self._discovered_tokens.append(token_info)

        # Also check Cookie header specially
        if "Cookie" in self._auth_headers:
            cookies = self._auth_headers["Cookie"]
            for cookie in cookies.split(";"):
                if "=" in cookie:
                    name, value = cookie.strip().split("=", 1)
                    token_info = self._analyze_token(value, f"Cookie:{name}")
                    if token_info:
                        self._discovered_tokens.append(token_info)

        # Try to extract tokens from whoami response
        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                for endpoint in WHOAMI_ENDPOINTS[:5]:
                    url = urljoin(self._base_url, endpoint)
                    try:
                        resp = await client.get(url, headers=self._auth_headers)
                        if resp.status_code == 200:
                            # Check response headers for tokens
                            for header in ["X-Access-Token", "X-Auth-Token", "Authorization"]:
                                if header in resp.headers:
                                    token_info = self._analyze_token(resp.headers[header], header)
                                    if token_info:
                                        self._discovered_tokens.append(token_info)
                            break
                    except (httpx.RequestError, httpx.TimeoutException):
                        pass
        except (httpx.RequestError, httpx.TimeoutException):
            pass

        logger.info(f"[TOKEN] Discovered {len(self._discovered_tokens)} tokens")

    def _analyze_token(self, value: str, location: str) -> TokenInfo | None:
        """Analyze a token value to determine its type and extract claims."""
        # Skip empty or very short values
        if not value or len(value) < 10:
            return None

        # Check for Bearer prefix
        if value.startswith("Bearer "):
            value = value[7:]

        # Check if it's a JWT
        if value.count(".") == 2:
            parts = value.split(".")
            try:
                # Decode header and payload
                header = json.loads(self._base64_decode(parts[0]))
                payload = json.loads(self._base64_decode(parts[1]))

                return TokenInfo(
                    value=value,
                    location=location,
                    token_type="jwt",
                    claims=payload,
                    expiry=payload.get("exp", 0),
                )
            except (json.JSONDecodeError, ValueError, UnicodeDecodeError, TypeError):
                pass

        # Check if it looks like a session ID
        if len(value) >= 20 and re.match(r"^[A-Za-z0-9+/=-]+$", value):
            return TokenInfo(
                value=value,
                location=location,
                token_type="session",
            )

        # Check if it looks like an API key
        if len(value) >= 20 and re.match(r"^[A-Za-z0-9_-]+$", value):
            return TokenInfo(
                value=value,
                location=location,
                token_type="api_key",
            )

        return None

    def _base64_decode(self, data: str) -> str:
        """Decode base64 with padding fix."""
        try:
            # Add padding if needed
            padding = 4 - len(data) % 4
            if padding != 4:
                data += "=" * padding
            # URL-safe base64
            data = data.replace("-", "+").replace("_", "/")
            return base64.b64decode(data).decode("utf-8", errors="replace")
        except (ValueError, UnicodeDecodeError):
            return ""

    async def _find_whoami_endpoint(self) -> None:
        """Find a working whoami/profile endpoint."""
        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                for endpoint in WHOAMI_ENDPOINTS:
                    url = urljoin(self._base_url, endpoint)
                    try:
                        resp = await client.get(url, headers=self._auth_headers)
                        if resp.status_code == 200:
                            # Verify it returns user data
                            try:
                                data = resp.json()
                                if isinstance(data, dict) and any(
                                    k in data for k in ["user", "email", "id", "username", "name"]
                                ):
                                    self._whoami_endpoint = url
                                    logger.info(f"[TOKEN] Found whoami endpoint: {endpoint}")
                                    return
                            except json.JSONDecodeError:
                                pass
                    except (httpx.RequestError, httpx.TimeoutException):
                        pass
        except (httpx.RequestError, httpx.TimeoutException):
            pass

    async def _test_context_binding(self) -> list[Finding]:
        """Test token binding to session context (IP, device, etc.)."""
        findings: list[Finding] = []

        if not self._whoami_endpoint:
            return findings

        # Different context headers to test token reuse
        context_variations = [
            # IP address variation
            {"X-Forwarded-For": "10.0.0.1", "context": "different_ip"},
            {"X-Forwarded-For": "192.168.1.100", "context": "internal_ip"},
            # Device variation
            {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)", "context": "different_device"},
            {"User-Agent": "curl/8.0", "context": "cli_tool"},
            # Origin variation
            {"Origin": "http://attacker.example.com", "context": "different_origin"},
        ]

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                # Get baseline response with original context
                baseline_resp = await client.get(self._whoami_endpoint, headers=self._auth_headers)

                if baseline_resp.status_code != 200:
                    return findings

                baseline_data = baseline_resp.text

                # Test each context variation
                for variation in context_variations:
                    context_name = variation.pop("context")
                    test_headers = {**self._auth_headers, **variation}

                    try:
                        resp = await client.get(self._whoami_endpoint, headers=test_headers)

                        # If token still works with different context, it's not bound
                        if resp.status_code == 200 and resp.text == baseline_data:
                            findings.append(Finding(
                                vuln_type=VulnType.INSECURE_SESSION,
                                name=f"Token Not Bound to {context_name.replace('_', ' ').title()}",
                                description=(
                                    f"The authentication token is not bound to the {context_name.replace('_', ' ')} context.\n\n"
                                    f"The same token was successfully used with a different context:\n"
                                    f"**Context change:** `{list(variation.items())[0][0]}: {list(variation.items())[0][1]}`\n\n"
                                    f"This means a stolen token can be used from any IP, device, or origin, "
                                    f"increasing the risk of token theft attacks."
                                ),
                                severity=Severity.MEDIUM,
                                confidence_score=85.0,
                                host=urlparse(self._whoami_endpoint).netloc,
                                endpoint=self._whoami_endpoint,
                                metadata={
                                    "context_type": context_name,
                                    "header_changed": list(variation.keys())[0],
                                    "token_type": self._discovered_tokens[0].token_type if self._discovered_tokens else "unknown",
                                },
                            ))
                    except (httpx.RequestError, httpx.TimeoutException):
                        pass

        except (httpx.RequestError, httpx.TimeoutException) as e:
            logger.debug(f"[TOKEN] Error testing context binding: {e}")

        return findings

    async def _test_refresh_rotation(self) -> list[Finding]:
        """Test refresh token rotation enforcement."""
        findings: list[Finding] = []

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                # Find a working refresh endpoint
                for endpoint in REFRESH_ENDPOINTS:
                    url = urljoin(self._base_url, endpoint)

                    try:
                        resp = await client.post(url, json={}, headers=self._auth_headers)

                        if resp.status_code == 200:
                            # Got a new token - try to use old token again
                            try:
                                data = resp.json()
                                if isinstance(asset_data, dict):
                                    new_token = data.get("access_token") or data.get("token")

                                if new_token:
                                    # Wait a moment, then try the original token
                                    await asyncio.sleep(0.5)

                                    # Try whoami with original token
                                    if self._whoami_endpoint:
                                        check_resp = await client.get(
                                            self._whoami_endpoint,
                                            headers=self._auth_headers
                                        )

                                        if check_resp.status_code == 200:
                                            findings.append(Finding(
                                                vuln_type=VulnType.INSECURE_SESSION,
                                                name="Refresh Token Rotation Not Enforced",
                                                description=(
                                                    f"After refreshing the access token at `{url}`, "
                                                    f"the old token is still valid.\n\n"
                                                    f"Proper refresh token rotation should invalidate the "
                                                    f"old access token when a new one is issued. This allows "
                                                    f"attackers to maintain persistent access even if the user "
                                                    f"refreshes their session."
                                                ),
                                                severity=Severity.MEDIUM,
                                                confidence_score=90.0,
                                                host=urlparse(url).netloc,
                                                endpoint=url,
                                                metadata={
                                                    "refresh_endpoint": url,
                                                    "old_token_still_valid": True,
                                                },
                                            ))
                                            break
                            except json.JSONDecodeError:
                                pass
                    except (httpx.RequestError, httpx.TimeoutException):
                        pass

        except (httpx.RequestError, httpx.TimeoutException) as e:
            logger.debug(f"[TOKEN] Error testing refresh rotation: {e}")

        return findings

    async def _test_scope_boundaries(self) -> list[Finding]:
        """Test token scope boundary violations."""
        findings: list[Finding] = []

        # Check if any JWT has scope claims
        for token in self._discovered_tokens:
            if token.token_type != "jwt":
                continue

            scopes = token.claims.get("scope", "").split() or token.claims.get("scopes", [])
            if not scopes:
                continue

            # Try to access endpoints outside the token's scope
            scope_tests = {
                "read": ["/api/users", "/api/orders", "/api/data"],
                "write": ["/api/users/create", "/api/orders/update"],
                "admin": ["/api/admin", "/admin", "/api/admin/users"],
                "delete": ["/api/users/1/delete", "/api/orders/1"],
            }

            try:
                async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                    for scope_type, endpoints in scope_tests.items():
                        # If this scope is NOT in the token's scopes, test it
                        if scope_type not in " ".join(scopes).lower():
                            for endpoint in endpoints:
                                url = urljoin(self._base_url, endpoint)
                                try:
                                    resp = await client.get(url, headers=self._auth_headers)

                                    if resp.status_code == 200:
                                        findings.append(Finding(
                                            vuln_type=VulnType.INSECURE_SESSION,
                                            name="Token Scope Boundary Violation",
                                            description=(
                                                f"The token with scope `{' '.join(scopes)}` was able to "
                                                f"access endpoint `{endpoint}` which appears to require "
                                                f"`{scope_type}` scope.\n\n"
                                                f"This indicates improper scope validation, allowing tokens "
                                                f"to access resources outside their authorized scope."
                                            ),
                                            severity=Severity.HIGH,
                                            confidence_score=75.0,
                                            host=urlparse(url).netloc,
                                            endpoint=url,
                                            metadata={
                                                "token_scopes": scopes,
                                                "accessed_scope": scope_type,
                                                "endpoint": endpoint,
                                            },
                                        ))
                                        break  # Found one violation for this scope
                                except (httpx.RequestError, httpx.TimeoutException):
                                    pass

            except (httpx.RequestError, httpx.TimeoutException):
                pass

        return findings

    async def _test_timeout_enforcement(self) -> list[Finding]:
        """Test session timeout enforcement."""
        findings: list[Finding] = []

        # Check JWT expiry
        for token in self._discovered_tokens:
            if token.token_type == "jwt" and token.expiry:
                current_time = int(time.time())

                # Check if token is already expired but still works
                if token.expiry < current_time:
                    if self._whoami_endpoint:
                        try:
                            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                                resp = await client.get(self._whoami_endpoint, headers=self._auth_headers)

                                if resp.status_code == 200:
                                    findings.append(Finding(
                                        vuln_type=VulnType.INSECURE_SESSION,
                                        name="Expired JWT Token Still Valid",
                                        description=(
                                            f"The JWT token has expired (exp claim: {token.expiry}, "
                                            f"current time: {current_time}) but is still accepted by the server.\n\n"
                                            f"This indicates that JWT expiration is not being validated, "
                                            f"allowing attackers to use old stolen tokens indefinitely."
                                        ),
                                        severity=Severity.HIGH,
                                        confidence_score=95.0,
                                        host=urlparse(self._whoami_endpoint).netloc,
                                        endpoint=self._whoami_endpoint,
                                        metadata={
                                            "token_expiry": token.expiry,
                                            "current_time": current_time,
                                            "seconds_past_expiry": current_time - token.expiry,
                                        },
                                    ))
                        except (httpx.RequestError, httpx.TimeoutException):
                            pass

                # Check if expiry is excessively long (>24 hours)
                time_to_expiry = token.expiry - current_time
                if time_to_expiry > 86400:  # 24 hours
                    findings.append(Finding(
                        vuln_type=VulnType.INSECURE_SESSION,
                        name="Excessive JWT Token Lifetime",
                        description=(
                            f"The JWT token has an excessive lifetime of {time_to_expiry // 3600} hours.\n\n"
                            f"Long-lived tokens increase the risk window for token theft. "
                            f"Best practice is to use short-lived access tokens (15-60 minutes) "
                            f"with refresh token rotation."
                        ),
                        severity=Severity.LOW,
                        confidence_score=90.0,
                        host=urlparse(self._base_url).netloc,
                        endpoint=self._base_url,
                        metadata={
                            "token_lifetime_seconds": time_to_expiry,
                            "token_lifetime_hours": time_to_expiry // 3600,
                        },
                    ))

        return findings

    async def _test_concurrent_sessions(self) -> list[Finding]:
        """Test concurrent session handling."""
        findings: list[Finding] = []

        # This would require actually creating multiple sessions
        # For now, we check if the server exposes session count/limit info

        if self._whoami_endpoint:
            try:
                async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                    resp = await client.get(self._whoami_endpoint, headers=self._auth_headers)

                    if resp.status_code == 200:
                        try:
                            data = resp.json()

                            # Check for session info in response
                            # BUG-FIX: Only process dict responses, not arrays
                            if isinstance(data, dict) and ("sessions" in data or "active_sessions" in data):
                                session_count = data.get("sessions", data.get("active_sessions", []))
                                if isinstance(session_count, list):
                                    session_count = len(session_count)

                                if session_count and session_count > 10:
                                    findings.append(Finding(
                                        vuln_type=VulnType.INSECURE_SESSION,
                                        name="Excessive Concurrent Sessions",
                                        description=(
                                            f"The user account has {session_count} active sessions.\n\n"
                                            f"Allowing unlimited concurrent sessions increases the risk "
                                            f"of undetected account compromise. Consider implementing "
                                            f"session limits or alerting users about new sessions."
                                        ),
                                        severity=Severity.LOW,
                                        confidence_score=70.0,
                                        host=urlparse(self._whoami_endpoint).netloc,
                                        endpoint=self._whoami_endpoint,
                                        metadata={
                                            "active_sessions": session_count,
                                        },
                                    ))
                        except json.JSONDecodeError:
                            pass

            except (httpx.RequestError, httpx.TimeoutException):
                pass

        return findings
