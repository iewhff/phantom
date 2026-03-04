"""
Auth Testing - State-Aware and Cross-User Testing.

Provides infrastructure for testing authentication and authorization:
- Phase 4.55: State-aware retest (auth vs no-auth comparison)
- Phase 4.56: Cross-user identity variation testing

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol
from urllib.parse import urlparse

import aiohttp

from utils.logger import get_logger
from scanning.auth_testing.helpers import (
    AuthContextProtocol,
    extract_user_identifiers,
    contains_victim_data,
    extract_data_content,
)

logger = get_logger(__name__)


# =============================================================================
# PROTOCOLS
# =============================================================================


class ScanResultProtocol(Protocol):
    """Protocol for scan result objects."""

    @property
    def findings(self) -> list[dict]:
        ...


class UserPersonasProtocol(Protocol):
    """Protocol for user personas manager."""

    @property
    def has_multiple_users(self) -> bool:
        ...

    def get_cross_user_pairs(self) -> list[tuple[Any, Any]]:
        ...


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class AuthTestConfig:
    """Configuration for auth testing."""

    max_endpoints: int = 10
    max_user_pairs: int = 3
    timeout_seconds: float = 10.0
    verify_ssl: bool = False
    log_debug: bool = True
    log_info: bool = True

    # Public paths to skip in state-aware retest
    public_paths: list[str] = field(
        default_factory=lambda: [
            "/",
            "/index",
            "/index.html",
            "/home",
            "/login",
            "/signin",
            "/signup",
            "/register",
            "/health",
            "/healthz",
            "/ready",
            "/readyz",
            "/metrics",
            "/prometheus",
            "/robots.txt",
            "/sitemap.xml",
            "/favicon.ico",
            "/api-docs",
            "/swagger",
            "/openapi",
        ]
    )

    # Sensitive patterns that indicate real user data
    sensitive_patterns: list[str] = field(
        default_factory=lambda: [
            "@",  # Email addresses
            '"email":',
            '"username":',
            '"user_id":',
            '"profile":',
            '"account_id":',
            '"customer_id":',
            '"phone":',
            '"address":',
            '"ssn":',
            '"dob":',
            '"balance":',
            '"credit_card":',
            '"account_balance":',
            '"transaction_id":',
            '"payment_id":',
            '"password":',
            '"secret":',
            '"api_key":',
            '"access_token":',
            '"role":',
            '"is_admin":',
            '"permissions":',
        ]
    )


@dataclass
class StateRetestResult:
    """Result of state-aware retest."""

    auth_bypasses: list[dict] = field(default_factory=list)
    endpoints_tested: int = 0
    endpoints_skipped: int = 0


@dataclass
class CrossUserResult:
    """Result of cross-user testing."""

    findings: list[dict] = field(default_factory=list)
    pairs_tested: int = 0
    endpoints_tested: int = 0


# =============================================================================
# MAIN CLASS
# =============================================================================


class AuthTester:
    """
    Handles state-aware and cross-user authentication testing.

    Usage:
        tester = AuthTester(auth_context, config)
        state_result = await tester.state_aware_retest(result, target)
        cross_result = await tester.identity_variation_retest(result, target, personas)
    """

    def __init__(
        self,
        auth_context: Optional[AuthContextProtocol] = None,
        config: Optional[AuthTestConfig] = None,
    ):
        """
        Initialize auth tester.

        Args:
            auth_context: Authentication context with token/cookies
            config: Test configuration
        """
        self.auth_context = auth_context
        self.config = config or AuthTestConfig()
        self._ssl_ctx = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context for requests."""
        ctx = ssl.create_default_context()
        if not self.config.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _get_auth_headers(self) -> dict[str, str]:
        """Get authentication headers from auth context."""
        headers: dict[str, str] = {}
        if self.auth_context:
            if self.auth_context.token:
                headers["Authorization"] = f"Bearer {self.auth_context.token}"
            if self.auth_context.cookies:
                headers["Cookie"] = "; ".join(
                    f"{k}={v}" for k, v in self.auth_context.cookies.items()
                )
        return headers

    def _is_public_path(self, url: str) -> bool:
        """Check if URL is a known public path."""
        parsed = urlparse(url)
        path = parsed.path.rstrip("/")
        return any(
            path == p.rstrip("/") or path.startswith(p + "/")
            for p in self.config.public_paths
        )

    def _has_sensitive_data(self, body: str) -> bool:
        """Check if response contains sensitive data patterns."""
        return any(p in body for p in self.config.sensitive_patterns)

    async def state_aware_retest(
        self, result: ScanResultProtocol, target: str
    ) -> StateRetestResult:
        """
        Phase 4.55: State-Aware Retest.

        Re-test endpoints that had findings WITH auth by testing them WITHOUT auth.
        This discovers auth bypasses and state-dependent vulnerabilities.

        Philosophy: "Testaste estados alternativos?"
        - If endpoint works WITH auth but also WITHOUT → Auth Bypass!
        - If endpoint returns DIFFERENT data WITHOUT auth → Info Disclosure differential
        - If endpoint returns ERROR without auth → Auth working correctly (good)

        Args:
            result: Scan result with findings
            target: Target URL

        Returns:
            StateRetestResult with auth bypass findings
        """
        retest_result = StateRetestResult()

        # Only run if we have auth context
        if not self.auth_context:
            return retest_result

        # Extract unique endpoints from HIGH+ findings
        endpoints_to_retest: set[str] = set()
        for finding in result.findings:
            if isinstance(finding, dict):
                severity = finding.get("severity", "MEDIUM")
                if severity in ("HIGH", "CRITICAL"):
                    url = (
                        finding.get("matched_at")
                        or finding.get("url")
                        or finding.get("host")
                    )
                    if url and url.startswith("http"):
                        endpoints_to_retest.add(url.split("?")[0])  # Base URL

        if not endpoints_to_retest:
            if self.config.log_debug:
                logger.debug("[StateRetest] No HIGH+ endpoints to retest")
            return retest_result

        if self.config.log_info:
            logger.info(
                f"🔄 Phase 4.55: State-aware retest on {len(endpoints_to_retest)} endpoints"
            )

        auth_headers = self._get_auth_headers()

        async with aiohttp.ClientSession() as session:
            for endpoint in list(endpoints_to_retest)[: self.config.max_endpoints]:
                try:
                    bypass = await self._test_endpoint_bypass(
                        session, endpoint, auth_headers, target
                    )
                    if bypass:
                        retest_result.auth_bypasses.append(bypass)
                    retest_result.endpoints_tested += 1
                except Exception as e:
                    if self.config.log_debug:
                        logger.debug(f"[StateRetest] Error testing {endpoint}: {e}")

        return retest_result

    async def _test_endpoint_bypass(
        self,
        session: aiohttp.ClientSession,
        endpoint: str,
        auth_headers: dict[str, str],
        target: str,
    ) -> Optional[dict]:
        """Test if an endpoint has auth bypass vulnerability."""
        timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)

        # Get response WITH auth (baseline)
        async with session.get(
            endpoint, headers=auth_headers, ssl=self._ssl_ctx, timeout=timeout
        ) as auth_resp:
            auth_status = auth_resp.status
            auth_body = await auth_resp.text()

        # Test WITHOUT auth
        async with session.get(
            endpoint, ssl=self._ssl_ctx, timeout=timeout
        ) as noauth_resp:
            noauth_status = noauth_resp.status
            noauth_body = await noauth_resp.text()

        # Analysis: Compare responses
        if auth_status == 200 and noauth_status == 200:
            if len(noauth_body) > 100:  # Meaningful response
                # Skip known public endpoints
                if self._is_public_path(endpoint):
                    if self.config.log_debug:
                        logger.debug(
                            f"[StateRetest] {endpoint}: Public path, skipping"
                        )
                    return None

                # FIX 2026-03-02: Detect SPA shell responses.
                # SPAs return the same HTML shell for ALL routes (existing or not).
                # If both responses are HTML and nearly identical in size, it's a
                # SPA catch-all — not an auth bypass.
                noauth_lower = noauth_body.lower()
                is_html = "<!doctype" in noauth_lower or "<html" in noauth_lower
                size_ratio = min(len(auth_body), len(noauth_body)) / max(len(auth_body), len(noauth_body), 1)
                if is_html and size_ratio > 0.95:
                    if self.config.log_debug:
                        logger.debug(
                            f"[StateRetest] {endpoint}: SPA shell (HTML, {len(noauth_body)} bytes), skipping"
                        )
                    return None

                has_sensitive = self._has_sensitive_data(noauth_body)

                # Compare data content
                auth_data = extract_data_content(auth_body)
                noauth_data = extract_data_content(noauth_body)
                unique_to_auth = auth_data - noauth_data

                data_similarity = (
                    len(auth_data & noauth_data) / max(len(auth_data), 1)
                    if auth_data
                    else 0
                )

                # Only flag as bypass if:
                # 1. Has sensitive patterns AND data is highly similar (>95%)
                # 2. OR no unique auth data (exactly same content)
                is_bypass = (has_sensitive and data_similarity > 0.95) or (
                    len(unique_to_auth) < 3 and data_similarity > 0.98
                )

                if is_bypass:
                    logger.warning(f"🔓 AUTH BYPASS FOUND: {endpoint}")
                    return {
                        "type": "auth_bypass",
                        "name": "Authentication Bypass - Endpoint Accessible Without Auth",
                        "severity": "CRITICAL",
                        "description": (
                            f"Endpoint returns data without authentication. "
                            f"Auth response: {auth_status}/{len(auth_body)} bytes. "
                            f"No-auth response: {noauth_status}/{len(noauth_body)} bytes."
                        ),
                        "host": target,
                        "matched_at": endpoint,
                        "evidence": [
                            f"Endpoint: {endpoint}",
                            f"With auth: HTTP {auth_status}, {len(auth_body)} bytes",
                            f"Without auth: HTTP {noauth_status}, {len(noauth_body)} bytes",
                            "Data similarity indicates bypass (both return user data)",
                        ],
                        "cvss_score": 9.8,
                        "cwe": "CWE-306",
                        "confidence": 90.0,
                        "remediation": (
                            "Enforce authentication on all sensitive endpoints. "
                            "Verify JWT/session tokens before returning data."
                        ),
                        "metadata": {
                            "state_aware_discovery": True,
                            "original_auth_status": auth_status,
                            "noauth_status": noauth_status,
                        },
                    }

        elif auth_status == 200 and noauth_status in (401, 403):
            # Good - auth is working
            if self.config.log_debug:
                logger.debug(
                    f"[StateRetest] {endpoint}: Auth working correctly ({noauth_status})"
                )

        return None

    async def identity_variation_retest(
        self,
        result: ScanResultProtocol,
        target: str,
        user_personas: Optional[UserPersonasProtocol],
    ) -> CrossUserResult:
        """
        Phase 4.56: Cross-User Identity Variation Testing.

        Philosophy: "Simple targets 'dry out' the scanner because PHANTOM
        doesn't simulate complete users with distinct roles and permissions."

        This phase replays discovered sensitive actions with different user contexts
        to find horizontal and vertical privilege escalation:
        - User A accessing User B's resources (horizontal IDOR)
        - Regular user accessing admin endpoints (vertical privilege escalation)

        Args:
            result: Scan result with findings
            target: Target URL
            user_personas: User personas manager

        Returns:
            CrossUserResult with privilege escalation findings
        """
        cross_result = CrossUserResult()

        if not user_personas or not user_personas.has_multiple_users:
            return cross_result

        if self.config.log_info:
            logger.info("🔄 Phase 4.56: Cross-User Identity Variation Testing")

        # Collect sensitive endpoints from findings
        sensitive_types = {
            "idor",
            "authorization",
            "access_control",
            "business_logic",
            "authentication",
            "privilege_escalation",
            "insecure_direct_object",
        }

        user_specific_endpoints: list[tuple[str, str, dict]] = []

        for finding in result.findings:
            if not isinstance(finding, dict):
                continue

            finding_type = finding.get("type", "").lower()
            url = finding.get("matched_at") or finding.get("host", "")

            if any(t in finding_type for t in sensitive_types):
                method = (finding.get("metadata", {}).get("method") or "GET").upper()
                user_specific_endpoints.append((url, method, finding))
            elif url and any(
                p in url.lower()
                for p in ["/user/", "/profile", "/account", "/basket", "/cart", "/order"]
            ):
                method = (finding.get("metadata", {}).get("method") or "GET").upper()
                user_specific_endpoints.append((url, method, finding))

        if not user_specific_endpoints:
            if self.config.log_debug:
                logger.debug("[IdentityVariation] No user-specific endpoints to test")
            return cross_result

        pairs = user_personas.get_cross_user_pairs()
        if self.config.log_info:
            logger.info(
                f"[IdentityVariation] Testing {len(user_specific_endpoints)} endpoints "
                f"with {len(pairs)} user pairs"
            )

        timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds * 1.5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            for url, method, original_finding in user_specific_endpoints[:15]:
                for attacker, victim in pairs[: self.config.max_user_pairs]:
                    try:
                        findings = await self._test_cross_user_access(
                            session, url, method, attacker, victim, original_finding, target
                        )
                        cross_result.findings.extend(findings)
                        cross_result.pairs_tested += 1
                    except Exception as e:
                        if self.config.log_debug:
                            logger.debug(f"[IdentityVariation] Error testing {url}: {e}")
                cross_result.endpoints_tested += 1

        if cross_result.findings and self.config.log_info:
            logger.info(
                f"🔓 Found {len(cross_result.findings)} cross-user vulnerabilities"
            )

        return cross_result

    async def _test_cross_user_access(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        attacker: Any,
        victim: Any,
        original_finding: dict,
        target: str,
    ) -> list[dict]:
        """Test if attacker can access victim's resource."""
        findings: list[dict] = []

        # Skip if URL doesn't look like it has user-specific data
        if not url or url == target:
            return findings

        try:
            # Get victim's resource with victim's auth
            victim_headers = getattr(victim, "auth_headers", {})
            async with session.get(
                url, headers=victim_headers, ssl=self._ssl_ctx
            ) as victim_resp:
                victim_status = victim_resp.status
                victim_body = await victim_resp.text()

            if victim_status != 200:
                return findings  # Can't access as victim, skip

            # Extract victim-specific identifiers
            victim_identifiers = extract_user_identifiers(victim_body, victim)

            # Try to access same resource with attacker's auth
            attacker_headers = getattr(attacker, "auth_headers", {})
            async with session.get(
                url, headers=attacker_headers, ssl=self._ssl_ctx
            ) as attacker_resp:
                attacker_status = attacker_resp.status
                attacker_body = await attacker_resp.text()

            if attacker_status != 200:
                return findings  # Attacker can't access, no vuln

            # Check if attacker got victim's data
            if contains_victim_data(attacker_body, victim_identifiers, victim):
                attacker_email = getattr(attacker, "email", "unknown")
                attacker_id = getattr(attacker, "user_id", "unknown")
                attacker_persona = getattr(attacker, "persona_name", "attacker")
                victim_email = getattr(victim, "email", "unknown")
                victim_id = getattr(victim, "user_id", "unknown")
                victim_persona = getattr(victim, "persona_name", "victim")

                findings.append({
                    "type": "horizontal_privesc",
                    "name": "Cross-User Data Access (Horizontal Privilege Escalation)",
                    "severity": "CRITICAL",
                    "confidence": 90.0,
                    "description": (
                        f"User '{attacker_email}' (persona: {attacker_persona}) can access "
                        f"data belonging to user '{victim_email}' (persona: {victim_persona}). "
                        f"This indicates broken access control allowing horizontal privilege escalation."
                    ),
                    "host": target,
                    "matched_at": url,
                    "evidence": [
                        f"Attacker user: {attacker_email} (ID: {attacker_id})",
                        f"Victim user: {victim_email} (ID: {victim_id})",
                        f"Endpoint: {url}",
                        f"Attacker got victim's data: {victim_identifiers[:3]}",
                    ],
                    "cvss_score": 8.8,
                    "cwe": "CWE-639",
                    "remediation": (
                        "Implement proper authorization checks to ensure users can only access "
                        "their own resources. Use the authenticated user's ID from the session, "
                        "not from user-supplied input."
                    ),
                    "metadata": {
                        "attacker_user": attacker_email,
                        "victim_user": victim_email,
                        "cross_user_test": True,
                        "original_finding": original_finding.get("name", ""),
                        "can_chain": True,
                        "scanner": "identity_variation",
                    },
                })

        except Exception as e:
            if self.config.log_debug:
                logger.debug(f"[IdentityVariation] Cross-user test failed: {e}")

        return findings


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


async def state_aware_retest(
    result: ScanResultProtocol,
    target: str,
    auth_context: Optional[AuthContextProtocol] = None,
    config: Optional[AuthTestConfig] = None,
) -> StateRetestResult:
    """
    Convenience function for state-aware retest.

    Args:
        result: Scan result with findings
        target: Target URL
        auth_context: Authentication context
        config: Test configuration

    Returns:
        StateRetestResult
    """
    tester = AuthTester(auth_context, config)
    return await tester.state_aware_retest(result, target)


async def identity_variation_retest(
    result: ScanResultProtocol,
    target: str,
    user_personas: Optional[UserPersonasProtocol] = None,
    auth_context: Optional[AuthContextProtocol] = None,
    config: Optional[AuthTestConfig] = None,
) -> CrossUserResult:
    """
    Convenience function for identity variation retest.

    Args:
        result: Scan result with findings
        target: Target URL
        user_personas: User personas manager
        auth_context: Authentication context
        config: Test configuration

    Returns:
        CrossUserResult
    """
    tester = AuthTester(auth_context, config)
    return await tester.identity_variation_retest(result, target, user_personas)
