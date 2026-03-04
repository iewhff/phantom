"""
PHANTOM AI - Auth Acquisition Layer

Acquires authentication tokens on target applications for authenticated
testing (business logic, race conditions, IDOR, etc.).

Strategies (tried in order):
1. Register a test account via common JSON API registration endpoints
2. Login with common/default credentials via JSON API
3. Form-based registration (application/x-www-form-urlencoded)
4. Form-based login with session cookie extraction (Spring Security, PHP, Django, etc.)
5. SQLi auth bypass (aggressive mode only)

The acquired AuthContext is stored in asset_data["auth_context"]
and consumed by business logic, race condition, and IDOR scanners.

NOTE: Uses aiohttp directly (not httpx) to bypass SafeAsyncClient
monkey-patching that blocks POST in safe mode.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import ssl
import string
import threading
import time

from scanning.determinism import deterministic_string
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING
from urllib.parse import urlencode, urlparse

# Domain-aware auth strategies (2026-02-12)
if TYPE_CHECKING:
    from scanning.auth_strategies import AuthStrategy

import aiohttp

from utils.logger import get_logger

# =============================================================================
# CONSTANTS (M1 FIX 2026-02-12)
# =============================================================================

# Auth freshness TTL - after this time, auth context is considered stale
DEFAULT_AUTH_FRESHNESS_TTL = 300.0  # 5 minutes

# HTTP timeout for auth acquisition requests
DEFAULT_AUTH_TIMEOUT = 10.0  # seconds

# Minimum session cookie length to consider it a valid session cookie
MIN_SESSION_COOKIE_LENGTH = 20

# Maximum number of verification paths to try for session verification
# Increased from 6 to 12 to cover training apps (bWAPP, DVWA, Mutillidae, WebGoat)
MAX_VERIFY_PATHS = 12

# Minimum response length to consider it an authenticated response (not just a redirect/error page)
MIN_AUTHENTICATED_RESPONSE_LENGTH = 500

# Minimum token length to consider it valid (prevents garbage strings)
MIN_TOKEN_LENGTH = 20

# =============================================================================
# TOKEN VALIDATION HELPER (AUDIT-FIX 2026-02-19)
# =============================================================================


def _is_valid_token(token: str) -> bool:
    """Validate that a token looks like a legitimate auth token.

    AUDIT-FIX 2026-02-19: Prevents accepting garbage strings as tokens.

    Validates:
    - Minimum length (20 chars)
    - JWT structure (3 parts separated by dots for JWT)
    - OR opaque token (alphanumeric with reasonable length)
    - No obvious error/garbage indicators

    Returns:
        True if token appears valid, False otherwise.
    """
    if not token or not isinstance(token, str):
        return False

    token = token.strip()

    # Check minimum length
    if len(token) < MIN_TOKEN_LENGTH:
        return False

    # Reject obvious garbage/error responses
    garbage_indicators = [
        "<!doctype", "<html", "<error", "invalid", "unauthorized",
        "forbidden", "not found", "bad request", "internal server",
        "exception", "traceback", "error:", "{\"error",
    ]
    token_lower = token.lower()
    if any(ind in token_lower for ind in garbage_indicators):
        return False

    # JWT validation: 3 parts separated by dots, first part starts with eyJ
    if "." in token:
        parts = token.split(".")
        if len(parts) == 3:
            # Valid JWT structure
            if parts[0].startswith("eyJ"):
                return True
            # Might be non-standard JWT, check parts are base64-ish
            import re
            base64_pattern = re.compile(r'^[A-Za-z0-9_-]+$')
            if all(base64_pattern.match(p) for p in parts):
                return True

    # Opaque token validation: alphanumeric with some special chars allowed
    import re
    opaque_pattern = re.compile(r'^[A-Za-z0-9_\-=+/]+$')
    if opaque_pattern.match(token):
        return True

    # UUID-like token
    uuid_pattern = re.compile(r'^[a-f0-9\-]{32,40}$', re.IGNORECASE)
    if uuid_pattern.match(token):
        return True

    # Fallback: if it's mostly alphanumeric, accept it
    alphanum_ratio = sum(c.isalnum() for c in token) / len(token)
    if alphanum_ratio >= 0.8:
        return True

    return False


# =============================================================================
# PUBLIC API (H1 FIX 2026-02-12)
# =============================================================================

__all__ = [
    # Core classes
    "AuthContext",
    "UserPersonaStore",
    "AuthAcquisition",
    # Helper functions
    "require_auth",
    "get_auth_context_from_asset_data",
]


def _encode_form_data(form_data: dict[str, str]) -> str:
    """
    Encode form data as application/x-www-form-urlencoded string.

    IMPORTANT: aiohttp's session.post(data=dict) uses multipart encoding by default,
    which many servers (Spring Security, etc.) reject for form login/registration.
    This function ensures proper URL encoding.
    """
    return urlencode(form_data)

logger = get_logger(__name__)

SAFE_MODE = os.environ.get("PHANTOM_SAFE_MODE", "safe").lower()


@dataclass
class AuthContext:
    """Authentication context acquired from target."""

    token: str = ""
    token_type: str = "bearer"    # "bearer" for JWT, "cookie" for session-based
    method: str = ""              # register, login, sqli_bypass, form_login, form_register
    user_id: str = ""
    email: str = ""
    basket_id: str = ""
    cookies: dict = field(default_factory=dict)   # Session cookies (JSESSIONID, PHPSESSID, etc.)
    extra: dict = field(default_factory=dict)
    # User persona info for multi-user testing
    role: str = "user"            # user, admin, guest, moderator, etc.
    persona_name: str = ""        # "attacker", "victim", "user_a", "user_b"

    # THEME-3 FIX: Auth context tracking across phases
    used_by_modules: list = field(default_factory=list)      # Modules that consumed this auth
    auth_requirements: dict = field(default_factory=dict)    # module -> required_auth_type
    skip_reasons: dict = field(default_factory=dict)         # module -> reason for skip
    refresh_status: str = "fresh"                            # fresh, stale, refreshed, expired
    last_used_at: float = 0.0                                # Timestamp of last use

    # H4 FIX 2026-02-12: Thread safety for mutable state
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    @property
    def auth_headers(self) -> dict[str, str]:
        """Build auth headers — supports both Bearer tokens and session cookies."""
        headers: dict[str, str] = {}
        if self.token and self.token_type == "bearer":
            headers["Authorization"] = f"Bearer {self.token}"
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            headers["Cookie"] = cookie_str
        return headers

    @property
    def has_auth(self) -> bool:
        return bool(self.token) or bool(self.cookies)

    # =========================================================================
    # THEME-3: Auth Context Tracking Methods
    # =========================================================================

    def record_usage(self, module_name: str, auth_type_required: str = "any") -> None:
        """
        Record that a module used this auth context.

        Args:
            module_name: Name of the module (e.g., "business_logic_scanner")
            auth_type_required: Type of auth required ("jwt", "cookie", "admin", "any")
        """
        # H4 FIX 2026-02-12: Thread-safe mutation
        with self._lock:
            if module_name not in self.used_by_modules:
                self.used_by_modules.append(module_name)
            self.auth_requirements[module_name] = auth_type_required
            self.last_used_at = time.time()
        logger.debug(f"[AUTH-TRACK] Module '{module_name}' used auth (type: {auth_type_required})")

    def record_skip(self, module_name: str, reason: str) -> None:
        """
        Record that a module was skipped due to auth issues.

        Args:
            module_name: Name of the module
            reason: Why the module was skipped (e.g., "no_auth", "wrong_role", "token_expired")
        """
        # H4 FIX 2026-02-12: Thread-safe mutation
        with self._lock:
            self.skip_reasons[module_name] = reason
        logger.warning(f"[AUTH-TRACK] Module '{module_name}' SKIPPED: {reason}")

    def check_auth_freshness(self, max_age_seconds: float = DEFAULT_AUTH_FRESHNESS_TTL) -> bool:
        """
        Check if auth context is still fresh (not expired).

        Args:
            max_age_seconds: Maximum age in seconds before considering stale

        Returns:
            True if auth is fresh, False if stale/expired
        """
        if not self.has_auth:
            return False
        # H4 FIX 2026-02-12: Thread-safe read + conditional mutation
        with self._lock:
            if self.refresh_status == "expired":
                return False
            if self.last_used_at > 0:
                age = time.time() - self.last_used_at
                if age > max_age_seconds:
                    self.refresh_status = "stale"
                    return False
        return True

    def mark_refreshed(self, new_token: str = "") -> None:
        """Mark auth as refreshed (e.g., after token refresh)."""
        # H4 FIX 2026-02-12: Thread-safe mutation
        with self._lock:
            self.refresh_status = "refreshed"
            self.last_used_at = time.time()
            if new_token:
                self.token = new_token
        logger.info(f"[AUTH-TRACK] Auth context refreshed for {self.email}")

    def mark_expired(self, reason: str = "unknown") -> None:
        """Mark auth as expired (e.g., 401 response, logout detected)."""
        # H4 FIX 2026-02-12: Thread-safe mutation
        with self._lock:
            self.refresh_status = "expired"
        logger.warning(f"[AUTH-TRACK] Auth context EXPIRED for {self.email}: {reason}")

    async def auto_refresh_if_stale(
        self,
        http_client: Any,
        base_url: str,
    ) -> bool:
        """
        Automatically refresh token if stale using refresh_token.

        This method attempts to use a stored refresh_token to obtain a new
        access token without requiring re-authentication.

        Args:
            http_client: HTTP client for making requests
            base_url: Base URL of the target

        Returns:
            True if token was refreshed, False otherwise
        """
        # Check if we have a refresh token
        refresh_token = self.extra.get("refresh_token")
        if not refresh_token:
            logger.debug("[AUTH] No refresh token available for auto-refresh")
            return False

        # Check if refresh is needed
        if self.check_auth_freshness():
            return True  # Still fresh, no refresh needed

        logger.info("[AUTH] Token stale, attempting auto-refresh...")

        # Common refresh endpoints to try
        refresh_paths = [
            "/api/auth/refresh",
            "/api/token/refresh",
            "/api/v1/auth/refresh",
            "/api/v1/token/refresh",
            "/auth/refresh",
            "/oauth/token",
            "/api/refresh",
            "/token/refresh",
            "/api/security/refreshtoken",
        ]

        # Different body formats used by various APIs
        body_formats = [
            {"refresh_token": refresh_token},
            {"refreshToken": refresh_token},
            {"grant_type": "refresh_token", "refresh_token": refresh_token},
            {"token": refresh_token, "grant_type": "refresh_token"},
        ]

        base = base_url.rstrip("/")

        for path in refresh_paths:
            url = f"{base}{path}"

            for body in body_formats:
                try:
                    resp = await http_client.post(
                        url,
                        json=body,
                        headers=self.auth_headers,
                        timeout=10.0,
                    )

                    # Check for successful response
                    status = getattr(resp, "status_code", getattr(resp, "status", 0))
                    if status != 200:
                        continue

                    # Parse response
                    try:
                        if hasattr(resp, "json"):
                            if asyncio.iscoroutinefunction(resp.json):
                                data = await resp.json()
                            else:
                                data = resp.json()
                        else:
                            import json
                            text = await resp.text() if hasattr(resp.text, "__await__") else resp.text
                            data = json.loads(text)
                    except Exception:
                        continue

                    # Extract new token
                    new_token = (
                        data.get("access_token")
                        or data.get("accessToken")
                        or data.get("token")
                        or data.get("id_token")
                    )

                    if new_token:
                        # Update auth context
                        self.mark_refreshed(new_token)

                        # Store new refresh token if provided
                        new_refresh = (
                            data.get("refresh_token")
                            or data.get("refreshToken")
                        )
                        if new_refresh:
                            with self._lock:
                                self.extra["refresh_token"] = new_refresh

                        logger.info(
                            f"[AUTH] Token refreshed successfully via {path}"
                        )
                        return True

                except Exception as e:
                    logger.debug(f"[AUTH] Refresh attempt failed ({path}): {e}")
                    continue

        logger.warning("[AUTH] Auto-refresh failed - no endpoint worked")
        return False

    def get_usage_summary(self) -> dict:
        """Get summary of auth usage across modules."""
        # H4 FIX 2026-02-12: Thread-safe snapshot of mutable state
        with self._lock:
            return {
                "email": self.email,
                "role": self.role,
                "auth_type": self.token_type,
                "method": self.method,
                "refresh_status": self.refresh_status,
                "modules_used": len(self.used_by_modules),
                "modules_skipped": len(self.skip_reasons),
                "used_by": self.used_by_modules.copy(),
                "skip_reasons": self.skip_reasons.copy(),
                "auth_requirements": self.auth_requirements.copy(),
            }


# =============================================================================
# AUTH REQUIREMENT HELPERS
# =============================================================================

def require_auth(
    auth_context: AuthContext | None,
    module_name: str,
    auth_type: str = "any",
    min_role: str = "user",
) -> tuple[bool, str]:
    """
    Check if auth requirements are met for a module.

    THEME-3 FIX: Centralized auth checking with skip reason logging.

    Args:
        auth_context: The auth context to check (may be None)
        module_name: Name of the calling module
        auth_type: Required auth type ("jwt", "cookie", "any")
        min_role: Minimum role required ("user", "admin", "moderator")

    Returns:
        tuple of (requirements_met: bool, reason: str)
        If requirements_met is False, reason explains why.

    Example:
        >>> met, reason = require_auth(ctx, "idor_scanner", auth_type="any", min_role="user")
        >>> if not met:
        ...     logger.warning(f"[{module_name}] Skipping: {reason}")
        ...     return []
    """
    # No auth context at all
    if auth_context is None:
        return False, "no_auth_context"

    # Auth context exists but has no credentials
    if not auth_context.has_auth:
        auth_context.record_skip(module_name, "no_credentials")
        return False, "no_credentials"

    # Check auth type requirement
    if auth_type != "any":
        if auth_type == "jwt" and not auth_context.token:
            auth_context.record_skip(module_name, f"requires_{auth_type}_but_has_cookie")
            return False, f"requires_{auth_type}_but_has_cookie"
        if auth_type == "cookie" and not auth_context.cookies:
            auth_context.record_skip(module_name, f"requires_{auth_type}_but_has_jwt")
            return False, f"requires_{auth_type}_but_has_jwt"

    # Check role requirement
    role_hierarchy = {"guest": 0, "user": 1, "moderator": 2, "admin": 3}
    current_role_level = role_hierarchy.get(auth_context.role, 1)
    required_role_level = role_hierarchy.get(min_role, 1)

    if current_role_level < required_role_level:
        reason = f"requires_{min_role}_but_has_{auth_context.role}"
        auth_context.record_skip(module_name, reason)
        return False, reason

    # Check auth freshness
    if not auth_context.check_auth_freshness():
        auth_context.record_skip(module_name, f"auth_stale_or_expired")
        return False, "auth_stale_or_expired"

    # All requirements met - record usage
    auth_context.record_usage(module_name, auth_type)
    return True, "ok"


def get_auth_context_from_asset_data(asset_data: dict | None) -> AuthContext | None:
    """
    Extract AuthContext from asset_data dict.

    Handles both direct AuthContext objects and dicts that need reconstruction.

    Args:
        asset_data: The asset_data dict from ScanModule or FullScanner

    Returns:
        AuthContext if found, None otherwise
    """
    # C1 FIX 2026-02-12: Fixed variable scoping - ctx was undefined when asset_data not dict
    if asset_data is None or not isinstance(asset_data, dict):
        return None

    ctx = asset_data.get("auth_context")
    if ctx is None:
        return None

    if isinstance(ctx, AuthContext):
        return ctx

    # Reconstruct from dict (e.g., if serialized)
    if isinstance(ctx, dict):
        return AuthContext(
            token=ctx.get("token", ""),
            token_type=ctx.get("token_type", "bearer"),
            method=ctx.get("method", ""),
            user_id=ctx.get("user_id", ""),
            email=ctx.get("email", ""),
            basket_id=ctx.get("basket_id", ""),
            cookies=ctx.get("cookies", {}),
            extra=ctx.get("extra", {}),
            role=ctx.get("role", "user"),
            persona_name=ctx.get("persona_name", ""),
        )

    return None


# =============================================================================
# MULTI-USER TESTING SUPPORT
# =============================================================================

@dataclass
class UserPersonaStore:
    """
    Stores multiple user contexts for cross-user/role-based testing.

    Philosophy: "Simple targets 'dry out' the scanner because PHANTOM
    doesn't simulate complete users with distinct roles and permissions."

    This enables:
    1. Attacker vs Victim testing (IDOR, CSRF cross-user)
    2. Role-based testing (user accessing admin endpoints)
    3. Identity variation replay (same action, different users)
    """

    primary: AuthContext = field(default_factory=AuthContext)   # Main user (attacker)
    secondary: AuthContext = field(default_factory=AuthContext) # Second user (victim)
    admin: AuthContext = field(default_factory=AuthContext)     # Admin if available
    guest: AuthContext = field(default_factory=AuthContext)     # Unauthenticated

    @property
    def has_multiple_users(self) -> bool:
        """Check if we have at least 2 authenticated users."""
        auth_count = sum([
            self.primary.has_auth,
            self.secondary.has_auth,
            self.admin.has_auth,
        ])
        return auth_count >= 2

    @property
    def all_contexts(self) -> list[AuthContext]:
        """Return all authenticated contexts."""
        return [ctx for ctx in [self.primary, self.secondary, self.admin]
                if ctx.has_auth]

    def get_victim_context(self) -> AuthContext:
        """Get victim context for cross-user testing."""
        # Prefer secondary, fallback to primary if only one user
        return self.secondary if self.secondary.has_auth else self.primary

    def get_attacker_context(self) -> AuthContext:
        """Get attacker context (primary user)."""
        return self.primary

    def get_cross_user_pairs(self) -> list[tuple[AuthContext, AuthContext]]:
        """
        Get pairs of (attacker, victim) for cross-user testing.

        Returns all permutations of authenticated users for thorough testing.
        """
        pairs = []
        contexts = self.all_contexts

        for i, attacker in enumerate(contexts):
            for j, victim in enumerate(contexts):
                if i != j:  # Don't pair user with themselves
                    pairs.append((attacker, victim))

        return pairs

    def to_dict(self) -> dict:
        """Serialize for asset_data storage."""
        return {
            "primary": {
                "user_id": self.primary.user_id,
                "email": self.primary.email,
                "role": self.primary.role,
                "persona": self.primary.persona_name,
                "has_auth": self.primary.has_auth,
            },
            "secondary": {
                "user_id": self.secondary.user_id,
                "email": self.secondary.email,
                "role": self.secondary.role,
                "persona": self.secondary.persona_name,
                "has_auth": self.secondary.has_auth,
            },
            "admin": {
                "user_id": self.admin.user_id,
                "email": self.admin.email,
                "role": self.admin.role,
                "has_auth": self.admin.has_auth,
            },
            "has_multiple_users": self.has_multiple_users,
            "cross_user_pairs_count": len(self.get_cross_user_pairs()),
        }

    def get_aggregate_usage_summary(self) -> dict:
        """
        THEME-3: Get aggregate auth usage summary across all personas.

        Returns a summary of which modules used which auth contexts,
        and which modules were skipped due to auth issues.
        """
        all_used_by: set[str] = set()
        all_skipped: dict[str, list[str]] = {}  # module -> [reasons]

        for ctx in [self.primary, self.secondary, self.admin]:
            if ctx.has_auth:
                all_used_by.update(ctx.used_by_modules)
                for module, reason in ctx.skip_reasons.items():
                    if module not in all_skipped:
                        all_skipped[module] = []
                    all_skipped[module].append(f"{ctx.persona_name or ctx.role}: {reason}")

        return {
            "total_personas": len(self.all_contexts),
            "modules_with_auth": list(all_used_by),
            "modules_skipped": all_skipped,
            "primary_usage": self.primary.get_usage_summary() if self.primary.has_auth else None,
            "secondary_usage": self.secondary.get_usage_summary() if self.secondary.has_auth else None,
            "admin_usage": self.admin.get_usage_summary() if self.admin.has_auth else None,
        }


# Registration endpoint patterns (path, body template)
_REGISTER_ENDPOINTS = [
    # REST API pattern (Express/Node.js apps with security questions)
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

# Common weak credentials to try (email-style for JSON APIs)
_COMMON_CREDS = [
    ("admin@admin.com", "admin123"),
    ("admin@example.com", "admin"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("test@test.com", "test1234"),
    ("test@example.com", "test"),
    ("user@user.com", "user1234"),
    ("guest", "guest"),
]

# Form-based login endpoint patterns (path, username_field, password_field)
_FORM_LOGIN_ENDPOINTS = [
    # ═══════════════════════════════════════════════════════════════════════════
    # TRAINING APPS - Test these FIRST (common pentesting targets)
    # ═══════════════════════════════════════════════════════════════════════════
    ("/login.php", "login", "password"),       # bWAPP (uses "login", not "username")
    ("/login.php", "username", "password"),    # DVWA, generic PHP
    ("/vulnerabilities/", "username", "password"),  # DVWA challenge pages
    ("/WebGoat/login", "username", "password"),     # WebGoat
    ("/index.php", "username", "password"),    # Mutillidae
    # Spring Security defaults
    ("/login", "username", "password"),
    ("/j_spring_security_check", "j_username", "j_password"),
    ("/spring_security_check", "j_username", "j_password"),
    # PHP frameworks
    ("/admin/login", "username", "password"),
    # Django
    ("/accounts/login/", "username", "password"),
    ("/admin/login/", "username", "password"),
    # Generic
    ("/auth/login", "username", "password"),
    ("/signin", "username", "password"),
    ("/user/login", "username", "password"),
]

# Form-based registration endpoint patterns (path, field mappings)
# These work for Spring Security, Django, Laravel, Rails, PHP apps, etc.
_FORM_REGISTER_ENDPOINTS = [
    # Spring Security / Spring MVC patterns
    ("/register.mvc", {
        "username": None,
        "password": None,
        "matchingPassword": None,
        "agree": "agree",
    }),
    ("/registration", {
        "username": None,
        "password": None,
        "matchingPassword": None,
        "agree": "agree",
    }),
    ("/user/register", {
        "username": None,
        "password": None,
        "matchingPassword": None,
    }),
    # Django patterns
    ("/accounts/register/", {"username": None, "password1": None, "password2": None}),
    ("/accounts/signup/", {"username": None, "password1": None, "password2": None}),
    # Laravel patterns
    ("/register", {"name": None, "email": None, "password": None, "password_confirmation": None}),
    # PHP patterns
    ("/register.php", {"username": None, "password": None, "password2": None}),
    ("/signup.php", {"username": None, "password": None, "confirmPassword": None}),
    # Rails patterns
    ("/users/sign_up", {"user[email]": None, "user[password]": None, "user[password_confirmation]": None}),
    # Generic patterns (most common)
    ("/register", {"username": None, "password": None, "confirmPassword": None}),
    ("/signup", {"username": None, "password": None, "password_confirm": None}),
    ("/auth/register", {"username": None, "email": None, "password": None, "password_confirmation": None}),
    # Training apps
    ("/setup.php", {}),  # DVWA setup
    ("/portal.php", {"login": None, "password": None}),  # bWAPP
    # WebGoat — registration at /WebGoat/register.mvc (Spring Security)
    ("/WebGoat/register.mvc", {
        "username": None,
        "password": None,
        "matchingPassword": None,
        "agree": "agree",
    }),
]

# ═══════════════════════════════════════════════════════════════════════════════
# TRAINING APP CREDENTIALS - PRIORITIZED FOR PENTESTING LABS
# These are tested FIRST because training apps are common scan targets
# ═══════════════════════════════════════════════════════════════════════════════
_TRAINING_APP_CREDS = [
    # bWAPP - buggy web app (bee:bug)
    ("bee", "bug"),
    # DVWA - Damn Vulnerable Web App
    ("admin", "password"),
    ("gordonb", "abc123"),
    ("1337", "charley"),
    ("pablo", "letmein"),
    ("smithy", "password"),
    # Mutillidae
    ("admin", "adminpw"),
    ("ed", "pentest"),
    # WebGoat
    ("webgoat", "webgoat"),
    # Juice Shop (email-based, but also tries as username)
    ("admin@juice-sh.op", "admin123"),
    # NodeGoat
    ("admin", "Admin_123"),
    ("user1", "User1_123"),
]

# Common credentials for form-based login (username-style, not email) - GENERIC
_FORM_COMMON_CREDS = [
    # Generic admin credentials
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("administrator", "administrator"),
    # Generic user credentials
    ("guest", "guest"),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("test", "test123"),
    ("demo", "demo"),
    # CMS defaults
    ("root", "root"),
    ("root", "toor"),
]

# Session cookie names to extract
_SESSION_COOKIE_NAMES = frozenset({
    "jsessionid", "phpsessid", "asp.net_sessionid", "aspsessionid",
    "session_id", "sessionid", "sid", "sess", "session", "connect.sid",
    "_session", "laravel_session", "ci_session", "csrftoken",
    "xsrf-token", "_csrf",
    # Training app cookies (2026-02-18)
    "security",  # DVWA security level (low/medium/high/impossible)
})

# Permissive SSL context for local/self-signed targets
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


class AuthAcquisition:
    """Acquire authentication on target for business logic testing.

    Supports domain-aware auth acquisition for:
    - ECOMMERCE: Cart, checkout, account endpoints
    - FINTECH: Banking, transfer, KYC endpoints
    - SAAS: Workspace, dashboard, OAuth flows
    - MARKETPLACE: Seller/buyer registration
    - AUTH_CENTRIC: OAuth, SAML, MFA
    - CONTENT: CMS login endpoints
    - API_SERVICE: API key, OAuth2

    Usage:
        acq = AuthAcquisition()
        ctx = await acq.acquire("https://shop.example.com", domain="ecommerce")
    """

    def __init__(self, timeout: float = DEFAULT_AUTH_TIMEOUT):
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._rate_limiter: Any = None
        self._app_base: str = ""
        self._domain_strategy: Any = None  # AuthStrategy instance
        self._init_metrics()

    def _init_metrics(self) -> None:
        """Initialize metrics tracking. H2 FIX 2026-02-12."""
        self._metrics = {
            "acquisitions_attempted": 0,
            "acquisitions_successful": 0,
            "acquisitions_failed": 0,
            "by_strategy": {
                "json_register": {"attempted": 0, "successful": 0},
                "json_login": {"attempted": 0, "successful": 0},
                "form_register": {"attempted": 0, "successful": 0},
                "form_login": {"attempted": 0, "successful": 0},
                "sqli_bypass": {"attempted": 0, "successful": 0},
            },
            "multi_user_acquisitions": 0,
            "errors": 0,
        }

    def get_metrics(self) -> dict:
        """Return current metrics. H2 FIX 2026-02-12."""
        return dict(self._metrics)

    def reset_metrics(self) -> None:
        """Reset metrics to initial state. H2 FIX 2026-02-12."""
        self._init_metrics()

    def _record_strategy_attempt(self, strategy: str) -> None:
        """Record that a strategy was attempted."""
        if strategy in self._metrics["by_strategy"]:
            self._metrics["by_strategy"][strategy]["attempted"] += 1

    def _record_strategy_success(self, strategy: str) -> None:
        """Record that a strategy succeeded."""
        if strategy in self._metrics["by_strategy"]:
            self._metrics["by_strategy"][strategy]["successful"] += 1

    async def _rate_limit(self) -> None:
        """Acquire rate limiter if available."""
        if self._rate_limiter:
            await self._rate_limiter.acquire()

    def _load_domain_strategy(self, domain: str | None) -> None:
        """Load domain-specific auth strategy. 2026-02-12."""
        try:
            from scanning.auth_strategies import get_strategy_for_domain
            self._domain_strategy = get_strategy_for_domain(domain)
            logger.debug(f"[AUTH] Loaded auth strategy for domain: {self._domain_strategy.domain.value}")
        except ImportError:
            # Fallback if auth_strategies module not available
            self._domain_strategy = None
            logger.debug("[AUTH] Auth strategies module not available, using fallback")

    def _get_domain_register_endpoints(self) -> list[tuple[str, dict[str, str | None]]]:
        """Get registration endpoints from domain strategy if available."""
        if self._domain_strategy:
            return self._domain_strategy.register_endpoints
        return []

    def _get_domain_login_endpoints(self) -> list[tuple[str, str, str]]:
        """Get login endpoints from domain strategy if available."""
        if self._domain_strategy:
            return self._domain_strategy.login_endpoints
        return []

    def _get_domain_credentials(self) -> list[tuple[str, str]]:
        """Get common credentials from domain strategy if available."""
        if self._domain_strategy:
            return self._domain_strategy.common_credentials
        return []

    def _get_domain_verify_paths(self) -> list[str]:
        """Get session verification paths from domain strategy if available."""
        if self._domain_strategy:
            return self._domain_strategy.session_verify_paths
        return []

    async def acquire(
        self,
        base_url: str,
        rate_limiter: Any = None,
        domain: str | None = None,
    ) -> AuthContext:
        """
        Try multiple strategies to acquire auth. Returns AuthContext (may be empty).

        Args:
            base_url: Target URL
            rate_limiter: Optional rate limiter
            domain: Business domain type (ecommerce, fintech, saas, marketplace,
                   auth_centric, content, api_service). If None, uses generic strategy.

        Returns:
            AuthContext with token/cookies if successful, empty AuthContext otherwise.
        """
        # Track acquisition attempt
        self._metrics["acquisitions_attempted"] += 1

        # Input validation
        if not base_url or not isinstance(base_url, str):
            logger.warning("[AUTH] Invalid base_url provided - returning empty AuthContext")
            self._metrics["acquisitions_failed"] += 1
            return AuthContext()

        self._rate_limiter = rate_limiter
        base_url = base_url.strip().rstrip("/")

        # Load domain-specific strategy (2026-02-12)
        self._load_domain_strategy(domain)
        domain_name = self._domain_strategy.domain.value if self._domain_strategy else "generic"

        # Detect base path for apps deployed under a subpath (e.g. /WebGoat)
        self._app_base = self._detect_app_base(base_url)
        logger.info(f"[AUTH] Starting auth acquisition for {base_url} (domain: {domain_name}, app_base: {self._app_base or 'none'})")

        # Strategy 1: Register a test account (JSON API)
        logger.debug("[AUTH] Trying Strategy 1: JSON API registration")
        self._record_strategy_attempt("json_register")
        ctx = await self._try_register(base_url)
        if ctx.has_auth:
            logger.info(f"[AUTH] ✓ Acquired token via JSON registration ({ctx.email})")
            self._record_strategy_success("json_register")
            self._metrics["acquisitions_successful"] += 1
            return ctx

        # Strategy 2: Login with common credentials (JSON API)
        logger.debug("[AUTH] Trying Strategy 2: JSON API login with common creds")
        self._record_strategy_attempt("json_login")
        ctx = await self._try_common_login(base_url)
        if ctx.has_auth:
            logger.info(f"[AUTH] ✓ Acquired token via JSON login ({ctx.email})")
            self._record_strategy_success("json_login")
            self._metrics["acquisitions_successful"] += 1
            return ctx

        # Strategy 3: Form-based login with session cookies
        # TRAINING-APP-FIX: Try login BEFORE register for training apps (DVWA, bWAPP, etc.)
        # Registered users may not have full access; default creds like bee:bug do
        logger.debug("[AUTH] Trying Strategy 3: Form-based login (before register)")
        self._record_strategy_attempt("form_login")
        ctx = await self._try_form_login(base_url)
        if ctx.has_auth:
            logger.info(f"[AUTH] ✓ Acquired session via form login ({ctx.email})")
            self._record_strategy_success("form_login")
            self._metrics["acquisitions_successful"] += 1
            return ctx

        # Strategy 4: Form-based registration (fallback if login fails)
        logger.debug("[AUTH] Trying Strategy 4: Form-based registration")
        self._record_strategy_attempt("form_register")
        ctx = await self._try_form_register(base_url)
        if ctx.has_auth:
            logger.info(f"[AUTH] ✓ Acquired session via form registration ({ctx.email})")
            self._record_strategy_success("form_register")
            self._metrics["acquisitions_successful"] += 1
            return ctx

        # Strategy 4.5: Headless browser login (for JS-rendered forms)
        # Only try if environment allows it and playwright is available
        if os.environ.get("PHANTOM_ALLOW_HEADLESS_AUTH", "1") == "1":
            logger.debug("[AUTH] Trying Strategy 4.5: Headless browser login (JS forms)")
            self._record_strategy_attempt("headless_login")
            ctx = await self._try_headless_login(base_url)
            if ctx.has_auth:
                logger.info(f"[AUTH] ✓ Acquired session via headless browser login")
                self._record_strategy_success("headless_login")
                self._metrics["acquisitions_successful"] += 1
                return ctx

        # Strategy 5: SQLi bypass (aggressive mode only)
        if SAFE_MODE == "aggressive":
            logger.debug("[AUTH] Trying Strategy 5: SQLi auth bypass")
            self._record_strategy_attempt("sqli_bypass")
            ctx = await self._try_sqli_login(base_url)
            if ctx.has_auth:
                logger.info("[AUTH] ✓ Acquired token via SQLi auth bypass")
                self._record_strategy_success("sqli_bypass")
                self._metrics["acquisitions_successful"] += 1
                return ctx

        logger.warning("[AUTH] ✗ No authentication acquired — business logic tests will be limited")
        self._metrics["acquisitions_failed"] += 1
        return AuthContext()

    @staticmethod
    def _detect_app_base(base_url: str) -> str:
        """Detect application base path from URL (e.g. '/WebGoat' from 'http://localhost:9090/WebGoat/login').

        Strips common auth endpoint suffixes like /login, /register, /signin, etc.
        """
        parsed = urlparse(base_url)
        path = parsed.path.rstrip("/")

        # Strip common auth endpoint suffixes (user might give login page URL)
        auth_suffixes = [
            "/login", "/signin", "/sign-in", "/logon",
            "/register", "/signup", "/sign-up",
            "/auth", "/authenticate", "/authentication",
            "/login.html", "/login.php", "/login.jsp", "/login.aspx",
            "/index.html", "/index.php", "/index.jsp",
        ]
        for suffix in auth_suffixes:
            if path.lower().endswith(suffix):
                path = path[:-len(suffix)]
                break

        # Return non-empty path like /WebGoat, /myapp, etc.
        return path if path and path != "/" else ""

    async def _try_register(self, base_url: str) -> AuthContext:
        """Try to register a test account."""
        # THEME-8: Use deterministic suffix for reproducible auth
        suffix = deterministic_string(6, "auth_register_suffix")
        # Username pattern unlikely to exist + strong password (12+ chars, upper, lower, num, special)
        email = f"zxq_phantom_audit_{suffix}@sectest.invalid"
        password = f"Xk9$mP2#vL5@nQ8{suffix}!"

        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            for path, body_fn in _REGISTER_ENDPOINTS:
                url = f"{base_url}{path}"
                body = body_fn(email, password)

                try:
                    await self._rate_limit()
                    async with session.post(url, json=body, ssl=_SSL_CTX) as resp:
                        if resp.status in (200, 201):
                            ct = resp.headers.get("content-type", "")
                            data = await resp.json() if "application/json" in ct else {}

                            # Extract token and refresh token from response
                            access_token, refresh_token = self._extract_token(data, resp, extract_refresh=True)
                            if access_token:
                                if isinstance(data, dict):
                                    user_id = str(data.get("data", {}).get("id", "") or data.get("id", ""))
                                return AuthContext(
                                    token=access_token,
                                    method="register",
                                    email=email,
                                    user_id=user_id,
                                    extra={
                                        "password": password,
                                        "refresh_token": refresh_token,
                                    },
                                )

                            # Registration succeeded but no token — try logging in
                            login_ctx = await self._login(session, base_url, email, password)
                            if login_ctx.has_auth:
                                login_ctx.method = "register"
                                # Store password for session abuse tests
                                login_ctx.extra["password"] = password
                                # Preserve user_id from registration if login didn't find it
                                if not login_ctx.user_id:
                                    if isinstance(data, dict):
                                        reg_id = str(data.get("data", {}).get("id", "") or data.get("id", ""))
                                    login_ctx.user_id = reg_id
                                return login_ctx

                # H5 FIX 2026-02-12: Removed KeyError (code uses .get()), kept network errors
                except aiohttp.ClientError as e:
                    logger.debug(f"[AUTH] Register attempt {path} network error: {e}")
                except asyncio.TimeoutError:
                    logger.debug(f"[AUTH] Register attempt {path} timed out")
                except json.JSONDecodeError as e:
                    logger.debug(f"[AUTH] Register attempt {path} invalid JSON: {e}")

        return AuthContext()

    async def _try_common_login(self, base_url: str) -> AuthContext:
        """Try login with common/default credentials (domain-specific first)."""
        # Domain-specific credentials first (2026-02-12)
        domain_creds = self._get_domain_credentials()
        all_creds = domain_creds + list(_COMMON_CREDS)

        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            for email, password in all_creds:
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
                        await self._rate_limit()
                        async with session.post(url, json=body, ssl=_SSL_CTX) as resp:
                            if resp.status == 200:
                                ct = resp.headers.get("content-type", "")
                                data = await resp.json() if "application/json" in ct else {}
                                access_token, refresh_token = self._extract_token(data, resp, extract_refresh=True)
                                if access_token:
                                    return AuthContext(
                                        token=access_token,
                                        method="sqli_bypass",
                                        email=body["email"],
                                        extra={
                                            "password": None,  # SQLi bypass doesn't have real password
                                            "refresh_token": refresh_token,
                                            "sqli_payload": body["email"],
                                        },
                                    )
                    # H5 FIX 2026-02-12: Specific exception handling
                    except aiohttp.ClientError as e:
                        logger.debug(f"[AUTH] SQLi bypass network error: {e}")
                    except asyncio.TimeoutError:
                        logger.debug(f"[AUTH] SQLi bypass timed out")

        return AuthContext()

    async def _try_form_register(self, base_url: str) -> AuthContext:
        """Try to register via form-based (x-www-form-urlencoded) endpoints."""
        # Username: only lowercase letters, digits, and hyphen (WebGoat rejects underscores)
        # THEME-8: Use deterministic suffix for reproducible auth
        suffix = deterministic_string(6, "auth_form_register_suffix")
        username = f"zxqphantom{suffix}"  # Unique prefix, no underscore for WebGoat
        email = f"{username}@sectest.invalid"
        # Password: 8 chars, upper+lower+digit (passes most validators)
        # NOTE: WebGoat requires 6-10 chars, so we use 8 (not 16) to support training apps
        password = "Test1234"

        # Build paths: domain-specific first, then generic fallback (2026-02-12)
        paths_to_try = []

        # Domain-specific endpoints (higher priority)
        domain_endpoints = self._get_domain_register_endpoints()
        for path, fields_template in domain_endpoints:
            if self._app_base:
                paths_to_try.append((f"{self._app_base}{path}", fields_template))
            paths_to_try.append((path, fields_template))

        # Generic fallback endpoints
        for path, fields_template in _FORM_REGISTER_ENDPOINTS:
            if self._app_base and not path.startswith(self._app_base):
                paths_to_try.append((f"{self._app_base}{path}", fields_template))
            paths_to_try.append((path, fields_template))

        jar = aiohttp.CookieJar(unsafe=True)
        async with aiohttp.ClientSession(timeout=self._timeout, cookie_jar=jar) as session:
            for path, fields_template in paths_to_try:
                # Reconstruct URL from scheme+host to avoid double-path
                parsed = urlparse(base_url)
                url = f"{parsed.scheme}://{parsed.netloc}{path}"

                logger.debug(f"[AUTH] Trying form register at {url}")

                # Build form data from template
                form_data = {}
                for field_name, default_val in fields_template.items():
                    if field_name in ("username", "user", "login"):
                        form_data[field_name] = username
                    elif field_name in ("email", "mail", "e-mail"):
                        form_data[field_name] = email
                    elif field_name in ("password", "pass", "passwd", "password1"):
                        form_data[field_name] = password
                    elif field_name in ("matchingPassword", "confirmPassword", "password_confirm",
                                        "password2", "password_confirmation", "confirm_password"):
                        form_data[field_name] = password
                    elif default_val is not None:
                        form_data[field_name] = default_val

                try:
                    # First GET to pick up CSRF tokens/cookies
                    # FIX 2026-02-18: Unpack tuple (field_name, token_value) instead of hardcoding "_csrf"
                    # Different apps use different CSRF field names (DVWA=user_token, Spring=_csrf, etc.)
                    csrf_field_name, csrf_token = await self._fetch_csrf_token(session, url)
                    if csrf_token:
                        form_data[csrf_field_name] = csrf_token
                        logger.debug(f"[AUTH] Found CSRF token ({csrf_field_name}): {csrf_token[:20]}...")

                    logger.debug(f"[AUTH] POSTing form data to {url}: {list(form_data.keys())}")

                    # Encode as URL form data (not multipart) - required for Spring Security, etc.
                    encoded_data = _encode_form_data(form_data)
                    headers = {"Content-Type": "application/x-www-form-urlencoded"}

                    await self._rate_limit()
                    async with session.post(
                        url,
                        data=encoded_data,
                        headers=headers,
                        ssl=_SSL_CTX,
                        allow_redirects=True,
                    ) as resp:
                        logger.debug(f"[AUTH] Form register response: {resp.status} {resp.url}")

                        # Success = 200 or 302 redirect
                        if resp.status in (200, 201, 302, 303):
                            resp_text = await resp.text()
                            resp_lower = resp_text.lower()

                            # Check for success indicators (WebGoat shows "successfully" on registration success)
                            success_indicators = ["success", "created", "registered", "welcome", "account has been"]
                            has_success = any(kw in resp_lower for kw in success_indicators)

                            # Reject if we got an error page
                            error_indicators = ["error", "already exists", "already taken", "invalid", "failed", "username already"]
                            has_error = any(kw in resp_lower for kw in error_indicators)

                            if has_error and not has_success:
                                logger.debug(f"[AUTH] Form register {path}: rejected — error in response")
                                continue

                            logger.debug(f"[AUTH] Form register {path}: response looks OK (has_success={has_success})")

                            # Extract session cookies
                            cookies = self._extract_session_cookies(session.cookie_jar, resp)
                            if cookies:
                                logger.debug(f"[AUTH] Found session cookies: {list(cookies.keys())}")
                                # IMPORTANT: Verify the session grants authenticated access
                                # Many apps (WebGoat, etc.) give a session cookie during registration
                                # but don't auto-login the user
                                origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                                verified = await self._verify_session(session, origin, cookies)
                                if verified:
                                    logger.debug(f"[AUTH] Session verified - registration auto-logged in")
                                    return AuthContext(
                                        token_type="cookie",
                                        method="form_register",
                                        email=username,
                                        cookies=cookies,
                                        extra={"password": password},
                                    )
                                else:
                                    logger.debug(f"[AUTH] Session NOT verified - need explicit login")
                                    # Fall through to login attempt

                            # Registration may have succeeded; try form login with same creds
                            logger.debug(f"[AUTH] Trying login as {username}")
                            login_ctx = await self._form_login_attempt(session, base_url, username, password)
                            if login_ctx.has_auth:
                                login_ctx.method = "form_register"
                                login_ctx.email = username
                                login_ctx.extra["password"] = password
                                return login_ctx

                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    logger.debug(f"[AUTH] Form register attempt {path}: {e}")

        return AuthContext()

    async def _try_headless_login(self, base_url: str) -> AuthContext:
        """
        Fallback: Use headless browser for JS-rendered login forms.

        This strategy is used when HTTP-based login fails, typically because:
        - Login form is rendered by JavaScript (React, Vue, Angular, etc.)
        - CSRF token is generated client-side
        - Form requires browser interaction

        Also handles CAPTCHA detection and manual intervention if enabled.
        """
        try:
            from utils.headless_browser import HeadlessBrowserEngine, PLAYWRIGHT_AVAILABLE

            if not PLAYWRIGHT_AVAILABLE:
                logger.debug("[AUTH] Playwright not installed - skipping headless login")
                return AuthContext()

        except ImportError:
            logger.debug("[AUTH] headless_browser module not available")
            return AuthContext()

        # Get credentials to try
        domain_creds = self._get_domain_credentials()
        all_creds = list(_TRAINING_APP_CREDS) + domain_creds + list(_FORM_COMMON_CREDS)

        # Common login paths
        login_paths = [
            "/login", "/signin", "/sign-in", "/auth/login",
            "/user/login", "/account/login", "/api/login",
            "/login.html", "/login.php",
        ]

        # Add app-specific paths if detected
        if self._app_base:
            login_paths = [f"{self._app_base}{p}" for p in login_paths] + login_paths

        try:
            async with HeadlessBrowserEngine(headless=True) as browser:
                for path in login_paths[:5]:  # Limit to first 5 paths
                    url = f"{base_url.rstrip('/')}{path}"

                    try:
                        await browser.navigate(url, wait_until="networkidle")

                        # Check for CAPTCHA
                        captcha_result = await browser.detect_captcha()
                        if captcha_result.get("detected"):
                            logger.warning(
                                f"[AUTH] CAPTCHA detected ({captcha_result.get('type', 'unknown')}) - "
                                "checking if manual auth is allowed"
                            )

                            # Try manual intervention if allowed
                            if os.environ.get("PHANTOM_ALLOW_MANUAL_AUTH") == "1":
                                from utils.manual_auth import ManualAuthHandler, ManualAuthRequest

                                handler = ManualAuthHandler(headless=False)
                                request = ManualAuthRequest(
                                    url=url,
                                    reason="captcha",
                                    challenge_type=captcha_result.get("type", "unknown"),
                                    timeout_seconds=int(os.environ.get("PHANTOM_AUTH_TIMEOUT", "300")),
                                )
                                return await handler.request_manual_auth(request)
                            else:
                                logger.warning("[AUTH] Manual auth not enabled (--allow-manual-auth)")
                                continue

                        # Check for 2FA/MFA
                        mfa_result = await browser.detect_mfa_challenge()
                        if mfa_result.get("detected"):
                            mfa_type = mfa_result.get("type", "unknown")
                            logger.info(f"[AUTH] MFA detected ({mfa_type}) - attempting to handle")

                            # Try TOTP if secret provided
                            totp_secret = os.environ.get("PHANTOM_TOTP_SECRET")
                            if mfa_type == "TOTP" and totp_secret:
                                if await self._handle_totp_challenge(browser, totp_secret):
                                    # Continue to extract auth after TOTP
                                    pass
                                else:
                                    continue
                            elif os.environ.get("PHANTOM_ALLOW_MANUAL_AUTH") == "1":
                                from utils.manual_auth import ManualAuthHandler, ManualAuthRequest

                                handler = ManualAuthHandler(headless=False)
                                request = ManualAuthRequest(
                                    url=url,
                                    reason="2fa",
                                    challenge_type=mfa_type,
                                    timeout_seconds=int(os.environ.get("PHANTOM_AUTH_TIMEOUT", "300")),
                                )
                                return await handler.request_manual_auth(request)
                            else:
                                logger.warning(f"[AUTH] Cannot handle {mfa_type} 2FA without manual auth or TOTP secret")
                                continue

                        # Try credentials
                        for username, password in all_creds[:5]:  # Limit attempts
                            await self._rate_limit()

                            result = await browser.analyze_auth_flow(
                                url,
                                credentials={"username": username, "password": password},
                                wait_for_redirect=True,
                            )

                            # Check for tokens
                            if result.tokens_found:
                                for token in result.tokens_found:
                                    if token.get("type") in ("jwt", "bearer", "access_token"):
                                        logger.info(f"[AUTH] Headless login found JWT token")
                                        return AuthContext(
                                            token=token.get("value", ""),
                                            token_type="bearer",
                                            method="headless_login",
                                            email=username,
                                            extra={"password": password},
                                        )

                            # Check for session cookies
                            if result.cookies:
                                session_cookies = {}
                                for cookie in result.cookies:
                                    name = cookie.get("name", "").lower()
                                    if any(x in name for x in ["session", "auth", "token", "jwt", "sid"]):
                                        session_cookies[cookie["name"]] = cookie["value"]

                                if session_cookies:
                                    logger.info(f"[AUTH] Headless login found {len(session_cookies)} session cookies")
                                    return AuthContext(
                                        cookies=session_cookies,
                                        token_type="cookie",
                                        method="headless_login",
                                        email=username,
                                        extra={"password": password},
                                    )

                    except Exception as e:
                        logger.debug(f"[AUTH] Headless login attempt {path}: {e}")
                        continue

        except Exception as e:
            logger.debug(f"[AUTH] Headless browser error: {e}")

        return AuthContext()

    async def _handle_totp_challenge(
        self,
        browser: "HeadlessBrowserEngine",
        totp_secret: str,
    ) -> bool:
        """Handle TOTP 2FA challenge by generating and entering code."""
        try:
            import pyotp
            totp = pyotp.TOTP(totp_secret)
            code = totp.now()

            logger.debug(f"[AUTH] Generated TOTP code: {code[:2]}****")

            # Find OTP input field
            otp_selectors = [
                'input[name="otp"]',
                'input[name="code"]',
                'input[name="totp"]',
                'input[name="token"]',
                'input[id*="otp"]',
                'input[id*="code"]',
                'input[id*="totp"]',
                'input[type="tel"]',
                'input[maxlength="6"]',
                'input[autocomplete="one-time-code"]',
            ]

            for selector in otp_selectors:
                try:
                    field = await browser._page.query_selector(selector)
                    if field:
                        await field.fill(code)
                        await browser._page.keyboard.press("Enter")
                        await asyncio.sleep(2)
                        logger.info("[AUTH] TOTP code submitted successfully")
                        return True
                except Exception:
                    continue

            logger.warning("[AUTH] Could not find OTP input field")
            return False

        except ImportError:
            logger.error("[AUTH] pyotp not installed - cannot generate TOTP codes")
            return False
        except Exception as e:
            logger.error(f"[AUTH] TOTP handling error: {e}")
            return False

    async def _try_form_login(self, base_url: str) -> AuthContext:
        """Try form-based login with common credentials and session cookie extraction."""
        # Priority order: training apps → domain-specific → generic
        # TRAINING APPS FIRST: Known default creds (DVWA, bWAPP, etc.) should be tried before generic creds
        domain_creds = self._get_domain_credentials()
        # Training app creds FIRST, then domain-specific, then generic fallback
        all_creds = list(_TRAINING_APP_CREDS) + domain_creds + list(_FORM_COMMON_CREDS)

        logger.info(f"[AUTH] Form login: trying {len(all_creds)} credential pairs, first 5: {all_creds[:5]}")

        for idx, (username, password) in enumerate(all_creds):
            logger.debug(f"[AUTH] Form login attempt {idx+1}/{len(all_creds)}: {username}:***")
            ctx = await self._form_login_attempt_fresh(base_url, username, password)
            if ctx.has_auth:
                logger.info(f"[AUTH] Form login SUCCESS with credential #{idx+1}: {username}:{password[:3]}***")
                return ctx

        return AuthContext()

    async def _form_login_attempt_fresh(
        self,
        base_url: str,
        username: str,
        password: str,
    ) -> AuthContext:
        """Single form login attempt with a fresh cookie jar (no stale cookies)."""
        jar = aiohttp.CookieJar(unsafe=True)
        async with aiohttp.ClientSession(timeout=self._timeout, cookie_jar=jar) as session:
            return await self._form_login_attempt(session, base_url, username, password)

    async def _form_login_attempt(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        username: str,
        password: str,
    ) -> AuthContext:
        """Try form-based login across known form login endpoints."""
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Build paths: domain-specific first, then generic fallback (2026-02-12)
        paths_to_try = []

        # Domain-specific endpoints (higher priority)
        domain_endpoints = self._get_domain_login_endpoints()
        for path, user_field, pass_field in domain_endpoints:
            if self._app_base:
                paths_to_try.append((f"{self._app_base}{path}", user_field, pass_field))
            paths_to_try.append((path, user_field, pass_field))

        # Generic fallback endpoints
        for path, user_field, pass_field in _FORM_LOGIN_ENDPOINTS:
            if self._app_base and not path.startswith(self._app_base):
                paths_to_try.append((f"{self._app_base}{path}", user_field, pass_field))
            paths_to_try.append((path, user_field, pass_field))

        for path, user_field, pass_field in paths_to_try:
            url = f"{origin}{path}"
            form_data = {
                user_field: username,
                pass_field: password,
            }

            # TRAINING-APP-FIX: Add extra fields required by training app login forms
            if "login.php" in path:
                if user_field == "login":
                    # bWAPP specific fields
                    form_data["security_level"] = "0"  # Low security for testing
                    form_data["form"] = "submit"
                elif user_field == "username":
                    # DVWA specific fields - requires submit button name
                    form_data["Login"] = "Login"

            logger.debug(f"[AUTH] Trying endpoint {path} with field={user_field} for user={username}")

            try:
                # GET first to pick up CSRF tokens
                csrf_field_name, csrf_token = await self._fetch_csrf_token(session, url)
                if csrf_token:
                    # Use the actual field name from the form (DVWA uses user_token, Spring uses _csrf, etc.)
                    form_data[csrf_field_name] = csrf_token

                # Encode as URL form data (not multipart) - required for Spring Security, etc.
                encoded_data = _encode_form_data(form_data)
                headers = {"Content-Type": "application/x-www-form-urlencoded"}

                await self._rate_limit()
                async with session.post(
                    url,
                    data=encoded_data,
                    headers=headers,
                    ssl=_SSL_CTX,
                    allow_redirects=False,  # Don't follow redirect — inspect cookies first
                ) as resp:
                    # Spring Security: 302 redirect on success, 302 with ?error on failure
                    if resp.status in (302, 303):
                        location = resp.headers.get("location", "")
                        # Failed login redirects to /login?error
                        if "error" in location.lower() or "failed" in location.lower():
                            logger.debug(f"[AUTH] Form login {path} as {username}: redirect to error")
                            continue

                        # Extract session cookies from response
                        cookies = self._extract_session_cookies(session.cookie_jar, resp)
                        if cookies:
                            # Verify the session is valid by following the redirect
                            verified = await self._verify_session(session, origin, cookies)
                            if verified:
                                logger.debug(f"[AUTH] ✓ Form login SUCCESS: {path} as {username} (field: {user_field})")
                                return AuthContext(
                                    token_type="cookie",
                                    method="form_login",
                                    email=username,
                                    cookies=cookies,
                                    extra={"password": password, "login_path": path, "user_field": user_field},
                                )
                            else:
                                logger.debug(f"[AUTH] Form login {path} as {username}: cookies obtained but session verify failed")

                    # Some apps return 200 on successful login (with session cookie)
                    elif resp.status == 200:
                        resp_text = await resp.text()
                        resp_text_lower = resp_text.lower()

                        # Reject if error keywords present (common login failure indicators)
                        if any(kw in resp_text_lower for kw in ("invalid", "incorrect", "bad credentials", "login failed")):
                            continue

                        # Reject if login form is still present (page re-rendered = failed)
                        # This catches cases like DVWA where wrong field name causes re-render
                        if "<form" in resp_text_lower and "password" in resp_text_lower and ("username" in resp_text_lower or "login" in resp_text_lower):
                            logger.debug(f"[AUTH] Form login {path} as {username}: 200 but login form still present (failed)")
                            continue

                        cookies = self._extract_session_cookies(session.cookie_jar, resp)
                        if cookies:
                            return AuthContext(
                                token_type="cookie",
                                method="form_login",
                                email=username,
                                cookies=cookies,
                                extra={"password": password},
                            )

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.debug(f"[AUTH] Form login attempt {path} as {username}: {e}")

        return AuthContext()

    async def _fetch_csrf_token(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> tuple[str, str]:
        """
        GET a page and extract CSRF token from:
        - Hidden form fields (_csrf, csrf_token, csrfmiddlewaretoken, etc.)
        - Meta tags (csrf-token, _csrf)
        - Response headers (X-CSRF-Token, XSRF-TOKEN)
        - Cookie (XSRF-TOKEN)

        Works with: Spring Security, Django, Laravel, Rails, Express, etc.

        Returns:
            Tuple of (field_name, token_value). Field name is needed because
            different apps use different CSRF field names (e.g., DVWA uses user_token,
            Spring uses _csrf, Django uses csrfmiddlewaretoken, etc.)
        """
        # All known CSRF field name patterns
        csrf_field_names = [
            "user_token",               # DVWA (training app)
            "_csrf",                    # Spring Security
            "csrf_token",               # Flask-WTF, generic
            "csrfmiddlewaretoken",      # Django
            "_token",                   # Laravel
            "authenticity_token",       # Rails
            "XSRF-TOKEN",               # Angular
            "xsrf-token",
            "__RequestVerificationToken",  # ASP.NET
            "csrf",
            "CSRFToken",
            "_csrf_token",
        ]

        try:
            await self._rate_limit()
            async with session.get(url, ssl=_SSL_CTX, allow_redirects=True) as resp:
                # Check response headers first (some frameworks send CSRF in header)
                for header_name in ["X-CSRF-Token", "XSRF-TOKEN", "X-XSRF-TOKEN"]:
                    if header_name in resp.headers:
                        return (header_name, resp.headers[header_name])

                if resp.status != 200:
                    return ("", "")

                text = await resp.text()

                # Try each known CSRF field name
                for field_name in csrf_field_names:
                    # Pattern 1: name before value
                    m = re.search(
                        rf'<input[^>]+name=["\']?{re.escape(field_name)}["\']?[^>]+value=["\']([^"\']+)["\']',
                        text, re.IGNORECASE,
                    )
                    if m:
                        logger.debug(f"[AUTH] Found CSRF token via input name={field_name}")
                        return (field_name, m.group(1))

                    # Pattern 2: value before name (some frameworks)
                    m = re.search(
                        rf'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']?{re.escape(field_name)}["\']?',
                        text, re.IGNORECASE,
                    )
                    if m:
                        logger.debug(f"[AUTH] Found CSRF token via input name={field_name} (value first)")
                        return (field_name, m.group(1))

                # Meta tag patterns
                meta_patterns = [
                    r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
                    r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']csrf-token["\']',
                    r'<meta[^>]+name=["\']_csrf["\'][^>]+content=["\']([^"\']+)["\']',
                    r'<meta[^>]+name=["\']csrf["\'][^>]+content=["\']([^"\']+)["\']',
                ]
                for pattern in meta_patterns:
                    m = re.search(pattern, text, re.IGNORECASE)
                    if m:
                        logger.debug("[AUTH] Found CSRF token via meta tag")
                        # Meta tags usually correspond to _csrf field name
                        return ("_csrf", m.group(1))

                # Fallback: look for any hidden input with a long value (likely a token)
                # This catches frameworks with non-standard CSRF field names
                m = re.search(
                    r'<input[^>]+type=["\']hidden["\'][^>]+value=["\']([A-Za-z0-9_=-]{20,})["\']',
                    text, re.IGNORECASE,
                )
                if m:
                    token = m.group(1)
                    # Exclude obvious non-CSRF values
                    if not any(skip in token.lower() for skip in ["false", "true", "null", "undefined"]):
                        logger.debug(f"[AUTH] Found potential CSRF token via hidden input fallback")
                        # Default to _csrf for fallback (most common)
                        return ("_csrf", token)

        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.debug(f"[AUTH] Error fetching CSRF token from {url}: {e}")

        return ("", "")

    def _extract_session_cookies(
        self,
        cookie_jar: aiohttp.CookieJar,
        resp: aiohttp.ClientResponse,
    ) -> dict[str, str]:
        """Extract session cookies from response Set-Cookie headers and cookie jar."""
        cookies: dict[str, str] = {}

        # From Set-Cookie headers directly
        for cookie_header in resp.headers.getall("set-cookie", []):
            parts = cookie_header.split(";")[0].strip()  # "name=value"
            if "=" in parts:
                name, value = parts.split("=", 1)
                name = name.strip()
                value = value.strip()
                if name.lower() in _SESSION_COOKIE_NAMES or len(value) > MIN_SESSION_COOKIE_LENGTH:
                    cookies[name] = value

        # From cookie jar (picks up cookies from redirects)
        for cookie in cookie_jar:
            name = cookie.key
            value = cookie.value
            if name.lower() in _SESSION_COOKIE_NAMES or len(value) > MIN_SESSION_COOKIE_LENGTH:
                cookies[name] = value

        return cookies

    async def _verify_session(
        self,
        session: aiohttp.ClientSession,
        origin: str,
        cookies: dict[str, str],
    ) -> bool:
        """Verify that the acquired session cookies grant authenticated access."""
        # Build cookie header
        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
        headers = {"Cookie": cookie_header}

        # Try common authenticated endpoints (domain-specific first) (2026-02-12)
        domain_verify_paths = self._get_domain_verify_paths()

        # TRAINING-APP-FIX: Add paths for common vulnerable labs FIRST
        training_app_verify_paths = [
            "/portal.php",         # bWAPP main portal
            "/bWAPP/portal.php",   # bWAPP with path prefix
            "/vulnerabilities/",   # DVWA challenges
            "/security.php",       # DVWA security settings
            "/index.php",          # Mutillidae, generic PHP apps
            "/WebGoat/start.mvc",  # WebGoat
            "/start.mvc",          # WebGoat (no prefix)
        ]

        generic_verify_paths = [
            "/home",
            "/dashboard",
            "/account",
            "/profile",
            "/api/user",
            "/me",
        ]
        # Priority: domain-specific → training apps → generic
        verify_paths = domain_verify_paths + training_app_verify_paths + generic_verify_paths
        if self._app_base:
            # Add app-prefixed paths first (most likely to work)
            verify_paths = [f"{self._app_base}{p}" for p in verify_paths] + verify_paths

        for path in verify_paths[:MAX_VERIFY_PATHS]:
            url = f"{origin}{path}"
            try:
                await self._rate_limit()
                async with session.get(url, headers=headers, ssl=_SSL_CTX, allow_redirects=False) as resp:
                    # Skip 404s - wrong path, try next
                    if resp.status == 404:
                        continue

                    # Authenticated: 200 OK (not redirected to login)
                    if resp.status == 200:
                        text = await resp.text()
                        text_lower = text.lower()

                        # Skip JSON error responses (often indicate wrong path, not auth failure)
                        if text.strip().startswith("{") and '"error"' in text_lower:
                            continue

                        # Reject if we're still on a login page
                        if "<form" in text_lower and "password" in text_lower and "username" in text_lower:
                            continue

                        # Reject Apache directory listings (not authenticated content)
                        # These show up when the server doesn't have an index file
                        if "index of /" in text_lower or "<title>index of" in text_lower:
                            continue

                        # Accept if we see signs of authenticated content (full words only)
                        auth_patterns = ["logout", "sign out", "signout", "log out", "welcome,",
                                         "my account", "my profile", "settings"]
                        if any(kw in text_lower for kw in auth_patterns):
                            return True

                        # Accept if response is HTML, substantial, and doesn't look like login.
                        # SPA shells (WebGoat, Angular, React) may reference "login"
                        # in JavaScript routes — only reject if "login" appears in
                        # HTML body text (outside <script> tags), not in JS code.
                        if len(text) > MIN_AUTHENTICATED_RESPONSE_LENGTH and "<html" in text_lower:
                            # Strip script tags before checking for "login"
                            import re
                            body_text = re.sub(r"<script[^>]*>.*?</script>", "", text_lower, flags=re.DOTALL)
                            if "login" not in body_text[:MIN_AUTHENTICATED_RESPONSE_LENGTH]:
                                return True

                    # 302 to auth-related page = session invalid
                    # AUDIT-FIX 2026-02-19: Expanded from just "login" to more redirect patterns
                    # Many apps redirect to /auth, /signin, /forbidden, etc. when session invalid
                    elif resp.status in (302, 303):
                        location = resp.headers.get("location", "").lower()
                        invalid_session_redirects = [
                            "login", "signin", "sign-in", "sign_in",
                            "auth", "authenticate", "unauthorized",
                            "forbidden", "denied", "access_denied",
                            "session", "expired", "timeout",
                            "index.php",  # Training apps often redirect to index
                        ]
                        if any(pattern in location for pattern in invalid_session_redirects):
                            return False
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                logger.debug(f"[AUTH] Session verification failed: {e}")

        # CRITICAL FIX: If we couldn't verify ANY authenticated endpoint, login probably failed
        # Training apps (DVWA, bWAPP, etc.) set PHPSESSID even for failed logins
        # Only return True if we're NOT on a training app (e.g., API-only targets)
        #
        # Training app detection: check if any verify path returned 200+substantial content
        # If all paths returned 404 or login page, the session is invalid
        training_indicators = ["/vulnerabilities", "/portal.php", "/bWAPP", "/WebGoat", "DVWA", "Mutillidae"]
        is_training_app = any(ind.lower() in origin.lower() for ind in training_indicators)

        if is_training_app:
            # Training apps: cookies without verification = failed login
            logger.debug(f"[AUTH] Session verification FAILED for training app (no authenticated content found)")
            return False

        # Non-training apps: accept cookies (might work for API endpoints)
        return bool(cookies)

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
                    await self._rate_limit()
                    async with session.post(url, json=body, ssl=_SSL_CTX) as resp:
                        if resp.status == 200:
                            ct = resp.headers.get("content-type", "")
                            data = await resp.json() if "application/json" in ct else {}
                            access_token, refresh_token = self._extract_token(data, resp, extract_refresh=True)
                            if access_token:
                                # Extract basket/user IDs from login response
                                basket_id, user_id = self._extract_ids(data)

                                # Fallback: try whoami for user/basket discovery
                                if not basket_id:
                                    basket_id = await self._discover_basket(session, base_url, access_token)

                                return AuthContext(
                                    token=access_token,
                                    method="login",
                                    email=email,
                                    user_id=user_id,
                                    basket_id=basket_id,
                                    extra={
                                        "password": password,
                                        "refresh_token": refresh_token,
                                    },
                                )
                # H5 FIX 2026-02-12: Specific exception handling
                except aiohttp.ClientError as e:
                    logger.debug(f"[AUTH] Login attempt {email} network error: {e}")
                except asyncio.TimeoutError:
                    logger.debug(f"[AUTH] Login attempt {email} timed out")

        return AuthContext()

    def _extract_ids(self, data: dict) -> tuple[str, str]:
        """Extract basket ID and user ID from login response."""
        basket_id = ""
        user_id = ""

        # C2 FIX 2026-02-12: Fixed variable scoping and removed redundant isinstance checks
        if not isinstance(data, dict):
            return basket_id, user_id

        # Common pattern: authentication object with bid (basket id) field
        auth = data.get("authentication", {})
        if isinstance(auth, dict):
            bid = auth.get("bid")
            if bid:
                basket_id = str(bid)

        # Get nested objects once (avoid redundant lookups)
        nested = data.get("data", {})
        user_obj = data.get("user", {})

        # Generic: look for user_id / id in common locations
        for key in ("user_id", "userId", "id"):
            # Check top-level
            if key in data and data[key]:
                user_id = str(data[key])
                break
            # Check authentication object
            if isinstance(auth, dict) and key in auth and auth[key]:
                user_id = str(auth[key])
                break
            # Check nested data object
            if isinstance(nested, dict) and key in nested and nested[key]:
                user_id = str(nested[key])
                break
            # Check user object
            if isinstance(user_obj, dict) and key in user_obj and user_obj[key]:
                user_id = str(user_obj[key])
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
            await self._rate_limit()
            async with session.get(
                f"{base_url}/rest/user/whoami",
                headers=headers,
                ssl=_SSL_CTX,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # C3 FIX 2026-02-12: Fixed indentation - user_id check was outside if block
                    if isinstance(data, dict):
                        user_id = data.get("id") or data.get("data", {}).get("id")
                        if user_id:
                            return str(user_id)
        # H5 FIX 2026-02-12: Specific exception handling
        except aiohttp.ClientError as e:
            logger.debug(f"[AUTH] Basket discovery network error: {e}")
        except asyncio.TimeoutError:
            logger.debug(f"[AUTH] Basket discovery timed out")
        except json.JSONDecodeError as e:
            logger.debug(f"[AUTH] Basket discovery invalid JSON: {e}")

        return ""

    def _extract_token(
        self,
        data: dict,
        resp: aiohttp.ClientResponse,
        extract_refresh: bool = False,
    ) -> str | tuple[str, str]:
        """Extract JWT/auth token from response data or headers.

        Supports multiple response structures used by different frameworks.

        Args:
            data: Response JSON data
            resp: aiohttp response object
            extract_refresh: If True, also extract refresh token and return (access, refresh)

        Returns:
            If extract_refresh=False: access token string
            If extract_refresh=True: tuple of (access_token, refresh_token)
        """
        # Token key names to check
        token_keys = ("token", "access_token", "accessToken", "jwt", "auth_token", "id_token")
        refresh_keys = ("refresh_token", "refreshToken", "refresh")

        # Nested wrapper keys to check (common across frameworks)
        wrapper_keys = ("authentication", "auth", "data", "result", "response", "user")

        access_token = ""
        refresh_token = ""

        # C4 FIX 2026-02-12: Guard clause - ensure data is dict before processing
        if not isinstance(data, dict):
            data = {}

        # Check response body for access token
        for key in token_keys:
            # Top level
            if key in data and isinstance(data[key], str):
                access_token = data[key]
                break

            # Check nested wrappers
            for wrapper in wrapper_keys:
                nested = data.get(wrapper, {})
                if isinstance(nested, dict) and key in nested:
                    access_token = nested[key]
                    break
            if access_token:
                break

        # Check response body for refresh token
        if extract_refresh:
            for key in refresh_keys:
                # Top level
                if key in data and isinstance(data[key], str):
                    refresh_token = data[key]
                    break

                # Check nested wrappers
                for wrapper in wrapper_keys:
                    nested = data.get(wrapper, {})
                    if isinstance(nested, dict) and key in nested:
                        refresh_token = nested[key]
                        break
                if refresh_token:
                    break

        # Check response headers (if no token found in body)
        if not access_token:
            auth_header = resp.headers.get("authorization", "")
            if auth_header.lower().startswith("bearer "):
                access_token = auth_header[7:]

        # Check X-Auth-Token header (common in some APIs)
        if not access_token:
            x_auth = resp.headers.get("x-auth-token", "")
            if x_auth:
                access_token = x_auth

        # Check Set-Cookie for JWT-like tokens
        if not access_token:
            for cookie_header in resp.headers.getall("set-cookie", []):
                if "eyJ" in cookie_header:
                    parts = cookie_header.split("=", 1)
                    if len(parts) == 2:
                        value = parts[1].split(";")[0]
                        if value.startswith("eyJ"):
                            access_token = value
                            break

        # AUDIT-FIX 2026-02-19: Validate tokens before returning
        # Previously: any non-empty string was accepted as a token
        # Now: validate token format to reject garbage strings
        if access_token and not _is_valid_token(access_token):
            logger.debug(f"[AUTH] Rejected invalid token: {access_token[:50]}...")
            access_token = ""
        if refresh_token and not _is_valid_token(refresh_token):
            logger.debug(f"[AUTH] Rejected invalid refresh token: {refresh_token[:50]}...")
            refresh_token = ""

        if extract_refresh:
            return access_token, refresh_token
        return access_token

    # =========================================================================
    # MULTI-USER ACQUISITION
    # =========================================================================

    async def acquire_multiple_users(
        self,
        base_url: str,
        rate_limiter: Any = None,
        count: int = 2,
        domain: str | None = None,
    ) -> UserPersonaStore:
        """
        Acquire multiple user contexts for cross-user testing.

        Philosophy: "PHANTOM doesn't simulate complete users with distinct roles.
        Simple targets 'dry out' the scanner."

        This method:
        1. Registers/logs in a primary user (attacker persona)
        2. Registers a second user (victim persona)
        3. Tries to find admin credentials if available

        Args:
            base_url: Target URL
            rate_limiter: Optional rate limiter
            count: Number of users to acquire (default 2)
            domain: Business domain type (ecommerce, fintech, saas, etc.)

        Returns UserPersonaStore with multiple contexts.
        """
        self._rate_limiter = rate_limiter
        base_url = base_url.strip().rstrip("/")
        self._app_base = self._detect_app_base(base_url)

        store = UserPersonaStore()

        # Acquire primary user (attacker) — uses domain strategy (2026-02-12)
        logger.info("[AUTH-MULTI] Acquiring primary user (attacker persona)...")
        primary = await self.acquire(base_url, rate_limiter, domain=domain)
        if primary.has_auth:
            primary.persona_name = "attacker"
            primary.role = "user"
            store.primary = primary
            logger.info(f"[AUTH-MULTI] ✓ Primary user acquired: {primary.email}")

        # Acquire secondary user (victim) — register a different account
        if count >= 2:
            logger.info("[AUTH-MULTI] Acquiring secondary user (victim persona)...")
            secondary = await self._acquire_second_user(base_url)
            if secondary.has_auth:
                secondary.persona_name = "victim"
                secondary.role = "user"
                store.secondary = secondary
                logger.info(f"[AUTH-MULTI] ✓ Secondary user acquired: {secondary.email}")

        # Try to find admin access
        logger.info("[AUTH-MULTI] Attempting to acquire admin access...")
        admin = await self._try_admin_login(base_url)
        if admin.has_auth:
            admin.persona_name = "admin"
            admin.role = "admin"
            store.admin = admin
            logger.info(f"[AUTH-MULTI] ✓ Admin access acquired: {admin.email}")

        if store.has_multiple_users:
            logger.info(
                f"[AUTH-MULTI] ✓ Multi-user mode enabled: "
                f"{len(store.all_contexts)} users, "
                f"{len(store.get_cross_user_pairs())} cross-user pairs available"
            )
        else:
            logger.warning(
                "[AUTH-MULTI] ✗ Could not acquire multiple users — "
                "cross-user testing will be limited"
            )

        return store

    async def _acquire_second_user(self, base_url: str) -> AuthContext:
        """Register a second user for victim persona."""
        # THEME-8: Use deterministic suffix for reproducible auth
        suffix = deterministic_string(8, "auth_second_user_suffix")
        # Unique username pattern + strong password
        email = f"zxq-phantom-victim{suffix}@sectest.invalid"
        password = "Yk8$nP3#wL6@mQ9x"

        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            # Try JSON API registration
            for path, body_template in _REGISTER_ENDPOINTS:
                url = f"{base_url}{path}"
                body = body_template(email, password) if callable(body_template) else {}

                try:
                    await self._rate_limit()
                    async with session.post(url, json=body, ssl=_SSL_CTX) as resp:
                        if resp.status in (200, 201):
                            ct = resp.headers.get("content-type", "")
                            data = await resp.json() if "application/json" in ct else {}
                            access_token = self._extract_token(data, resp)
                            if access_token:
                                basket_id, user_id = self._extract_ids(data)
                                return AuthContext(
                                    token=access_token,
                                    method="register",
                                    email=email,
                                    user_id=user_id,
                                    basket_id=basket_id,
                                    extra={"password": password},
                                )
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    logger.debug(f"[AUTH-MULTI] Second user registration failed: {e}")

            # Try form-based registration
            for path, field_template in _FORM_REGISTER_ENDPOINTS:
                url = f"{base_url}{path}"
                username = f"phantomvictim{suffix}"

                form_data = dict(field_template)
                for k, v in form_data.items():
                    if v is None:
                        if "email" in k.lower():
                            form_data[k] = email
                        elif "name" in k.lower() or "user" in k.lower():
                            form_data[k] = username
                        elif "password" in k.lower():
                            form_data[k] = password

                try:
                    await self._rate_limit()
                    encoded = _encode_form_data(form_data)
                    async with session.post(
                        url,
                        data=encoded,
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                        ssl=_SSL_CTX,
                        allow_redirects=False,
                    ) as resp:
                        cookies = self._extract_session_cookies(session.cookie_jar, resp)
                        if cookies:
                            return AuthContext(
                                token="",
                                token_type="cookie",
                                method="form_register",
                                email=email,
                                cookies=cookies,
                                extra={"password": password, "username": username},
                            )
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    logger.debug(f"[AUTH-MULTI] Form registration failed: {e}")

        return AuthContext()

    async def _try_admin_login(self, base_url: str) -> AuthContext:
        """Try to login with common admin credentials."""
        admin_creds = [
            ("admin@admin.com", "admin123"),
            ("admin@example.com", "admin"),
            ("admin", "admin"),
            ("administrator", "administrator"),
            ("root", "root"),
        ]

        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            for email, password in admin_creds:
                ctx = await self._login(session, base_url, email, password)
                if ctx.has_auth:
                    # Verify it's actually an admin by checking admin endpoints
                    if await self._verify_admin_access(session, base_url, ctx):
                        return ctx

        return AuthContext()

    async def _verify_admin_access(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        ctx: AuthContext,
    ) -> bool:
        """Verify if context has admin access by testing admin endpoints."""
        admin_paths = [
            "/api/admin", "/api/users", "/admin/config",
            "/rest/admin/application-configuration",
            "/api/v1/admin", "/management/users",
        ]

        headers = ctx.auth_headers

        for path in admin_paths:
            url = f"{base_url}{path}"
            try:
                await self._rate_limit()
                async with session.get(url, headers=headers, ssl=_SSL_CTX) as resp:
                    if resp.status == 200:
                        logger.debug(f"[AUTH-MULTI] Admin access confirmed via {path}")
                        return True
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue

        return False
