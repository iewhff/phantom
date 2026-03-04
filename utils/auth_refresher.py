"""
Auto Auth Refresher v1.0 - Automatic Re-authentication on Session Expiry

This module provides automatic re-authentication capabilities:
1. Stores credentials securely during initial login
2. Provides refresh callbacks for SessionWatchdog
3. Handles various auth methods (form login, JWT refresh, OAuth token)
4. Integrates with AuthContext for seamless auth updates

Philosophy: "Scans should NEVER die due to session expiry - auto-recover and continue."

Integration:
    - auth_context.py stores initial credentials
    - session_watchdog.py uses refresh callbacks
    - full_scanner.py orchestrates the integration

Author: PetNTester AI
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import base64
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Callable, Optional

from utils.logger import get_logger

if TYPE_CHECKING:
    from scanning.auth_context import AuthContext

logger = get_logger(__name__)


class AuthMethod(Enum):
    """Supported authentication methods."""

    FORM_LOGIN = auto()
    BASIC_AUTH = auto()
    JWT_BEARER = auto()
    JWT_REFRESH = auto()
    OAUTH2_CLIENT_CREDS = auto()
    OAUTH2_REFRESH = auto()
    API_KEY = auto()
    COOKIE_SESSION = auto()
    CUSTOM = auto()


@dataclass
class StoredCredentials:
    """Securely stored credentials for re-authentication."""

    method: AuthMethod = AuthMethod.FORM_LOGIN

    # Form login
    login_url: str = ""
    username_field: str = "username"
    password_field: str = "password"
    username: str = ""
    password: str = ""
    extra_fields: dict[str, str] = field(default_factory=dict)

    # JWT
    jwt_refresh_url: str = ""
    refresh_token: str = ""

    # OAuth2
    oauth_token_url: str = ""
    client_id: str = ""
    client_secret: str = ""
    scope: str = ""

    # API Key
    api_key: str = ""
    api_key_header: str = "X-API-Key"

    # Custom callback
    custom_callback: Optional[Callable[[], Any]] = None

    # Metadata
    stored_at: float = field(default_factory=time.time)
    last_refresh: float = 0.0
    refresh_count: int = 0


@dataclass
class RefreshResult:
    """Result of a refresh attempt."""

    success: bool = False
    new_token: str | None = None
    new_cookies: dict[str, str] = field(default_factory=dict)
    error: str = ""
    took_seconds: float = 0.0


class AutoAuthRefresher:
    """
    Automatic authentication refresher.

    Usage:
        refresher = AutoAuthRefresher(auth_context)

        # Store credentials after successful login
        refresher.store_form_credentials(
            login_url="https://example.com/login",
            username="admin",
            password="password123"
        )

        # Later, when session expires:
        result = await refresher.refresh()
        if result.success:
            # auth_context is automatically updated
            pass
    """

    def __init__(
        self,
        auth_context: "AuthContext",
        http_client: Optional[Any] = None,
    ):
        """
        Initialize auth refresher.

        Args:
            auth_context: AuthContext to update on successful refresh
            http_client: HTTP client for making auth requests
        """
        self._auth = auth_context
        self._client = http_client
        self._credentials: StoredCredentials | None = None
        self._lock = asyncio.Lock()
        self._refresh_in_progress = False

        # Rate limiting for refreshes
        self._min_refresh_interval = 5.0  # Minimum 5 seconds between refreshes
        self._max_refresh_attempts = 3
        self._recent_attempts: list[float] = []

    def store_form_credentials(
        self,
        login_url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        extra_fields: dict[str, str] | None = None,
    ) -> None:
        """
        Store form-based login credentials for re-authentication.

        Args:
            login_url: URL of the login form
            username: Username to use
            password: Password to use
            username_field: Form field name for username
            password_field: Form field name for password
            extra_fields: Additional form fields (e.g., CSRF token field name)
        """
        self._credentials = StoredCredentials(
            method=AuthMethod.FORM_LOGIN,
            login_url=login_url,
            username=username,
            password=password,
            username_field=username_field,
            password_field=password_field,
            extra_fields=extra_fields or {},
        )
        logger.info(
            f"[AUTH_REFRESHER] Stored form credentials "
            f"(url={login_url}, user={username[:3]}***)"
        )

    def store_jwt_refresh(
        self,
        refresh_url: str,
        refresh_token: str,
    ) -> None:
        """
        Store JWT refresh token for token rotation.

        Args:
            refresh_url: URL of the token refresh endpoint
            refresh_token: Current refresh token
        """
        self._credentials = StoredCredentials(
            method=AuthMethod.JWT_REFRESH,
            jwt_refresh_url=refresh_url,
            refresh_token=refresh_token,
        )
        logger.info(f"[AUTH_REFRESHER] Stored JWT refresh token (url={refresh_url})")

    def store_oauth2_client_credentials(
        self,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: str = "",
    ) -> None:
        """
        Store OAuth2 client credentials for token refresh.

        Args:
            token_url: OAuth2 token endpoint
            client_id: Client ID
            client_secret: Client secret
            scope: OAuth2 scope
        """
        self._credentials = StoredCredentials(
            method=AuthMethod.OAUTH2_CLIENT_CREDS,
            oauth_token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
        )
        logger.info(f"[AUTH_REFRESHER] Stored OAuth2 client credentials")

    def store_oauth2_refresh(
        self,
        token_url: str,
        client_id: str,
        refresh_token: str,
        client_secret: str = "",
    ) -> None:
        """
        Store OAuth2 refresh token for token rotation.

        Args:
            token_url: OAuth2 token endpoint
            client_id: Client ID
            refresh_token: Refresh token
            client_secret: Client secret (optional)
        """
        self._credentials = StoredCredentials(
            method=AuthMethod.OAUTH2_REFRESH,
            oauth_token_url=token_url,
            client_id=client_id,
            client_secret=client_secret,
            refresh_token=refresh_token,
        )
        logger.info(f"[AUTH_REFRESHER] Stored OAuth2 refresh token")

    def store_basic_auth(
        self,
        username: str,
        password: str,
    ) -> None:
        """
        Store Basic Auth credentials.

        Args:
            username: Username
            password: Password
        """
        self._credentials = StoredCredentials(
            method=AuthMethod.BASIC_AUTH,
            username=username,
            password=password,
        )
        logger.info(f"[AUTH_REFRESHER] Stored Basic Auth credentials")

    def store_api_key(
        self,
        api_key: str,
        header_name: str = "X-API-Key",
    ) -> None:
        """
        Store API key for re-authentication.

        Args:
            api_key: API key value
            header_name: Header name for the API key
        """
        self._credentials = StoredCredentials(
            method=AuthMethod.API_KEY,
            api_key=api_key,
            api_key_header=header_name,
        )
        logger.info(f"[AUTH_REFRESHER] Stored API key (header={header_name})")

    def store_custom_callback(
        self,
        callback: Callable[[], Any],
    ) -> None:
        """
        Store custom re-authentication callback.

        Args:
            callback: Async function that returns new auth (token or AuthContext)
        """
        self._credentials = StoredCredentials(
            method=AuthMethod.CUSTOM,
            custom_callback=callback,
        )
        logger.info("[AUTH_REFRESHER] Stored custom auth callback")

    def has_credentials(self) -> bool:
        """Check if credentials are stored."""
        return self._credentials is not None

    def get_method(self) -> AuthMethod | None:
        """Get stored auth method."""
        return self._credentials.method if self._credentials else None

    async def refresh(self) -> RefreshResult:
        """
        Attempt to refresh authentication.

        Returns:
            RefreshResult with success status and new credentials
        """
        if not self._credentials:
            return RefreshResult(success=False, error="No credentials stored")

        # Rate limiting
        if not self._can_attempt_refresh():
            return RefreshResult(
                success=False,
                error="Rate limited - too many refresh attempts"
            )

        async with self._lock:
            if self._refresh_in_progress:
                return RefreshResult(success=False, error="Refresh already in progress")
            self._refresh_in_progress = True

        try:
            self._recent_attempts.append(time.time())
            start_time = time.time()

            method = self._credentials.method
            result: RefreshResult

            if method == AuthMethod.FORM_LOGIN:
                result = await self._refresh_form_login()
            elif method == AuthMethod.BASIC_AUTH:
                result = await self._refresh_basic_auth()
            elif method == AuthMethod.JWT_REFRESH:
                result = await self._refresh_jwt()
            elif method == AuthMethod.OAUTH2_CLIENT_CREDS:
                result = await self._refresh_oauth2_client()
            elif method == AuthMethod.OAUTH2_REFRESH:
                result = await self._refresh_oauth2_token()
            elif method == AuthMethod.API_KEY:
                result = await self._refresh_api_key()
            elif method == AuthMethod.CUSTOM:
                result = await self._refresh_custom()
            else:
                result = RefreshResult(success=False, error=f"Unsupported method: {method}")

            result.took_seconds = time.time() - start_time

            if result.success:
                self._credentials.last_refresh = time.time()
                self._credentials.refresh_count += 1
                logger.info(
                    f"[AUTH_REFRESHER] Refresh successful "
                    f"(method={method.name}, took={result.took_seconds:.2f}s)"
                )
                # Update auth context
                await self._update_auth_context(result)
            else:
                logger.warning(
                    f"[AUTH_REFRESHER] Refresh failed "
                    f"(method={method.name}, error={result.error})"
                )

            return result

        finally:
            self._refresh_in_progress = False

    def _can_attempt_refresh(self) -> bool:
        """Check if we can attempt a refresh (rate limiting)."""
        now = time.time()

        # Clean old attempts
        self._recent_attempts = [
            t for t in self._recent_attempts
            if now - t < 60.0  # Keep last minute
        ]

        # Check rate limits
        if len(self._recent_attempts) >= self._max_refresh_attempts:
            return False

        if self._recent_attempts:
            last_attempt = self._recent_attempts[-1]
            if now - last_attempt < self._min_refresh_interval:
                return False

        return True

    async def _refresh_form_login(self) -> RefreshResult:
        """Refresh via form login."""
        creds = self._credentials
        if not creds or not creds.login_url:
            return RefreshResult(success=False, error="Missing login URL")

        try:
            import aiohttp

            # Fetch login page to get CSRF token if needed
            csrf_token = None
            csrf_field = None

            async with aiohttp.ClientSession() as session:
                # Get login page for CSRF
                async with session.get(creds.login_url, ssl=False) as resp:
                    if resp.status == 200:
                        html = await resp.text()
                        csrf_token, csrf_field = self._extract_csrf_from_html(html)

                # Build form data
                form_data = {
                    creds.username_field: creds.username,
                    creds.password_field: creds.password,
                }

                # Add extra fields
                form_data.update(creds.extra_fields)

                # Add CSRF token if found
                if csrf_token and csrf_field:
                    form_data[csrf_field] = csrf_token

                # Handle special cases (DVWA, etc.)
                login_path = urllib.parse.urlparse(creds.login_url).path.lower()
                if "login.php" in login_path:
                    if creds.username_field == "username":
                        form_data["Login"] = "Login"

                # Submit login form
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                encoded_data = urllib.parse.urlencode(form_data)

                async with session.post(
                    creds.login_url,
                    data=encoded_data,
                    headers=headers,
                    ssl=False,
                    allow_redirects=False,
                ) as resp:
                    # Check for success indicators
                    cookies = {k: v.value for k, v in resp.cookies.items()}

                    # Success = got session cookie OR redirect to non-login page
                    has_session = any(
                        "session" in k.lower() or "phpsessid" in k.lower()
                        for k in cookies
                    )

                    is_redirect = resp.status in (301, 302, 303, 307, 308)
                    redirect_to_login = False

                    if is_redirect:
                        location = resp.headers.get("Location", "")
                        redirect_to_login = "login" in location.lower()

                    if has_session or (is_redirect and not redirect_to_login):
                        return RefreshResult(
                            success=True,
                            new_cookies=cookies,
                        )

                    # Try to follow redirect and check response
                    if is_redirect:
                        location = resp.headers.get("Location", "")
                        if location:
                            full_url = urllib.parse.urljoin(creds.login_url, location)
                            async with session.get(full_url, ssl=False) as final:
                                final_text = await final.text()
                                final_lower = final_text.lower()

                                # Success if no login form in response
                                if "password" not in final_lower or "logout" in final_lower:
                                    cookies.update({
                                        k: v.value for k, v in final.cookies.items()
                                    })
                                    return RefreshResult(
                                        success=True,
                                        new_cookies=cookies,
                                    )

                    return RefreshResult(
                        success=False,
                        error=f"Login failed (status={resp.status})"
                    )

        except Exception as e:
            return RefreshResult(success=False, error=str(e))

    def _extract_csrf_from_html(self, html: str) -> tuple[str | None, str | None]:
        """Extract CSRF token and field name from HTML."""
        import re

        html_lower = html.lower()

        # Common CSRF field names
        csrf_names = [
            "csrf_token", "_csrf", "csrftoken", "user_token",
            "authenticity_token", "_token", "csrf", "__RequestVerificationToken"
        ]

        for name in csrf_names:
            # Try hidden input
            pattern = rf'<input[^>]+name=["\']?{name}["\']?[^>]+value=["\']?([^"\'>\s]+)'
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1), name

            # Try value before name
            pattern = rf'<input[^>]+value=["\']?([^"\'>\s]+)[^>]+name=["\']?{name}'
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1), name

        return None, None

    async def _refresh_basic_auth(self) -> RefreshResult:
        """Refresh Basic Auth - just return the same credentials."""
        creds = self._credentials
        if not creds:
            return RefreshResult(success=False, error="No credentials")

        # Basic auth doesn't expire, just return same credentials
        encoded = base64.b64encode(
            f"{creds.username}:{creds.password}".encode()
        ).decode()

        return RefreshResult(
            success=True,
            new_token=f"Basic {encoded}",
        )

    async def _refresh_jwt(self) -> RefreshResult:
        """Refresh JWT using refresh token."""
        creds = self._credentials
        if not creds or not creds.jwt_refresh_url:
            return RefreshResult(success=False, error="Missing JWT refresh URL")

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                payload = {"refresh_token": creds.refresh_token}

                async with session.post(
                    creds.jwt_refresh_url,
                    json=payload,
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        new_token = data.get("access_token") or data.get("token")
                        new_refresh = data.get("refresh_token")

                        if new_token:
                            # Update stored refresh token if rotated
                            if new_refresh:
                                creds.refresh_token = new_refresh

                            return RefreshResult(
                                success=True,
                                new_token=new_token,
                            )

                    return RefreshResult(
                        success=False,
                        error=f"JWT refresh failed (status={resp.status})"
                    )

        except Exception as e:
            return RefreshResult(success=False, error=str(e))

    async def _refresh_oauth2_client(self) -> RefreshResult:
        """Refresh OAuth2 using client credentials grant."""
        creds = self._credentials
        if not creds or not creds.oauth_token_url:
            return RefreshResult(success=False, error="Missing OAuth2 token URL")

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                payload = {
                    "grant_type": "client_credentials",
                    "client_id": creds.client_id,
                    "client_secret": creds.client_secret,
                }

                if creds.scope:
                    payload["scope"] = creds.scope

                async with session.post(
                    creds.oauth_token_url,
                    data=payload,
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        new_token = data.get("access_token")

                        if new_token:
                            return RefreshResult(
                                success=True,
                                new_token=new_token,
                            )

                    return RefreshResult(
                        success=False,
                        error=f"OAuth2 client creds failed (status={resp.status})"
                    )

        except Exception as e:
            return RefreshResult(success=False, error=str(e))

    async def _refresh_oauth2_token(self) -> RefreshResult:
        """Refresh OAuth2 using refresh token grant."""
        creds = self._credentials
        if not creds or not creds.oauth_token_url:
            return RefreshResult(success=False, error="Missing OAuth2 token URL")

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                payload = {
                    "grant_type": "refresh_token",
                    "refresh_token": creds.refresh_token,
                    "client_id": creds.client_id,
                }

                if creds.client_secret:
                    payload["client_secret"] = creds.client_secret

                async with session.post(
                    creds.oauth_token_url,
                    data=payload,
                    ssl=False,
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        new_token = data.get("access_token")
                        new_refresh = data.get("refresh_token")

                        if new_token:
                            # Update stored refresh token if rotated
                            if new_refresh:
                                creds.refresh_token = new_refresh

                            return RefreshResult(
                                success=True,
                                new_token=new_token,
                            )

                    return RefreshResult(
                        success=False,
                        error=f"OAuth2 refresh failed (status={resp.status})"
                    )

        except Exception as e:
            return RefreshResult(success=False, error=str(e))

    async def _refresh_api_key(self) -> RefreshResult:
        """API key refresh - just return the stored key."""
        creds = self._credentials
        if not creds or not creds.api_key:
            return RefreshResult(success=False, error="No API key stored")

        # API keys don't expire in our control - just return same key
        return RefreshResult(
            success=True,
            new_token=creds.api_key,
        )

    async def _refresh_custom(self) -> RefreshResult:
        """Execute custom refresh callback."""
        creds = self._credentials
        if not creds or not creds.custom_callback:
            return RefreshResult(success=False, error="No custom callback")

        try:
            result = creds.custom_callback()

            if asyncio.iscoroutine(result):
                result = await result

            if result:
                if isinstance(result, str):
                    return RefreshResult(success=True, new_token=result)
                elif isinstance(result, dict):
                    return RefreshResult(
                        success=True,
                        new_token=result.get("token"),
                        new_cookies=result.get("cookies", {}),
                    )
                else:
                    # Assume AuthContext-like object
                    return RefreshResult(
                        success=True,
                        new_token=getattr(result, "token", None),
                        new_cookies=getattr(result, "cookies", {}),
                    )

            return RefreshResult(success=False, error="Custom callback returned None")

        except Exception as e:
            return RefreshResult(success=False, error=str(e))

    async def _update_auth_context(self, result: RefreshResult) -> None:
        """Update AuthContext with refresh result."""
        if not result.success:
            return

        # Update token
        if result.new_token:
            self._auth.token = result.new_token

            # Detect token type
            if result.new_token.startswith("Basic "):
                self._auth.token_type = "Basic"
            elif "." in result.new_token and len(result.new_token) > 50:
                self._auth.token_type = "Bearer"
            else:
                self._auth.token_type = "Bearer"  # Default

        # Update cookies
        if result.new_cookies:
            if not self._auth.cookies:
                self._auth.cookies = {}
            self._auth.cookies.update(result.new_cookies)

        # Mark as refreshed
        if hasattr(self._auth, "mark_refreshed"):
            self._auth.mark_refreshed(result.new_token)

        logger.debug(
            f"[AUTH_REFRESHER] Updated auth context "
            f"(token={'yes' if result.new_token else 'no'}, "
            f"cookies={len(result.new_cookies)})"
        )

    def get_refresh_callback(self) -> Callable[[], Any]:
        """
        Get a callback function for SessionWatchdog.

        Returns:
            Async function that attempts refresh and returns new token
        """
        async def _callback() -> str | None:
            result = await self.refresh()
            return result.new_token if result.success else None

        return _callback

    def get_reauth_callback(self) -> Callable[[], Any]:
        """
        Get a re-auth callback for SessionWatchdog.

        Returns:
            Async function that re-authenticates and returns AuthContext-like object
        """
        async def _callback() -> Optional["AuthContext"]:
            result = await self.refresh()
            if result.success:
                return self._auth
            return None

        return _callback

    def get_summary(self) -> dict[str, Any]:
        """Get refresher summary for reports."""
        if not self._credentials:
            return {"configured": False}

        return {
            "configured": True,
            "method": self._credentials.method.name,
            "refresh_count": self._credentials.refresh_count,
            "last_refresh": self._credentials.last_refresh,
            "recent_attempts": len(self._recent_attempts),
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def create_refresher_from_auth_context(
    auth_context: "AuthContext",
    http_client: Optional[Any] = None,
) -> AutoAuthRefresher:
    """
    Create an AutoAuthRefresher from existing AuthContext.

    Attempts to infer the auth method and credentials from the context.

    Args:
        auth_context: Existing auth context with credentials
        http_client: HTTP client for making requests

    Returns:
        Configured AutoAuthRefresher
    """
    refresher = AutoAuthRefresher(auth_context, http_client)

    # Try to infer method from auth context
    if hasattr(auth_context, "extra") and auth_context.extra:
        extra = auth_context.extra

        # Check for stored login info
        if "login_url" in extra and "username" in extra and "password" in extra:
            refresher.store_form_credentials(
                login_url=extra["login_url"],
                username=extra["username"],
                password=extra["password"],
                username_field=extra.get("username_field", "username"),
                password_field=extra.get("password_field", "password"),
                extra_fields=extra.get("extra_fields", {}),
            )
            return refresher

        # Check for refresh token
        if "refresh_token" in extra:
            if "token_url" in extra:
                refresher.store_oauth2_refresh(
                    token_url=extra["token_url"],
                    client_id=extra.get("client_id", ""),
                    refresh_token=extra["refresh_token"],
                )
            else:
                refresher.store_jwt_refresh(
                    refresh_url=extra.get("refresh_url", ""),
                    refresh_token=extra["refresh_token"],
                )
            return refresher

        # Check for OAuth2 client credentials
        if "client_id" in extra and "client_secret" in extra:
            refresher.store_oauth2_client_credentials(
                token_url=extra.get("token_url", ""),
                client_id=extra["client_id"],
                client_secret=extra["client_secret"],
                scope=extra.get("scope", ""),
            )
            return refresher

    # Check for Basic Auth
    if auth_context.token and auth_context.token_type == "Basic":
        try:
            decoded = base64.b64decode(
                auth_context.token.replace("Basic ", "")
            ).decode()
            username, password = decoded.split(":", 1)
            refresher.store_basic_auth(username, password)
            return refresher
        except Exception:
            pass

    # Check for API key
    if auth_context.token and len(auth_context.token) < 64 and "." not in auth_context.token:
        refresher.store_api_key(auth_context.token)
        return refresher

    logger.debug("[AUTH_REFRESHER] Could not infer auth method from context")
    return refresher


def setup_auth_refresher_for_target(
    auth_context: "AuthContext",
    target: str,
) -> Optional[AutoAuthRefresher]:
    """
    Set up auth refresher with credentials from auth_context for a target.

    This comprehensive function handles all auth types:
    - JWT with refresh token
    - Form-based login (DVWA, WebGoat, PHP apps)
    - OAuth2 client credentials
    - Basic Auth
    - API Key

    Args:
        auth_context: The acquired auth context with credentials
        target: The target URL (used to build auth endpoints)

    Returns:
        Configured AutoAuthRefresher or None if credentials not available
    """
    if not auth_context or not getattr(auth_context, "has_auth", False):
        return None

    from urllib.parse import urlparse
    parsed = urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    refresher = AutoAuthRefresher(auth_context)
    method = getattr(auth_context, "method", "")
    extra = getattr(auth_context, "extra", {}) or {}

    # JWT with refresh token
    if extra.get("refresh_token"):
        refresh_url = extra.get("refresh_url", "")
        if not refresh_url:
            # Use first common refresh endpoint
            refresh_url = f"{base_url}/api/auth/refresh"
        refresher.store_jwt_refresh(
            refresh_url=refresh_url,
            refresh_token=extra["refresh_token"],
        )
        return refresher

    # Form-based login
    if method in ("form_login", "form_register", "register") and extra.get("password"):
        login_path = extra.get("login_path", "")
        login_url = f"{base_url}{login_path}" if login_path else f"{base_url}/login"
        refresher.store_form_credentials(
            login_url=login_url,
            username=getattr(auth_context, "email", "") or "",
            password=extra.get("password", ""),
            username_field=extra.get("user_field", "username"),
            password_field="password",
            extra_fields=extra.get("extra_fields", {}),
        )
        return refresher

    # OAuth2 client credentials
    if extra.get("client_id") and extra.get("client_secret"):
        token_url = extra.get("token_url", f"{base_url}/oauth/token")
        refresher.store_oauth2_client_credentials(
            token_url=token_url,
            client_id=extra["client_id"],
            client_secret=extra["client_secret"],
            scope=extra.get("scope", ""),
        )
        return refresher

    # Basic Auth
    if getattr(auth_context, "token_type", "") == "Basic":
        email = getattr(auth_context, "email", "")
        if email and extra.get("password"):
            refresher.store_basic_auth(username=email, password=extra["password"])
            return refresher

    # API Key
    if extra.get("api_key"):
        refresher.store_api_key(
            api_key=extra["api_key"],
            header_name=extra.get("api_key_header", "X-API-Key"),
        )
        return refresher

    # Fallback: try to infer from auth context
    return create_refresher_from_auth_context(auth_context)


async def auto_refresh_on_error(
    refresher: AutoAuthRefresher,
    error_status: int,
) -> bool:
    """
    Attempt auto-refresh when auth error encountered.

    Args:
        refresher: Configured AutoAuthRefresher
        error_status: HTTP status code (401, 403, etc.)

    Returns:
        True if refresh was successful
    """
    if error_status not in (401, 403):
        return False

    if not refresher.has_credentials():
        return False

    result = await refresher.refresh()
    return result.success
