"""
Session Watchdog v1.0 - Monitor Auth Health During Scan

This module monitors authentication session health during long-running scans:
1. Periodic auth freshness checks (every 60 seconds)
2. Detects unexpected logout via baseline comparison
3. Auto-refreshes tokens when stale
4. Triggers re-authentication on failure

Integration:
    - full_scanner.py initializes watchdog at scan start
    - Modules can check session health via watchdog.is_healthy()
    - Watchdog logs all auth events for audit

Author: PetNTester AI
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Callable, Optional

from utils.logger import get_logger

if TYPE_CHECKING:
    from scanning.auth_context import AuthContext

logger = get_logger(__name__)


class SessionState(Enum):
    """Current session state."""

    HEALTHY = auto()
    STALE = auto()  # Token about to expire
    INVALID = auto()  # Got 401/403
    EXPIRED = auto()  # Confirmed expired
    REFRESHING = auto()  # Currently refreshing
    UNKNOWN = auto()


@dataclass
class SessionHealth:
    """Current session health status."""

    state: SessionState = SessionState.UNKNOWN
    last_check: float = 0.0
    last_successful_request: float = 0.0
    consecutive_failures: int = 0
    total_refreshes: int = 0
    total_reauths: int = 0
    last_failure_reason: str = ""
    is_valid: bool = True


@dataclass
class WatchdogConfig:
    """Configuration for session watchdog."""

    check_interval: float = 60.0  # Check every 60 seconds
    max_consecutive_failures: int = 3  # Re-auth after 3 failures
    stale_threshold_seconds: float = 300.0  # Consider stale after 5 min no use
    auto_refresh: bool = True  # Auto-refresh tokens when stale
    auto_reauth: bool = True  # Auto re-authenticate on failure


class SessionWatchdog:
    """
    Monitor and maintain session health during scan.

    Usage:
        watchdog = SessionWatchdog(
            auth_context=ctx,
            whoami_endpoint="https://api.example.com/me",
            http_client=client,
            reauth_callback=async_reauth_func,
        )
        await watchdog.start()

        # ... scan runs ...

        if not watchdog.is_healthy():
            logger.warning("Session degraded")

        await watchdog.stop()
    """

    def __init__(
        self,
        auth_context: "AuthContext",
        whoami_endpoint: str,
        http_client: Any,
        reauth_callback: Optional[Callable[[], Any]] = None,
        refresh_callback: Optional[Callable[[], Any]] = None,
        config: Optional[WatchdogConfig] = None,
    ):
        """
        Initialize session watchdog.

        Args:
            auth_context: Current auth context to monitor
            whoami_endpoint: Endpoint to check session validity (e.g., /api/me)
            http_client: HTTP client for making requests
            reauth_callback: Async function to re-authenticate (returns new AuthContext)
            refresh_callback: Async function to refresh token (returns new token)
            config: Watchdog configuration
        """
        self._auth = auth_context
        self._whoami = whoami_endpoint
        self._client = http_client
        self._reauth_callback = reauth_callback
        self._refresh_callback = refresh_callback
        self._config = config or WatchdogConfig()
        self._health = SessionHealth()
        self._baseline_response: str | None = None
        self._baseline_user_id: str | None = None
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None

    @property
    def health(self) -> SessionHealth:
        """Get current session health."""
        return self._health

    def is_healthy(self) -> bool:
        """Check if session is currently healthy."""
        return (
            self._health.is_valid
            and self._health.state in (SessionState.HEALTHY, SessionState.STALE)
            and self._health.consecutive_failures < self._config.max_consecutive_failures
        )

    async def start(self) -> None:
        """Start background session monitoring."""
        if self._running:
            logger.debug("[SESSION_WATCHDOG] Already running")
            return

        self._running = True
        self._health.last_check = time.time()

        # Capture baseline response for comparison
        await self._capture_baseline()

        logger.info(
            f"[SESSION_WATCHDOG] Started monitoring "
            f"(interval={self._config.check_interval}s, endpoint={self._whoami})"
        )

        # Start background monitoring loop
        self._monitor_task = asyncio.create_task(self._monitor_loop())

    async def stop(self) -> None:
        """Stop monitoring."""
        self._running = False

        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass

        logger.info(
            f"[SESSION_WATCHDOG] Stopped "
            f"(refreshes={self._health.total_refreshes}, reauths={self._health.total_reauths})"
        )

    async def _monitor_loop(self) -> None:
        """Background monitoring loop."""
        while self._running:
            try:
                await asyncio.sleep(self._config.check_interval)

                if not self._running:
                    break

                await self.check_session_health()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"[SESSION_WATCHDOG] Monitor loop error: {e}")

    async def _capture_baseline(self) -> None:
        """Capture baseline response for comparison."""
        try:
            response = await self._get_whoami_response()
            if response:
                self._baseline_response = response
                # Try to extract user ID from response
                self._baseline_user_id = self._extract_user_id(response)
                self._health.state = SessionState.HEALTHY
                self._health.is_valid = True
                logger.debug(
                    f"[SESSION_WATCHDOG] Baseline captured "
                    f"(length={len(response)}, user_id={self._baseline_user_id})"
                )
            else:
                logger.warning("[SESSION_WATCHDOG] Could not capture baseline")
                self._health.state = SessionState.INVALID
                self._health.is_valid = False
        except Exception as e:
            logger.debug(f"[SESSION_WATCHDOG] Baseline capture error: {e}")

    async def check_session_health(self) -> SessionHealth:
        """
        Perform session health check.

        Returns:
            Updated SessionHealth status
        """
        self._health.last_check = time.time()

        try:
            current_response = await self._get_whoami_response()

            if current_response is None:
                # 401/403 or network error
                await self._handle_auth_failure("401/403 response or network error")

            elif self._detect_logout(current_response):
                # Response changed significantly - likely logged out
                await self._handle_auth_failure("unexpected_logout_detected")

            elif self._detect_user_change(current_response):
                # User ID changed - session hijacked or switched
                await self._handle_auth_failure("user_identity_changed")

            else:
                # Session OK
                self._health.state = SessionState.HEALTHY
                self._health.is_valid = True
                self._health.consecutive_failures = 0
                self._health.last_successful_request = time.time()

        except Exception as e:
            logger.debug(f"[SESSION_WATCHDOG] Health check error: {e}")
            self._health.last_failure_reason = str(e)

        return self._health

    async def _handle_auth_failure(self, reason: str) -> None:
        """Handle authentication failure."""
        self._health.consecutive_failures += 1
        self._health.last_failure_reason = reason
        self._health.is_valid = False
        self._health.state = SessionState.INVALID

        logger.warning(
            f"[SESSION_WATCHDOG] Auth failure: {reason} "
            f"({self._health.consecutive_failures}/{self._config.max_consecutive_failures})"
        )

        # Attempt recovery
        if self._health.consecutive_failures >= self._config.max_consecutive_failures:
            if self._config.auto_reauth and self._reauth_callback:
                await self._attempt_reauth()
            else:
                self._health.state = SessionState.EXPIRED
                logger.error("[SESSION_WATCHDOG] Session expired, no auto-reauth configured")
        elif self._config.auto_refresh and self._refresh_callback:
            await self._attempt_refresh()

    async def _attempt_refresh(self) -> bool:
        """Attempt to refresh the token."""
        if not self._refresh_callback:
            return False

        logger.info("[SESSION_WATCHDOG] Attempting token refresh...")
        self._health.state = SessionState.REFRESHING

        try:
            new_token = await self._refresh_callback()

            if new_token:
                self._auth.mark_refreshed(new_token)
                self._health.total_refreshes += 1
                self._health.state = SessionState.HEALTHY
                self._health.is_valid = True
                self._health.consecutive_failures = 0

                # Update baseline
                await self._capture_baseline()

                logger.info("[SESSION_WATCHDOG] Token refreshed successfully")
                return True

        except Exception as e:
            logger.warning(f"[SESSION_WATCHDOG] Token refresh failed: {e}")

        return False

    async def _attempt_reauth(self) -> bool:
        """Attempt to re-authenticate."""
        if not self._reauth_callback:
            return False

        logger.info("[SESSION_WATCHDOG] Attempting re-authentication...")
        self._health.state = SessionState.REFRESHING

        try:
            new_auth = await self._reauth_callback()

            if new_auth and hasattr(new_auth, "has_auth") and new_auth.has_auth:
                # Update auth context with new credentials
                self._auth.token = new_auth.token
                self._auth.cookies = new_auth.cookies
                self._auth.token_type = new_auth.token_type

                if hasattr(new_auth, "extra"):
                    self._auth.extra.update(new_auth.extra)

                self._health.total_reauths += 1
                self._health.state = SessionState.HEALTHY
                self._health.is_valid = True
                self._health.consecutive_failures = 0

                # Update baseline
                await self._capture_baseline()

                logger.info("[SESSION_WATCHDOG] Re-authentication successful")
                return True

        except Exception as e:
            logger.error(f"[SESSION_WATCHDOG] Re-auth failed: {e}")

        self._health.state = SessionState.EXPIRED
        return False

    async def _get_whoami_response(self) -> str | None:
        """Get current user info from whoami endpoint."""
        try:
            # Build headers with current auth
            headers = {}
            if hasattr(self._auth, "auth_headers"):
                headers = self._auth.auth_headers or {}

            # Make request
            resp = await self._client.get(
                self._whoami,
                headers=headers,
                timeout=10.0,
            )

            # Check for auth errors
            if hasattr(resp, "status_code"):
                if resp.status_code in (401, 403):
                    return None
            elif hasattr(resp, "status"):
                if resp.status in (401, 403):
                    return None

            # Get response text
            if hasattr(resp, "text"):
                if asyncio.iscoroutinefunction(resp.text) or asyncio.iscoroutine(resp.text):
                    return await resp.text()
                elif callable(resp.text):
                    return resp.text()
                else:
                    return resp.text
            elif hasattr(resp, "content"):
                content = resp.content
                if isinstance(content, bytes):
                    return content.decode("utf-8", errors="replace")
                return str(content)

            return str(resp)

        except Exception as e:
            logger.debug(f"[SESSION_WATCHDOG] Whoami request error: {e}")
            return None

    def _detect_logout(self, current: str) -> bool:
        """Detect unexpected logout by comparing responses."""
        if not self._baseline_response:
            return False

        current_lower = current.lower()

        # Check for login page indicators in response
        login_indicators = [
            "login",
            "sign in",
            "log in",
            "authenticate",
            "unauthorized",
            "access denied",
            "session expired",
            "please log in",
        ]

        # These should NOT appear in authenticated response
        for indicator in login_indicators:
            if indicator in current_lower and indicator not in self._baseline_response.lower():
                logger.debug(f"[SESSION_WATCHDOG] Login indicator appeared: {indicator}")
                return True

        # Response shrunk significantly (lost user data)
        baseline_len = len(self._baseline_response)
        current_len = len(current)

        if baseline_len > 100 and current_len < baseline_len * 0.5:
            logger.debug(
                f"[SESSION_WATCHDOG] Response shrunk: {baseline_len} -> {current_len}"
            )
            return True

        return False

    def _detect_user_change(self, current: str) -> bool:
        """Detect if user identity changed (session hijack/switch)."""
        if not self._baseline_user_id:
            return False

        current_user_id = self._extract_user_id(current)

        if current_user_id and current_user_id != self._baseline_user_id:
            logger.warning(
                f"[SESSION_WATCHDOG] User changed: {self._baseline_user_id} -> {current_user_id}"
            )
            return True

        return False

    def _extract_user_id(self, response: str) -> str | None:
        """Extract user ID from response."""
        import re

        # Common patterns for user ID in JSON responses
        patterns = [
            r'"user_id"\s*:\s*"?(\d+)"?',
            r'"userId"\s*:\s*"?(\d+)"?',
            r'"id"\s*:\s*"?(\d+)"?',
            r'"uid"\s*:\s*"?(\d+)"?',
            r'"sub"\s*:\s*"([^"]+)"',  # JWT sub claim
            r'"email"\s*:\s*"([^"]+)"',
            r'"username"\s*:\s*"([^"]+)"',
        ]

        for pattern in patterns:
            match = re.search(pattern, response)
            if match:
                return match.group(1)

        return None

    async def record_successful_request(self) -> None:
        """Record that a request succeeded (called by modules)."""
        self._health.last_successful_request = time.time()
        if self._health.state == SessionState.STALE:
            self._health.state = SessionState.HEALTHY

    async def record_auth_error(self, status_code: int) -> None:
        """Record an authentication error from a module."""
        if status_code in (401, 403):
            await self.check_session_health()

    def get_summary(self) -> dict[str, Any]:
        """Get watchdog summary for reports."""
        return {
            "state": self._health.state.name,
            "is_healthy": self.is_healthy(),
            "last_check": self._health.last_check,
            "consecutive_failures": self._health.consecutive_failures,
            "total_refreshes": self._health.total_refreshes,
            "total_reauths": self._health.total_reauths,
            "last_failure_reason": self._health.last_failure_reason,
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def detect_whoami_endpoint(base_url: str, discovered_endpoints: list[str] | None = None) -> str:
    """
    Detect the best whoami/me endpoint for session monitoring.

    Args:
        base_url: Base URL of the target
        discovered_endpoints: List of discovered endpoints from crawling

    Returns:
        Best endpoint for session health checks
    """
    base = base_url.rstrip("/")

    # Common whoami endpoints in priority order
    whoami_candidates = [
        "/api/me",
        "/api/user",
        "/api/v1/me",
        "/api/v1/user",
        "/api/v1/users/me",
        "/api/users/me",
        "/api/auth/me",
        "/api/auth/user",
        "/me",
        "/user",
        "/users/me",
        "/account",
        "/api/account",
        "/api/v1/account",
        "/api/profile",
        "/profile",
    ]

    # If we have discovered endpoints, prioritize those
    if discovered_endpoints:
        for endpoint in discovered_endpoints:
            endpoint_lower = endpoint.lower()
            if any(x in endpoint_lower for x in ["/me", "/user", "/account", "/profile"]):
                return endpoint

    # Return first candidate (most common)
    return f"{base}{whoami_candidates[0]}"
