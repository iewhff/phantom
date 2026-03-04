"""
Manual Authentication Handler v1.0

When scanner detects CAPTCHA or 2FA, this module:
1. Opens a VISIBLE browser window for user interaction
2. Waits for user to complete the authentication challenge
3. Extracts cookies/tokens after manual login
4. Returns AuthContext to continue scan

This is the fallback mechanism for sites that cannot be automated.

Author: PetNTester AI
Version: 1.0.0
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Optional

from utils.logger import get_logger

if TYPE_CHECKING:
    from scanning.auth_context import AuthContext

logger = get_logger(__name__)


@dataclass
class ManualAuthRequest:
    """Request for manual authentication."""

    url: str
    reason: str  # "captcha", "2fa", "unknown_challenge"
    challenge_type: str  # "reCAPTCHA", "hCaptcha", "TOTP", etc.
    timeout_seconds: int = 300  # 5 minutes max
    instructions: str = ""  # Additional instructions for user


@dataclass
class ManualAuthResult:
    """Result of manual authentication."""

    success: bool
    elapsed_seconds: float = 0.0
    final_url: str = ""
    token: str = ""
    token_type: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    local_storage: dict[str, str] = field(default_factory=dict)
    session_storage: dict[str, str] = field(default_factory=dict)
    error: str = ""


class ManualAuthHandler:
    """
    Handle manual authentication challenges.

    Opens a visible browser window for the user to complete
    CAPTCHA/2FA challenges that cannot be automated.
    """

    def __init__(self, headless: bool = False):
        """
        Initialize manual auth handler.

        Args:
            headless: If False (default), shows browser window for user.
                      If True, runs headless (useful for testing only).
        """
        self._headless = headless

    async def request_manual_auth(
        self,
        request: ManualAuthRequest,
        on_progress: Optional[Callable[[float, int], None]] = None,
    ) -> ManualAuthResult:
        """
        Open browser for manual authentication.

        Args:
            request: ManualAuthRequest with URL and challenge details
            on_progress: Optional callback(elapsed_seconds, timeout_seconds)
                         for progress reporting

        Returns:
            ManualAuthResult with tokens/cookies after successful login
        """
        # Check if manual auth is allowed
        if os.environ.get("PHANTOM_ALLOW_MANUAL_AUTH", "0") != "1":
            logger.warning(
                "[MANUAL_AUTH] Manual auth requested but PHANTOM_ALLOW_MANUAL_AUTH != 1"
            )
            return ManualAuthResult(
                success=False,
                error="Manual auth not allowed. Set PHANTOM_ALLOW_MANUAL_AUTH=1",
            )

        # Import here to avoid circular imports and check availability
        try:
            from utils.headless_browser import (
                HeadlessBrowserEngine,
                BrowserConfig,
                PLAYWRIGHT_AVAILABLE,
            )

            if not PLAYWRIGHT_AVAILABLE:
                return ManualAuthResult(
                    success=False,
                    error="Playwright not installed. Run: pip install playwright && playwright install",
                )
        except ImportError as e:
            return ManualAuthResult(
                success=False,
                error=f"Failed to import headless browser: {e}",
            )

        # Log manual auth request
        logger.warning(
            f"\n"
            f"{'='*60}\n"
            f"  MANUAL AUTHENTICATION REQUIRED\n"
            f"{'='*60}\n"
            f"  Reason: {request.reason}\n"
            f"  Challenge Type: {request.challenge_type}\n"
            f"  URL: {request.url}\n"
            f"  Timeout: {request.timeout_seconds} seconds\n"
            f"{'='*60}\n"
            f"  A browser window will open.\n"
            f"  Please complete the login/verification.\n"
            f"{'='*60}\n"
        )

        if request.instructions:
            logger.info(f"  Instructions: {request.instructions}")

        # Create browser config for VISIBLE window
        config = BrowserConfig(
            headless=self._headless,  # False = visible window
            security_level="RELAXED",
        )

        browser = HeadlessBrowserEngine(config)

        try:
            await browser.start()

            # Navigate to login URL
            logger.info(f"[MANUAL_AUTH] Navigating to: {request.url}")
            await browser.navigate(request.url)

            # Wait for manual login completion
            result = await browser.wait_for_manual_login(
                timeout_seconds=request.timeout_seconds,
                check_interval=1.0,
            )

            if result.get("success"):
                logger.info("[MANUAL_AUTH] Login completed successfully")

                # Extract auth data
                tokens = result.get("tokens", [])
                cookies = result.get("cookies", [])
                local_storage = result.get("local_storage", {})
                session_storage = result.get("session_storage", {})

                # Find primary token (JWT/Bearer)
                primary_token = ""
                token_type = ""
                for token in tokens:
                    if token.get("type") in ("jwt", "bearer", "token"):
                        primary_token = token.get("value", "")
                        token_type = "bearer"
                        break

                # Also check localStorage for tokens
                if not primary_token:
                    for key, value in local_storage.items():
                        if any(x in key.lower() for x in ["token", "jwt", "auth"]):
                            primary_token = value
                            token_type = "bearer"
                            break

                # Build cookies dict
                cookies_dict = {}
                for cookie in cookies:
                    name = cookie.get("name", "")
                    value = cookie.get("value", "")
                    # Prioritize session/auth cookies
                    if any(x in name.lower() for x in ["session", "auth", "token", "jwt", "sid"]):
                        cookies_dict[name] = value

                return ManualAuthResult(
                    success=True,
                    elapsed_seconds=result.get("elapsed", 0.0),
                    final_url=result.get("final_url", ""),
                    token=primary_token,
                    token_type=token_type,
                    cookies=cookies_dict,
                    local_storage=local_storage,
                    session_storage=session_storage,
                )

            else:
                error = result.get("error", "Unknown error")
                logger.warning(f"[MANUAL_AUTH] Login failed: {error}")
                return ManualAuthResult(
                    success=False,
                    elapsed_seconds=result.get("elapsed", 0.0),
                    error=error,
                )

        except Exception as e:
            logger.error(f"[MANUAL_AUTH] Exception: {e}")
            return ManualAuthResult(
                success=False,
                error=str(e),
            )

        finally:
            await browser.stop()

    async def convert_to_auth_context(
        self,
        result: ManualAuthResult,
    ) -> "AuthContext":
        """
        Convert ManualAuthResult to AuthContext.

        Args:
            result: ManualAuthResult from request_manual_auth()

        Returns:
            AuthContext with extracted credentials
        """
        # Import here to avoid circular imports
        from scanning.auth_context import AuthContext

        if not result.success:
            return AuthContext()

        ctx = AuthContext(method="manual")

        # Set token if found
        if result.token:
            ctx.token = result.token
            ctx.token_type = result.token_type or "bearer"

        # Set cookies
        if result.cookies:
            ctx.cookies = result.cookies
            if not ctx.token:
                ctx.token_type = "cookie"

        # Store additional data in extra
        if result.local_storage:
            ctx.extra["local_storage"] = result.local_storage
        if result.session_storage:
            ctx.extra["session_storage"] = result.session_storage

        logger.info(
            f"[MANUAL_AUTH] Converted to AuthContext: "
            f"token={bool(ctx.token)}, cookies={len(ctx.cookies)}"
        )

        return ctx


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


async def request_manual_auth_for_captcha(
    url: str,
    captcha_type: str = "Unknown CAPTCHA",
    timeout: int = 300,
) -> ManualAuthResult:
    """
    Request manual authentication for CAPTCHA challenge.

    Usage:
        result = await request_manual_auth_for_captcha(
            "https://example.com/login",
            captcha_type="reCAPTCHA"
        )
    """
    handler = ManualAuthHandler(headless=False)
    request = ManualAuthRequest(
        url=url,
        reason="captcha",
        challenge_type=captcha_type,
        timeout_seconds=timeout,
        instructions="Please solve the CAPTCHA and complete the login.",
    )
    return await handler.request_manual_auth(request)


async def request_manual_auth_for_2fa(
    url: str,
    mfa_type: str = "Unknown 2FA",
    timeout: int = 300,
) -> ManualAuthResult:
    """
    Request manual authentication for 2FA challenge.

    Usage:
        result = await request_manual_auth_for_2fa(
            "https://example.com/2fa",
            mfa_type="TOTP"
        )
    """
    handler = ManualAuthHandler(headless=False)
    request = ManualAuthRequest(
        url=url,
        reason="2fa",
        challenge_type=mfa_type,
        timeout_seconds=timeout,
        instructions="Please enter the 2FA code and complete verification.",
    )
    return await handler.request_manual_auth(request)


def is_manual_auth_allowed() -> bool:
    """Check if manual authentication is allowed via environment variable."""
    return os.environ.get("PHANTOM_ALLOW_MANUAL_AUTH", "0") == "1"
