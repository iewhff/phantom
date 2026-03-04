"""
Headless Browser Engine v1.0 - Playwright Integration for PetNTester

Enterprise-grade headless browser for:
- Real DOM XSS detection with JavaScript execution
- Authentication flow analysis (OAuth, SAML, MFA)
- Single Page Application (SPA) crawling
- Dynamic content rendering
- JavaScript-based vulnerability testing
- Client-side security analysis

Author: PetNTester AI
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urlparse

from utils.logger import get_logger

# Playwright imports (optional dependency)
try:
    from playwright.async_api import (
        async_playwright,
        Browser,
        BrowserContext,
        Page,
        Playwright,
        Response,
        ConsoleMessage,
        Dialog,
        Error as PlaywrightError,
    )
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    Browser = Any
    BrowserContext = Any
    Page = Any
    Playwright = Any

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


# =============================================================================
# CONSTANTS & CONFIGURATION
# =============================================================================

HEADLESS_ENGINE_VERSION = "1.0.0"

# Default browser settings
DEFAULT_VIEWPORT = {"width": 1920, "height": 1080}
DEFAULT_TIMEOUT = 30000  # 30 seconds
DEFAULT_NAVIGATION_TIMEOUT = 60000  # 60 seconds

# XSS detection markers
XSS_MARKERS = [
    "XSS_DETECTED_",
    "PETNTESTER_XSS_",
    "DOM_XSS_PROOF_",
]

# Dangerous JavaScript patterns for DOM XSS
DANGEROUS_JS_PATTERNS = [
    r"eval\s*\(",
    r"Function\s*\(",
    r"setTimeout\s*\([^,]*['\"]",
    r"setInterval\s*\([^,]*['\"]",
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"insertAdjacentHTML\s*\(",
    r"\.html\s*\(",  # jQuery
]

# CAPTCHA detection indicators
CAPTCHA_INDICATORS = [
    # reCAPTCHA v2/v3
    "g-recaptcha",
    "grecaptcha",
    "recaptcha-token",
    "www.google.com/recaptcha",
    "www.gstatic.com/recaptcha",
    "recaptcha.net",
    # hCaptcha
    "h-captcha",
    "hcaptcha",
    "hcaptcha.com",
    "hcaptcha-response",
    # Cloudflare Turnstile
    "cf-turnstile",
    "challenges.cloudflare.com/turnstile",
    "cf-chl-widget",
    # FunCaptcha/Arkose Labs
    "funcaptcha",
    "arkoselabs",
    "arkose",
    # GeeTest
    "geetest",
    "gt_captcha",
    # Generic
    "captcha",
    "verify you are human",
    "i'm not a robot",
    "i am not a robot",
    "security check",
    "bot protection",
    "human verification",
    "prove you are human",
]

# MFA/2FA detection indicators
MFA_INDICATORS = [
    "two-factor",
    "two factor",
    "2fa",
    "mfa",
    "multi-factor",
    "multifactor",
    "authenticator",
    "verification code",
    "security code",
    "one-time",
    "one time",
    "otp",
    "enter code",
    "6-digit",
    "six digit",
    "totp",
    "google authenticator",
    "authy",
    "microsoft authenticator",
    "sms code",
    "text message code",
    "email code",
    "backup code",
    "recovery code",
    "verify your identity",
    "additional verification",
]


class BrowserType(Enum):
    """Supported browser types."""
    CHROMIUM = "chromium"
    FIREFOX = "firefox"
    WEBKIT = "webkit"


class SecurityLevel(Enum):
    """Browser security levels for testing."""
    STRICT = auto()      # Full security, CSP enabled
    RELAXED = auto()     # Some security bypassed for testing
    PERMISSIVE = auto()  # Minimal security for vulnerability testing


@dataclass
class BrowserConfig:
    """Configuration for headless browser."""
    browser_type: BrowserType = BrowserType.CHROMIUM
    headless: bool = True
    security_level: SecurityLevel = SecurityLevel.RELAXED
    viewport: dict = field(default_factory=lambda: DEFAULT_VIEWPORT.copy())
    timeout: int = DEFAULT_TIMEOUT
    navigation_timeout: int = DEFAULT_NAVIGATION_TIMEOUT
    proxy: Optional[str] = None
    user_agent: Optional[str] = None
    ignore_https_errors: bool = True  # For pentesting self-signed certs
    java_script_enabled: bool = True
    capture_console: bool = True
    capture_network: bool = True
    block_resources: list[str] = field(default_factory=list)  # e.g., ["image", "font"]
    extra_http_headers: dict[str, str] = field(default_factory=dict)


@dataclass
class PageEvent:
    """Captured page event."""
    event_type: str
    timestamp: float
    data: dict[str, Any]


@dataclass
class XSSResult:
    """Result of XSS test."""
    vulnerable: bool
    payload: str
    execution_context: str
    evidence: list[str]
    console_messages: list[str]
    triggered_dialogs: list[str]
    confidence: float
    screenshot: Optional[bytes] = None


@dataclass
class AuthFlowResult:
    """Result of authentication flow analysis."""
    flow_type: str  # oauth, saml, basic, form, mfa
    steps: list[dict[str, Any]]
    tokens_found: list[dict[str, str]]
    vulnerabilities: list[dict[str, Any]]
    cookies: list[dict[str, Any]]
    local_storage: dict[str, str]
    session_storage: dict[str, str]


# =============================================================================
# HEADLESS BROWSER ENGINE
# =============================================================================

class HeadlessBrowserEngine:
    """
    Enterprise-grade headless browser engine using Playwright.

    Features:
    - Real JavaScript execution for DOM XSS
    - Multi-browser support (Chromium, Firefox, WebKit)
    - Authentication flow analysis
    - Network interception
    - Console/dialog capture
    - Screenshot evidence
    - SPA support
    """

    def __init__(self, config: Optional[BrowserConfig] = None):
        if not PLAYWRIGHT_AVAILABLE:
            raise ImportError(
                "Playwright is not installed. Install with: pip install playwright && playwright install"
            )

        self.config = config or BrowserConfig()
        self._playwright: Optional[Playwright] = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
        self._page: Optional[Page] = None

        # Event capture
        self._console_messages: list[str] = []
        self._dialogs: list[str] = []
        self._network_requests: list[dict] = []
        self._network_responses: list[dict] = []
        self._page_events: list[PageEvent] = []
        self._xss_detected: bool = False
        self._xss_evidence: list[str] = []

    async def __aenter__(self) -> "HeadlessBrowserEngine":
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.stop()

    async def start(self) -> None:
        """Start the browser engine."""
        logger.info(f"[HeadlessBrowser] Starting {self.config.browser_type.value} browser")

        self._playwright = await async_playwright().start()

        # Select browser
        browser_launcher = {
            BrowserType.CHROMIUM: self._playwright.chromium,
            BrowserType.FIREFOX: self._playwright.firefox,
            BrowserType.WEBKIT: self._playwright.webkit,
        }[self.config.browser_type]

        # Launch options
        launch_options = {
            "headless": self.config.headless,
        }

        if self.config.proxy:
            launch_options["proxy"] = {"server": self.config.proxy}

        # Security-specific args for Chromium
        if self.config.browser_type == BrowserType.CHROMIUM:
            args = []
            if self.config.security_level == SecurityLevel.PERMISSIVE:
                args.extend([
                    "--disable-web-security",
                    "--disable-features=IsolateOrigins,site-per-process",
                    "--allow-running-insecure-content",
                ])
            elif self.config.security_level == SecurityLevel.RELAXED:
                args.extend([
                    "--disable-features=IsolateOrigins",
                ])
            if args:
                launch_options["args"] = args

        self._browser = await browser_launcher.launch(**launch_options)

        # Create context with settings
        context_options = {
            "viewport": self.config.viewport,
            "ignore_https_errors": self.config.ignore_https_errors,
            "java_script_enabled": self.config.java_script_enabled,
        }

        if self.config.user_agent:
            context_options["user_agent"] = self.config.user_agent

        if self.config.extra_http_headers:
            context_options["extra_http_headers"] = self.config.extra_http_headers

        self._context = await self._browser.new_context(**context_options)

        # Set timeouts
        self._context.set_default_timeout(self.config.timeout)
        self._context.set_default_navigation_timeout(self.config.navigation_timeout)

        # Create page
        self._page = await self._context.new_page()

        # Setup event handlers
        await self._setup_event_handlers()

        logger.info("[HeadlessBrowser] Browser started successfully")

    async def stop(self) -> None:
        """Stop the browser engine."""
        if self._page:
            await self._page.close()
        if self._context:
            await self._context.close()
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

        logger.info("[HeadlessBrowser] Browser stopped")

    async def _setup_event_handlers(self) -> None:
        """Setup page event handlers for capturing security events."""
        if not self._page:
            return

        # Console messages (critical for XSS detection)
        async def on_console(msg: ConsoleMessage) -> None:
            text = msg.text
            self._console_messages.append(text)

            # Check for XSS markers
            for marker in XSS_MARKERS:
                if marker in text:
                    self._xss_detected = True
                    self._xss_evidence.append(f"Console: {text}")
                    logger.warning(f"[HeadlessBrowser] XSS DETECTED via console: {text}")

        self._page.on("console", on_console)

        # Dialog handling (alert, confirm, prompt - XSS indicators)
        async def on_dialog(dialog: Dialog) -> None:
            message = dialog.message
            dialog_type = dialog.type
            self._dialogs.append(f"{dialog_type}: {message}")

            # Check for XSS markers
            for marker in XSS_MARKERS:
                if marker in message:
                    self._xss_detected = True
                    self._xss_evidence.append(f"Dialog ({dialog_type}): {message}")
                    logger.warning(f"[HeadlessBrowser] XSS DETECTED via {dialog_type}: {message}")

            # Auto-dismiss dialogs
            await dialog.dismiss()

        self._page.on("dialog", on_dialog)

        # Network capture
        if self.config.capture_network:
            async def on_request(request) -> None:
                self._network_requests.append({
                    "url": request.url,
                    "method": request.method,
                    "headers": dict(request.headers),
                    "timestamp": time.time(),
                })

            async def on_response(response: Response) -> None:
                self._network_responses.append({
                    "url": response.url,
                    "status": response.status,
                    "headers": dict(response.headers),
                    "timestamp": time.time(),
                })

            self._page.on("request", on_request)
            self._page.on("response", on_response)

        # Page errors
        async def on_page_error(error) -> None:
            self._page_events.append(PageEvent(
                event_type="page_error",
                timestamp=time.time(),
                data={"error": str(error)},
            ))

        self._page.on("pageerror", on_page_error)

    def _reset_detection_state(self) -> None:
        """Reset XSS detection state for new test."""
        self._xss_detected = False
        self._xss_evidence = []
        self._console_messages = []
        self._dialogs = []

    # =========================================================================
    # NAVIGATION
    # =========================================================================

    async def navigate(self, url: str, wait_until: str = "networkidle") -> Response | None:
        """
        Navigate to a URL.

        Args:
            url: Target URL
            wait_until: Wait condition (load, domcontentloaded, networkidle)

        Returns:
            Response object or None if navigation failed
        """
        if not self._page:
            raise RuntimeError("Browser not started")

        logger.debug(f"[HeadlessBrowser] Navigating to {url}")

        # FIX 2026-02-16: Handle navigation errors gracefully
        # Prevents "Future exception was never retrieved" when browser/frame is closed
        try:
            response = await self._page.goto(url, wait_until=wait_until)
            return response
        except Exception as e:
            error_msg = str(e).lower()
            # Recoverable errors that shouldn't crash the scanner
            recoverable_errors = [
                "target", "closed", "context", "browser",  # TargetClosedError
                "aborted", "detached", "frame",  # ERR_ABORTED / frame detached
                "net::", "err_",  # Network errors
                "timeout", "navigation",  # Navigation errors
            ]
            if any(x in error_msg for x in recoverable_errors):
                logger.debug(f"[HeadlessBrowser] Navigation error (recoverable): {url[:50]}...")
                return None
            # Re-raise non-recoverable errors
            raise

    async def get_page_content(self) -> str:
        """Get current page HTML content."""
        if not self._page:
            raise RuntimeError("Browser not started")
        return await self._page.content()

    async def get_page_text(self) -> str:
        """Get current page text content (no HTML)."""
        if not self._page:
            raise RuntimeError("Browser not started")
        return await self._page.inner_text("body")

    async def screenshot(self, full_page: bool = False) -> bytes:
        """Take a screenshot."""
        if not self._page:
            raise RuntimeError("Browser not started")
        return await self._page.screenshot(full_page=full_page)

    # =========================================================================
    # DOM XSS TESTING
    # =========================================================================

    async def test_dom_xss(
        self,
        url: str,
        payloads: list[str] | None = None,
        injection_points: list[str] | None = None,
    ) -> list[XSSResult]:
        """
        Test for DOM-based XSS with real JavaScript execution.

        Args:
            url: Target URL
            payloads: XSS payloads to test (uses defaults if None)
            injection_points: URL parameters/fragments to inject into

        Returns:
            List of XSSResult for each finding
        """
        if not self._page:
            raise RuntimeError("Browser not started")

        results = []

        # Default payloads with unique markers
        if payloads is None:
            payloads = self._get_dom_xss_payloads()

        # Parse URL for injection points
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Test hash-based injection (most common DOM XSS vector)
        logger.info(f"[HeadlessBrowser] Testing DOM XSS on {url}")

        for payload in payloads:
            self._reset_detection_state()

            # Generate unique marker for this payload
            marker = f"XSS_DETECTED_{hashlib.md5(payload.encode()).hexdigest()[:8]}"
            marked_payload = payload.replace("XSS", marker).replace("1", f"'{marker}'")

            # Test in URL hash
            test_url = f"{base_url}#{marked_payload}"

            try:
                await self.navigate(test_url, wait_until="domcontentloaded")

                # Wait for potential XSS execution
                await asyncio.sleep(0.5)

                # Trigger common DOM XSS scenarios
                await self._trigger_dom_xss_scenarios()

                # Check if XSS was detected
                if self._xss_detected or marker in " ".join(self._console_messages + self._dialogs):
                    result = XSSResult(
                        vulnerable=True,
                        payload=payload,
                        execution_context="DOM (hash)",
                        evidence=self._xss_evidence.copy(),
                        console_messages=self._console_messages.copy(),
                        triggered_dialogs=self._dialogs.copy(),
                        confidence=95.0,
                        screenshot=await self.screenshot(),
                    )
                    results.append(result)
                    logger.warning(f"[HeadlessBrowser] DOM XSS CONFIRMED: {payload[:50]}...")

            except Exception as e:
                logger.debug(f"[HeadlessBrowser] Error testing payload: {e}")

        # Test URL parameter injection
        if injection_points:
            for param in injection_points:
                for payload in payloads[:5]:  # Limit for efficiency
                    self._reset_detection_state()
                    marker = f"XSS_DETECTED_{hashlib.md5(payload.encode()).hexdigest()[:8]}"
                    marked_payload = payload.replace("XSS", marker)

                    test_url = f"{base_url}?{param}={marked_payload}"

                    try:
                        await self.navigate(test_url, wait_until="domcontentloaded")
                        await asyncio.sleep(0.5)
                        await self._trigger_dom_xss_scenarios()

                        if self._xss_detected or marker in " ".join(self._console_messages + self._dialogs):
                            result = XSSResult(
                                vulnerable=True,
                                payload=payload,
                                execution_context=f"DOM (param: {param})",
                                evidence=self._xss_evidence.copy(),
                                console_messages=self._console_messages.copy(),
                                triggered_dialogs=self._dialogs.copy(),
                                confidence=95.0,
                                screenshot=await self.screenshot(),
                            )
                            results.append(result)

                    except Exception as e:
                        logger.debug(f"[HeadlessBrowser] Error testing param {param}: {e}")

        return results

    async def _trigger_dom_xss_scenarios(self) -> None:
        """Trigger common DOM XSS scenarios by interacting with the page."""
        if not self._page:
            return

        try:
            # Trigger hashchange event
            await self._page.evaluate("window.dispatchEvent(new HashChangeEvent('hashchange'))")

            # Trigger popstate
            await self._page.evaluate("window.dispatchEvent(new PopStateEvent('popstate'))")

            # Focus on input fields (for autofocus XSS)
            inputs = await self._page.query_selector_all("input, textarea")
            for inp in inputs[:3]:
                try:
                    await inp.focus()
                except Exception:
                    pass

            # Click on interactive elements
            clickables = await self._page.query_selector_all("a, button, [onclick]")
            for elem in clickables[:3]:
                try:
                    await elem.click(timeout=1000)
                except Exception:
                    pass

        except Exception as e:
            logger.debug(f"[HeadlessBrowser] Error triggering scenarios: {e}")

    def _get_dom_xss_payloads(self) -> list[str]:
        """Get DOM XSS payloads with execution markers."""
        return [
            # Console-based detection (works with CSP)
            '"><img src=x onerror="console.log(\'XSS_DETECTED_1\')">',
            "'-console.log('XSS_DETECTED_2')-'",
            '";console.log("XSS_DETECTED_3");//',
            "${console.log('XSS_DETECTED_4')}",

            # Alert-based detection (classic)
            '"><script>alert("XSS_DETECTED_5")</script>',
            '<img src=x onerror=alert("XSS_DETECTED_6")>',
            '<svg onload=alert("XSS_DETECTED_7")>',
            "javascript:alert('XSS_DETECTED_8')",

            # Event handler based
            '" onmouseover="console.log(\'XSS_DETECTED_9\')" x="',
            "' onfocus='console.log(\"XSS_DETECTED_10\")' autofocus='",

            # Template literal
            '${alert("XSS_DETECTED_11")}',
            '`-alert("XSS_DETECTED_12")-`',

            # DOM clobbering
            '<form id="test"><input name="innerHTML" value="XSS_DETECTED_13"></form>',

            # Prototype pollution trigger
            '__proto__[innerHTML]=<img src=x onerror=console.log("XSS_DETECTED_14")>',
        ]

    # =========================================================================
    # AUTHENTICATION FLOW ANALYSIS
    # =========================================================================

    async def analyze_auth_flow(
        self,
        login_url: str,
        credentials: dict[str, str] | None = None,
        wait_for_redirect: bool = True,
    ) -> AuthFlowResult:
        """
        Analyze authentication flow for vulnerabilities.

        Args:
            login_url: Login page URL
            credentials: Optional credentials to attempt login
            wait_for_redirect: Wait for post-login redirect

        Returns:
            AuthFlowResult with flow analysis
        """
        if not self._page:
            raise RuntimeError("Browser not started")

        logger.info(f"[HeadlessBrowser] Analyzing auth flow at {login_url}")

        steps = []
        tokens_found = []
        vulnerabilities = []

        # Navigate to login page
        await self.navigate(login_url)
        steps.append({
            "step": "navigate",
            "url": login_url,
            "timestamp": time.time(),
        })

        # Detect auth flow type
        flow_type = await self._detect_auth_flow_type()
        steps.append({
            "step": "detect_flow",
            "flow_type": flow_type,
            "timestamp": time.time(),
        })

        # Analyze page for vulnerabilities
        page_vulns = await self._analyze_auth_page_vulnerabilities()
        vulnerabilities.extend(page_vulns)

        # Look for tokens in page
        page_tokens = await self._find_tokens_in_page()
        tokens_found.extend(page_tokens)

        # If credentials provided, attempt login
        if credentials:
            login_result = await self._attempt_login(credentials)
            steps.append({
                "step": "login_attempt",
                "result": login_result,
                "timestamp": time.time(),
            })

            if wait_for_redirect:
                await asyncio.sleep(2)

                # Analyze post-login state
                post_tokens = await self._find_tokens_in_page()
                tokens_found.extend(post_tokens)

        # Get storage data
        local_storage = await self._page.evaluate("() => Object.assign({}, localStorage)")
        session_storage = await self._page.evaluate("() => Object.assign({}, sessionStorage)")

        # Get cookies
        cookies = await self._context.cookies()

        # Analyze token security
        token_vulns = self._analyze_token_security(tokens_found, cookies)
        vulnerabilities.extend(token_vulns)

        return AuthFlowResult(
            flow_type=flow_type,
            steps=steps,
            tokens_found=tokens_found,
            vulnerabilities=vulnerabilities,
            cookies=[dict(c) for c in cookies],
            local_storage=local_storage,
            session_storage=session_storage,
        )

    async def _detect_auth_flow_type(self) -> str:
        """Detect the type of authentication flow."""
        if not self._page:
            return "unknown"

        content = await self.get_page_content()
        url = self._page.url

        # OAuth detection
        if any(x in url.lower() for x in ["oauth", "authorize", "client_id"]):
            return "oauth"
        if any(x in content.lower() for x in ["oauth", "sign in with google", "sign in with facebook"]):
            return "oauth"

        # SAML detection
        if any(x in content.lower() for x in ["samlrequest", "samlresponse", "saml"]):
            return "saml"

        # MFA detection
        if any(x in content.lower() for x in ["two-factor", "2fa", "mfa", "authenticator", "verification code"]):
            return "mfa"

        # Basic form auth
        forms = await self._page.query_selector_all("form")
        for form in forms:
            inputs = await form.query_selector_all("input")
            input_types = []
            for inp in inputs:
                inp_type = await inp.get_attribute("type")
                input_types.append(inp_type)

            if "password" in input_types:
                return "form"

        return "unknown"

    async def _analyze_auth_page_vulnerabilities(self) -> list[dict]:
        """Analyze authentication page for vulnerabilities."""
        vulns = []

        if not self._page:
            return vulns

        content = await self.get_page_content()

        # Check for autocomplete on password fields
        password_fields = await self._page.query_selector_all('input[type="password"]')
        for field in password_fields:
            autocomplete = await field.get_attribute("autocomplete")
            if autocomplete != "off" and autocomplete != "new-password":
                vulns.append({
                    "type": "autocomplete_enabled",
                    "severity": "LOW",
                    "description": "Password field has autocomplete enabled",
                    "cwe": "CWE-525",
                })

        # Check for CSRF token
        csrf_found = any(x in content.lower() for x in ["csrf", "_token", "authenticity_token"])
        if not csrf_found:
            forms = await self._page.query_selector_all("form")
            if forms:
                vulns.append({
                    "type": "missing_csrf",
                    "severity": "MEDIUM",
                    "description": "Login form may lack CSRF protection",
                    "cwe": "CWE-352",
                })

        # Check for password in URL
        if "password" in self._page.url.lower() or "pass=" in self._page.url.lower():
            vulns.append({
                "type": "password_in_url",
                "severity": "HIGH",
                "description": "Password may be transmitted in URL",
                "cwe": "CWE-598",
            })

        # Check for HTTP (non-HTTPS)
        if self._page.url.startswith("http://"):
            vulns.append({
                "type": "no_https",
                "severity": "HIGH",
                "description": "Login page served over HTTP (no encryption)",
                "cwe": "CWE-319",
            })

        return vulns

    async def _find_tokens_in_page(self) -> list[dict]:
        """Find authentication tokens in page."""
        tokens = []

        if not self._page:
            return tokens

        content = await self.get_page_content()

        # JWT patterns
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        for match in re.finditer(jwt_pattern, content):
            tokens.append({
                "type": "jwt",
                "value": match.group()[:50] + "...",
                "location": "page_content",
            })

        # Bearer tokens
        bearer_pattern = r'Bearer\s+([A-Za-z0-9_-]+)'
        for match in re.finditer(bearer_pattern, content):
            tokens.append({
                "type": "bearer",
                "value": match.group(1)[:30] + "...",
                "location": "page_content",
            })

        # API keys
        api_key_patterns = [
            (r'api[_-]?key["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})', "api_key"),
            (r'secret["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})', "secret"),
            (r'token["\']?\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})', "token"),
        ]

        for pattern, token_type in api_key_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                tokens.append({
                    "type": token_type,
                    "value": match.group(1)[:30] + "...",
                    "location": "page_content",
                })

        # Check localStorage and sessionStorage
        try:
            local_storage = await self._page.evaluate("() => Object.entries(localStorage)")
            for key, value in local_storage:
                if any(x in key.lower() for x in ["token", "jwt", "auth", "session", "key"]):
                    tokens.append({
                        "type": "localStorage",
                        "key": key,
                        "value": str(value)[:50] + "..." if len(str(value)) > 50 else str(value),
                        "location": "localStorage",
                    })
        except Exception:
            pass

        return tokens

    async def _attempt_login(self, credentials: dict[str, str]) -> dict:
        """Attempt to fill and submit login form."""
        if not self._page:
            return {"success": False, "error": "Browser not started"}

        # Validate credentials dict
        if not credentials:
            return {"success": False, "error": "No credentials provided"}

        username = credentials.get("username") or credentials.get("email") or ""
        password = credentials.get("password") or ""

        if not username or not password:
            return {"success": False, "error": "Missing username/email or password in credentials"}

        try:
            # Find username/email field
            username_selectors = [
                'input[name="username"]',
                'input[name="email"]',
                'input[name="user"]',
                'input[name="login"]',
                'input[type="email"]',
                'input[id*="user"]',
                'input[id*="email"]',
            ]

            username_field = None
            for selector in username_selectors:
                field = await self._page.query_selector(selector)
                if field:
                    username_field = field
                    break

            # Find password field
            password_field = await self._page.query_selector('input[type="password"]')

            if not username_field or not password_field:
                return {"success": False, "error": "Could not find login fields"}

            # Fill credentials
            await username_field.fill(username)
            await password_field.fill(password)

            # Submit form
            submit_button = await self._page.query_selector(
                'button[type="submit"], input[type="submit"], button:has-text("Login"), button:has-text("Sign in")'
            )

            if submit_button:
                await submit_button.click()
                await asyncio.sleep(2)
                return {"success": True, "final_url": self._page.url}
            else:
                # Try pressing Enter
                await password_field.press("Enter")
                await asyncio.sleep(2)
                return {"success": True, "final_url": self._page.url}

        except (TimeoutError, asyncio.TimeoutError) as e:
            return {"success": False, "error": f"Timeout during login: {e}"}
        except (AttributeError, TypeError) as e:
            return {"success": False, "error": f"Element interaction failed: {e}"}

    def _analyze_token_security(
        self,
        tokens: list[dict],
        cookies: list[dict],
    ) -> list[dict]:
        """Analyze token security for vulnerabilities."""
        vulns = []

        # Check for tokens in localStorage (XSS vulnerable)
        for token in tokens:
            if token.get("location") == "localStorage":
                vulns.append({
                    "type": "token_in_localstorage",
                    "severity": "MEDIUM",
                    "description": f"Sensitive token '{token.get('key')}' stored in localStorage (XSS vulnerable)",
                    "cwe": "CWE-922",
                })

        # Check cookie security
        for cookie in cookies:
            name = cookie.get("name", "")
            if any(x in name.lower() for x in ["session", "token", "auth", "jwt"]):
                if not cookie.get("httpOnly"):
                    vulns.append({
                        "type": "cookie_not_httponly",
                        "severity": "MEDIUM",
                        "description": f"Cookie '{name}' lacks HttpOnly flag (XSS vulnerable)",
                        "cwe": "CWE-1004",
                    })

                if not cookie.get("secure"):
                    vulns.append({
                        "type": "cookie_not_secure",
                        "severity": "MEDIUM",
                        "description": f"Cookie '{name}' lacks Secure flag",
                        "cwe": "CWE-614",
                    })

                if cookie.get("sameSite") == "None" or not cookie.get("sameSite"):
                    vulns.append({
                        "type": "cookie_samesite_none",
                        "severity": "LOW",
                        "description": f"Cookie '{name}' has SameSite=None or missing",
                        "cwe": "CWE-1275",
                    })

        return vulns

    # =========================================================================
    # JAVASCRIPT ANALYSIS
    # =========================================================================

    async def analyze_javascript_security(self, url: str) -> dict[str, Any]:
        """
        Analyze JavaScript on a page for security issues.

        Returns:
            Dict with JS security analysis results
        """
        if not self._page:
            raise RuntimeError("Browser not started")

        await self.navigate(url)

        results = {
            "url": url,
            "dangerous_patterns": [],
            "external_scripts": [],
            "inline_scripts": [],
            "event_handlers": [],
            "postmessage_handlers": False,
            "eval_usage": False,
        }

        content = await self.get_page_content()

        # Find dangerous patterns
        for pattern in DANGEROUS_JS_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                results["dangerous_patterns"].append({
                    "pattern": pattern,
                    "count": len(matches),
                })

        # Find external scripts
        scripts = await self._page.query_selector_all("script[src]")
        for script in scripts:
            src = await script.get_attribute("src")
            if src:
                results["external_scripts"].append(src)

        # Find inline scripts
        inline_scripts = await self._page.query_selector_all("script:not([src])")
        results["inline_scripts"] = len(inline_scripts)

        # Check for event handlers in HTML
        event_attrs = ["onclick", "onerror", "onload", "onmouseover", "onfocus", "onblur"]
        for attr in event_attrs:
            elements = await self._page.query_selector_all(f"[{attr}]")
            if elements:
                results["event_handlers"].append({
                    "attribute": attr,
                    "count": len(elements),
                })

        # Check for postMessage handlers
        results["postmessage_handlers"] = "addEventListener" in content and "message" in content

        # Check for eval usage
        results["eval_usage"] = "eval(" in content or "Function(" in content

        return results

    # =========================================================================
    # SPA CRAWLING
    # =========================================================================

    async def crawl_spa(
        self,
        start_url: str,
        max_pages: int = 50,
        wait_time: float = 1.0,
        auth_cookies: Optional[dict[str, str]] = None,
    ) -> list[dict]:
        """
        Crawl a Single Page Application with optional authentication.

        Args:
            start_url: Starting URL
            max_pages: Maximum pages to crawl
            wait_time: Time to wait for dynamic content
            auth_cookies: Optional dict of cookies from AuthContext for authenticated crawling

        Returns:
            List of discovered pages/endpoints
        """
        if not self._page:
            raise RuntimeError("Browser not started")

        # Set auth cookies if provided — enables authenticated SPA crawling
        if auth_cookies:
            from urllib.parse import urlparse
            domain = urlparse(start_url).netloc
            await self.set_auth_cookies(auth_cookies, domain)
            logger.info(f"[HeadlessBrowser] SPA crawl with authenticated session")

        discovered = []
        visited = set()
        queue = [start_url]

        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc

        logger.info(f"[HeadlessBrowser] Starting SPA crawl from {start_url}")

        while queue and len(discovered) < max_pages:
            url = queue.pop(0)

            if url in visited:
                continue

            visited.add(url)

            try:
                await self.navigate(url, wait_until="networkidle")
                await asyncio.sleep(wait_time)

                # Get page info
                page_info = {
                    "url": self._page.url,
                    "title": await self._page.title(),
                    "forms": [],
                    "links": [],
                    "api_calls": [],
                }

                # Find forms
                forms = await self._page.query_selector_all("form")
                for form in forms:
                    action = await form.get_attribute("action") or ""
                    method = await form.get_attribute("method") or "GET"
                    inputs = await form.query_selector_all("input, textarea, select")

                    input_info = []
                    for inp in inputs:
                        name = await inp.get_attribute("name")
                        inp_type = await inp.get_attribute("type")
                        if name:
                            input_info.append({"name": name, "type": inp_type})

                    page_info["forms"].append({
                        "action": action,
                        "method": method,
                        "inputs": input_info,
                    })

                # Find links
                links = await self._page.query_selector_all("a[href]")
                for link in links:
                    href = await link.get_attribute("href")
                    if href and not href.startswith(("#", "javascript:", "mailto:")):
                        # Make absolute URL
                        if href.startswith("/"):
                            href = f"{parsed_start.scheme}://{base_domain}{href}"
                        elif not href.startswith("http"):
                            href = f"{parsed_start.scheme}://{base_domain}/{href}"

                        # Only follow same-domain links
                        if urlparse(href).netloc == base_domain:
                            page_info["links"].append(href)
                            if href not in visited:
                                queue.append(href)

                # Get API calls from network requests
                for req in self._network_requests[-50:]:
                    if "/api" in req["url"] or "graphql" in req["url"].lower():
                        page_info["api_calls"].append({
                            "url": req["url"],
                            "method": req["method"],
                        })

                discovered.append(page_info)

            except Exception as e:
                logger.debug(f"[HeadlessBrowser] Error crawling {url}: {e}")

        logger.info(f"[HeadlessBrowser] SPA crawl complete: {len(discovered)} pages discovered")
        return discovered

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    async def execute_js(self, script: str) -> Any:
        """Execute JavaScript in page context."""
        if not self._page:
            raise RuntimeError("Browser not started")
        return await self._page.evaluate(script)

    async def wait_for_selector(self, selector: str, timeout: int = 30000) -> bool:
        """Wait for a selector to appear."""
        if not self._page:
            return False
        try:
            await self._page.wait_for_selector(selector, timeout=timeout)
            return True
        except Exception:
            return False

    async def fill_form(self, form_data: dict[str, str]) -> None:
        """Fill form fields by name or selector."""
        if not self._page:
            raise RuntimeError("Browser not started")

        for selector, value in form_data.items():
            try:
                # Try by name first
                field = await self._page.query_selector(f'[name="{selector}"]')
                if not field:
                    field = await self._page.query_selector(selector)

                if field:
                    await field.fill(value)
            except Exception as e:
                logger.debug(f"[HeadlessBrowser] Error filling {selector}: {e}")

    def get_console_messages(self) -> list[str]:
        """Get captured console messages."""
        return self._console_messages.copy()

    async def add_cookies(self, cookies: list[dict[str, Any]]) -> None:
        """
        Add cookies to the browser context for authenticated crawling.

        Args:
            cookies: List of cookie dicts with keys: name, value, domain, path, etc.
                     Example: [{"name": "JSESSIONID", "value": "abc123", "domain": "localhost", "path": "/"}]
        """
        if not self._context:
            raise RuntimeError("Browser not started")

        # Playwright requires domain to be set
        for cookie in cookies:
            if "domain" not in cookie:
                # Parse from current page URL if available
                if self._page and self._page.url:
                    from urllib.parse import urlparse
                    cookie["domain"] = urlparse(self._page.url).netloc

        await self._context.add_cookies(cookies)
        logger.debug(f"[HeadlessBrowser] Added {len(cookies)} cookies to context")

    async def set_auth_cookies(self, auth_cookies: dict[str, str], domain: str) -> None:
        """
        Set authentication cookies from an AuthContext.

        Args:
            auth_cookies: Dict of cookie name -> value from AuthContext
            domain: Target domain for cookies
        """
        if not auth_cookies:
            return

        cookies = []
        for name, value in auth_cookies.items():
            cookies.append({
                "name": name,
                "value": value,
                "domain": domain,
                "path": "/",
                "httpOnly": True,
            })

        await self.add_cookies(cookies)
        logger.info(f"[HeadlessBrowser] Set {len(cookies)} auth cookies for {domain}")

    def get_dialogs(self) -> list[str]:
        """Get captured dialogs."""
        return self._dialogs.copy()

    def get_network_requests(self) -> list[dict]:
        """Get captured network requests."""
        return self._network_requests.copy()

    def get_network_responses(self) -> list[dict]:
        """Get captured network responses."""
        return self._network_responses.copy()

    # =========================================================================
    # CAPTCHA & MFA DETECTION
    # =========================================================================

    async def detect_captcha(self) -> dict[str, Any]:
        """
        Detect CAPTCHA on current page.

        Returns:
            Dict with:
                - detected: bool
                - type: str (reCAPTCHA, hCaptcha, Turnstile, etc.)
                - url: str (current page URL)
                - confidence: float (0.0-1.0)
                - indicators: list[str] (matched patterns)
        """
        if not self._page:
            return {"detected": False, "error": "Browser not started"}

        try:
            content = await self._page.content()
            content_lower = content.lower()
            matched_indicators = []

            # Check page content for CAPTCHA indicators
            for indicator in CAPTCHA_INDICATORS:
                if indicator in content_lower:
                    matched_indicators.append(indicator)

            # Check for iframe-based CAPTCHA (reCAPTCHA, hCaptcha, Turnstile)
            frames = self._page.frames
            for frame in frames:
                frame_url = frame.url.lower()
                for indicator in ["recaptcha", "hcaptcha", "turnstile", "funcaptcha", "arkoselabs"]:
                    if indicator in frame_url:
                        matched_indicators.append(f"iframe:{indicator}")

            # Check for CAPTCHA-specific elements
            captcha_selectors = [
                'div.g-recaptcha',
                'div.h-captcha',
                'div.cf-turnstile',
                'iframe[src*="recaptcha"]',
                'iframe[src*="hcaptcha"]',
                'iframe[src*="turnstile"]',
            ]

            for selector in captcha_selectors:
                try:
                    element = await self._page.query_selector(selector)
                    if element:
                        matched_indicators.append(f"selector:{selector}")
                except Exception:
                    pass

            if matched_indicators:
                captcha_type = self._classify_captcha(matched_indicators)
                confidence = min(1.0, len(matched_indicators) * 0.3)

                logger.info(
                    f"[HeadlessBrowser] CAPTCHA detected: {captcha_type} "
                    f"(confidence: {confidence:.0%}, indicators: {len(matched_indicators)})"
                )

                return {
                    "detected": True,
                    "type": captcha_type,
                    "url": self._page.url,
                    "confidence": confidence,
                    "indicators": matched_indicators[:5],  # Limit for brevity
                }

            return {"detected": False, "url": self._page.url}

        except Exception as e:
            logger.debug(f"[HeadlessBrowser] CAPTCHA detection error: {e}")
            return {"detected": False, "error": str(e)}

    async def detect_mfa_challenge(self) -> dict[str, Any]:
        """
        Detect MFA/2FA challenge on current page.

        Returns:
            Dict with:
                - detected: bool
                - type: str (TOTP, SMS, Email, etc.)
                - url: str (current page URL)
                - confidence: float (0.0-1.0)
                - indicators: list[str] (matched patterns)
        """
        if not self._page:
            return {"detected": False, "error": "Browser not started"}

        try:
            content = await self._page.content()
            content_lower = content.lower()
            matched_indicators = []

            # Check page content for MFA indicators
            for indicator in MFA_INDICATORS:
                if indicator in content_lower:
                    matched_indicators.append(indicator)

            # Check for OTP input fields
            otp_selectors = [
                'input[name="otp"]',
                'input[name="code"]',
                'input[name="totp"]',
                'input[name="verification_code"]',
                'input[name="mfa_code"]',
                'input[id*="otp"]',
                'input[id*="code"]',
                'input[type="tel"][maxlength="6"]',
                'input[maxlength="6"][inputmode="numeric"]',
                'input[autocomplete="one-time-code"]',
            ]

            for selector in otp_selectors:
                try:
                    element = await self._page.query_selector(selector)
                    if element:
                        matched_indicators.append(f"input:{selector}")
                except Exception:
                    pass

            # Check for MFA-related buttons/links
            mfa_button_texts = [
                "verify",
                "confirm",
                "submit code",
                "resend code",
                "use backup code",
                "try another way",
            ]

            for text in mfa_button_texts:
                if text in content_lower:
                    matched_indicators.append(f"button:{text}")

            if matched_indicators:
                mfa_type = self._classify_mfa(matched_indicators, content_lower)
                confidence = min(1.0, len(matched_indicators) * 0.25)

                logger.info(
                    f"[HeadlessBrowser] MFA challenge detected: {mfa_type} "
                    f"(confidence: {confidence:.0%}, indicators: {len(matched_indicators)})"
                )

                return {
                    "detected": True,
                    "type": mfa_type,
                    "url": self._page.url,
                    "confidence": confidence,
                    "indicators": matched_indicators[:5],
                }

            return {"detected": False, "url": self._page.url}

        except Exception as e:
            logger.debug(f"[HeadlessBrowser] MFA detection error: {e}")
            return {"detected": False, "error": str(e)}

    def _classify_captcha(self, indicators: list[str]) -> str:
        """Classify CAPTCHA type based on matched indicators."""
        indicators_str = " ".join(indicators).lower()

        if any(x in indicators_str for x in ["recaptcha", "g-recaptcha", "grecaptcha"]):
            return "reCAPTCHA"
        elif any(x in indicators_str for x in ["hcaptcha", "h-captcha"]):
            return "hCaptcha"
        elif any(x in indicators_str for x in ["turnstile", "cf-turnstile"]):
            return "Cloudflare Turnstile"
        elif any(x in indicators_str for x in ["funcaptcha", "arkose"]):
            return "FunCaptcha/Arkose"
        elif "geetest" in indicators_str:
            return "GeeTest"
        else:
            return "Unknown CAPTCHA"

    def _classify_mfa(self, indicators: list[str], content: str) -> str:
        """Classify MFA type based on matched indicators."""
        indicators_str = " ".join(indicators).lower()

        if any(x in indicators_str for x in ["authenticator", "totp", "google authenticator", "authy"]):
            return "TOTP"
        elif any(x in content for x in ["sms", "text message", "phone number"]):
            return "SMS"
        elif any(x in content for x in ["email", "sent to your email", "check your inbox"]):
            return "Email"
        elif any(x in indicators_str for x in ["backup code", "recovery code"]):
            return "Backup Code"
        elif "push" in content and "notification" in content:
            return "Push Notification"
        else:
            return "Unknown 2FA"

    async def wait_for_manual_login(
        self,
        timeout_seconds: int = 300,
        check_interval: float = 1.0,
        success_indicators: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Wait for user to complete manual login (for CAPTCHA/2FA).

        This is used when automatic login cannot proceed due to CAPTCHA or 2FA.
        The browser window should be visible (headless=False) for user interaction.

        Args:
            timeout_seconds: Maximum time to wait for login completion
            check_interval: How often to check for success indicators
            success_indicators: List of text/elements indicating successful login

        Returns:
            Dict with login result, tokens, and cookies
        """
        if not self._page:
            return {"success": False, "error": "Browser not started"}

        default_success_indicators = success_indicators or [
            "logout",
            "sign out",
            "my account",
            "dashboard",
            "welcome",
            "profile",
        ]

        start_time = time.time()
        start_url = self._page.url

        logger.info(
            f"[HeadlessBrowser] Waiting for manual login completion "
            f"(timeout: {timeout_seconds}s, start URL: {start_url})"
        )

        while True:
            elapsed = time.time() - start_time

            if elapsed > timeout_seconds:
                logger.warning("[HeadlessBrowser] Manual login timeout")
                return {
                    "success": False,
                    "error": "timeout",
                    "elapsed": elapsed,
                }

            try:
                current_url = self._page.url
                content = await self._page.content()
                content_lower = content.lower()

                # Check 1: URL changed from login page
                url_changed = current_url != start_url and "/login" not in current_url.lower()

                # Check 2: Success indicators in page
                has_success_indicator = any(
                    ind in content_lower for ind in default_success_indicators
                )

                # Check 3: No longer on login/captcha page
                still_on_challenge = any(
                    x in content_lower
                    for x in ["login", "sign in", "captcha", "verification", "2fa", "mfa"]
                )

                if (url_changed and has_success_indicator) or (url_changed and not still_on_challenge):
                    logger.info("[HeadlessBrowser] Manual login completed successfully")

                    # Extract tokens and cookies
                    tokens = await self._find_tokens_in_page()
                    cookies = await self._context.cookies()
                    local_storage = await self._page.evaluate("() => Object.assign({}, localStorage)")
                    session_storage = await self._page.evaluate("() => Object.assign({}, sessionStorage)")

                    return {
                        "success": True,
                        "elapsed": elapsed,
                        "final_url": current_url,
                        "tokens": tokens,
                        "cookies": [dict(c) for c in cookies],
                        "local_storage": local_storage,
                        "session_storage": session_storage,
                    }

            except Exception as e:
                logger.debug(f"[HeadlessBrowser] Check error: {e}")

            await asyncio.sleep(check_interval)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

@asynccontextmanager
async def create_browser(
    config: Optional[BrowserConfig] = None,
) -> HeadlessBrowserEngine:
    """
    Create a headless browser as async context manager.

    Usage:
        async with create_browser() as browser:
            await browser.navigate("https://example.com")
            results = await browser.test_dom_xss(url)
    """
    browser = HeadlessBrowserEngine(config)
    await browser.start()
    try:
        yield browser
    finally:
        await browser.stop()


async def quick_dom_xss_test(url: str, payloads: list[str] | None = None) -> list[XSSResult]:
    """
    Quick DOM XSS test without managing browser lifecycle.

    Usage:
        results = await quick_dom_xss_test("https://example.com/page#test")
    """
    async with create_browser() as browser:
        return await browser.test_dom_xss(url, payloads)


async def quick_auth_analysis(login_url: str) -> AuthFlowResult:
    """
    Quick authentication flow analysis.

    Usage:
        result = await quick_auth_analysis("https://example.com/login")
    """
    async with create_browser() as browser:
        return await browser.analyze_auth_flow(login_url)


def is_playwright_available() -> bool:
    """Check if Playwright is available."""
    return PLAYWRIGHT_AVAILABLE


# Alias for backwards compatibility
HeadlessBrowser = HeadlessBrowserEngine
