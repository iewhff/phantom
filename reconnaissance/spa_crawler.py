"""
SPA-Aware Crawler - Intelligent endpoint discovery for modern web applications.

Handles:
- Single Page Applications (Angular, React, Vue, etc.)
- Traditional multi-page applications
- API endpoint discovery via common patterns
- JavaScript-rendered content

Falls back gracefully when headless browser is unavailable.
"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

import aiohttp

from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)

# Common API endpoint patterns for web applications
COMMON_API_ENDPOINTS = [
    # REST API patterns
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/rest",
    "/rest/v1",
    "/graphql",
    "/graphql/v1",

    # User/Auth endpoints (common in bug bounties)
    "/api/users",
    "/api/user",
    "/api/auth",
    "/api/login",
    "/api/register",
    "/api/signup",
    "/api/me",
    "/api/profile",
    "/api/account",
    "/api/accounts",
    "/api/sessions",
    "/api/tokens",
    "/api/password",
    "/api/reset",
    "/api/verify",
    "/api/oauth",

    # Data endpoints
    "/api/data",
    "/api/items",
    "/api/products",
    "/api/orders",
    "/api/cart",
    "/api/checkout",
    "/api/payments",
    "/api/transactions",
    "/api/search",
    "/api/query",

    # Admin endpoints (high value)
    "/api/admin",
    "/api/admin/users",
    "/api/admin/settings",
    "/api/config",
    "/api/settings",
    "/api/internal",

    # File/Upload endpoints (potential for vulns)
    "/api/upload",
    "/api/files",
    "/api/images",
    "/api/documents",
    "/api/attachments",
    "/api/media",

    # Common framework patterns
    "/api/v1/users",
    "/api/v1/products",
    "/api/v1/orders",
    "/rest/user",
    "/rest/users",

    # Juice Shop specific (for testing)
    "/rest/user/login",
    "/rest/user/whoami",
    "/rest/products/search",
    "/rest/basket",
    "/rest/captcha",
    "/rest/admin",
    "/api/Users",
    "/api/Products",
    "/api/BasketItems",
    "/api/Feedbacks",
    "/api/Complaints",
    "/api/Recycles",
    "/api/SecurityQuestions",
    "/api/Challenges",
    "/api/Quantitys",

    # Swagger/OpenAPI (for API discovery)
    "/swagger",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger/v1/swagger.json",
    "/api-docs",
    "/api-docs.json",
    "/openapi.json",
    "/openapi.yaml",
    "/docs",
    "/redoc",
]

# Patterns that indicate SPA frameworks
SPA_INDICATORS = {
    "angular": [
        r'ng-app',
        r'ng-controller',
        r'ng-model',
        r'\[\(ngModel\)\]',
        r'angular\.module',
        r'@angular/core',
        r'zone\.js',
    ],
    "react": [
        r'react-dom',
        r'__REACT_DEVTOOLS',
        r'data-reactroot',
        r'_reactRootContainer',
        r'react\.development\.js',
        r'react\.production\.min\.js',
    ],
    "vue": [
        r'vue\.js',
        r'vue\.min\.js',
        r'__VUE__',
        r'v-app',
        r'v-model',
        r'v-bind',
        r'Vue\.component',
    ],
    "svelte": [
        r'svelte',
        r'__svelte',
    ],
    "next": [
        r'__NEXT_DATA__',
        r'_next/static',
        r'next\.js',
    ],
    "nuxt": [
        r'__NUXT__',
        r'nuxt\.js',
    ],
}


class SPAAwareCrawler:
    """
    Intelligent crawler that handles both SPAs and traditional web apps.

    Features:
    - Auto-detects SPA frameworks
    - Uses headless browser for SPAs when available
    - Falls back to API endpoint probing
    - Discovers hidden endpoints via common patterns
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.user_agent = settings.reconnaissance.crawler.user_agent
        self._headless_available = False
        self._check_headless()

    def _check_headless(self) -> None:
        """Check if headless browser is available."""
        try:
            from utils.headless_browser import HeadlessBrowser, PLAYWRIGHT_AVAILABLE
            self._headless_available = PLAYWRIGHT_AVAILABLE
            if PLAYWRIGHT_AVAILABLE:
                logger.info("Headless browser available for SPA crawling")
        except ImportError:
            self._headless_available = False

    async def crawl(
        self,
        target: str,
        max_depth: int = 5,
        max_pages: int = 200,
        probe_api: bool = True,
    ) -> dict[str, Any]:
        """
        Crawl target with SPA awareness.

        Args:
            target: Target URL
            max_depth: Max crawl depth
            max_pages: Max pages to discover
            probe_api: Whether to probe common API endpoints

        Returns:
            Dict with discovered URLs, endpoints, forms, etc.
        """
        start_url = target if target.startswith(('http://', 'https://')) else f"https://{target}"

        result = {
            "urls": [],
            "api_endpoints": [],
            "forms": [],
            "js_files": [],
            "parameters": set(),
            "is_spa": False,
            "spa_framework": None,
            "technologies": [],
        }

        logger.info(f"Starting SPA-aware crawl of {start_url}")

        # Step 1: Fetch main page and detect SPA
        spa_info = await self._detect_spa(start_url)
        result["is_spa"] = spa_info["is_spa"]
        result["spa_framework"] = spa_info["framework"]

        if spa_info["is_spa"]:
            logger.info(f"SPA detected: {spa_info['framework']} - using enhanced discovery")
            result["technologies"].append(spa_info["framework"])

        # Step 2: Choose crawling strategy
        if spa_info["is_spa"] and self._headless_available:
            # Use headless browser for SPA
            spa_urls = await self._crawl_with_headless(start_url, max_pages)
            result["urls"].extend(spa_urls)
        else:
            # Use basic crawler
            basic_urls = await self._crawl_basic(start_url, max_depth, max_pages)
            result["urls"].extend(basic_urls)

        # Step 3: Probe common API endpoints
        if probe_api:
            api_endpoints = await self._probe_api_endpoints(start_url)
            result["api_endpoints"].extend(api_endpoints)
            # Add API endpoints to URLs for scanning
            result["urls"].extend(api_endpoints)

        # Step 4: Extract parameters from discovered URLs
        for url in result["urls"]:
            params = self._extract_parameters(url)
            result["parameters"].update(params)

        result["parameters"] = list(result["parameters"])

        # Deduplicate URLs
        result["urls"] = list(set(result["urls"]))
        result["api_endpoints"] = list(set(result["api_endpoints"]))

        logger.info(
            f"SPA-aware crawl complete: {len(result['urls'])} URLs, "
            f"{len(result['api_endpoints'])} API endpoints, "
            f"{len(result['parameters'])} parameters"
        )

        return result

    async def _detect_spa(self, url: str) -> dict[str, Any]:
        """Detect if target is a SPA and identify framework."""
        result = {"is_spa": False, "framework": None, "content": ""}

        try:
            timeout = aiohttp.ClientTimeout(total=15)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {"User-Agent": self.user_agent}
                async with session.get(url, headers=headers, ssl=False) as resp:
                    content = await resp.text()
                    result["content"] = content

                    # Check for SPA indicators
                    for framework, patterns in SPA_INDICATORS.items():
                        for pattern in patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                result["is_spa"] = True
                                result["framework"] = framework
                                return result

                    # Check for minimal HTML (common in SPAs)
                    # SPAs often have very little initial HTML
                    body_content = re.search(r'<body[^>]*>(.*?)</body>', content, re.DOTALL)
                    if body_content:
                        body_text = body_content.group(1)
                        # Strip script/style tags
                        body_text = re.sub(r'<script[^>]*>.*?</script>', '', body_text, flags=re.DOTALL)
                        body_text = re.sub(r'<style[^>]*>.*?</style>', '', body_text, flags=re.DOTALL)
                        body_text = re.sub(r'<[^>]+>', '', body_text)

                        # If body has very little text, likely SPA
                        if len(body_text.strip()) < 100:
                            result["is_spa"] = True
                            result["framework"] = "unknown_spa"

        except Exception as e:
            logger.warning(f"SPA detection failed: {e}")

        return result

    async def _crawl_with_headless(self, url: str, max_pages: int) -> list[str]:
        """Crawl using headless browser for JavaScript rendering."""
        urls = []

        try:
            from utils.headless_browser import HeadlessBrowser

            async with HeadlessBrowser() as browser:
                spa_results = await browser.crawl_spa(url, max_pages=max_pages)

                for page_info in spa_results:
                    if isinstance(page_info, dict):
                        urls.append(page_info.get("url", ""))
                        # Extract links from page
                        urls.extend(page_info.get("links", []))
                    elif isinstance(page_info, str):
                        urls.append(page_info)

        except Exception as e:
            logger.warning(f"Headless crawling failed: {e}, falling back to basic crawler")
            urls = await self._crawl_basic(url, max_depth=3, max_pages=max_pages)

        return urls

    async def _crawl_basic(self, url: str, max_depth: int, max_pages: int) -> list[str]:
        """Basic HTML crawler fallback."""
        try:
            from reconnaissance.crawler import WebCrawler
            crawler = WebCrawler(self.settings)
            return await crawler.crawl(url, max_depth=max_depth, max_pages=max_pages)
        except Exception as e:
            logger.warning(f"Basic crawling failed: {e}")
            return [url]

    async def _probe_api_endpoints(self, base_url: str) -> list[str]:
        """Probe common API endpoints to discover hidden APIs."""
        discovered = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        logger.info(f"Probing {len(COMMON_API_ENDPOINTS)} common API endpoints...")

        timeout = aiohttp.ClientTimeout(total=5)
        connector = aiohttp.TCPConnector(limit=20, ssl=False)

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            # Process in batches
            batch_size = 20
            for i in range(0, len(COMMON_API_ENDPOINTS), batch_size):
                batch = COMMON_API_ENDPOINTS[i:i + batch_size]
                tasks = [self._check_endpoint(session, base, endpoint) for endpoint in batch]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for j, result in enumerate(results):
                    if result and not isinstance(result, Exception):
                        full_url = urljoin(base, batch[j])
                        discovered.append(full_url)

                # Small delay between batches
                await asyncio.sleep(0.1)

        logger.info(f"API probing found {len(discovered)} endpoints")
        return discovered

    async def _check_endpoint(
        self,
        session: aiohttp.ClientSession,
        base: str,
        endpoint: str,
    ) -> bool:
        """Check if an API endpoint exists."""
        url = urljoin(base, endpoint)

        try:
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "application/json, text/plain, */*",
            }

            async with session.get(url, headers=headers, allow_redirects=False) as resp:
                # Consider endpoint valid if:
                # - 200 OK
                # - 401/403 (exists but needs auth)
                # - 405 (method not allowed but endpoint exists)
                if resp.status in (200, 201, 401, 403, 405):
                    return True

                # Also check for JSON response (API indicator)
                content_type = resp.headers.get("Content-Type", "")
                if "application/json" in content_type:
                    return True

        except Exception:
            pass

        return False

    def _extract_parameters(self, url: str) -> set[str]:
        """Extract parameter names from URL."""
        params = set()
        parsed = urlparse(url)

        if parsed.query:
            # Extract parameter names from query string
            for param in parsed.query.split("&"):
                if "=" in param:
                    name = param.split("=")[0]
                    params.add(name)

        # Also extract path parameters (e.g., /api/users/123)
        path_parts = parsed.path.split("/")
        for i, part in enumerate(path_parts):
            # Check if part looks like an ID
            if part.isdigit() or (len(part) > 20 and all(c.isalnum() or c in '-_' for c in part)):
                # The previous part is likely the resource name
                if i > 0 and path_parts[i-1]:
                    params.add(f"path:{path_parts[i-1]}_id")

        return params


async def crawl_with_spa_support(settings: Settings, target: str) -> dict[str, Any]:
    """
    Convenience function to crawl a target with SPA support.

    Args:
        settings: Application settings
        target: Target URL

    Returns:
        Crawl results dict
    """
    crawler = SPAAwareCrawler(settings)
    return await crawler.crawl(target)
