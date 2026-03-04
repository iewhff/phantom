"""
Authenticated Crawling Module.

Re-crawls target with authentication to discover protected endpoints.
Essential for SPAs and apps where most content is behind authentication.

Uses SPAAwareCrawler with auth cookies for JavaScript SPA support.
Falls back to basic HTML crawling if SPA crawler unavailable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol
from urllib.parse import urljoin, urlparse

from utils.logger import get_logger

logger = get_logger(__name__)


class AuthContextProtocol(Protocol):
    """Protocol for auth context objects."""

    @property
    def has_auth(self) -> bool:
        ...

    @property
    def cookies(self) -> Optional[dict[str, str]]:
        ...

    @property
    def auth_headers(self) -> dict[str, str]:
        ...

    @property
    def session_cookie(self) -> Optional[str]:
        ...


class SettingsProtocol(Protocol):
    """Protocol for settings objects."""

    pass  # SPA crawler uses settings, but structure varies


@dataclass
class CrawlConfig:
    """Configuration for authenticated crawling."""

    max_depth: int = 3
    max_pages: int = 50
    timeout: float = 10.0
    request_timeout: float = 5.0
    probe_api: bool = True
    user_agent: str = "PenTestAI-Crawler/1.0"


@dataclass
class CrawlResult:
    """Result of authenticated crawling."""

    endpoints: list[str] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    spa_crawler_used: bool = False
    error: Optional[str] = None


class AuthenticatedCrawler:
    """
    Crawler that uses authentication to discover protected endpoints.

    Strategies:
    1. SPA-aware crawler with authentication (handles JavaScript SPAs)
    2. Basic HTML crawling with auth headers (fallback)
    """

    def __init__(
        self,
        auth_context: AuthContextProtocol,
        settings: Optional[SettingsProtocol] = None,
        config: Optional[CrawlConfig] = None,
    ):
        self.auth_context = auth_context
        self.settings = settings
        self.config = config or CrawlConfig()
        self._discovered_forms: list[dict[str, Any]] = []

    async def crawl(self, target: str) -> CrawlResult:
        """
        Crawl target with authentication.

        Args:
            target: Target URL to crawl

        Returns:
            CrawlResult with discovered endpoints and forms
        """
        if not self.auth_context or not self.auth_context.has_auth:
            return CrawlResult(error="No authentication context available")

        result = CrawlResult()

        # Strategy 1: Try SPA-aware crawler
        spa_result = await self._try_spa_crawl(target)
        if spa_result.endpoints:
            return spa_result

        # Strategy 2: Fall back to basic HTML crawling
        return await self._basic_html_crawl(target)

    async def _try_spa_crawl(self, target: str) -> CrawlResult:
        """Try SPA-aware crawling with authentication."""
        result = CrawlResult()

        try:
            from reconnaissance.spa_crawler import SPAAwareCrawler

            logger.debug("[AUTH-CRAWL] Using SPA-aware crawler with authentication")
            spa_crawler = SPAAwareCrawler(self.settings)
            spa_result = await spa_crawler.crawl(
                target,
                max_depth=self.config.max_depth,
                max_pages=self.config.max_pages,
                probe_api=self.config.probe_api,
                auth_cookies=self.auth_context.cookies,
                auth_headers=self.auth_context.auth_headers,
            )

            # Collect discovered URLs and API endpoints
            result.endpoints.extend(spa_result.get("urls", []))
            result.api_endpoints.extend(spa_result.get("api_endpoints", []))

            # Process and validate forms
            result.forms = self._process_forms(spa_result.get("forms", []), target)
            result.spa_crawler_used = True

            if result.endpoints:
                logger.info(
                    f"[AUTH-CRAWL] SPA crawler discovered {len(result.endpoints)} endpoints"
                )

        except Exception as e:
            logger.debug(f"[AUTH-CRAWL] SPA crawler failed: {e}, falling back to basic crawl")
            result.error = str(e)

        return result

    def _process_forms(
        self, forms: list[dict[str, Any]], target: str
    ) -> list[dict[str, Any]]:
        """
        Process and validate forms for injection testing.

        Validates form structure before passing to injection scanners.
        """
        valid_forms: list[dict[str, Any]] = []
        invalid_count = 0

        for form in forms:
            # Validate form has required fields
            if not isinstance(form, dict):
                invalid_count += 1
                continue
            if not form.get("action"):
                invalid_count += 1
                continue

            # Validate inputs exist and are well-formed
            inputs = form.get("inputs", [])
            if not isinstance(inputs, list):
                # Try to extract inputs if they're in a different format
                inputs = form.get("fields", []) or form.get("parameters", []) or []

            # Filter malformed inputs
            valid_inputs: list[dict[str, Any]] = []
            for inp in inputs:
                if isinstance(inp, dict) and inp.get("name"):
                    valid_inputs.append(inp)
                elif isinstance(inp, str):
                    # Convert string to dict format
                    valid_inputs.append({"name": inp, "type": "text"})

            # Only add form if it has at least one valid input
            if not valid_inputs:
                # Allow forms without inputs only if method is GET
                if form.get("method", "GET").upper() != "GET":
                    invalid_count += 1
                    continue

            # Build validated form
            form_copy = dict(form)
            form_copy["action"] = urljoin(target, form["action"])
            form_copy["inputs"] = valid_inputs
            valid_forms.append(form_copy)

        if invalid_count > 0:
            logger.debug(f"[AUTH-CRAWL] Filtered {invalid_count} malformed forms")
        if valid_forms:
            logger.info(
                f"[AUTH-CRAWL] Discovered {len(valid_forms)} valid forms for injection testing"
            )

        return valid_forms

    async def _basic_html_crawl(self, target: str) -> CrawlResult:
        """Fall back to basic HTML crawling with auth headers."""
        import httpx

        result = CrawlResult()
        visited: set[str] = set()
        to_visit: set[str] = set()

        # Parse target
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        app_base = parsed.path.rstrip("/") or ""

        # Start from target and common authenticated entry points
        to_visit.add(target)
        if app_base:
            to_visit.add(f"{base_url}{app_base}/")
            # Common authenticated pages
            for page in [
                "/home",
                "/dashboard",
                "/welcome",
                "/start",
                "/main",
                "/lessons",
                "/lesson",
                "/attack",
            ]:
                to_visit.add(f"{base_url}{app_base}{page}")

        # Build headers with auth
        headers = {
            "User-Agent": self.config.user_agent,
            **self.auth_context.auth_headers,
        }

        try:
            async with httpx.AsyncClient(
                timeout=self.config.timeout,
                follow_redirects=True,
                verify=False,
                headers=headers,
            ) as client:
                for depth in range(self.config.max_depth):
                    if not to_visit:
                        break

                    current_level = list(to_visit - visited)[: self.config.max_pages]
                    to_visit = set()

                    for url in current_level:
                        if url in visited:
                            continue
                        visited.add(url)

                        try:
                            resp = await client.get(
                                url, timeout=self.config.request_timeout
                            )

                            # Skip non-200 responses
                            if resp.status_code != 200:
                                continue

                            # Skip if redirected to login (session expired)
                            if "/login" in str(resp.url).lower():
                                continue

                            result.endpoints.append(url)

                            # Extract links
                            links = re.findall(r'href=["\']([^"\']+)["\']', resp.text)
                            links += re.findall(
                                r'action=["\']([^"\']+)["\']', resp.text
                            )

                            for link in links:
                                processed = self._process_link(link, url, parsed)
                                if processed:
                                    result.endpoints.append(processed)
                                    # Add to visit queue for next depth
                                    if depth < self.config.max_depth - 1 and "?" not in processed:
                                        to_visit.add(processed)

                        except Exception:
                            continue

        except Exception as e:
            logger.debug(f"[AUTH-CRAWL] Error: {e}")
            result.error = str(e)

        # Deduplicate endpoints
        result.endpoints = list(set(result.endpoints))
        return result

    def _process_link(
        self, link: str, current_url: str, parsed_target: Any
    ) -> Optional[str]:
        """Process and validate a discovered link."""
        # Skip anchors, javascript, mailto
        if link.startswith(("#", "javascript:", "mailto:")):
            return None

        # Handle external links
        if link.startswith(("http://", "https://")):
            if parsed_target.netloc not in link:
                return None
            return link

        # Resolve relative URLs
        resolved = urljoin(current_url, link)

        # Same domain check
        if parsed_target.netloc not in resolved:
            return None

        return resolved


async def authenticated_crawl(
    target: str,
    auth_context: AuthContextProtocol,
    settings: Optional[SettingsProtocol] = None,
    config: Optional[CrawlConfig] = None,
) -> CrawlResult:
    """
    Convenience function for authenticated crawling.

    Args:
        target: Target URL to crawl
        auth_context: Authentication context with cookies/headers
        settings: Optional settings for SPA crawler
        config: Optional crawl configuration

    Returns:
        CrawlResult with discovered endpoints and forms
    """
    crawler = AuthenticatedCrawler(auth_context, settings, config)
    return await crawler.crawl(target)
