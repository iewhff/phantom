"""
Authenticated Crawler - Discover pages behind authentication.

PROBLEM: Regular crawler only finds public pages. Authenticated content
(where vulns typically hide) is never discovered.

SOLUTION: Crawler that:
1. Uses session cookies/tokens for all requests
2. Follows links in authenticated responses
3. Extracts forms with their full context
4. Discovers API endpoints from JavaScript
5. Handles SPA routing

Author: PHANTOM AI
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import re
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque
import hashlib
import time

logger = logging.getLogger(__name__)


@dataclass
class CrawlResult:
    """Result of crawling a single page."""
    url: str
    status_code: int
    content_type: str
    content_length: int
    title: Optional[str] = None
    links: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    requires_auth: bool = False
    content_hash: str = ""
    crawl_time_ms: float = 0.0


@dataclass
class CrawlSummary:
    """Summary of crawl operation."""
    total_urls_discovered: int = 0
    total_urls_crawled: int = 0
    total_urls_skipped: int = 0
    total_forms_found: int = 0
    total_api_endpoints: int = 0
    total_parameters: int = 0
    auth_required_pages: int = 0
    unique_paths: int = 0
    by_content_type: Dict[str, int] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_urls_discovered": self.total_urls_discovered,
            "total_urls_crawled": self.total_urls_crawled,
            "total_urls_skipped": self.total_urls_skipped,
            "total_forms_found": self.total_forms_found,
            "total_api_endpoints": self.total_api_endpoints,
            "total_parameters": self.total_parameters,
            "auth_required_pages": self.auth_required_pages,
            "unique_paths": self.unique_paths,
            "by_content_type": self.by_content_type,
            "error_count": len(self.errors),
            "duration_seconds": self.duration_seconds,
        }


class AuthenticatedCrawler:
    """
    Crawler that uses authentication to discover protected pages.

    Features:
    - Uses session cookies/tokens for all requests
    - Follows links in authenticated responses
    - Extracts forms with hidden fields
    - Discovers API endpoints from JavaScript
    - Handles SPA navigation
    - Respects rate limits
    - Tracks auth state
    """

    # Skip these file extensions
    SKIP_EXTENSIONS = {
        '.css', '.js', '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.mp3', '.mp4', '.webm',
        '.pdf', '.zip', '.tar', '.gz', '.rar',
    }

    # Skip these path patterns
    SKIP_PATTERNS = [
        r'/static/', r'/assets/', r'/images/', r'/img/', r'/css/', r'/js/',
        r'/fonts/', r'/media/', r'/_next/', r'/__webpack/',
        r'\.map$', r'\.min\.', r'/node_modules/',
    ]

    # Auth failure indicators
    AUTH_FAILURE_INDICATORS = [
        'login', 'signin', 'sign-in', 'authenticate',
        'unauthorized', 'forbidden', 'access denied',
        'session expired', 'please log in',
    ]

    # API endpoint patterns in JS
    JS_API_PATTERNS = [
        r'["\']/(api|v\d+)/[^"\']+["\']',
        r'fetch\s*\(["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        r'url:\s*["\']([^"\']+)["\']',
        r'\$\.(get|post|ajax)\(["\']([^"\']+)["\']',
    ]

    def __init__(
        self,
        http_client: Any,
        auth_context: Optional[Any] = None,
        max_pages: int = 500,
        max_depth: int = 10,
        rate_limit_rps: float = 10.0,
        timeout_seconds: float = 15.0,
        respect_robots: bool = True,
        follow_external: bool = False,
    ):
        """
        Initialize authenticated crawler.

        Args:
            http_client: HTTP client for making requests
            auth_context: Authentication context with cookies/tokens
            max_pages: Maximum pages to crawl
            max_depth: Maximum crawl depth
            rate_limit_rps: Requests per second limit
            timeout_seconds: Request timeout
            respect_robots: Respect robots.txt
            follow_external: Follow links to external domains
        """
        self._client = http_client
        self._auth = auth_context
        self._max_pages = max_pages
        self._max_depth = max_depth
        self._rate_limit = rate_limit_rps
        self._timeout = timeout_seconds
        self._respect_robots = respect_robots
        self._follow_external = follow_external

        # State
        self._visited: Set[str] = set()
        self._queued: Set[str] = set()
        self._results: Dict[str, CrawlResult] = {}
        self._base_domain: str = ""
        self._last_request_time: float = 0.0
        self._disallowed_paths: Set[str] = set()

        # Summary
        self._summary = CrawlSummary()

    async def crawl(self, start_url: str) -> Tuple[Dict[str, CrawlResult], CrawlSummary]:
        """
        Start crawling from the given URL.

        Returns:
            Tuple of (results dict, summary)
        """
        start_time = time.time()

        # Parse base domain
        parsed = urlparse(start_url)
        self._base_domain = parsed.netloc

        # Fetch robots.txt if respecting it
        if self._respect_robots:
            await self._fetch_robots(f"{parsed.scheme}://{parsed.netloc}/robots.txt")

        # BFS crawl
        queue: deque = deque([(start_url, 0)])  # (url, depth)
        self._queued.add(start_url)

        logger.info(f"[AuthCrawler] Starting crawl from {start_url}")

        while queue and len(self._visited) < self._max_pages:
            url, depth = queue.popleft()

            if depth > self._max_depth:
                continue

            if url in self._visited:
                continue

            # Check if URL should be skipped
            if self._should_skip(url):
                self._summary.total_urls_skipped += 1
                continue

            # Rate limiting
            await self._rate_limit_wait()

            # Crawl the page
            result = await self._crawl_page(url)

            if result:
                self._visited.add(url)
                self._results[url] = result
                self._summary.total_urls_crawled += 1

                # Update content type stats
                ct = result.content_type.split(';')[0].strip()
                self._summary.by_content_type[ct] = self._summary.by_content_type.get(ct, 0) + 1

                # Track auth-required pages
                if result.requires_auth:
                    self._summary.auth_required_pages += 1

                # Count forms and parameters
                self._summary.total_forms_found += len(result.forms)
                self._summary.total_parameters += len(result.parameters)
                self._summary.total_api_endpoints += len(result.api_endpoints)

                # Add discovered links to queue
                for link in result.links:
                    if link not in self._visited and link not in self._queued:
                        queue.append((link, depth + 1))
                        self._queued.add(link)
                        self._summary.total_urls_discovered += 1

                # Add API endpoints to queue
                for api_url in result.api_endpoints:
                    if api_url not in self._visited and api_url not in self._queued:
                        queue.append((api_url, depth + 1))
                        self._queued.add(api_url)
                        self._summary.total_urls_discovered += 1

        # Calculate unique paths
        unique_paths = {urlparse(url).path for url in self._visited}
        self._summary.unique_paths = len(unique_paths)

        self._summary.duration_seconds = time.time() - start_time

        logger.info(
            f"[AuthCrawler] Crawl complete: {self._summary.total_urls_crawled} pages, "
            f"{self._summary.total_forms_found} forms, {self._summary.total_api_endpoints} API endpoints"
        )

        return self._results, self._summary

    async def _crawl_page(self, url: str) -> Optional[CrawlResult]:
        """Crawl a single page."""
        start_time = time.time()

        try:
            # Build headers with auth
            headers = self._get_auth_headers()

            # Make request
            response = await self._client.get(
                url,
                headers=headers,
                cookies=self._get_auth_cookies(),
                timeout=self._timeout,
                follow_redirects=True,
            )

            status_code = getattr(response, 'status_code', getattr(response, 'status', 0))
            content_type = response.headers.get('content-type', 'text/html')

            # Get response text
            if hasattr(response, 'text'):
                if asyncio.iscoroutine(response.text):
                    content = await response.text
                elif callable(response.text):
                    content = response.text()
                else:
                    content = response.text
            else:
                content = ""

            # Check for auth failure
            requires_auth = self._check_auth_failure(status_code, content)

            # Parse the page
            result = CrawlResult(
                url=url,
                status_code=status_code,
                content_type=content_type,
                content_length=len(content),
                title=self._extract_title(content),
                requires_auth=requires_auth,
                content_hash=hashlib.md5(content.encode()[:1024]).hexdigest(),
                crawl_time_ms=(time.time() - start_time) * 1000,
            )

            # Only parse HTML content
            if 'html' in content_type.lower():
                result.links = self._extract_links(content, url)
                result.forms = self._extract_forms(content, url)
                result.scripts = self._extract_scripts(content)
                result.parameters = self._extract_parameters(content, url)

                # Extract API endpoints from inline scripts
                for script in result.scripts:
                    if script.startswith('http'):
                        # External script - skip for now
                        continue
                    # Inline script content
                    result.api_endpoints.extend(
                        self._extract_api_endpoints(script, url)
                    )

            # For JSON responses, extract structure
            elif 'json' in content_type.lower():
                result.parameters = self._extract_json_params(content, url)

            return result

        except asyncio.TimeoutError:
            logger.debug(f"[AuthCrawler] Timeout: {url}")
            self._summary.errors.append({"url": url, "error": "timeout"})
        except Exception as e:
            logger.debug(f"[AuthCrawler] Error crawling {url}: {e}")
            self._summary.errors.append({"url": url, "error": str(e)})

        return None

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        if self._auth:
            if hasattr(self._auth, 'get_headers'):
                auth_headers = self._auth.get_headers()
                if auth_headers:
                    headers.update(auth_headers)
            elif hasattr(self._auth, 'auth_headers'):
                auth_headers = self._auth.auth_headers
                if auth_headers:
                    headers.update(auth_headers)
            elif hasattr(self._auth, 'token') and self._auth.token:
                headers["Authorization"] = f"Bearer {self._auth.token}"

        return headers

    def _get_auth_cookies(self) -> Dict[str, str]:
        """Get authentication cookies."""
        if self._auth and hasattr(self._auth, 'cookies'):
            return self._auth.cookies or {}
        return {}

    def _should_skip(self, url: str) -> bool:
        """Check if URL should be skipped."""
        parsed = urlparse(url)

        # Check domain
        if not self._follow_external and parsed.netloc != self._base_domain:
            return True

        # Check extension
        path_lower = parsed.path.lower()
        for ext in self.SKIP_EXTENSIONS:
            if path_lower.endswith(ext):
                return True

        # Check patterns
        for pattern in self.SKIP_PATTERNS:
            if re.search(pattern, url, re.I):
                return True

        # Check robots.txt disallowed
        if parsed.path in self._disallowed_paths:
            return True

        return False

    def _check_auth_failure(self, status_code: int, content: str) -> bool:
        """Check if response indicates auth failure."""
        if status_code in (401, 403):
            return True

        content_lower = content.lower()
        for indicator in self.AUTH_FAILURE_INDICATORS:
            if indicator in content_lower:
                return True

        return False

    def _extract_title(self, html: str) -> Optional[str]:
        """Extract page title."""
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.I)
        return match.group(1).strip() if match else None

    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML."""
        links = []
        seen = set()

        # <a href="...">
        for match in re.finditer(r'<a[^>]+href=["\']([^"\'#]+)["\']', html, re.I):
            href = match.group(1)
            full_url = self._resolve_url(base_url, href)
            if full_url and full_url not in seen:
                links.append(full_url)
                seen.add(full_url)

        # <form action="...">
        for match in re.finditer(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.I):
            action = match.group(1)
            full_url = self._resolve_url(base_url, action)
            if full_url and full_url not in seen:
                links.append(full_url)
                seen.add(full_url)

        # <link href="..."> (for API discovery)
        for match in re.finditer(r'<link[^>]+href=["\']([^"\']+)["\']', html, re.I):
            href = match.group(1)
            if 'api' in href.lower() or href.endswith('.json'):
                full_url = self._resolve_url(base_url, href)
                if full_url and full_url not in seen:
                    links.append(full_url)
                    seen.add(full_url)

        return links

    def _extract_forms(self, html: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract all forms with their fields."""
        forms = []

        for form_match in re.finditer(r'<form([^>]*)>(.*?)</form>', html, re.I | re.S):
            form_attrs = form_match.group(1)
            form_content = form_match.group(2)

            # Extract form attributes
            action = self._extract_attr(form_attrs, 'action') or base_url
            method = self._extract_attr(form_attrs, 'method') or 'GET'
            enctype = self._extract_attr(form_attrs, 'enctype') or 'application/x-www-form-urlencoded'

            form = {
                "action": self._resolve_url(base_url, action),
                "method": method.upper(),
                "enctype": enctype,
                "fields": [],
            }

            # Extract input fields
            for input_match in re.finditer(r'<input([^>]*)/?>', form_content, re.I):
                attrs = input_match.group(1)
                name = self._extract_attr(attrs, 'name')
                if name:
                    field = {
                        "name": name,
                        "type": self._extract_attr(attrs, 'type') or 'text',
                        "value": self._extract_attr(attrs, 'value'),
                        "required": 'required' in attrs.lower(),
                    }
                    form["fields"].append(field)

            # Extract select fields
            for select_match in re.finditer(r'<select([^>]*)>(.*?)</select>', form_content, re.I | re.S):
                attrs = select_match.group(1)
                name = self._extract_attr(attrs, 'name')
                if name:
                    # Get options
                    options = re.findall(r'<option[^>]*value=["\']([^"\']*)["\']', select_match.group(2))
                    form["fields"].append({
                        "name": name,
                        "type": "select",
                        "options": options,
                        "value": options[0] if options else None,
                    })

            # Extract textarea fields
            for textarea_match in re.finditer(r'<textarea([^>]*)>(.*?)</textarea>', form_content, re.I | re.S):
                attrs = textarea_match.group(1)
                name = self._extract_attr(attrs, 'name')
                if name:
                    form["fields"].append({
                        "name": name,
                        "type": "textarea",
                        "value": textarea_match.group(2).strip(),
                    })

            forms.append(form)

        return forms

    def _extract_scripts(self, html: str) -> List[str]:
        """Extract script content (inline and URLs)."""
        scripts = []

        # Inline scripts
        for match in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.I | re.S):
            content = match.group(1).strip()
            if content and len(content) > 10:
                scripts.append(content)

        # External script URLs
        for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
            scripts.append(match.group(1))

        return scripts

    def _extract_parameters(self, html: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract all parameters from the page."""
        params = []
        seen = set()

        # From forms
        for form in self._extract_forms(html, base_url):
            for field in form.get("fields", []):
                name = field.get("name")
                if name and name not in seen:
                    params.append({
                        "name": name,
                        "source": "form",
                        "type": field.get("type"),
                        "endpoint": form.get("action"),
                        "method": form.get("method"),
                    })
                    seen.add(name)

        # From URL query strings in links
        for link in self._extract_links(html, base_url):
            parsed = urlparse(link)
            query_params = parse_qs(parsed.query)
            for name in query_params:
                if name not in seen:
                    params.append({
                        "name": name,
                        "source": "url",
                        "endpoint": link.split('?')[0],
                        "method": "GET",
                    })
                    seen.add(name)

        return params

    def _extract_api_endpoints(self, js_content: str, base_url: str) -> List[str]:
        """Extract API endpoints from JavaScript."""
        endpoints = []
        seen = set()

        for pattern in self.JS_API_PATTERNS:
            for match in re.finditer(pattern, js_content, re.I):
                # Get the captured group
                url = match.group(1) if match.lastindex else match.group(0)
                url = url.strip('"\'')

                # Skip if not a path
                if not url.startswith('/') and not url.startswith('http'):
                    continue

                full_url = self._resolve_url(base_url, url)
                if full_url and full_url not in seen:
                    endpoints.append(full_url)
                    seen.add(full_url)

        return endpoints

    def _extract_json_params(self, json_content: str, url: str) -> List[Dict[str, Any]]:
        """Extract parameter names from JSON response."""
        import json as json_module
        params = []

        try:
            data = json_module.loads(json_content)
            params.extend(self._extract_json_keys(data, url))
        except json_module.JSONDecodeError:
            pass

        return params

    def _extract_json_keys(self, data: Any, url: str, prefix: str = "") -> List[Dict[str, Any]]:
        """Recursively extract keys from JSON."""
        params = []

        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                params.append({
                    "name": full_key,
                    "source": "json",
                    "endpoint": url,
                    "method": "POST",
                })
                if isinstance(value, (dict, list)):
                    params.extend(self._extract_json_keys(value, url, full_key))
        elif isinstance(data, list) and data:
            params.extend(self._extract_json_keys(data[0], url, f"{prefix}[0]"))

        return params

    def _extract_attr(self, attrs: str, name: str) -> Optional[str]:
        """Extract attribute value from attribute string."""
        match = re.search(rf'{name}\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
        return match.group(1) if match else None

    def _resolve_url(self, base: str, url: str) -> Optional[str]:
        """Resolve URL against base."""
        if not url:
            return None

        # Skip javascript:, mailto:, etc.
        if ':' in url and not url.startswith('http'):
            if not url.startswith('/'):
                return None

        try:
            resolved = urljoin(base, url)

            # Filter out non-HTTP
            if not resolved.startswith('http'):
                return None

            return resolved
        except Exception:
            return None

    async def _rate_limit_wait(self) -> None:
        """Wait for rate limiting."""
        if self._rate_limit <= 0:
            return

        min_interval = 1.0 / self._rate_limit
        elapsed = time.time() - self._last_request_time

        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)

        self._last_request_time = time.time()

    async def _fetch_robots(self, robots_url: str) -> None:
        """Fetch and parse robots.txt."""
        try:
            response = await self._client.get(robots_url, timeout=5.0)
            if response.status_code == 200:
                content = response.text if hasattr(response, 'text') else ""
                if asyncio.iscoroutine(content):
                    content = await content

                for line in content.split('\n'):
                    line = line.strip()
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path:
                            self._disallowed_paths.add(path)

                logger.debug(f"[AuthCrawler] Loaded {len(self._disallowed_paths)} disallowed paths from robots.txt")
        except Exception as e:
            logger.debug(f"[AuthCrawler] Could not fetch robots.txt: {e}")

    def get_all_endpoints(self) -> List[str]:
        """Get all discovered endpoints."""
        endpoints = set()
        for url in self._visited:
            endpoints.add(url)
        for result in self._results.values():
            for api in result.api_endpoints:
                endpoints.add(api)
            for form in result.forms:
                if form.get("action"):
                    endpoints.add(form["action"])
        return sorted(endpoints)

    def get_all_forms(self) -> List[Dict[str, Any]]:
        """Get all discovered forms."""
        forms = []
        for result in self._results.values():
            forms.extend(result.forms)
        return forms

    def get_all_parameters(self) -> List[Dict[str, Any]]:
        """Get all discovered parameters."""
        params = []
        seen = set()
        for result in self._results.values():
            for param in result.parameters:
                key = (param.get("name"), param.get("endpoint"))
                if key not in seen:
                    params.append(param)
                    seen.add(key)
        return params
