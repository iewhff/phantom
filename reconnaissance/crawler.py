"""
Web crawler for URL discovery.
Recursively crawls websites while respecting limits.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

import aiohttp

from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


@dataclass
class CrawlResult:
    """Result of a crawl operation."""
    
    url: str
    status: int
    content_type: str = ""
    title: str = ""
    forms: list[dict] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)


class WebCrawler:
    """
    Async web crawler for URL and resource discovery.
    
    Features:
    - Respects robots.txt (optional)
    - Rate limiting
    - Depth control
    - Form detection
    - Parameter extraction
    """
    
    def __init__(self, settings: Settings) -> None:
        """
        Initialize crawler.
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        self.config = settings.reconnaissance.crawler
        self.user_agent = self.config.user_agent
        self.excluded_extensions = set(self.config.excluded_extensions)
    
    async def crawl(
        self,
        host: str,
        max_depth: int | None = None,
        max_pages: int | None = None,
    ) -> list[str]:
        """
        Crawl a website and discover URLs.
        
        Args:
            host: Target hostname
            max_depth: Maximum crawl depth
            max_pages: Maximum pages to crawl
            
        Returns:
            List of discovered URLs
        """
        max_depth = max_depth or self.config.max_depth
        max_pages = max_pages or self.config.max_pages
        
        # Normalize start URL
        start_url = host if host.startswith(('http://', 'https://')) else f"https://{host}"
        base_domain = urlparse(start_url).netloc
        
        logger.info(f"Starting crawl of {start_url} (depth={max_depth}, max_pages={max_pages})")
        
        visited: set[str] = set()
        to_visit: list[tuple[str, int]] = [(start_url, 0)]
        discovered: list[str] = []
        
        # Rate limiting
        semaphore = asyncio.Semaphore(10)
        delay = 0.1
        
        # Load robots.txt if configured
        disallowed: set[str] = set()
        if self.config.respect_robots:
            disallowed = await self._load_robots(start_url)
        
        timeout = aiohttp.ClientTimeout(total=10)
        connector = aiohttp.TCPConnector(limit=20, ssl=False)
        
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
        ) as session:
            while to_visit and len(discovered) < max_pages:
                # Process batch
                batch = []
                while to_visit and len(batch) < 10:
                    url, depth = to_visit.pop(0)
                    
                    # Skip already visited or disallowed
                    if url in visited:
                        continue
                    if self._is_disallowed(url, disallowed):
                        continue
                    
                    visited.add(url)
                    batch.append((url, depth))
                
                if not batch:
                    break
                
                # Crawl batch in parallel
                tasks = [
                    self._crawl_url(session, url, semaphore)
                    for url, _ in batch
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, result in enumerate(results):
                    url, depth = batch[i]
                    
                    if isinstance(result, Exception):
                        logger.debug(f"Failed to crawl {url}: {result}")
                        continue
                    
                    if result:
                        discovered.append(url)
                        
                        # Add new URLs to queue if within depth
                        if depth < max_depth:
                            for link in result.links:
                                # Only crawl same domain
                                if urlparse(link).netloc == base_domain:
                                    if link not in visited:
                                        to_visit.append((link, depth + 1))
                
                await asyncio.sleep(delay)
        
        # FIX 2026-02-19: Auto-discover training app endpoints
        # WebGoat, DVWA, Mutillidae have predictable structures
        training_endpoints = await self.discover_training_app_endpoints(start_url)
        for endpoint in training_endpoints:
            if endpoint not in discovered:
                discovered.append(endpoint)

        logger.info(f"Crawl completed: discovered {len(discovered)} URLs")
        return discovered
    
    async def _crawl_url(
        self,
        session: aiohttp.ClientSession,
        url: str,
        semaphore: asyncio.Semaphore,
    ) -> CrawlResult | None:
        """Crawl a single URL."""
        async with semaphore:
            try:
                headers = {"User-Agent": self.user_agent}

                async with session.get(
                    url,
                    headers=headers,
                    allow_redirects=True,
                ) as resp:
                    # Skip non-HTML
                    content_type = resp.headers.get("Content-Type", "")
                    if "text/html" not in content_type.lower():
                        return None

                    body = await resp.text()
                    title = self._extract_title(body)

                    # Check for directory listing - use enhanced extraction
                    if self._is_directory_listing(body, title):
                        logger.info(f"[CRAWLER] Directory listing detected at {url} - extracting entries")
                        # Extract both regular links AND directory entries
                        regular_links = self._extract_links(body, url)
                        directory_entries = self._extract_directory_entries(body, url)
                        # Merge, prioritizing directory entries
                        all_links = list(set(regular_links) | set(directory_entries))
                        logger.info(f"[CRAWLER] Found {len(directory_entries)} directory entries, {len(all_links)} total links")
                    else:
                        all_links = self._extract_links(body, url)

                    return CrawlResult(
                        url=str(resp.url),
                        status=resp.status,
                        content_type=content_type,
                        title=title,
                        forms=self._extract_forms(body, url),
                        links=all_links,
                        scripts=self._extract_scripts(body),
                        parameters=self._extract_parameters(body, url),
                    )

            except asyncio.TimeoutError:
                return None
            except Exception as e:
                logger.debug(f"Error crawling {url}: {e}")
                return None
    
    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """Extract links from HTML."""
        links: set[str] = set()
        
        # href attributes
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in href_pattern.finditer(html):
            href = match.group(1)
            
            # Skip anchors, javascript, mailto
            if href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
                continue
            
            # Skip excluded extensions
            ext = '.' + href.split('.')[-1].split('?')[0].lower() if '.' in href else ''
            if ext in self.excluded_extensions:
                continue
            
            # Make absolute URL
            absolute_url = urljoin(base_url, href)

            # Parse URL - preserve fragments for SPA route discovery
            parsed = urlparse(absolute_url)

            # Build URL with optional query and fragment
            # SPAs use hash routes like /#/search, /#/profile - these are valid attack surfaces
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                clean_url += f"?{parsed.query}"
            if parsed.fragment:
                # Preserve fragment for SPA routes (e.g., /#/admin, /#/search?q=)
                clean_url += f"#{parsed.fragment}"

            links.add(clean_url)
        
        return list(links)
    
    def _extract_forms(self, html: str, base_url: str) -> list[dict]:
        """Extract forms from HTML."""
        forms: list[dict] = []
        
        form_pattern = re.compile(
            r'<form[^>]*>(.*?)</form>',
            re.IGNORECASE | re.DOTALL,
        )
        
        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            
            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else ""
            action = urljoin(base_url, action) if action else base_url
            
            # Extract method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else "GET"
            
            # Extract inputs
            inputs = []
            input_pattern = re.compile(
                r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>',
                re.IGNORECASE,
            )
            for input_match in input_pattern.finditer(form_html):
                name = input_match.group(1)
                
                # Get type
                type_match = re.search(r'type=["\']([^"\']*)["\']', input_match.group(0), re.IGNORECASE)
                input_type = type_match.group(1) if type_match else "text"
                
                inputs.append({
                    "name": name,
                    "type": input_type,
                })
            
            # Add textarea and select
            for tag in ['textarea', 'select']:
                tag_pattern = re.compile(
                    rf'<{tag}[^>]*name=["\']([^"\']*)["\'][^>]*>',
                    re.IGNORECASE,
                )
                for tag_match in tag_pattern.finditer(form_html):
                    inputs.append({
                        "name": tag_match.group(1),
                        "type": tag,
                    })
            
            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs,
            })
        
        return forms
    
    def _extract_scripts(self, html: str) -> list[str]:
        """Extract script sources."""
        scripts: list[str] = []
        
        pattern = re.compile(r'<script[^>]*src=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in pattern.finditer(html):
            scripts.append(match.group(1))
        
        return scripts
    
    def _extract_parameters(self, html: str, url: str) -> list[str]:
        """Extract URL parameters from page."""
        params: set[str] = set()
        
        # From current URL
        parsed = urlparse(url)
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    params.add(param.split('=')[0])
        
        # From links
        for link in self._extract_links(html, url):
            parsed = urlparse(link)
            if parsed.query:
                for param in parsed.query.split('&'):
                    if '=' in param:
                        params.add(param.split('=')[0])
        
        return list(params)
    
    def _extract_title(self, html: str) -> str:
        """Extract page title."""
        match = re.search(r'<title>([^<]*)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else ""
    
    async def _load_robots(self, base_url: str) -> set[str]:
        """Load robots.txt and return disallowed paths."""
        disallowed: set[str] = set()
        
        robots_url = urljoin(base_url, "/robots.txt")
        
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(robots_url) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        
                        for line in text.split('\n'):
                            line = line.strip()
                            if line.lower().startswith('disallow:'):
                                path = line.split(':', 1)[1].strip()
                                if path:
                                    disallowed.add(path)
        except Exception:
            pass  # FIX 2026-02-12: Expected error
        
        return disallowed
    
    def _is_disallowed(self, url: str, disallowed: set[str]) -> bool:
        """Check if URL is disallowed by robots.txt."""
        parsed = urlparse(url)
        path = parsed.path

        for pattern in disallowed:
            if pattern.endswith('*'):
                if path.startswith(pattern[:-1]):
                    return True
            elif path.startswith(pattern):
                return True

        return False

    def _is_directory_listing(self, html: str, title: str) -> bool:
        """
        Detect if page is a directory listing.

        Detects common directory listing patterns from:
        - Apache (Index of /)
        - Nginx (Index of /)
        - IIS
        - DirectoryLister (PHP)
        - h5ai
        - Other common directory listers
        """
        html_lower = html.lower()
        title_lower = title.lower()

        # Title-based detection
        title_indicators = [
            "index of /",
            "index of",
            "directory listing",
            "directory of",
            "folder listing",
        ]
        if any(ind in title_lower for ind in title_indicators):
            return True

        # HTML content-based detection
        content_indicators = [
            # Apache/Nginx
            '<title>index of',
            'parent directory</a>',
            '[dir]',
            '[to parent directory]',
            # DirectoryLister (like XSS Challenges uses)
            'id="directory-listing"',
            'id="directory-list"',
            'class="directory-listing"',
            'data-name=',
            'data-href=',
            # h5ai
            'h5ai',
            '_h5ai',
            # IIS
            '<pre><a href="?',
            '[to parent directory]',
            # Generic
            'parent directory',
            '<hr><pre>',
            'last modified</th>',
            'size</th>',
            '<th>name</th>',
        ]

        matches = sum(1 for ind in content_indicators if ind in html_lower)

        # If 2+ indicators match, it's likely a directory listing
        return matches >= 2

    def _extract_directory_entries(self, html: str, base_url: str) -> list[str]:
        """
        Extract directory entries (subdirectories and files) from a directory listing.

        This is more aggressive than _extract_links() - it specifically looks for
        directory listing patterns and ensures subdirectories are included.
        """
        entries: set[str] = set()

        # DirectoryLister pattern (data-href attribute)
        data_href_pattern = re.compile(r'data-href=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in data_href_pattern.finditer(html):
            href = match.group(1)
            if href and not href.startswith(('#', 'javascript:', '?')):
                absolute_url = urljoin(base_url, href)
                # Ensure trailing slash for directories
                if not absolute_url.endswith('/') and '.' not in href.split('/')[-1]:
                    absolute_url += '/'
                entries.add(absolute_url)

        # Apache/Nginx pattern (href in pre or table)
        href_pattern = re.compile(r'<a\s+href=["\']([^"\']+)["\'][^>]*>([^<]*)</a>', re.IGNORECASE)
        for match in href_pattern.finditer(html):
            href = match.group(1)
            link_text = match.group(2).strip()

            # Skip parent directory and sorting links
            if href in ('..', '../', '/', '?') or href.startswith('?'):
                continue
            if 'parent' in link_text.lower():
                continue

            # Skip static resources
            skip_extensions = {'.css', '.js', '.png', '.jpg', '.gif', '.ico', '.svg', '.woff', '.ttf'}
            if any(href.lower().endswith(ext) for ext in skip_extensions):
                continue

            absolute_url = urljoin(base_url, href)

            # Add trailing slash for directories (no extension)
            if not absolute_url.endswith('/') and '.' not in href.split('/')[-1]:
                absolute_url += '/'

            entries.add(absolute_url)

        logger.debug(f"[DIRLIST] Extracted {len(entries)} entries from directory listing at {base_url}")
        return list(entries)

    # =========================================================================
    # TRAINING APP DISCOVERY - Auto-discover endpoints for WebGoat, DVWA, etc.
    # =========================================================================

    async def discover_training_app_endpoints(
        self,
        base_url: str,
        cookies: dict[str, str] | None = None,
    ) -> list[str]:
        """
        Auto-discover endpoints for training apps like WebGoat, DVWA, etc.

        These apps have predictable structures that can be enumerated via their APIs.

        Args:
            base_url: Target URL
            cookies: Session cookies for authenticated requests

        Returns:
            List of discovered vulnerable endpoints
        """
        endpoints: list[str] = []

        # Detect which training app this is
        if "/WebGoat" in base_url or ":8080" in base_url:
            endpoints.extend(await self._discover_webgoat_lessons(base_url, cookies))

        if "dvwa" in base_url.lower() or base_url.endswith(":80") or "/login.php" in base_url:
            endpoints.extend(await self._discover_dvwa_pages(base_url, cookies))

        if "/mutillidae" in base_url.lower() or ":8082" in base_url:
            endpoints.extend(await self._discover_mutillidae_pages(base_url, cookies))

        if endpoints:
            logger.info(f"[TRAINING-APP] Discovered {len(endpoints)} training app endpoints")

        return endpoints

    async def _discover_webgoat_lessons(
        self,
        base_url: str,
        cookies: dict[str, str] | None = None,
    ) -> list[str]:
        """
        Discover WebGoat lesson endpoints via /service/lessonmenu.mvc API.

        WebGoat exposes all lessons via a menu API. Each lesson has multiple
        attack endpoints (attack1, attack2, etc.).
        """
        endpoints: list[str] = []

        # Normalize base URL
        if "/WebGoat" not in base_url:
            base_url = base_url.rstrip('/') + "/WebGoat"
        else:
            base_url = base_url.split("/WebGoat")[0] + "/WebGoat"

        menu_url = f"{base_url}/service/lessonmenu.mvc"

        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(menu_url, cookies=cookies, ssl=False) as resp:
                    if resp.status == 200:
                        data = await resp.json()

                        for category in data:
                            for lesson in category.get('children', []):
                                link = lesson.get('link', '')

                                # Format: "#lesson/SqlInjection.lesson"
                                if link.startswith('#lesson/'):
                                    lesson_name = link.split('/')[1].replace('.lesson', '')

                                    # Add multiple attack endpoints per lesson
                                    for i in range(1, 8):  # attack1 through attack7
                                        endpoints.append(f"{base_url}/{lesson_name}/attack{i}")

                                    # Also add common WebGoat API patterns
                                    endpoints.append(f"{base_url}/{lesson_name}")
                                    endpoints.append(f"{base_url}/{lesson_name}/assignment")

                        logger.info(f"[WEBGOAT] Discovered {len(endpoints)} lesson endpoints from menu API")
                    else:
                        logger.debug(f"[WEBGOAT] Menu API returned {resp.status}")
        except Exception as e:
            logger.debug(f"[WEBGOAT] Failed to discover lessons: {e}")

        return endpoints

    async def _discover_dvwa_pages(
        self,
        base_url: str,
        cookies: dict[str, str] | None = None,
    ) -> list[str]:
        """
        Discover DVWA vulnerable page endpoints.

        DVWA has a fixed set of vulnerability categories at /vulnerabilities/XXX/
        """
        endpoints: list[str] = []

        # Normalize base URL
        base_url = base_url.rstrip('/').replace('/login.php', '')

        # DVWA vulnerability pages (these are the attack endpoints)
        dvwa_pages = [
            "/vulnerabilities/brute/",
            "/vulnerabilities/exec/",
            "/vulnerabilities/csrf/",
            "/vulnerabilities/fi/?page=include.php",
            "/vulnerabilities/upload/",
            "/vulnerabilities/captcha/",
            "/vulnerabilities/sqli/",
            "/vulnerabilities/sqli_blind/",
            "/vulnerabilities/weak_id/",
            "/vulnerabilities/xss_d/",
            "/vulnerabilities/xss_r/",
            "/vulnerabilities/xss_s/",
            "/vulnerabilities/csp/",
            "/vulnerabilities/javascript/",
            "/vulnerabilities/authbypass/",
            "/vulnerabilities/open_redirect/",
        ]

        for page in dvwa_pages:
            endpoints.append(f"{base_url}{page}")

        # Also add the setup and security pages
        endpoints.append(f"{base_url}/setup.php")
        endpoints.append(f"{base_url}/security.php")

        logger.info(f"[DVWA] Added {len(endpoints)} known vulnerability endpoints")
        return endpoints

    async def _discover_mutillidae_pages(
        self,
        base_url: str,
        cookies: dict[str, str] | None = None,
    ) -> list[str]:
        """
        Discover Mutillidae vulnerable page endpoints.

        Mutillidae organizes vulns by OWASP category.
        """
        endpoints: list[str] = []

        # Normalize base URL
        base_url = base_url.rstrip('/')

        # Mutillidae vulnerability pages
        mutillidae_pages = [
            "/index.php?page=user-info.php",
            "/index.php?page=login.php",
            "/index.php?page=register.php",
            "/index.php?page=add-to-your-blog.php",
            "/index.php?page=view-someones-blog.php",
            "/index.php?page=dns-lookup.php",
            "/index.php?page=echo.php",
            "/index.php?page=source-viewer.php",
            "/index.php?page=text-file-viewer.php",
            "/index.php?page=arbitrary-file-inclusion.php",
            "/index.php?page=user-poll.php",
            "/index.php?page=pen-test-tool-lookup.php",
            "/index.php?page=user-agent-impersonation.php",
            "/index.php?page=client-side-control-challenge.php",
            "/index.php?page=repeater.php",
            "/webservices/rest/ws-user-account.php",
            "/webservices/soap/ws-lookup-dns.php",
        ]

        for page in mutillidae_pages:
            endpoints.append(f"{base_url}{page}")

        logger.info(f"[MUTILLIDAE] Added {len(endpoints)} known vulnerability endpoints")
        return endpoints
