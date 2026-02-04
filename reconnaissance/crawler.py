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
                    
                    return CrawlResult(
                        url=str(resp.url),
                        status=resp.status,
                        content_type=content_type,
                        title=self._extract_title(body),
                        forms=self._extract_forms(body, url),
                        links=self._extract_links(body, url),
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
            
            # Clean URL (remove fragments)
            parsed = urlparse(absolute_url)
            clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if parsed.query:
                clean_url += f"?{parsed.query}"
            
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
            pass
        
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
