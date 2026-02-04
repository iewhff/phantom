"""
Technology detection for web applications.
Identifies frameworks, CMS, servers, and libraries.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import aiohttp

from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


@dataclass
class Technology:
    """Detected technology information."""
    
    name: str
    category: str
    version: str = ""
    confidence: float = 1.0
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "category": self.category,
            "version": self.version,
            "confidence": self.confidence,
        }


class TechDetector:
    """
    Web technology detector.
    
    Detects:
    - Web servers (Apache, Nginx, IIS)
    - Programming languages (PHP, Python, ASP.NET)
    - Frameworks (Django, Laravel, Spring)
    - CMS (WordPress, Drupal, Joomla)
    - JavaScript libraries
    - Security headers
    """
    
    # Detection signatures
    SIGNATURES = {
        # Server headers
        "headers": {
            "server": {
                "Apache": ("apache", "web_server"),
                "nginx": ("nginx", "web_server"),
                "Microsoft-IIS": ("IIS", "web_server"),
                "cloudflare": ("Cloudflare", "cdn"),
                "gunicorn": ("Gunicorn", "web_server"),
            },
            "x-powered-by": {
                "PHP": ("PHP", "language"),
                "ASP.NET": ("ASP.NET", "framework"),
                "Express": ("Express.js", "framework"),
                "Next.js": ("Next.js", "framework"),
            },
            "x-generator": {
                "WordPress": ("WordPress", "cms"),
                "Drupal": ("Drupal", "cms"),
            },
        },
        # HTML patterns
        "html": [
            (r'<meta name="generator" content="WordPress ([^"]*)"', "WordPress", "cms"),
            (r'wp-content/', "WordPress", "cms"),
            (r'wp-includes/', "WordPress", "cms"),
            (r'/sites/default/', "Drupal", "cms"),
            (r'Drupal.settings', "Drupal", "cms"),
            (r'Joomla!', "Joomla", "cms"),
            (r'/__next/', "Next.js", "framework"),
            (r'/_next/static/', "Next.js", "framework"),
            (r'ng-version=', "Angular", "framework"),
            (r'data-reactroot', "React", "framework"),
            (r'__NUXT__', "Nuxt.js", "framework"),
            (r'vue\.js', "Vue.js", "framework"),
            (r'jquery', "jQuery", "javascript"),
            (r'bootstrap', "Bootstrap", "css_framework"),
        ],
        # Cookie patterns
        "cookies": {
            "PHPSESSID": ("PHP", "language"),
            "ASP.NET_SessionId": ("ASP.NET", "framework"),
            "JSESSIONID": ("Java", "language"),
            "csrftoken": ("Django", "framework"),
            "laravel_session": ("Laravel", "framework"),
            "ci_session": ("CodeIgniter", "framework"),
        },
        # URL patterns
        "urls": [
            (r'\.php', "PHP", "language"),
            (r'\.asp', "ASP", "language"),
            (r'\.aspx', "ASP.NET", "framework"),
            (r'\.jsp', "Java/JSP", "language"),
        ],
    }
    
    def __init__(self, settings: Settings) -> None:
        """
        Initialize detector.
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        self.user_agent = settings.reconnaissance.crawler.user_agent
    
    async def detect(self, host: str) -> list[Technology]:
        """
        Detect technologies used by a host.
        
        Args:
            host: Target hostname
            
        Returns:
            List of detected technologies
        """
        logger.info(f"Detecting technologies for {host}")
        technologies: dict[str, Technology] = {}
        
        # Ensure URL format
        url = host if host.startswith(('http://', 'https://')) else f"https://{host}"
        
        try:
            async with aiohttp.ClientSession() as session:
                # Try HTTPS first, fallback to HTTP
                response_data = await self._fetch_page(session, url)
                
                if response_data is None:
                    http_url = url.replace('https://', 'http://')
                    response_data = await self._fetch_page(session, http_url)
                
                if response_data:
                    # Analyze response
                    self._analyze_headers(response_data["headers"], technologies)
                    self._analyze_cookies(response_data["cookies"], technologies)
                    self._analyze_html(response_data["body"], technologies)
                    self._analyze_url(url, technologies)
        
        except Exception as e:
            logger.warning(f"Tech detection failed for {host}: {e}")
        
        result = list(technologies.values())
        logger.info(f"Detected {len(result)} technologies for {host}")
        return result
    
    async def _fetch_page(
        self,
        session: aiohttp.ClientSession,
        url: str,
    ) -> dict[str, Any] | None:
        """Fetch page for analysis."""
        timeout = aiohttp.ClientTimeout(total=15)
        headers = {"User-Agent": self.user_agent}
        
        try:
            async with session.get(
                url,
                headers=headers,
                timeout=timeout,
                ssl=False,
                allow_redirects=True,
            ) as resp:
                body = await resp.text()
                return {
                    "headers": dict(resp.headers),
                    "cookies": {c.key: c.value for c in resp.cookies.values()},
                    "body": body,
                    "status": resp.status,
                    "url": str(resp.url),
                }
        except Exception as e:
            logger.debug(f"Failed to fetch {url}: {e}")
            return None
    
    def _analyze_headers(
        self,
        headers: dict[str, str],
        technologies: dict[str, Technology],
    ) -> None:
        """Analyze response headers."""
        for header, patterns in self.SIGNATURES["headers"].items():
            value = headers.get(header, "").lower()
            if not value:
                continue
            
            for pattern, (name, category) in patterns.items():
                if pattern.lower() in value:
                    # Extract version if present
                    version = ""
                    version_match = re.search(r'[\d.]+', value)
                    if version_match:
                        version = version_match.group()
                    
                    tech = Technology(
                        name=name,
                        category=category,
                        version=version,
                        confidence=0.9,
                    )
                    technologies[name] = tech
    
    def _analyze_cookies(
        self,
        cookies: dict[str, str],
        technologies: dict[str, Technology],
    ) -> None:
        """Analyze cookies."""
        for cookie_name, (name, category) in self.SIGNATURES["cookies"].items():
            if cookie_name in cookies:
                tech = Technology(
                    name=name,
                    category=category,
                    confidence=0.8,
                )
                technologies[name] = tech
    
    def _analyze_html(
        self,
        html: str,
        technologies: dict[str, Technology],
    ) -> None:
        """Analyze HTML content."""
        html_lower = html.lower()
        
        for pattern, name, category in self.SIGNATURES["html"]:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                version = ""
                if match.groups():
                    version = match.group(1) if match.group(1) else ""
                
                tech = Technology(
                    name=name,
                    category=category,
                    version=version,
                    confidence=0.7 if pattern.startswith('r') else 0.6,
                )
                
                # Don't overwrite higher confidence matches
                if name not in technologies or technologies[name].confidence < tech.confidence:
                    technologies[name] = tech
    
    def _analyze_url(
        self,
        url: str,
        technologies: dict[str, Technology],
    ) -> None:
        """Analyze URL patterns."""
        for pattern, name, category in self.SIGNATURES["urls"]:
            if re.search(pattern, url, re.IGNORECASE):
                tech = Technology(
                    name=name,
                    category=category,
                    confidence=0.6,
                )
                if name not in technologies:
                    technologies[name] = tech
    
    async def detect_detailed(self, host: str) -> dict[str, Any]:
        """
        Get detailed technology information.
        
        Args:
            host: Target hostname
            
        Returns:
            Detailed technology analysis
        """
        technologies = await self.detect(host)
        
        # Group by category
        by_category: dict[str, list[dict]] = {}
        for tech in technologies:
            cat = tech.category
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(tech.to_dict())
        
        return {
            "host": host,
            "technologies": [t.to_dict() for t in technologies],
            "by_category": by_category,
            "count": len(technologies),
        }
