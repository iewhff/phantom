"""
PHANTOM AI - Semantic Response Analyzer

Provides semantic understanding of HTTP responses to:
1. Detect SPA fallback pages (same HTML for any route)
2. Recognize login/auth redirects and access control placeholders
3. Classify response types for accurate impact assessment
4. Filter false positives from generic framework responses

Usage:
    analyzer = SemanticAnalyzer()

    # Single response classification
    classification = await analyzer.classify_response(url, response)

    # Compare responses for SPA detection
    is_spa_fallback = await analyzer.is_spa_fallback(base_url, test_url)

    # Check if response is meaningful content
    is_meaningful = analyzer.is_meaningful_content(response)
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any
from urllib.parse import urlparse

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)


class ResponseType(Enum):
    """Classification of HTTP response types."""
    REAL_CONTENT = auto()       # Unique, meaningful content
    SPA_FALLBACK = auto()       # SPA returning same HTML for all routes
    LOGIN_REDIRECT = auto()     # Redirect to login page
    LOGIN_PAGE = auto()         # Login form page
    ACCESS_DENIED = auto()      # 401/403 access denied
    ERROR_PAGE = auto()         # 404/500 error page
    API_RESPONSE = auto()       # JSON/XML API response
    API_ERROR = auto()          # API error response
    EMPTY_RESPONSE = auto()     # Empty or minimal response
    REDIRECT = auto()           # Generic redirect
    UNKNOWN = auto()            # Unable to classify


@dataclass
class ResponseClassification:
    """Result of response classification."""
    response_type: ResponseType
    confidence: float  # 0.0 - 1.0
    is_meaningful: bool  # True if this is real, unique content
    is_access_control: bool  # True if this is a login/auth placeholder
    is_error: bool  # True if this is an error response
    content_hash: str  # Hash of normalized content for comparison
    indicators: list[str] = field(default_factory=list)  # Why we classified this way


# Patterns for detecting login/auth pages
_LOGIN_INDICATORS = frozenset({
    "login", "sign in", "signin", "log in", "authenticate",
    "username", "password", "credentials", "forgot password",
    "remember me", "keep me logged", "forgot your password",
    "enter your email", "enter your username",
})

_LOGIN_FORM_PATTERNS = [
    r'<form[^>]*action=["\'][^"\']*login[^"\']*["\']',
    r'<input[^>]*type=["\']password["\']',
    r'<input[^>]*name=["\'](?:password|passwd|pass|pwd)["\']',
    r'name=["\'](?:username|user|email|login)["\'].*name=["\'](?:password|passwd)["\']',
]

# Patterns for error pages
_ERROR_INDICATORS = {
    "404": ["not found", "page not found", "404", "does not exist", "couldn't find"],
    "403": ["forbidden", "access denied", "not authorized", "permission denied", "403"],
    "401": ["unauthorized", "authentication required", "please log in", "401"],
    "500": ["internal server error", "500", "something went wrong", "error occurred"],
}

# Patterns for SPA frameworks (Theme 11: updated for 2026 frameworks)
_SPA_INDICATORS = [
    # Classic SPAs
    r'<div\s+id=["\'](?:root|app|__next|__nuxt|__remix|__qwik|__svelte|__solid)["\']',
    r'<script[^>]*src=["\'][^"\']*(?:bundle|main|app|chunk)[^"\']*\.js["\']',
    r'ng-app|ng-controller|v-app|\[routerLink\]',  # Angular, Vue
    r'data-reactroot|data-react-helmet',  # React
    r'window\.__INITIAL_STATE__|window\.__NUXT__|window\.__remixContext',  # SSR hydration

    # Modern meta-frameworks
    r'data-svelte|svelte-\w+|class="svelte-',  # Svelte/SvelteKit
    r'data-qwik|q:container|qwik/optimizer',  # Qwik
    r'data-solid|_\$HY',  # SolidJS
    r'astro-island|data-astro-cid-|astro:',  # Astro (islands architecture)
    r'__REMIX_CONTEXT__|__remix_ssr__',  # Remix

    # HTMX / Hypermedia-driven (very popular 2025-2026)
    r'\shx-(?:get|post|put|patch|delete|trigger|target|swap|boost)\s*=',  # HTMX attributes
    r'\shx-ext\s*=|htmx\.org',  # HTMX extensions/CDN

    # Alpine.js (lightweight reactive)
    r'\sx-(?:data|bind|on|text|html|model|show|if|for|transition|init)\s*=',  # Alpine attributes
    r'@click\s*=|@submit\s*=|@input\s*=',  # Alpine shorthand events

    # Turbo/Hotwire (Rails ecosystem)
    r'data-turbo(?:-frame|-stream|-action|-method|-confirm)?\s*=',  # Turbo attributes
    r'<turbo-frame|<turbo-stream',  # Turbo custom elements

    # Inertia.js (Laravel/Rails + Vue/React/Svelte)
    r'data-page\s*=\s*["\'].*?"inertiaVersion"',  # Inertia page props

    # Fresh (Deno framework)
    r'data-fresh-key|__FRESH_SERVER_DATA|preact-refresh',  # Fresh/Preact

    # Leptos (Rust WASM)
    r'data-leptos|hk-\d+|leptos-',  # Leptos hydration markers

    # Lit / Web Components
    r'lit-html|lit-element|\$lit\$',  # Lit framework

    # Marko
    r'data-marko|marko-\w+',  # Marko framework

    # Million.js (React virtual DOM replacement)
    r'data-million|__MILLION',  # Million.js markers

    # Petite-vue (lightweight Vue alternative)
    r'v-scope\s*=',  # Petite-vue directive
]

# Common SPA route patterns (these are fake paths that resolve to index.html)
_LIKELY_SPA_PATHS = [
    "/dashboard", "/home", "/profile", "/settings", "/account",
    "/admin", "/app", "/user", "/about", "/help",
]


class SemanticAnalyzer:
    """
    Analyzes HTTP responses for semantic understanding.

    Helps scanners distinguish between:
    - Real content that might have vulnerabilities
    - Access control placeholders (login pages, redirects)
    - Framework noise (SPA fallbacks, error pages)
    """

    def __init__(self, timeout: float = 10.0):
        self._timeout = timeout
        self._response_cache: dict[str, str] = {}  # URL -> content hash
        self._baseline_hash: str = ""  # Hash of baseline (homepage) response
        self._spa_detected: bool = False

    async def initialize(self, base_url: str, auth_headers: dict[str, str] | None = None) -> None:
        """
        Initialize analyzer with baseline response from target.

        Should be called once at scan start to establish baseline for SPA detection.
        """
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout,
                verify=False,
                follow_redirects=True,
                headers=auth_headers or {},
            ) as client:
                # Get baseline (homepage) response
                resp = await client.get(base_url)
                if resp.status_code == 200:
                    self._baseline_hash = self._hash_content(resp.text)
                    self._spa_detected = self._detect_spa_framework(resp.text)

                    if self._spa_detected:
                        logger.info("[SemanticAnalyzer] SPA framework detected - will check for fallback pages")

                    # Cache baseline
                    self._response_cache[base_url] = self._baseline_hash

        except Exception as e:
            logger.debug(f"[SemanticAnalyzer] Initialization error: {e}")

    def classify_response(
        self,
        url: str,
        response: httpx.Response | None = None,
        response_text: str | None = None,
        status_code: int = 200,
    ) -> ResponseClassification:
        """
        Classify an HTTP response semantically.

        Args:
            url: The URL that was requested
            response: httpx.Response object (optional)
            response_text: Response body text (if response not provided)
            status_code: HTTP status code (if response not provided)

        Returns:
            ResponseClassification with type, confidence, and indicators
        """
        if response:
            status_code = response.status_code
            response_text = response.text

        if response_text is None:
            response_text = ""

        text_lower = response_text.lower()
        content_hash = self._hash_content(response_text)
        indicators: list[str] = []

        # Check for empty/minimal response
        if len(response_text) < 50:
            return ResponseClassification(
                response_type=ResponseType.EMPTY_RESPONSE,
                confidence=0.95,
                is_meaningful=False,
                is_access_control=False,
                is_error=False,
                content_hash=content_hash,
                indicators=["Response too short (<50 chars)"],
            )

        # Check for redirects
        if status_code in (301, 302, 303, 307, 308):
            location = ""
            if response:
                location = response.headers.get("location", "").lower()

            if any(kw in location for kw in ("login", "signin", "auth", "sso")):
                return ResponseClassification(
                    response_type=ResponseType.LOGIN_REDIRECT,
                    confidence=0.95,
                    is_meaningful=False,
                    is_access_control=True,
                    is_error=False,
                    content_hash=content_hash,
                    indicators=[f"Redirect to login: {location}"],
                )
            return ResponseClassification(
                response_type=ResponseType.REDIRECT,
                confidence=0.9,
                is_meaningful=False,
                is_access_control=False,
                is_error=False,
                content_hash=content_hash,
                indicators=[f"Redirect: {location}"],
            )

        # Check for API responses (JSON/XML)
        content_type = ""
        if response:
            content_type = response.headers.get("content-type", "").lower()

        if "application/json" in content_type or response_text.strip().startswith(("{", "[")):
            # Check if it's an API error
            if self._is_api_error(response_text, status_code):
                return ResponseClassification(
                    response_type=ResponseType.API_ERROR,
                    confidence=0.9,
                    is_meaningful=False,
                    is_access_control=status_code in (401, 403),
                    is_error=True,
                    content_hash=content_hash,
                    indicators=["API error response"],
                )
            return ResponseClassification(
                response_type=ResponseType.API_RESPONSE,
                confidence=0.95,
                is_meaningful=True,
                is_access_control=False,
                is_error=False,
                content_hash=content_hash,
                indicators=["JSON/API response"],
            )

        # Check for access denied (401/403)
        if status_code in (401, 403):
            return ResponseClassification(
                response_type=ResponseType.ACCESS_DENIED,
                confidence=0.95,
                is_meaningful=False,
                is_access_control=True,
                is_error=False,
                content_hash=content_hash,
                indicators=[f"HTTP {status_code} access denied"],
            )

        # Check for error pages (404/500)
        if status_code >= 400:
            error_type = self._detect_error_type(text_lower, status_code)
            return ResponseClassification(
                response_type=ResponseType.ERROR_PAGE,
                confidence=0.9,
                is_meaningful=False,
                is_access_control=False,
                is_error=True,
                content_hash=content_hash,
                indicators=[f"Error page: {error_type}"],
            )

        # Check for login page
        if self._is_login_page(text_lower):
            indicators.append("Login form detected")
            return ResponseClassification(
                response_type=ResponseType.LOGIN_PAGE,
                confidence=0.9,
                is_meaningful=False,
                is_access_control=True,
                is_error=False,
                content_hash=content_hash,
                indicators=indicators,
            )

        # Check for SPA fallback (same content as baseline)
        if self._baseline_hash and content_hash == self._baseline_hash:
            parsed = urlparse(url)
            if parsed.path and parsed.path != "/":
                indicators.append("Same content as homepage (SPA fallback)")
                return ResponseClassification(
                    response_type=ResponseType.SPA_FALLBACK,
                    confidence=0.85,
                    is_meaningful=False,
                    is_access_control=False,
                    is_error=False,
                    content_hash=content_hash,
                    indicators=indicators,
                )

        # Default: real content
        return ResponseClassification(
            response_type=ResponseType.REAL_CONTENT,
            confidence=0.7,
            is_meaningful=True,
            is_access_control=False,
            is_error=False,
            content_hash=content_hash,
            indicators=["Unique content"],
        )

    async def is_spa_fallback(
        self,
        base_url: str,
        test_url: str,
        auth_headers: dict[str, str] | None = None,
    ) -> bool:
        """
        Check if test_url returns the same content as base_url (SPA fallback pattern).

        SPAs often return the same index.html for any route, with client-side
        routing handling the actual navigation. This causes false positives
        when scanners think they found a real page.
        """
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout,
                verify=False,
                follow_redirects=True,
                headers=auth_headers or {},
            ) as client:
                # Get baseline if not cached
                if base_url not in self._response_cache:
                    resp = await client.get(base_url)
                    if resp.status_code == 200:
                        self._response_cache[base_url] = self._hash_content(resp.text)

                # Get test URL
                resp = await client.get(test_url)
                if resp.status_code == 200:
                    test_hash = self._hash_content(resp.text)

                    # Compare with baseline
                    baseline_hash = self._response_cache.get(base_url, "")
                    if baseline_hash and test_hash == baseline_hash:
                        return True

        except Exception:
            pass

        return False

    def is_meaningful_content(
        self,
        response_text: str,
        status_code: int = 200,
    ) -> bool:
        """
        Quick check if response contains meaningful content.

        Returns False for:
        - Empty/minimal responses
        - Login pages
        - Error pages
        - SPA fallbacks (if baseline is set)
        """
        if len(response_text) < 50:
            return False

        text_lower = response_text.lower()

        # Check for login page
        if self._is_login_page(text_lower):
            return False

        # Check for error indicators
        if status_code >= 400:
            return False

        for error_type, indicators in _ERROR_INDICATORS.items():
            if any(ind in text_lower for ind in indicators):
                return False

        # Check for SPA fallback
        if self._baseline_hash:
            content_hash = self._hash_content(response_text)
            if content_hash == self._baseline_hash:
                return False

        return True

    def is_access_control_response(
        self,
        response_text: str,
        status_code: int = 200,
        location_header: str = "",
    ) -> bool:
        """
        Check if response is an access control placeholder.

        Returns True for:
        - Login pages
        - Login redirects
        - 401/403 responses
        """
        if status_code in (401, 403):
            return True

        if status_code in (301, 302, 303, 307, 308):
            if any(kw in location_header.lower() for kw in ("login", "signin", "auth", "sso")):
                return True

        if self._is_login_page(response_text.lower()):
            return True

        return False

    def compare_responses(
        self,
        response1: str,
        response2: str,
        threshold: float = 0.95,
    ) -> bool:
        """
        Compare two responses for similarity.

        Returns True if responses are similar enough to be considered the same.
        Useful for detecting SPA fallbacks and generic error pages.
        """
        hash1 = self._hash_content(response1)
        hash2 = self._hash_content(response2)

        if hash1 == hash2:
            return True

        # For more nuanced comparison, use content length ratio
        len1 = len(response1)
        len2 = len(response2)

        if len1 == 0 or len2 == 0:
            return len1 == len2

        ratio = min(len1, len2) / max(len1, len2)
        return ratio >= threshold

    def _hash_content(self, content: str) -> str:
        """
        Create a hash of normalized content for comparison.

        Normalizes by:
        - Removing whitespace variations
        - Removing dynamic tokens (CSRF, nonce, timestamps)
        - Removing session-specific content
        """
        # Normalize whitespace
        normalized = " ".join(content.split())

        # Remove common dynamic tokens
        normalized = re.sub(r'csrf[_-]?token["\']?\s*[:=]\s*["\'][^"\']+["\']', 'CSRF_TOKEN', normalized, flags=re.I)
        normalized = re.sub(r'nonce["\']?\s*[:=]\s*["\'][^"\']+["\']', 'NONCE', normalized, flags=re.I)
        normalized = re.sub(r'\d{10,}', 'TIMESTAMP', normalized)  # Unix timestamps
        normalized = re.sub(r'[a-f0-9]{32,}', 'HASH', normalized, flags=re.I)  # Long hex strings

        return hashlib.md5(normalized.encode()).hexdigest()

    def _is_login_page(self, text_lower: str) -> bool:
        """Check if content is a login page."""
        # Count login indicators
        indicator_count = sum(1 for ind in _LOGIN_INDICATORS if ind in text_lower)

        if indicator_count >= 3:
            return True

        # Check for login form patterns
        for pattern in _LOGIN_FORM_PATTERNS:
            if re.search(pattern, text_lower, re.I):
                return True

        return False

    def _detect_spa_framework(self, content: str) -> bool:
        """Detect if content is from a SPA framework."""
        for pattern in _SPA_INDICATORS:
            if re.search(pattern, content, re.I):
                return True
        return False

    def _detect_error_type(self, text_lower: str, status_code: int) -> str:
        """Detect the type of error page."""
        for error_code, indicators in _ERROR_INDICATORS.items():
            if any(ind in text_lower for ind in indicators):
                return f"HTTP {error_code}"
        return f"HTTP {status_code}"

    def _is_api_error(self, response_text: str, status_code: int) -> bool:
        """Check if JSON response is an error."""
        if status_code >= 400:
            return True

        text_lower = response_text.lower()
        error_keys = ['"error"', '"message":', '"status":', '"code":']

        if any(key in text_lower for key in error_keys):
            # Check for error patterns
            if any(word in text_lower for word in ["not found", "unauthorized", "forbidden", "invalid"]):
                return True

        return False


# Global instance for shared use
_global_analyzer: SemanticAnalyzer | None = None


def get_semantic_analyzer() -> SemanticAnalyzer:
    """Get the global semantic analyzer instance."""
    global _global_analyzer
    if _global_analyzer is None:
        _global_analyzer = SemanticAnalyzer()
    return _global_analyzer


async def initialize_semantic_analyzer(base_url: str, auth_headers: dict[str, str] | None = None) -> SemanticAnalyzer:
    """Initialize and return the global semantic analyzer."""
    global _global_analyzer
    _global_analyzer = SemanticAnalyzer()
    await _global_analyzer.initialize(base_url, auth_headers)
    return _global_analyzer


def is_meaningful_response(
    response_text: str,
    status_code: int = 200,
    baseline_text: str = "",
) -> bool:
    """
    Quick utility to check if a response contains meaningful content.

    Returns False for:
    - Empty/minimal responses
    - Login pages
    - Error pages
    - SPA fallbacks (if baseline provided and matches)

    This is a lightweight check that doesn't require the full analyzer.
    """
    # Empty check
    if len(response_text) < 50:
        return False

    # Error status
    if status_code >= 400:
        return False

    text_lower = response_text.lower()

    # Login page check
    login_indicators = ["login", "sign in", "password", "forgot password", "remember me"]
    if sum(1 for ind in login_indicators if ind in text_lower) >= 3:
        return False
    if '<input' in text_lower and ('type="password"' in text_lower or "type='password'" in text_lower):
        return False

    # Error page check
    error_indicators = ["not found", "404", "forbidden", "403", "error", "unauthorized", "401"]
    if sum(1 for ind in error_indicators if ind in text_lower) >= 2:
        return False

    # SPA fallback check
    if baseline_text and len(baseline_text) > 100:
        # Compare normalized content
        if abs(len(response_text) - len(baseline_text)) < 100:
            # Quick hash comparison
            r1_start = response_text[:500].strip()
            b1_start = baseline_text[:500].strip()
            if r1_start == b1_start:
                return False

    return True


def is_access_control_page(response_text: str, status_code: int = 200, location: str = "") -> bool:
    """
    Check if response is an access control placeholder (login, redirect to login, 401/403).

    Useful for scanners to filter out responses that aren't real content.
    """
    # HTTP status check
    if status_code in (401, 403):
        return True

    # Redirect to login
    if status_code in (301, 302, 303, 307, 308):
        location_lower = location.lower()
        if any(kw in location_lower for kw in ("login", "signin", "auth", "sso")):
            return True

    # Login page content
    text_lower = response_text.lower()
    login_indicators = [
        "login", "sign in", "signin", "log in",
        "username", "password", "forgot password",
    ]
    if sum(1 for ind in login_indicators if ind in text_lower) >= 3:
        return True

    # Password field
    if '<input' in text_lower and ('type="password"' in text_lower or "type='password'" in text_lower):
        return True

    return False
