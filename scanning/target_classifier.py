"""
Target Classifier v1.0 - Intelligence Before Brute Force
=========================================================

Classifies target type BEFORE launching modules to:
1. Eliminate 80% of timeouts
2. Increase client confidence
3. Skip irrelevant modules intelligently
4. Focus on high-value attack vectors

Target Types:
- static_site: HTML + CDN (minimal attack surface)
- spa: React/Vue/Next (client-side focused)  
- backend_classic: PHP/Laravel/Rails/Django (full attack surface)
- api_first: REST/GraphQL API (API-specific attacks)
- cloud_only: S3 + CloudFront (cloud misconfig focus)
- baas: Supabase/Firebase (BaaS-specific attacks)
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import httpx

from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class TargetType(Enum):
    """Classification of target types."""
    STATIC_SITE = "static_site"
    SPA = "spa"
    SPA_WITH_BACKEND = "spa_with_backend"  # NEW: SPA frontend + Backend API (full testing)
    BACKEND_CLASSIC = "backend_classic"
    API_FIRST = "api_first"
    CLOUD_ONLY = "cloud_only"  # Internal value for compatibility
    BAAS_SUPABASE = "baas_supabase"
    BAAS_FIREBASE = "baas_firebase"
    UNKNOWN = "unknown"

    @property
    def display_name(self) -> str:
        """Professional display name for reports (avoids architectural assumptions)."""
        names = {
            TargetType.STATIC_SITE: "Static Content Surface",
            TargetType.SPA: "Single-Page Application (Frontend Only)",
            TargetType.SPA_WITH_BACKEND: "Full-Stack Application (SPA + Backend API)",
            TargetType.BACKEND_CLASSIC: "Traditional Web Application",
            TargetType.API_FIRST: "API-First Architecture",
            TargetType.CLOUD_ONLY: "Unauthenticated External Surface",  # NOT "cloud_only"
            TargetType.BAAS_SUPABASE: "Backend-as-a-Service (Supabase)",
            TargetType.BAAS_FIREBASE: "Backend-as-a-Service (Firebase)",
            TargetType.UNKNOWN: "Unclassified Target",
        }
        return names.get(self, self.value)

    @property
    def scope_description(self) -> str:
        """Describe what was actually tested (scope-based, not architectural)."""
        descriptions = {
            TargetType.STATIC_SITE: "Public static content served via CDN",
            TargetType.SPA: "Client-side JavaScript application (frontend only)",
            TargetType.SPA_WITH_BACKEND: "Full-stack application with frontend SPA and backend API endpoints",
            TargetType.BACKEND_CLASSIC: "Server-rendered web application with forms and sessions",
            TargetType.API_FIRST: "API endpoints (REST/GraphQL)",
            TargetType.CLOUD_ONLY: "Public-facing surface behind CDN (unauthenticated scope)",
            TargetType.BAAS_SUPABASE: "Supabase-hosted application",
            TargetType.BAAS_FIREBASE: "Firebase-hosted application",
            TargetType.UNKNOWN: "Target type could not be determined",
        }
        return descriptions.get(self, "Unknown scope")


@dataclass
class TargetClassification:
    """Result of target classification."""
    target_type: TargetType
    confidence: float  # 0.0 to 1.0
    
    # Detection evidence
    detected_technologies: List[str] = field(default_factory=list)
    detected_frameworks: List[str] = field(default_factory=list)
    detected_server: str = ""
    detected_cdn: str = ""
    
    # Module recommendations
    recommended_modules: List[str] = field(default_factory=list)
    skip_modules: List[str] = field(default_factory=list)
    skip_reasons: Dict[str, str] = field(default_factory=dict)
    
    # Additional info
    has_forms: bool = False
    has_login: bool = False
    has_api_endpoints: bool = False
    has_dynamic_content: bool = False
    has_cookies: bool = False
    has_sessions: bool = False
    
    # Raw signals
    signals: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "target_type": self.target_type.display_name,  # Professional name
            "target_type_code": self.target_type.value,     # Internal code for tools
            "scope_description": self.target_type.scope_description,
            "confidence": self.confidence,
            "detected_technologies": self.detected_technologies,
            "detected_frameworks": self.detected_frameworks,
            "detected_server": self.detected_server,
            "detected_cdn": self.detected_cdn,
            "recommended_modules": self.recommended_modules,
            "skip_modules": self.skip_modules,
            "skip_reasons": self.skip_reasons,
            "has_forms": self.has_forms,
            "has_login": self.has_login,
            "has_api_endpoints": self.has_api_endpoints,
            "has_dynamic_content": self.has_dynamic_content,
            "signals": self.signals,
        }


# Module categories by target type
MODULE_RECOMMENDATIONS = {
    # NOTE: Skip reasons are SCOPE-BASED, not architectural assumptions.
    # We don't assume "no database" - we say "not tested in this scope".
    # This is honest and professional.

    TargetType.STATIC_SITE: {
        "recommended": ["ssl", "headers", "cors", "cloud", "supply_chain", "secrets", "subdomain_takeover"],
        # FIX 2026-02-19: Added prototype_pollution - static sites have no backend
        "skip": ["auth", "csrf", "sqli", "ssrf", "oauth", "nosql", "ssti", "cmdi", "lfi", "xxe", "deserialization", "graphql", "prototype_pollution"],
        "skip_reasons": {
            "auth": "Not tested: No authentication endpoints identified in scope",
            "csrf": "Not tested: No state-changing forms identified",
            "sqli": "Not tested: No injectable database endpoints identified",
            "ssrf": "Not tested: No server-side request endpoints identified",
            "oauth": "Not tested: No OAuth endpoints identified",
            "nosql": "Not tested: No injectable database endpoints identified",
            "ssti": "Not tested: No template-rendering endpoints identified",
            "cmdi": "Not tested: No command execution vectors identified",
            "lfi": "Not tested: No file inclusion vectors identified",
            "xxe": "Not tested: No XML processing endpoints identified",
            "deserialization": "Not tested: No deserialization endpoints identified",
            "graphql": "Not tested: No GraphQL endpoint identified",
            "prototype_pollution": "Not applicable: Static site, no JavaScript backend",
        }
    },
    TargetType.SPA: {
        "recommended": ["xss", "cors", "headers", "ssl", "secrets", "supply_chain", "api", "jwt", "cloud", "subdomain_takeover"],
        "skip": ["sqli", "ssti", "cmdi", "lfi", "xxe", "deserialization", "smuggling"],
        "skip_reasons": {
            "sqli": "Not tested: Requires API endpoint testing (out of frontend scope)",
            "ssti": "Not tested: No server-side template endpoints identified in frontend",
            "cmdi": "Not tested: No command execution vectors identified in frontend",
            "lfi": "Not tested: No file inclusion vectors identified in frontend",
            "xxe": "Not tested: No XML processing identified in frontend",
            "deserialization": "Not tested: No deserialization identified in frontend",
            "smuggling": "Not tested: Requires direct backend access",
        }
    },
    # NEW: SPA with Backend API - FULL TESTING (don't skip injection modules!)
    # This is the most common real-world scenario: React/Angular/Vue frontend + REST API
    TargetType.SPA_WITH_BACKEND: {
        "recommended": [
            # Frontend testing
            "xss", "cors", "headers", "ssl", "secrets", "supply_chain", "jwt", "cloud",
            # Backend API testing - CRITICAL for finding real vulns
            "sqli", "nosql", "idor", "api", "auth", "business", "ssrf", "mass_assign",
            "ratelimit", "csrf", "xxe",
        ],
        "skip": ["wordpress", "drupal", "joomla", "firebase_rules", "supabase", "rls_bypass"],
        "skip_reasons": {
            "wordpress": "Not tested: No WordPress installation detected",
            "drupal": "Not tested: No Drupal installation detected",
            "joomla": "Not tested: No Joomla installation detected",
            "firebase_rules": "Not tested: No Firebase backend detected",
            "supabase": "Not tested: No Supabase backend detected",
            "rls_bypass": "Not tested: No BaaS with RLS detected",
        }
    },
    TargetType.BACKEND_CLASSIC: {
        "recommended": ["sqli", "xss", "csrf", "auth", "lfi", "ssti", "cmdi", "ssrf", "xxe",
                       "headers", "ssl", "cors", "nosql", "secrets", "upload", "idor", "api"],
        # FIX 2026-02-19: Skip JS-only modules for server-rendered backends (PHP, Ruby, Python, Java)
        "skip": ["graphql", "prototype_pollution", "dom_xss"],
        "skip_reasons": {
            "graphql": "Not tested: No GraphQL endpoint identified",
            "prototype_pollution": "Not applicable: Backend is not JavaScript (Node.js/Express)",
            "dom_xss": "Not applicable: Server-rendered pages, no client-side DOM manipulation",
        }
    },
    TargetType.API_FIRST: {
        "recommended": ["api", "jwt", "auth", "sqli", "nosql", "ssrf", "idor", "rate_limit",
                       "mass_assignment", "graphql", "cors", "headers", "ssl", "xxe"],
        "skip": ["xss", "csrf", "ssti", "lfi", "upload"],
        "skip_reasons": {
            "xss": "Not tested: API responses don't render in browser context",
            "csrf": "Not tested: API uses token auth (no cookie-based CSRF)",
            "ssti": "Not tested: No HTML template rendering identified in API",
            "lfi": "Not tested: No file serving endpoints identified",
            "upload": "Not tested: Covered by API endpoint testing",
        }
    },
    TargetType.CLOUD_ONLY: {
        "recommended": ["cloud", "s3", "cors", "headers", "ssl", "subdomain_takeover", "secrets"],
        # FIX 2026-02-19: Added prototype_pollution to skip list
        "skip": ["sqli", "xss", "csrf", "auth", "ssrf", "ssti", "cmdi", "lfi", "xxe",
                "nosql", "graphql", "deserialization", "oauth", "jwt", "prototype_pollution"],
        "skip_reasons": {
            "sqli": "Not tested: No injectable database endpoints identified (unauthenticated scope)",
            "xss": "Not tested: No exploitable dynamic rendering identified (unauthenticated scope)",
            "csrf": "Not tested: No testable state-changing operations identified (unauthenticated scope)",
            "auth": "Not tested: Authentication requires credentials (out of scope)",
            "ssrf": "Not tested: No server-side request endpoints identified",
            "ssti": "Not tested: No template-rendering endpoints identified",
            "cmdi": "Not tested: No command execution vectors identified",
            "lfi": "Not tested: No file inclusion vectors identified",
            "xxe": "Not tested: No XML processing endpoints identified",
            "nosql": "Not tested: No injectable database endpoints identified",
            "graphql": "Not tested: No GraphQL endpoint identified",
            "deserialization": "Not tested: No deserialization endpoints identified",
            "oauth": "Not tested: OAuth requires authenticated testing",
            "jwt": "Not tested: JWT requires authenticated testing",
            "prototype_pollution": "Not applicable: Cloud resources, no JavaScript backend",
        }
    },
    TargetType.BAAS_SUPABASE: {
        "recommended": ["supabase_rls", "jwt", "auth", "api", "cors", "headers", "ssl",
                       "secrets", "storage", "realtime", "edge_functions"],
        # FIX 2026-02-19: Added prototype_pollution - BaaS backends are not Node.js
        "skip": ["sqli", "ssti", "cmdi", "lfi", "xxe", "deserialization", "smuggling", "prototype_pollution"],
        "skip_reasons": {
            "sqli": "Not tested: Supabase uses RLS - test RLS bypass instead",
            "ssti": "Not tested: No template-rendering endpoints identified",
            "cmdi": "Not tested: No command execution vectors identified",
            "lfi": "Not tested: No file inclusion vectors identified",
            "xxe": "Not tested: No XML processing endpoints identified",
            "deserialization": "Not tested: No custom deserialization identified",
            "smuggling": "Not tested: Managed infrastructure",
            "prototype_pollution": "Not applicable: BaaS backend, no Node.js runtime",
        }
    },
    TargetType.BAAS_FIREBASE: {
        "recommended": ["firebase_auth", "firebase_rules", "jwt", "api", "cors", "headers",
                       "ssl", "secrets", "storage", "nosql"],
        # FIX 2026-02-19: Added prototype_pollution - Firebase backend is not Node.js
        "skip": ["sqli", "ssti", "cmdi", "lfi", "xxe", "deserialization", "smuggling", "prototype_pollution"],
        "skip_reasons": {
            "sqli": "Not tested: Firebase uses NoSQL - test security rules instead",
            "ssti": "Not tested: No template-rendering endpoints identified",
            "cmdi": "Not tested: No command execution vectors identified",
            "lfi": "Not tested: No file inclusion vectors identified",
            "xxe": "Not tested: No XML processing endpoints identified",
            "deserialization": "Not tested: No custom deserialization identified",
            "smuggling": "Not tested: Managed infrastructure",
            "prototype_pollution": "Not applicable: BaaS backend, no Node.js runtime",
        }
    },
    TargetType.UNKNOWN: {
        "recommended": ["headers", "ssl", "cors", "xss", "sqli", "auth", "secrets"],
        "skip": [],
        "skip_reasons": {}
    }
}


class TargetClassifier:
    """
    Intelligent Target Classifier - Intelligence Before Brute Force
    
    Analyzes target to determine type and recommend appropriate modules.
    This MUST run before any vulnerability scanning.
    """
    
    VERSION = "1.0.0"
    
    # Technology detection patterns
    PATTERNS = {
        # SPAs
        "react": [
            re.compile(r'react', re.I),
            re.compile(r'_react', re.I),
            re.compile(r'__REACT_DEVTOOLS', re.I),
            re.compile(r'data-reactroot', re.I),
            re.compile(r'react-dom', re.I),
        ],
        "vue": [
            re.compile(r'vue\.js', re.I),
            re.compile(r'vue\.min\.js', re.I),
            re.compile(r'__VUE__', re.I),
            re.compile(r'v-cloak', re.I),
            re.compile(r'data-v-[a-f0-9]+', re.I),
        ],
        "angular": [
            re.compile(r'ng-version', re.I),
            re.compile(r'ng-app', re.I),
            re.compile(r'angular\.js', re.I),
            re.compile(r'@angular', re.I),
            re.compile(r'<app-root', re.I),  # Angular CLI default root component
            re.compile(r'_nghost', re.I),
            re.compile(r'_ngcontent', re.I),
            # Angular CLI build artifacts (runtime + main + polyfills + vendor)
            re.compile(r'runtime\.js.*main\.js|main\.js.*runtime\.js', re.I),
            re.compile(r'polyfills\.js', re.I),
        ],
        "nextjs": [
            re.compile(r'/_next/', re.I),
            re.compile(r'__NEXT_DATA__', re.I),
            re.compile(r'next/dist', re.I),
            re.compile(r'NEXT_PUBLIC_', re.I),
        ],
        "nuxt": [
            re.compile(r'/_nuxt/', re.I),
            re.compile(r'__NUXT__', re.I),
            re.compile(r'nuxt\.js', re.I),
        ],
        "svelte": [
            re.compile(r'svelte', re.I),
            re.compile(r'__svelte', re.I),
            re.compile(r'\.svelte', re.I),
        ],
        "sveltekit": [
            re.compile(r'_app/immutable', re.I),
            re.compile(r'__sveltekit', re.I),
        ],
        "htmx": [
            re.compile(r'htmx\.org', re.I),
            re.compile(r'hx-get|hx-post|hx-target|hx-swap', re.I),
        ],
        "alpinejs": [
            re.compile(r'alpine\.js', re.I),
            re.compile(r'x-data|x-bind|x-on|x-show', re.I),
        ],
        "remix": [
            re.compile(r'remix', re.I),
            re.compile(r'__remix', re.I),
        ],
        "astro": [
            re.compile(r'astro', re.I),
            re.compile(r'data-astro', re.I),
        ],
        "solidjs": [
            re.compile(r'solid-js', re.I),
            re.compile(r'_\$', re.I),  # Solid's internal marker
        ],
        "qwik": [
            re.compile(r'qwik', re.I),
            re.compile(r'q:container', re.I),
        ],

        # Backend frameworks
        "php": [
            re.compile(r'\.php', re.I),
            re.compile(r'PHPSESSID', re.I),
            re.compile(r'X-Powered-By:\s*PHP', re.I),
        ],
        "laravel": [
            re.compile(r'laravel', re.I),
            re.compile(r'laravel_session', re.I),
            re.compile(r'XSRF-TOKEN', re.I),
            re.compile(r'csrf-token', re.I),
        ],
        "django": [
            re.compile(r'csrfmiddlewaretoken', re.I),
            re.compile(r'django', re.I),
            re.compile(r'__admin__', re.I),
        ],
        "rails": [
            re.compile(r'_rails', re.I),
            re.compile(r'rails-ujs', re.I),
            re.compile(r'authenticity_token', re.I),
        ],
        "aspnet": [
            re.compile(r'__VIEWSTATE', re.I),
            re.compile(r'__EVENTVALIDATION', re.I),
            re.compile(r'ASP\.NET', re.I),
            re.compile(r'\.aspx', re.I),
        ],
        "spring": [
            re.compile(r'JSESSIONID', re.I),
            re.compile(r'spring', re.I),
            re.compile(r'X-Application-Context', re.I),
        ],
        
        # BaaS
        "supabase": [
            re.compile(r'supabase\.co', re.I),
            re.compile(r'supabase', re.I),
            re.compile(r'SUPABASE_URL', re.I),
            re.compile(r'SUPABASE_ANON_KEY', re.I),
        ],
        "firebase": [
            re.compile(r'firebase', re.I),
            re.compile(r'firebaseio\.com', re.I),
            re.compile(r'firebaseapp\.com', re.I),
            re.compile(r'FIREBASE_', re.I),
        ],
        
        # CDN/Cloud
        "cloudflare": [
            re.compile(r'cloudflare', re.I),
            re.compile(r'cf-ray', re.I),
            re.compile(r'__cfduid', re.I),
        ],
        "cloudfront": [
            re.compile(r'cloudfront', re.I),
            re.compile(r'x-amz-cf-', re.I),
        ],
        "s3": [
            re.compile(r's3\.amazonaws\.com', re.I),
            re.compile(r'\.s3\.', re.I),
            re.compile(r'x-amz-', re.I),
        ],
        "vercel": [
            re.compile(r'vercel', re.I),
            re.compile(r'\.vercel\.app', re.I),
            re.compile(r'x-vercel-', re.I),
        ],
        "netlify": [
            re.compile(r'netlify', re.I),
            re.compile(r'\.netlify\.app', re.I),
            re.compile(r'x-nf-', re.I),
        ],
        
        # Servers
        "nginx": [re.compile(r'nginx', re.I)],
        "apache": [re.compile(r'apache', re.I)],
        "iis": [re.compile(r'IIS', re.I), re.compile(r'ASP\.NET', re.I)],
    }
    
    # Static site indicators
    STATIC_INDICATORS = [
        re.compile(r'github\.io', re.I),
        re.compile(r'gitlab\.io', re.I),
        re.compile(r'pages\.dev', re.I),
        re.compile(r'surge\.sh', re.I),
        re.compile(r'static', re.I),
    ]
    
    # API indicators
    API_INDICATORS = [
        re.compile(r'/api/', re.I),
        re.compile(r'/v\d+/', re.I),
        re.compile(r'application/json', re.I),
        re.compile(r'swagger', re.I),
        re.compile(r'openapi', re.I),
        re.compile(r'graphql', re.I),
    ]
    
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings
        self.timeout = httpx.Timeout(15.0)
    
    async def classify(self, target: str) -> TargetClassification:
        """
        Classify target type and recommend modules.
        
        Args:
            target: Target URL
            
        Returns:
            TargetClassification with type and module recommendations
        """
        logger.info(f"🎯 Target Classification starting for: {target}")
        
        result = TargetClassification(
            target_type=TargetType.UNKNOWN,
            confidence=0.0,
        )
        
        # Normalize URL
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
            ) as client:
                # Fetch main page
                response = await client.get(target)
                html = response.text
                headers = dict(response.headers)
                cookies = response.cookies
                http_status = response.status_code

                # Collect signals
                signals = await self._collect_signals(client, target, html, headers, cookies)
                signals["http_status"] = http_status  # Add HTTP status to signals

                # Log warning if main page is blocked
                if http_status in (401, 403, 503):
                    logger.warning(f"⚠️ Main page returned HTTP {http_status} - target may be behind WAF or access control")

                result.signals = signals
                
                # Detect technologies
                result.detected_technologies = self._detect_technologies(html, headers)
                result.detected_frameworks = self._detect_frameworks(html, headers)
                result.detected_server = self._detect_server(headers)
                result.detected_cdn = self._detect_cdn(headers)
                
                # Detect features
                result.has_forms = bool(re.search(r'<form', html, re.I))
                result.has_login = bool(re.search(r'password|login|signin|auth', html, re.I))
                result.has_api_endpoints = bool(re.search(r'/api/|/v\d/', html, re.I))
                result.has_dynamic_content = self._has_dynamic_content(html, headers)
                result.has_cookies = len(cookies) > 0
                result.has_sessions = bool(re.search(r'session|PHPSESSID|JSESSIONID|connect\.sid', str(cookies), re.I))
                
                # Classify target type
                result.target_type, result.confidence = self._classify_type(result, signals)
                
                # Get module recommendations
                recommendations = MODULE_RECOMMENDATIONS.get(result.target_type, MODULE_RECOMMENDATIONS[TargetType.UNKNOWN])
                result.recommended_modules = recommendations["recommended"]
                result.skip_modules = recommendations["skip"]
                result.skip_reasons = recommendations["skip_reasons"]
                
                logger.info(f"✅ Classification: {result.target_type.value} (confidence: {result.confidence:.0%})")
                logger.info(f"   Technologies: {result.detected_technologies}")
                logger.info(f"   Frameworks: {result.detected_frameworks}")
                logger.info(f"   Recommended: {len(result.recommended_modules)} modules")
                logger.info(f"   Skip: {len(result.skip_modules)} modules")
                
        except Exception as e:
            logger.warning(f"Classification failed: {e}")
            # Return default recommendations
            result.target_type = TargetType.UNKNOWN
            result.confidence = 0.0
            recommendations = MODULE_RECOMMENDATIONS[TargetType.UNKNOWN]
            result.recommended_modules = recommendations["recommended"]
            result.skip_modules = recommendations["skip"]
            result.skip_reasons = recommendations["skip_reasons"]
        
        return result
    
    async def _collect_signals(
        self,
        client: httpx.AsyncClient,
        target: str,
        html: str,
        headers: dict,
        cookies: httpx.Cookies
    ) -> dict:
        """Collect signals for classification with improved SPA detection."""
        signals = {
            "html_size": len(html),
            "has_html_doctype": html.strip().lower().startswith('<!doctype'),
            "has_body": '<body' in html.lower(),
            "script_count": len(re.findall(r'<script', html, re.I)),
            "link_count": len(re.findall(r'<a\s+href', html, re.I)),
            "form_count": len(re.findall(r'<form', html, re.I)),
            "input_count": len(re.findall(r'<input', html, re.I)),
            "cookie_count": len(cookies),
            "header_count": len(headers),
            "content_type": headers.get('content-type', ''),
            "server": headers.get('server', ''),
            "x_powered_by": headers.get('x-powered-by', ''),
        }

        # =====================================================================
        # SPA-SPECIFIC INDICATORS (IMPROVED)
        # =====================================================================
        spa_indicators = 0

        # React indicators
        if re.search(r'data-reactroot|_reactRootContainer|__REACT_DEVTOOLS|react\.production', html, re.I):
            spa_indicators += 2

        # Vue indicators
        if re.search(r'__VUE__|v-cloak|data-v-[a-f0-9]+|vue\.runtime', html, re.I):
            spa_indicators += 2

        # Angular indicators (including Angular CLI apps)
        if re.search(r'ng-version|ng-app|ng-controller|\[\(ngModel\)\]|@angular/core', html, re.I):
            spa_indicators += 2
        # Angular CLI default structure: <app-root> + runtime.js + main.js + polyfills.js
        if re.search(r'<app-root', html, re.I):
            spa_indicators += 1
            # If also has Angular CLI build artifacts, it's definitely Angular
            if re.search(r'runtime\.js', html, re.I) and re.search(r'main\.js', html, re.I):
                spa_indicators += 2  # Strong Angular CLI indicator

        # Next.js indicators
        if re.search(r'__NEXT_DATA__|/_next/static|x-nextjs', html, re.I):
            spa_indicators += 2

        # Nuxt indicators
        if re.search(r'__NUXT__|/_nuxt/', html, re.I):
            spa_indicators += 2

        # Generic SPA indicators (app shell pattern)
        if re.search(r'<app-root|<div\s+id=["\']app["\']|<div\s+id=["\']root["\']', html, re.I):
            spa_indicators += 1

        # State management / hydration
        if re.search(r'__INITIAL_STATE__|__PRELOADED_STATE__|window\.__', html, re.I):
            spa_indicators += 1

        # Webpack/bundler artifacts
        if re.search(r'webpackJsonp|__webpack_require__|runtime\.js|vendor\.js|main\.js', html, re.I):
            spa_indicators += 1

        signals["spa_indicators"] = spa_indicators

        # =====================================================================
        # API DETECTION (IMPROVED)
        # =====================================================================
        api_paths = ['/api', '/api/v1', '/graphql', '/.well-known/openapi.json']
        for path in api_paths:
            try:
                resp = await client.get(f"{target.rstrip('/')}{path}", timeout=5.0)
                # Consider 200, 201, 401, 403, 500 as valid API responses
                # FIX 2026-02-18: Added 400 — GraphQL returns 400 for malformed queries but still indicates endpoint exists
                if resp.status_code in (200, 201, 400, 401, 403, 500):
                    signals[f"api_endpoint_{path}"] = True
                    # Check if it returns JSON
                    if 'application/json' in resp.headers.get('content-type', ''):
                        signals[f"api_endpoint_{path}_json"] = True
                # FIX 2026-02-18: Also try POST for GraphQL (GET may return 405)
                if path == '/graphql' and resp.status_code == 405:
                    try:
                        post_resp = await client.post(
                            f"{target.rstrip('/')}{path}",
                            json={"query": "{ __typename }"},
                            timeout=5.0
                        )
                        if post_resp.status_code in (200, 400):
                            signals[f"api_endpoint_{path}"] = True
                            if 'application/json' in post_resp.headers.get('content-type', ''):
                                signals[f"api_endpoint_{path}_json"] = True
                    except Exception:
                        pass
            except Exception:
                pass

        # Check for OpenAPI/Swagger
        signals["has_openapi"] = (
            signals.get('api_endpoint_/.well-known/openapi.json', False) or
            '/swagger' in html.lower() or
            '/api-docs' in html.lower() or
            'openapi' in html.lower()
        )

        # =====================================================================
        # JS BUNDLE ANALYSIS (IMPROVED)
        # =====================================================================
        try:
            js_files = re.findall(r'src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', html)
            signals["js_file_count"] = len(js_files)

            # Calculate total JS bundle size (sum of all JS files)
            total_js_size = 0
            from urllib.parse import urljoin

            # Check main bundle files (limit to first 5 to avoid timeouts)
            for js_file in js_files[:5]:
                js_url = js_file
                if not js_url.startswith('http'):
                    js_url = urljoin(target, js_url)
                try:
                    js_resp = await client.head(js_url, timeout=3.0)
                    size = int(js_resp.headers.get('content-length', 0))
                    total_js_size += size
                except Exception:
                    pass

            signals["js_bundle_size"] = total_js_size

        except Exception:
            signals["js_file_count"] = 0
            signals["js_bundle_size"] = 0

        # =====================================================================
        # SERVER-SIDE RENDERING DETECTION
        # =====================================================================
        # If HTML has significant content (not just an app shell), it's likely SSR
        body_content_match = re.search(r'<body[^>]*>(.*?)</body>', html, re.DOTALL | re.I)
        if body_content_match:
            body_content = body_content_match.group(1)
            # Remove scripts and styles
            body_content = re.sub(r'<script[^>]*>.*?</script>', '', body_content, flags=re.DOTALL | re.I)
            body_content = re.sub(r'<style[^>]*>.*?</style>', '', body_content, flags=re.DOTALL | re.I)
            body_text = re.sub(r'<[^>]+>', '', body_content).strip()

            # If there's substantial text content, it's server-rendered
            signals["has_server_rendered_content"] = len(body_text) > 500
        else:
            signals["has_server_rendered_content"] = False

        return signals
    
    def _detect_technologies(self, html: str, headers: dict) -> List[str]:
        """Detect technologies from HTML and headers."""
        detected = []
        combined = html + str(headers)
        
        for tech, patterns in self.PATTERNS.items():
            for pattern in patterns:
                if pattern.search(combined):
                    detected.append(tech)
                    break
        
        return list(set(detected))
    
    def _detect_frameworks(self, html: str, headers: dict) -> List[str]:
        """Detect web frameworks (including modern frameworks)."""
        frameworks = []
        combined = html + str(headers)

        # All framework patterns from PATTERNS dict
        framework_patterns = {
            # SPAs / Frontend
            "react": self.PATTERNS.get("react", []),
            "vue": self.PATTERNS.get("vue", []),
            "angular": self.PATTERNS.get("angular", []),
            "nextjs": self.PATTERNS.get("nextjs", []),
            "nuxt": self.PATTERNS.get("nuxt", []),
            "svelte": self.PATTERNS.get("svelte", []),
            "sveltekit": self.PATTERNS.get("sveltekit", []),
            "htmx": self.PATTERNS.get("htmx", []),
            "alpinejs": self.PATTERNS.get("alpinejs", []),
            "remix": self.PATTERNS.get("remix", []),
            "astro": self.PATTERNS.get("astro", []),
            "solidjs": self.PATTERNS.get("solidjs", []),
            "qwik": self.PATTERNS.get("qwik", []),
            # Backend
            "laravel": self.PATTERNS.get("laravel", []),
            "django": self.PATTERNS.get("django", []),
            "rails": self.PATTERNS.get("rails", []),
            "aspnet": self.PATTERNS.get("aspnet", []),
            "spring": self.PATTERNS.get("spring", []),
        }

        for framework, patterns in framework_patterns.items():
            for pattern in patterns:
                if pattern.search(combined):
                    frameworks.append(framework)
                    break

        return frameworks
    
    def _detect_server(self, headers: dict) -> str:
        """Detect web server from headers."""
        server = headers.get('server', '').lower()
        x_powered = headers.get('x-powered-by', '').lower()
        
        if 'nginx' in server:
            return 'nginx'
        elif 'apache' in server:
            return 'apache'
        elif 'iis' in server or 'asp.net' in x_powered:
            return 'iis'
        elif 'cloudflare' in server:
            return 'cloudflare'
        elif 'vercel' in server:
            return 'vercel'
        
        return server[:50] if server else 'unknown'
    
    def _detect_cdn(self, headers: dict) -> str:
        """Detect CDN from headers."""
        for key, value in headers.items():
            key_lower = key.lower()
            if 'cf-ray' in key_lower or 'cf-cache' in key_lower:
                return 'cloudflare'
            elif 'x-amz-cf' in key_lower or 'x-cache' in key_lower and 'cloudfront' in str(value).lower():
                return 'cloudfront'
            elif 'x-vercel' in key_lower:
                return 'vercel'
            elif 'x-nf' in key_lower:
                return 'netlify'
        
        return ''
    
    def _has_dynamic_content(self, html: str, headers: dict) -> bool:
        """Check if site has dynamic content."""
        # Dynamic indicators
        dynamic_indicators = [
            'set-cookie' in str(headers).lower(),
            'csrf' in html.lower(),
            'session' in html.lower(),
            '<form' in html.lower() and 'action=' in html.lower(),
            'ajax' in html.lower(),
            'fetch(' in html.lower(),
            'XMLHttpRequest' in html,
        ]
        
        return sum(dynamic_indicators) >= 2
    
    def _classify_type(self, result: TargetClassification, signals: dict) -> tuple[TargetType, float]:
        """
        Determine target type based on collected information.

        IMPROVED LOGIC v2.0:
        - CDN presence is NOT an application type - it's just a delivery mechanism
        - CLOUD_ONLY is only for targets with NO application behind them (pure static hosting)
        - SPA detection is boosted when JS frameworks or large bundles are detected
        - API detection considers GraphQL and REST endpoints
        - Application type always takes priority over CDN/hosting type
        """
        scores = {
            TargetType.STATIC_SITE: 0.0,
            TargetType.SPA: 0.0,
            TargetType.SPA_WITH_BACKEND: 0.0,  # NEW: Full-stack apps (SPA + API)
            TargetType.BACKEND_CLASSIC: 0.0,
            TargetType.API_FIRST: 0.0,
            TargetType.CLOUD_ONLY: 0.0,
            TargetType.BAAS_SUPABASE: 0.0,
            TargetType.BAAS_FIREBASE: 0.0,
        }

        # =====================================================================
        # PHASE 1: BaaS Detection (HIGHEST PRIORITY)
        # =====================================================================
        if 'supabase' in result.detected_technologies:
            scores[TargetType.BAAS_SUPABASE] += 0.95
        if 'firebase' in result.detected_technologies:
            scores[TargetType.BAAS_FIREBASE] += 0.95

        # =====================================================================
        # PHASE 2: APPLICATION TYPE DETECTION
        # =====================================================================

        # --- SPA Detection (improved) ---
        spa_frameworks = {
            'react', 'vue', 'angular', 'nextjs', 'nuxt', 'svelte', 'sveltekit',
            'htmx', 'alpinejs', 'remix', 'astro', 'solidjs', 'qwik', 'ember', 'backbone'
        }
        spa_framework_detected = any(f in result.detected_frameworks for f in spa_frameworks)

        if spa_framework_detected:
            scores[TargetType.SPA] += 0.8  # Strong signal

        # Large JS bundles indicate SPA
        js_bundle_size = signals.get('js_bundle_size', 0)
        if js_bundle_size > 500000:  # > 500KB JS
            scores[TargetType.SPA] += 0.3
        elif js_bundle_size > 200000:  # > 200KB JS
            scores[TargetType.SPA] += 0.2
        elif js_bundle_size > 100000:  # > 100KB JS
            scores[TargetType.SPA] += 0.1

        # Multiple JS files indicate SPA
        js_file_count = signals.get('js_file_count', 0)
        if js_file_count > 10:
            scores[TargetType.SPA] += 0.2
        elif js_file_count > 5:
            scores[TargetType.SPA] += 0.15
        elif js_file_count > 3:
            scores[TargetType.SPA] += 0.1

        # SPA-specific patterns in HTML (app root, state hydration, etc.)
        spa_indicators = signals.get('spa_indicators', 0)
        if spa_indicators > 0:
            scores[TargetType.SPA] += 0.15 * min(spa_indicators, 3)

        # --- Backend Classic Detection ---
        backend_frameworks = {'php', 'laravel', 'django', 'rails', 'aspnet', 'spring', 'flask', 'express'}
        if any(f in result.detected_technologies for f in backend_frameworks):
            scores[TargetType.BACKEND_CLASSIC] += 0.8

        # Session cookies indicate server-side state management
        if result.has_sessions:
            scores[TargetType.BACKEND_CLASSIC] += 0.35

        # Forms with login indicate traditional web app
        if result.has_forms and result.has_login:
            scores[TargetType.BACKEND_CLASSIC] += 0.25
        elif result.has_forms:
            scores[TargetType.BACKEND_CLASSIC] += 0.15

        # Server-side rendering indicators
        if signals.get('has_server_rendered_content', False):
            scores[TargetType.BACKEND_CLASSIC] += 0.2

        # --- API-First Detection ---
        has_api_endpoint = signals.get('api_endpoint_/api', False)
        has_graphql = signals.get('api_endpoint_/graphql', False)
        has_openapi = signals.get('has_openapi', False)

        if has_graphql:
            scores[TargetType.API_FIRST] += 0.7
        if has_api_endpoint:
            scores[TargetType.API_FIRST] += 0.5
        if has_openapi:
            scores[TargetType.API_FIRST] += 0.3

        # JSON content type on main page suggests API
        if 'application/json' in signals.get('content_type', ''):
            scores[TargetType.API_FIRST] += 0.5

        # No HTML body suggests API-only
        if not signals.get('has_body', True):
            scores[TargetType.API_FIRST] += 0.3

        # =====================================================================
        # PHASE 3: STATIC/CLOUD-ONLY DETECTION (LOWEST PRIORITY)
        # Only when NO application indicators are present
        # =====================================================================

        # Calculate if there's any application detected
        has_application = (
            scores[TargetType.SPA] > 0.3 or
            scores[TargetType.BACKEND_CLASSIC] > 0.3 or
            scores[TargetType.API_FIRST] > 0.3 or
            scores[TargetType.BAAS_SUPABASE] > 0.3 or
            scores[TargetType.BAAS_FIREBASE] > 0.3
        )

        # Static site detection
        is_minimal_js = signals.get('script_count', 0) < 3
        is_no_forms = signals.get('form_count', 0) == 0
        is_small_html = signals.get('html_size', 0) < 50000
        is_few_js_files = signals.get('js_file_count', 0) < 3

        if not has_application:
            if is_minimal_js and is_no_forms:
                scores[TargetType.STATIC_SITE] += 0.6
            if not result.has_dynamic_content and not result.has_sessions:
                scores[TargetType.STATIC_SITE] += 0.3
            if is_small_html and is_few_js_files:
                scores[TargetType.STATIC_SITE] += 0.2

        # Cloud-only detection (VERY conservative - only for truly static/CDN-only)
        # CDN is NOT an application type - it's just hosting
        cloud_indicators = {'s3', 'cloudfront'}  # Only pure cloud storage, not generic CDNs
        pure_cloud_hosting = any(c in result.detected_technologies for c in cloud_indicators)

        # IMPORTANT: Cloudflare, Vercel, Netlify are NOT cloud-only indicators
        # They're just CDN/hosting providers that serve real applications

        if not has_application and pure_cloud_hosting:
            # Only boost cloud_only if there's literally no application
            if not result.has_dynamic_content and is_no_forms and is_minimal_js:
                scores[TargetType.CLOUD_ONLY] += 0.7
            elif not result.has_dynamic_content:
                scores[TargetType.CLOUD_ONLY] += 0.4

        # =====================================================================
        # PHASE 4: FINAL SCORING
        # =====================================================================

        # CRITICAL FIX: If SPA framework detected AND API endpoints found,
        # classify as SPA_WITH_BACKEND to enable FULL testing (including SQLi, IDOR, etc.)
        # This is the common real-world case: React/Angular/Vue + REST API backend
        api_endpoints_count = signals.get('api_endpoints_count', 0)
        has_discovered_apis = (
            has_api_endpoint or
            has_graphql or
            api_endpoints_count >= 3 or
            signals.get('has_rest_endpoints', False)
        )

        if spa_framework_detected and has_discovered_apis:
            # FULL-STACK APPLICATION: SPA frontend + Backend API
            # Must test BOTH frontend (XSS, CORS) AND backend (SQLi, IDOR, Auth)
            scores[TargetType.SPA_WITH_BACKEND] = max(
                scores[TargetType.SPA],
                scores[TargetType.API_FIRST]
            ) + 0.2  # Boost to ensure this wins over pure SPA
            logger.info(f"🎯 Detected SPA with Backend API - enabling full vulnerability testing")
        elif spa_framework_detected and scores[TargetType.API_FIRST] > 0.3:
            # API indicators present but not confirmed - still use SPA_WITH_BACKEND to be safe
            scores[TargetType.SPA_WITH_BACKEND] = scores[TargetType.SPA] + 0.1
            logger.info(f"🎯 SPA with potential backend API - enabling injection testing")

        # Find best match
        best_type = max(scores, key=scores.get)
        best_score = scores[best_type]

        # Log scoring for debugging
        logger.debug(f"Classification scores: {scores}")

        # Normalize confidence
        confidence = min(best_score, 1.0)

        # Default to UNKNOWN if low confidence
        if confidence < 0.3:
            return TargetType.UNKNOWN, confidence

        return best_type, confidence
    
    def get_skip_explanation(self, result: TargetClassification) -> str:
        """Generate human-readable skip explanation."""
        if not result.skip_modules:
            return "No modules skipped - full scan recommended."
        
        lines = [
            f"🎯 Target Type: {result.target_type.value} (confidence: {result.confidence:.0%})",
            f"📊 Detected: {', '.join(result.detected_technologies) or 'None'}",
            "",
            "⏭️ Skipped Modules:",
        ]
        
        for module in result.skip_modules:
            reason = result.skip_reasons.get(module, "Not applicable for this target type")
            lines.append(f"  • {module}: {reason}")
        
        return "\n".join(lines)
