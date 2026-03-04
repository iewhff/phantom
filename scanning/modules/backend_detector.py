"""
Backend Detector - Identifies backend type (Supabase, Firebase, Custom API).

This is FASE 0 of the SecureDev checklist - MANDATORY for all scans.
Based on detected backend, different testing phases will be executed.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx

from utils.logger import get_logger
from utils.scan_client import get_scan_client

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class BackendType(Enum):
    """Types of backend that can be detected."""
    SUPABASE = auto()
    FIREBASE = auto()
    MONGODB_ATLAS = auto()
    CUSTOM_REST = auto()
    CUSTOM_GRAPHQL = auto()
    UNKNOWN = auto()


@dataclass
class SupabaseConfig:
    """Supabase configuration extracted from target."""
    project_url: str = ""
    anon_key: str = ""
    service_role_key: str = ""  # CRITICAL if exposed
    project_ref: str = ""
    
    @property
    def is_valid(self) -> bool:
        return bool(self.project_url and self.anon_key)
    
    @property
    def has_service_role(self) -> bool:
        """Service role key exposed is CRITICAL vulnerability."""
        return bool(self.service_role_key)


@dataclass
class FirebaseConfig:
    """Firebase configuration extracted from target."""
    api_key: str = ""
    auth_domain: str = ""
    project_id: str = ""
    storage_bucket: str = ""
    messaging_sender_id: str = ""
    app_id: str = ""
    database_url: str = ""
    
    @property
    def is_valid(self) -> bool:
        return bool(self.api_key and self.project_id)


@dataclass
class ThirdPartyKeys:
    """Third-party service keys discovered."""
    stripe_publishable: list[str] = field(default_factory=list)
    stripe_secret: list[str] = field(default_factory=list)  # CRITICAL if found
    sentry_dsn: list[str] = field(default_factory=list)
    posthog_key: str = ""
    google_analytics: list[str] = field(default_factory=list)
    facebook_pixel: list[str] = field(default_factory=list)
    recaptcha_sitekey: str = ""
    hcaptcha_sitekey: str = ""
    
    @property
    def has_critical_exposure(self) -> bool:
        """Check if any secret keys are exposed."""
        return bool(self.stripe_secret)


@dataclass
class BackendDetectionResult:
    """Result of backend detection."""
    backend_type: BackendType
    confidence: float  # 0.0 to 1.0
    supabase_config: SupabaseConfig | None = None
    firebase_config: FirebaseConfig | None = None
    third_party: ThirdPartyKeys = field(default_factory=ThirdPartyKeys)
    api_endpoints: list[str] = field(default_factory=list)
    graphql_endpoint: str = ""
    websocket_endpoint: str = ""
    detected_frameworks: list[str] = field(default_factory=list)
    env_variables: dict[str, str] = field(default_factory=dict)
    
    def get_applicable_phases(self) -> list[str]:
        """Get SecureDev phases applicable to this backend."""
        # Common phases for all backends (ALWAYS RUN)
        common_phases = [
            "0",       # Backend Detection (already done)
            "7",       # Token Analysis
            "10",      # Third-Party Keys
            "12",      # JS Bundle Analysis
            "14",      # Mass Assignment
            "15",      # External Tools (nmap/nuclei)
            "19",      # SSL/TLS
            "CSRF",    # CSRF Testing
            # EXTRA phases - Universal, always run
            "XSS",     # XSS Testing (EXTRA-1)
            "SQLI",    # SQL Injection (EXTRA-2)
            "HEADERS", # Security Headers
        ]
        
        if self.backend_type == BackendType.SUPABASE:
            return common_phases + [
                "2",      # RLS Bypass
                "3",      # Storage
                "4",      # Edge Functions
                "5",      # Realtime
                "6",      # Auth Config
                "20",     # Dashboard Exposure
                "20-ADV", # Advanced RLS Bypass
            ]
        elif self.backend_type == BackendType.FIREBASE:
            return common_phases + [
                "F1",  # Firebase Auth
                "F2",  # Firestore Rules
                "F3",  # RTDB Rules
                "F4",  # Storage Rules
            ]
        else:  # Custom API
            return common_phases + [
                "C1",  # REST API Security
                "C2",  # GraphQL Security
                "C3",  # Auth Flow
                "C4",  # Rate Limiting
            ]


class BackendDetector:
    """
    Detects the backend type of a web application.
    
    This is FASE 0 of SecureDev checklist - determines which tests to run.
    
    Detection Order:
    1. Check for Supabase patterns (URL, anon key, JWT)
    2. Check for Firebase patterns (config object, auth domain)
    3. Check for MongoDB Atlas patterns
    4. Check for GraphQL endpoint
    5. Default to Custom REST API
    """
    
    # Supabase patterns
    SUPABASE_URL_PATTERN = re.compile(r'https://([a-z0-9]+)\.supabase\.co')
    SUPABASE_ANON_KEY_PATTERN = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
    
    # Firebase patterns
    FIREBASE_CONFIG_PATTERN = re.compile(
        r'(?:firebase|firebaseConfig)\s*[=:]\s*\{[^}]+apiKey[^}]+\}',
        re.IGNORECASE | re.DOTALL
    )
    FIREBASE_URL_PATTERN = re.compile(r'([a-z0-9-]+)\.firebaseio\.com')
    FIREBASE_AUTH_DOMAIN_PATTERN = re.compile(r'([a-z0-9-]+)\.firebaseapp\.com')
    
    # MongoDB patterns
    MONGODB_PATTERN = re.compile(r'mongodb\+srv://[^"\']+\.mongodb\.net')
    
    # GraphQL patterns
    GRAPHQL_PATTERNS = [
        re.compile(r'/graphql(?:/v\d+)?', re.IGNORECASE),
        re.compile(r'__typename', re.IGNORECASE),
        re.compile(r'query\s+\w+\s*\{', re.IGNORECASE),
    ]
    
    # Third-party patterns
    STRIPE_PK_PATTERN = re.compile(r'pk_(live|test)_[A-Za-z0-9]{24,}')
    STRIPE_SK_PATTERN = re.compile(r'sk_(live|test)_[A-Za-z0-9]{24,}')
    SENTRY_DSN_PATTERN = re.compile(r'https://[a-f0-9]+@o\d+\.ingest\.sentry\.io/\d+')
    POSTHOG_PATTERN = re.compile(r'phc_[A-Za-z0-9]{32,}')
    GA_PATTERN = re.compile(r'(?:UA-\d+-\d+|G-[A-Z0-9]+)')
    FB_PIXEL_PATTERN = re.compile(r'fbq\s*\(\s*[\'"]init[\'"]\s*,\s*[\'"](\d+)[\'"]')
    
    # Env variable patterns
    ENV_PATTERNS = [
        re.compile(r'(?:NEXT_PUBLIC|VITE|REACT_APP|VUE_APP|NUXT)_[A-Z_]+'),
        re.compile(r'process\.env\.([A-Z_]+)'),
    ]
    
    # Builder detection patterns
    BUILDERS = {
        "lovable": [re.compile(r'lovable\.dev'), re.compile(r'gptengineer\.app')],
        "bolt": [re.compile(r'bolt\.new'), re.compile(r'stackblitz')],
        "replit": [re.compile(r'replit\.com'), re.compile(r'\.repl\.co')],
        "vercel": [re.compile(r'vercel\.app'), re.compile(r'_vercel')],
        "netlify": [re.compile(r'netlify\.app'), re.compile(r'netlify')],
    }
    
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings
        self.timeout = httpx.Timeout(15.0)
    
    async def scan(self, target: str, asset_data: dict | None = None) -> dict:
        """
        Scan interface for compatibility with full_scanner.
        
        Args:
            target: Target URL to analyze
            asset_data: Optional asset data (ignored, for interface compatibility)
            
        Returns:
            Dict with findings and info from backend detection
        """
        result = await self.detect(target)
        
        findings = []
        info = []
        
        # Report critical findings as vulnerabilities
        if result.supabase_config and result.supabase_config.has_service_role:
            findings.append({
                "type": "critical_exposure",
                "title": "Supabase service_role key exposed",
                "severity": "critical",
                "description": "The Supabase service_role key is exposed in client-side code. This key has full database access and bypasses RLS policies.",
                "evidence": f"Project: {result.supabase_config.project_ref}",
                "remediation": "Remove service_role key from client code. Use only anon key on frontend.",
                "cwe": "CWE-798",
            })
        
        if result.third_party.has_critical_exposure:
            for key in result.third_party.stripe_secret:
                findings.append({
                    "type": "critical_exposure",
                    "title": "Stripe SECRET key exposed",
                    "severity": "critical",
                    "description": "A Stripe secret key was found in client-side code. This allows full access to the Stripe account.",
                    "evidence": f"Key: {key[:12]}...{key[-4:]}",
                    "remediation": "Rotate the key immediately and remove from client code.",
                    "cwe": "CWE-798",
                })
        
        # Add info about detected backend
        info.append({
            "type": "backend_detection",
            "backend_type": result.backend_type.name,
            "confidence": result.confidence,
            "frameworks": getattr(result, 'detected_frameworks', []),
            "api_endpoints": result.api_endpoints[:10],  # Limit output
            "graphql_endpoint": result.graphql_endpoint,
            "applicable_phases": result.get_applicable_phases(),
        })
        
        # Report exposed keys as info (not critical)
        if result.third_party.stripe_publishable:
            info.append({
                "type": "exposed_key",
                "key_type": "stripe_publishable",
                "count": len(result.third_party.stripe_publishable),
                "note": "Publishable keys are safe to expose (by design)",
            })
        
        if result.third_party.sentry_dsn:
            info.append({
                "type": "exposed_key", 
                "key_type": "sentry_dsn",
                "count": len(result.third_party.sentry_dsn),
                "note": "Sentry DSN exposure allows error submission (low risk)",
            })
        
        return {"findings": findings, "info": info}
    
    async def detect(self, target: str) -> BackendDetectionResult:
        """
        Detect backend type for target URL.
        
        Args:
            target: Target URL to analyze
            
        Returns:
            BackendDetectionResult with detected backend and configs
        """
        logger.info(f"🔍 FASE 0: Backend Detection for {target}")
        
        result = BackendDetectionResult(
            backend_type=BackendType.UNKNOWN,
            confidence=0.0,
        )
        
        # Normalize URL
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        try:
            async with get_scan_client(
                timeout=self.timeout,
                follow_redirects=True,
                verify_ssl=False,
            ) as client:
                # Fetch main page
                response = await client.get(target)
                html_content = response.text
                
                # Check window object for configs
                window_configs = await self._check_window_object(client, target)
                
                # Fetch JS bundles
                js_content = await self._fetch_js_bundles(client, target, html_content)
                all_content = html_content + js_content + json.dumps(window_configs)
                
                # Detect Supabase
                supabase_config = self._detect_supabase(all_content)
                if supabase_config and supabase_config.is_valid:
                    result.backend_type = BackendType.SUPABASE
                    result.supabase_config = supabase_config
                    result.confidence = 0.95
                    logger.info(f"✅ Detected: SUPABASE (project: {supabase_config.project_ref})")
                    if supabase_config.has_service_role:
                        logger.critical("🚨 CRITICAL: service_role key exposed!")
                
                # Detect Firebase
                firebase_config = self._detect_firebase(all_content)
                if firebase_config and firebase_config.is_valid:
                    if result.backend_type == BackendType.UNKNOWN:
                        result.backend_type = BackendType.FIREBASE
                        result.confidence = 0.95
                    result.firebase_config = firebase_config
                    logger.info(f"✅ Detected: FIREBASE (project: {firebase_config.project_id})")
                
                # Detect MongoDB Atlas
                if self._detect_mongodb(all_content):
                    if result.backend_type == BackendType.UNKNOWN:
                        result.backend_type = BackendType.MONGODB_ATLAS
                        result.confidence = 0.8
                    logger.info("✅ Detected: MongoDB Atlas connection string")
                
                # Detect GraphQL
                graphql_endpoint = await self._detect_graphql(client, target, all_content)
                if graphql_endpoint:
                    result.graphql_endpoint = graphql_endpoint
                    if result.backend_type == BackendType.UNKNOWN:
                        result.backend_type = BackendType.CUSTOM_GRAPHQL
                        result.confidence = 0.7
                    logger.info(f"✅ Detected: GraphQL endpoint at {graphql_endpoint}")
                
                # Detect third-party services
                result.third_party = self._detect_third_party(all_content)
                if result.third_party.stripe_publishable:
                    logger.info(f"📦 Stripe keys found: {len(result.third_party.stripe_publishable)}")
                if result.third_party.has_critical_exposure:
                    logger.critical("🚨 CRITICAL: Stripe SECRET key exposed!")
                
                # Extract API endpoints
                result.api_endpoints = self._extract_api_endpoints(all_content)
                
                # Extract env variables
                result.env_variables = self._extract_env_variables(all_content)
                
                # Detect builder/framework
                result.detected_frameworks = self._detect_builders(all_content, response.headers)
                
                # Default to Custom REST if nothing detected
                if result.backend_type == BackendType.UNKNOWN:
                    result.backend_type = BackendType.CUSTOM_REST
                    result.confidence = 0.5
                    logger.info("ℹ️ Defaulting to: CUSTOM_REST API")
                
        except Exception as e:
            logger.error(f"Backend detection failed: {e}")
            result.backend_type = BackendType.CUSTOM_REST
            result.confidence = 0.3
        
        # Log applicable phases
        phases = result.get_applicable_phases()
        logger.info(f"📋 Applicable SecureDev phases: {', '.join(phases)}")
        
        return result
    
    async def _check_window_object(self, client: httpx.AsyncClient, target: str) -> dict:
        """Check window object for exposed configs via JavaScript execution simulation."""
        configs = {}
        
        # Common window properties to check
        check_props = [
            "supabase", "firebase", "config", "env", 
            "NEXT_PUBLIC", "VITE", "API_URL", "apiKey"
        ]
        
        # This would ideally use Playwright/Puppeteer for real execution
        # For now, we'll extract from static analysis
        return configs
    
    async def _fetch_js_bundles(
        self, 
        client: httpx.AsyncClient, 
        target: str, 
        html: str
    ) -> str:
        """Fetch and concatenate JS bundle contents."""
        js_content = ""
        
        # Find script sources
        script_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)
        scripts = script_pattern.findall(html)
        
        # Filter for main bundles
        bundle_patterns = [
            r'main.*\.js', r'app.*\.js', r'bundle.*\.js',
            r'index.*\.js', r'chunk.*\.js', r'vendor.*\.js',
            r'_next/static.*\.js', r'assets/.*\.js',
        ]
        
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        tasks = []
        for script in scripts[:10]:  # Limit to 10 scripts
            for pattern in bundle_patterns:
                if re.search(pattern, script, re.IGNORECASE):
                    url = script if script.startswith('http') else f"{base_url}/{script.lstrip('/')}"
                    tasks.append(self._fetch_script(client, url))
                    break
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, str):
                    js_content += result
        
        return js_content
    
    async def _fetch_script(self, client: httpx.AsyncClient, url: str) -> str:
        """Fetch a single script."""
        try:
            response = await client.get(url)
            if response.status_code == 200:
                return response.text
        except Exception as e:
            # FIX 2026-02-12: Log script fetch error (DEBUG - expected for 404s)
            logger.debug(f"[BackendDetector] Script fetch error for {url}: {e}")
        return ""
    
    def _detect_supabase(self, content: str) -> SupabaseConfig | None:
        """Detect Supabase configuration."""
        config = SupabaseConfig()
        
        # Find Supabase URL
        url_match = self.SUPABASE_URL_PATTERN.search(content)
        if url_match:
            config.project_ref = url_match.group(1)
            config.project_url = url_match.group(0)
        
        # Find JWT tokens (potential anon or service_role keys)
        jwt_matches = self.SUPABASE_ANON_KEY_PATTERN.findall(content)
        for jwt in jwt_matches:
            try:
                # Decode JWT payload
                parts = jwt.split('.')
                if len(parts) >= 2:
                    # Add padding for base64
                    payload = parts[1] + '=' * (4 - len(parts[1]) % 4)
                    decoded = json.loads(base64.urlsafe_b64decode(payload))
                    
                    role = decoded.get('role', '')
                    
                    if role == 'anon':
                        config.anon_key = jwt
                    elif role == 'service_role':
                        config.service_role_key = jwt  # CRITICAL!
                    elif 'ref' in decoded:
                        # Likely Supabase JWT
                        if not config.anon_key:
                            config.anon_key = jwt
            except Exception:
                # If decoding fails, assume it might be anon key
                if not config.anon_key:
                    config.anon_key = jwt
        
        return config if config.project_url else None
    
    def _detect_firebase(self, content: str) -> FirebaseConfig | None:
        """Detect Firebase configuration."""
        config = FirebaseConfig()
        
        # Try to find firebase config object
        config_match = self.FIREBASE_CONFIG_PATTERN.search(content)
        if config_match:
            config_str = config_match.group(0)
            
            # Extract individual fields
            patterns = {
                'api_key': re.compile(r'apiKey["\']?\s*:\s*["\']([^"\']+)["\']'),
                'auth_domain': re.compile(r'authDomain["\']?\s*:\s*["\']([^"\']+)["\']'),
                'project_id': re.compile(r'projectId["\']?\s*:\s*["\']([^"\']+)["\']'),
                'storage_bucket': re.compile(r'storageBucket["\']?\s*:\s*["\']([^"\']+)["\']'),
                'messaging_sender_id': re.compile(r'messagingSenderId["\']?\s*:\s*["\']([^"\']+)["\']'),
                'app_id': re.compile(r'appId["\']?\s*:\s*["\']([^"\']+)["\']'),
            }
            
            for field, pattern in patterns.items():
                match = pattern.search(config_str)
                if match:
                    setattr(config, field, match.group(1))
        
        # Also check for Firebase URLs
        firebase_url = self.FIREBASE_URL_PATTERN.search(content)
        if firebase_url:
            config.database_url = firebase_url.group(0)
            if not config.project_id:
                config.project_id = firebase_url.group(1)
        
        auth_domain = self.FIREBASE_AUTH_DOMAIN_PATTERN.search(content)
        if auth_domain and not config.auth_domain:
            config.auth_domain = auth_domain.group(0)
            if not config.project_id:
                config.project_id = auth_domain.group(1)
        
        return config if (config.api_key or config.project_id) else None
    
    def _detect_mongodb(self, content: str) -> bool:
        """Detect MongoDB Atlas connection string."""
        return bool(self.MONGODB_PATTERN.search(content))
    
    async def _detect_graphql(
        self, 
        client: httpx.AsyncClient, 
        target: str,
        content: str
    ) -> str:
        """Detect GraphQL endpoint."""
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Common GraphQL paths
        graphql_paths = [
            "/graphql",
            "/graphql/v1",
            "/api/graphql",
            "/v1/graphql",
            "/query",
        ]
        
        # Check if GraphQL patterns in content
        for pattern in self.GRAPHQL_PATTERNS:
            if pattern.search(content):
                # Try to find the endpoint
                for path in graphql_paths:
                    try:
                        url = f"{base_url}{path}"
                        response = await client.post(
                            url,
                            json={"query": "{ __typename }"},
                            headers={"Content-Type": "application/json"},
                        )
                        if response.status_code == 200:
                            return url
                    except Exception as e:
                        # FIX 2026-02-12: Log GraphQL probe error (DEBUG - expected)
                        logger.debug(f"[BackendDetector] GraphQL probe error for {url}: {e}")

        return ""
    
    def _detect_third_party(self, content: str) -> ThirdPartyKeys:
        """Detect third-party service keys."""
        keys = ThirdPartyKeys()
        
        # Stripe
        keys.stripe_publishable = self.STRIPE_PK_PATTERN.findall(content)
        keys.stripe_secret = self.STRIPE_SK_PATTERN.findall(content)
        
        # Sentry
        keys.sentry_dsn = self.SENTRY_DSN_PATTERN.findall(content)
        
        # PostHog
        posthog_match = self.POSTHOG_PATTERN.search(content)
        if posthog_match:
            keys.posthog_key = posthog_match.group(0)
        
        # Google Analytics
        keys.google_analytics = self.GA_PATTERN.findall(content)
        
        # Facebook Pixel
        keys.facebook_pixel = self.FB_PIXEL_PATTERN.findall(content)
        
        # reCAPTCHA sitekey
        recaptcha_match = re.search(r'(?:recaptcha|grecaptcha)[^"\']*["\']([^"\']{30,})["\']', content)
        if recaptcha_match:
            keys.recaptcha_sitekey = recaptcha_match.group(1)
        
        # hCaptcha
        hcaptcha_match = re.search(r'hcaptcha[^"\']*sitekey["\']?\s*:\s*["\']([^"\']+)["\']', content)
        if hcaptcha_match:
            keys.hcaptcha_sitekey = hcaptcha_match.group(1)
        
        return keys
    
    def _extract_api_endpoints(self, content: str) -> list[str]:
        """Extract API endpoints from content."""
        endpoints = set()
        
        patterns = [
            re.compile(r'["\'](/api/[a-zA-Z0-9/_-]+)["\']'),
            re.compile(r'["\'](/v\d+/[a-zA-Z0-9/_-]+)["\']'),
            re.compile(r'fetch\s*\(\s*["\']([^"\']+/api/[^"\']+)["\']'),
            re.compile(r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']'),
        ]
        
        for pattern in patterns:
            matches = pattern.findall(content)
            endpoints.update(matches)
        
        return list(endpoints)[:50]  # Limit
    
    def _extract_env_variables(self, content: str) -> dict[str, str]:
        """Extract environment variables from content."""
        env_vars = {}
        
        # Pattern: NEXT_PUBLIC_VAR="value" or process.env.VAR
        patterns = [
            re.compile(r'((?:NEXT_PUBLIC|VITE|REACT_APP|VUE_APP)_[A-Z_0-9]+)\s*[=:]\s*["\']([^"\']+)["\']'),
            re.compile(r'process\.env\.([A-Z_0-9]+)'),
        ]
        
        for pattern in patterns:
            matches = pattern.findall(content)
            for match in matches:
                if isinstance(match, tuple):
                    env_vars[match[0]] = match[1] if len(match) > 1 else ""
                else:
                    env_vars[match] = ""
        
        return env_vars
    
    def _detect_builders(self, content: str, headers: httpx.Headers) -> list[str]:
        """Detect no-code builders and frameworks used."""
        detected = []
        
        for builder, patterns in self.BUILDERS.items():
            for pattern in patterns:
                if pattern.search(content):
                    detected.append(builder)
                    break
        
        # Check headers
        server = headers.get("server", "").lower()
        if "vercel" in server:
            detected.append("vercel")
        if "netlify" in server:
            detected.append("netlify")
        
        # Framework detection from content
        frameworks = [
            ("next.js", re.compile(r'__NEXT_DATA__|_next/static')),
            ("nuxt.js", re.compile(r'__NUXT__|_nuxt/')),
            ("react", re.compile(r'react|ReactDOM')),
            ("vue", re.compile(r'Vue\.|__vue__')),
            ("angular", re.compile(r'ng-version|angular')),
            ("svelte", re.compile(r'svelte')),
        ]
        
        for name, pattern in frameworks:
            if pattern.search(content):
                detected.append(name)
        
        return list(set(detected))
