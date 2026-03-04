"""
CSRF Scanner - Cross-Site Request Forgery Testing.
Enterprise Edition v2.0

Covers SecureDev checklist:
- FASE EXTRA-5: CSRF Testing (80% → 95%)
- SameSite Cookie verification
- CSRF Token validation
- State-changing endpoint testing

Enterprise Features Added:
=========================
1. Token Analysis:
   - Token entropy analysis (CWE-330)
   - Token reuse detection
   - Token leakage in URLs
   - Token binding verification
   - Double submit cookie validation

2. Advanced Attack Vectors:
   - JSON CSRF attacks (CWE-352)
   - Content-Type confusion
   - Flash-based CSRF (legacy)
   - PDF CSRF vectors
   - WebSocket CSRF (CSWSH)

3. Origin/Referer Bypass:
   - Null origin exploitation
   - Subdomain confusion
   - Protocol downgrade (HTTPS→HTTP)
   - Referer header removal
   - Origin header manipulation

4. Framework-Specific:
   - Django CSRF token patterns
   - Rails authenticity_token
   - Laravel X-CSRF-TOKEN
   - Spring Security patterns
   - Express.js csurf patterns

5. Clickjacking Combo:
   - X-Frame-Options analysis
   - CSP frame-ancestors check
   - UI redressing potential

CWE Coverage:
- CWE-352: Cross-Site Request Forgery
- CWE-330: Use of Insufficiently Random Values
- CWE-346: Origin Validation Error
- CWE-1021: Improper Restriction of Rendered UI Layers
- CWE-16: Configuration

Author: PetNTester AI Enterprise
Version: 2.0.0
"""

from __future__ import annotations

import asyncio
import base64
import math
import re
import secrets
import time
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlparse, urljoin

import httpx

from utils.logger import get_logger
from utils.scan_client import get_scan_client
from scanning.scan_context import ScanContext
from utils.shared_findings_store import SharedFindingsStore, VulnType as StoreVulnType

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)

# FIX SAFE-08: Safety mode check - CSRF testing uses POST requests
import os
SAFE_MODE = os.environ.get("PHANTOM_SAFE_MODE", "safe").lower()
ALLOW_CSRF_TESTING = SAFE_MODE in ("standard", "aggressive")


# ============================================================================
# ENTERPRISE DATA STRUCTURES
# ============================================================================

class CSRFVulnType(Enum):
    """Types of CSRF vulnerabilities."""
    MISSING_TOKEN = auto()
    WEAK_TOKEN = auto()
    TOKEN_REUSE = auto()
    TOKEN_LEAKAGE = auto()
    SAMESITE_MISSING = auto()
    SAMESITE_NONE = auto()
    ORIGIN_BYPASS = auto()
    REFERER_BYPASS = auto()
    JSON_CSRF = auto()
    CONTENT_TYPE_CONFUSION = auto()
    DOUBLE_SUBMIT_WEAK = auto()
    CLICKJACKING = auto()
    WEBSOCKET_CSRF = auto()
    CORS_CSRF_COMBO = auto()
    TOKEN_FIXATION = auto()
    WORKFLOW_BYPASS = auto()  # Multi-step workflow CSRF bypass


@dataclass
class TokenAnalysis:
    """Analysis of a CSRF token."""
    token_value: str
    entropy_bits: float
    is_predictable: bool
    pattern_detected: str | None
    is_bound_to_session: bool
    is_reusable: bool
    framework_hint: str | None


# Enterprise token patterns for framework detection
TOKEN_PATTERNS = {
    "django": re.compile(r"^[a-zA-Z0-9]{64}$"),
    "rails": re.compile(r"^[a-zA-Z0-9+/=]{44,88}$"),
    "laravel": re.compile(r"^[a-zA-Z0-9]{40}$"),
    "spring": re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"),
    "express_csurf": re.compile(r"^[a-zA-Z0-9_-]{24,48}$"),
    "asp_net": re.compile(r"^[a-zA-Z0-9+/=]{88,108}$"),
}

# Enterprise origin bypass payloads
ORIGIN_BYPASS_PAYLOADS = [
    "null",
    "https://evil.com",
    "https://target.com.evil.com",
    "https://targetcom.evil.com",
    "https://evil.com/target.com",
    "https://evil.com#@target.com",
    "https://target.com@evil.com",
    "https://target.com%00.evil.com",
    "https://target.com%0d%0a.evil.com",
    "https://target.com\t.evil.com",
]

# Enterprise referer bypass payloads
REFERER_BYPASS_PAYLOADS = [
    "",  # Empty referer
    "https://evil.com",
    "https://evil.com/target.com",
    "https://target.com.evil.com/path",
    "data:text/html,<script>fetch('target')</script>",
]

# Content-Type confusion payloads for JSON CSRF
CONTENT_TYPE_PAYLOADS = [
    "application/json",
    "text/plain",
    "application/x-www-form-urlencoded",
    "text/plain; charset=utf-8",
    "application/json; charset=utf-8",
    "multipart/form-data",
    "application/xml",
]

# JSON CSRF attack vectors
JSON_CSRF_PAYLOADS = [
    # Form-based JSON
    '{"action":"transfer","amount":1000}',
    # Array wrapping
    '[{"action":"transfer"}]',
    # JSONP callback abuse
    '{"callback":"alert"}',
    # Padding exploitation
    '/**/{"action":"delete"}',
]


@dataclass
class CSRFFinding:
    """A CSRF vulnerability finding - Enterprise Edition."""
    url: str
    method: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    remediation: str = ""
    cwe: str = "CWE-352"
    vuln_type: CSRFVulnType | None = None
    confidence: float = 60.0
    cvss: float = 0.0
    
    def to_dict(self) -> dict:
        return {
            "type": "CSRF",
            "url": self.url,
            "method": self.method,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence[:500] if self.evidence else "",
            "remediation": self.remediation,
            "cwe": self.cwe,
            "vuln_type": self.vuln_type.name if self.vuln_type else None,
            "confidence": self.confidence,
            "cvss": self.cvss,
        }


@dataclass
class CSRFScanResult:
    """Result of CSRF scan - Enterprise Edition."""
    findings: list[CSRFFinding] = field(default_factory=list)
    endpoints_tested: int = 0
    cookies_analyzed: int = 0
    tokens_analyzed: int = 0
    frameworks_detected: list[str] = field(default_factory=list)
    
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "CRITICAL")
    
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "HIGH")
    
    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "MEDIUM")


class CSRFScanner:
    """
    Cross-Site Request Forgery (CSRF) Scanner.
    Enterprise Edition v2.0
    
    Tests:
    1. SameSite cookie attribute
    2. CSRF token presence and validation
    3. Origin/Referer header validation
    4. State-changing operations without protection
    5. Token entropy and predictability
    6. JSON CSRF attacks
    7. Clickjacking combination
    8. WebSocket CSRF
    9. Framework-specific patterns
    10. Token reuse and leakage
    11. HIGH-IMPACT endpoint detection (password, email, delete)
    """
    
    # State-changing HTTP methods
    STATE_CHANGING_METHODS = ["POST", "PUT", "PATCH", "DELETE"]

    # SPA framework markers — detect when a response is an SPA shell, not an action result
    _SPA_MARKERS = [
        # Angular 1.x
        "ng-app", "ng-controller",
        # Angular 2+ / modern Angular
        "<app-root", "angular", "data-beasties",
        # React
        "react-root", "data-reactroot", "__next",
        # Vue / Nuxt
        "vue-app", "nuxt", "__nuxt",
        # Svelte / SvelteKit
        "svelte", "sveltekit",
        # Generic SPA root elements
        'id="app"', 'id="root"', 'id="__next"',
    ]

    # URL path fragments that indicate action endpoints (not page routes)
    _ACTION_PATH_FRAGMENTS = [
        "/api/", "/profile", "/account", "/admin",
        "/user", "/delete", "/update", "/password",
        "/email", "/settings", "/transfer", "/payment",
    ]

    @staticmethod
    def _is_spa_shell(body: str, content_type: str, url: str) -> bool:
        """Detect if an HTTP response is an SPA shell page, not an action result.

        SPAs return 200 + full HTML for all routes because the client-side router
        handles routing. This does NOT mean the server processed the action.
        """
        is_html = "text/html" in content_type.lower()
        if not is_html or len(body) < 2000:
            return False
        body_lower = body.lower() if body == body.lower() else body.lower()
        # Check 1: Known framework markers
        if any(m in body_lower for m in CSRFScanner._SPA_MARKERS):
            return True
        # Check 2: Full HTML document returned for an action/API endpoint
        if ("<!doctype html" in body_lower and "<script" in body_lower
                and any(p in url.lower() for p in CSRFScanner._ACTION_PATH_FRAGMENTS)):
            return True
        return False
    
    # ==========================================================================
    # HIGH-IMPACT CSRF ENDPOINTS - These make CSRF CRITICAL, not just "checkbox"
    # ==========================================================================
    
    # Password change endpoints
    PASSWORD_CHANGE_PATTERNS = [
        r"/password",
        r"/change.?password",
        r"/update.?password",
        r"/reset.?password",
        r"/profile.*password",
        r"/account.*password",
        r"/settings.*password",
        r"/user.*password",
        r"/api/.*password",
        r"/rest/.*password",
    ]
    
    # Email change endpoints
    EMAIL_CHANGE_PATTERNS = [
        r"/email",
        r"/change.?email",
        r"/update.?email",
        r"/profile.*email",
        r"/account.*email",
        r"/settings.*email",
        r"/user.*email",
        r"/api/.*email",
    ]
    
    # Account deletion endpoints
    ACCOUNT_DELETE_PATTERNS = [
        r"/delete.?account",
        r"/account.*delete",
        r"/user.*delete",
        r"/profile.*delete",
        r"/remove.?account",
        r"/deactivate",
        r"/close.?account",
        r"/api/users?/\d*$",  # DELETE /api/users/123
        r"/api/account",
    ]
    
    # Other high-impact endpoints
    HIGH_IMPACT_PATTERNS = [
        # Financial
        r"/transfer",
        r"/payment",
        r"/withdraw",
        r"/send.?money",
        r"/transaction",
        r"/purchase",
        r"/checkout",
        r"/order",
        r"/buy",
        
        # Admin actions
        r"/admin",
        r"/user.*role",
        r"/permissions",
        r"/grant",
        r"/revoke",
        r"/promote",
        r"/demote",
        
        # Security settings
        r"/2fa",
        r"/mfa",
        r"/totp",
        r"/security",
        r"/api.?key",
        r"/token",
        r"/sessions?/",
        r"/logout.?all",
        
        # Data modification
        r"/publish",
        r"/unpublish",
        r"/approve",
        r"/reject",
        r"/ban",
        r"/unban",
        r"/suspend",
        
        # E-commerce/REST API patterns (generic)
        r"/api/users?",           # User management
        r"/api/cards?",           # Payment cards
        r"/api/address(?:es)?",   # Addresses
        r"/api/deliver(?:y|ies)", # Delivery
        r"/api/complaints?",      # Complaints
        r"/api/feedbacks?",       # Feedbacks
        r"/api/reviews?",         # Reviews
        r"/api/products?",        # Products
        r"/api/orders?",          # Orders
        r"/rest/user",            # REST user endpoints
        r"/rest/basket",          # REST basket
        r"/rest/order",           # REST order
        r"/rest/product",         # REST product
        r"/graphql",              # GraphQL mutations
    ]
    
    # Common CSRF token parameter names - Extended
    CSRF_TOKEN_NAMES = [
        "csrf", "csrf_token", "csrftoken", "_csrf", "xsrf",
        "xsrf_token", "_xsrf", "authenticity_token", "_token",
        "token", "anti_csrf", "csrf_field", "CSRFToken",
        "__RequestVerificationToken", "antiForgery",
        "csrfmiddlewaretoken",  # Django
        "_csrf_token",  # Phoenix/Elixir
        "X-CSRF-Token",  # Rails meta tag
        "csrf_value", "csrf_key", "security_token",
        "__VIEWSTATE",  # ASP.NET
        "__EVENTVALIDATION",  # ASP.NET
    ]
    
    # Common CSRF header names - Extended
    CSRF_HEADER_NAMES = [
        "X-CSRF-Token", "X-XSRF-Token", "X-CSRFToken",
        "X-Requested-With", "X-Anti-Forgery-Token",
        "X-CSRF-PROTECTION", "X-Security-Token",
        "CSRF-Token", "Anti-CSRF-Token",
    ]
    
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings
        self.timeout = httpx.Timeout(15.0)
        self.result = CSRFScanResult()
        self._token_cache: dict[str, str] = {}  # Track tokens for reuse detection
        self._session_cookies: dict[str, str] = {}
        
        # Compile patterns for efficiency
        self._password_patterns = [re.compile(p, re.IGNORECASE) for p in self.PASSWORD_CHANGE_PATTERNS]
        self._email_patterns = [re.compile(p, re.IGNORECASE) for p in self.EMAIL_CHANGE_PATTERNS]
        self._delete_patterns = [re.compile(p, re.IGNORECASE) for p in self.ACCOUNT_DELETE_PATTERNS]
        self._high_impact_patterns = [re.compile(p, re.IGNORECASE) for p in self.HIGH_IMPACT_PATTERNS]
    
    def _classify_endpoint_impact(self, endpoint: str, method: str = "POST") -> tuple[str, str, float]:
        """
        Classify endpoint impact for CSRF vulnerability.
        
        Returns:
            tuple: (impact_type, severity, cvss_score)
            
        Impact types:
        - "password_change": CRITICAL - attacker can take over account
        - "email_change": CRITICAL - attacker can reset password via new email
        - "account_delete": CRITICAL - attacker can delete victim's account
        - "financial": CRITICAL - attacker can steal money
        - "admin_action": CRITICAL - privilege escalation
        - "data_modification": HIGH - attacker can modify victim's data
        - "generic": MEDIUM - standard CSRF without clear impact
        """
        endpoint_lower = endpoint.lower()
        
        # Password change = Account Takeover
        for pattern in self._password_patterns:
            if pattern.search(endpoint_lower):
                return ("password_change", "CRITICAL", 9.1)
        
        # Email change = Account Takeover via password reset
        for pattern in self._email_patterns:
            if pattern.search(endpoint_lower):
                return ("email_change", "CRITICAL", 9.1)
        
        # Account deletion = Data loss / DoS
        for pattern in self._delete_patterns:
            if pattern.search(endpoint_lower):
                return ("account_delete", "CRITICAL", 8.8)
        
        # DELETE method on user endpoints = likely account/data deletion
        if method.upper() == "DELETE":
            if any(x in endpoint_lower for x in ["user", "account", "profile"]):
                return ("account_delete", "CRITICAL", 8.8)
        
        # High-impact patterns
        for pattern in self._high_impact_patterns:
            if pattern.search(endpoint_lower):
                # Determine sub-type
                if any(x in endpoint_lower for x in ["transfer", "payment", "withdraw", "money", "purchase"]):
                    return ("financial", "CRITICAL", 9.3)
                if any(x in endpoint_lower for x in ["admin", "role", "permission", "promote", "grant"]):
                    return ("admin_action", "CRITICAL", 8.5)
                if any(x in endpoint_lower for x in ["2fa", "mfa", "security", "api.key", "token"]):
                    return ("security_bypass", "CRITICAL", 8.7)
                return ("high_impact_action", "HIGH", 7.5)
        
        # Generic state-changing endpoint
        return ("generic", "MEDIUM", 5.4)
    
    def _get_impact_description(self, impact_type: str) -> str:
        """Get detailed impact description for report."""
        descriptions = {
            "password_change": (
                "**ACCOUNT TAKEOVER** - An attacker can change the victim's password, "
                "completely locking them out of their account. The attacker gains full "
                "control over the account and all associated data."
            ),
            "email_change": (
                "**ACCOUNT TAKEOVER via EMAIL** - An attacker can change the victim's email address. "
                "This allows the attacker to trigger a password reset to their own email, "
                "effectively taking over the account."
            ),
            "account_delete": (
                "**ACCOUNT DELETION** - An attacker can delete the victim's account, "
                "causing permanent data loss and denial of service. This may violate "
                "data protection regulations (GDPR, CCPA)."
            ),
            "financial": (
                "**FINANCIAL THEFT** - An attacker can initiate financial transactions "
                "on behalf of the victim, potentially stealing money or making unauthorized "
                "purchases."
            ),
            "admin_action": (
                "**PRIVILEGE ESCALATION** - An attacker can perform administrative actions "
                "on behalf of a privileged user, potentially compromising the entire application."
            ),
            "security_bypass": (
                "**SECURITY BYPASS** - An attacker can modify security settings such as "
                "disabling 2FA/MFA, revoking API keys, or terminating sessions, "
                "weakening the account's security posture."
            ),
            "high_impact_action": (
                "**HIGH IMPACT ACTION** - An attacker can perform sensitive actions "
                "that may affect data integrity, user content, or application state."
            ),
            "generic": (
                "State-changing action that may be exploited via CSRF. "
                "Verify the actual impact based on the endpoint's functionality."
            ),
        }
        return descriptions.get(impact_type, descriptions["generic"])
    
    async def scan(
        self,
        host: str,
        asset_data: dict,
        rate_limiter: Any = None
    ) -> dict:
        """
        Scan for CSRF vulnerabilities - Enterprise Edition with HIGH-IMPACT DETECTION.

        Now detects CSRF on critical actions:
        - Password change → Account Takeover
        - Email change → Account Takeover via password reset
        - Account deletion → Data loss / DoS
        - Financial transactions → Theft
        - Admin actions → Privilege escalation

        Args:
            host: Target hostname
            asset_data: Contains endpoints, forms, cookies
            rate_limiter: Optional rate limiter
        """
        # FIX SAFE-08: CSRF testing requires POST - block in safe/cautious modes
        if not ALLOW_CSRF_TESTING:
            logger.info(f"⚠️ CSRF Scanner SKIPPED (safe_mode={SAFE_MODE}, requires standard/aggressive)")
            return {
                "findings": [],
                "info": [{"message": f"CSRF testing requires standard/aggressive mode (current: {SAFE_MODE})"}],
            }

        logger.info(f"🔍 CSRF Scanner Enterprise v3.0 starting for {host}")
        logger.info("🎯 HIGH-IMPACT mode: Targeting password/email/account/financial endpoints")

        base_url = f"https://{host}" if not host.startswith("http") else host

        # FIX: Add ScanContext for auth headers - CSRF testing needs auth to test authenticated endpoints
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers
        if self._ctx.has_auth:
            logger.info(f"[CSRF] Using authenticated session ({self._ctx.auth_method})")
        else:
            logger.warning("[CSRF] No auth token — CSRF tests will be unauthenticated (may miss vulns on protected endpoints)")

        if isinstance(asset_data, dict):
            endpoints = asset_data.get("endpoints", [])
        if isinstance(asset_data, dict):
            forms = asset_data.get("forms", [])

        # PERF-FIX 2026-02-12: Limit endpoints to prevent timeout in full scans
        max_endpoints = 30
        max_forms = 20
        scan_start = time.time()
        max_total_time = 180.0  # Max 3 minutes

        if len(endpoints) > max_endpoints:
            logger.info(f"[CSRF] Limiting endpoints from {len(endpoints)} to {max_endpoints}")
            endpoints = endpoints[:max_endpoints]
        if len(forms) > max_forms:
            logger.info(f"[CSRF] Limiting forms from {len(forms)} to {max_forms}")
            forms = forms[:max_forms]

        async with get_scan_client(
            timeout=self.timeout,
            follow_redirects=True,
            verify_ssl=False,
            custom_headers=self._auth_headers,  # FIX: Pass auth headers
        ) as client:
            # 0. PRIORITY: Test high-impact endpoints FIRST
            logger.info("🔴 Phase 0: Testing HIGH-IMPACT endpoints (password/email/account)")
            await self._test_high_impact_csrf(client, base_url, endpoints, rate_limiter)
            
            # 1. Test cookie SameSite attributes
            await self._test_samesite_cookies(client, base_url)
            
            # 2. Test forms for CSRF tokens
            for form in forms:
                await self._test_form_csrf(client, form)
            
            # 3. Test endpoints for CSRF protection
            for endpoint in endpoints:
                # PERF-FIX 2026-02-12: Check time limit
                if time.time() - scan_start > max_total_time:
                    logger.info(f"[CSRF] Time limit reached, stopping endpoint tests")
                    break
                if rate_limiter:
                    await rate_limiter.acquire(host)
                await self._test_endpoint_csrf(client, endpoint, base_url)

            # 4. Enterprise: Token entropy analysis (skip if time exceeded)
            if time.time() - scan_start < max_total_time:
                await self._analyze_token_entropy(client, base_url)

            # 5. Enterprise: JSON CSRF attacks (skip if time exceeded)
            if time.time() - scan_start < max_total_time:
                for endpoint in endpoints[:15]:  # PERF-FIX: Limit to 15 for JSON tests
                    if time.time() - scan_start > max_total_time:
                        break
                    if rate_limiter:
                        await rate_limiter.acquire(host)
                    await self._test_json_csrf(client, endpoint, base_url)
            
            # 6. Enterprise: Origin/Referer bypass testing
            for endpoint in endpoints:
                if rate_limiter:
                    await rate_limiter.acquire(host)
                await self._test_origin_bypass(client, endpoint, base_url)
            
            # 7. Enterprise: Clickjacking check
            await self._test_clickjacking(client, base_url)
            
            # 8. Enterprise: Token reuse detection
            await self._test_token_reuse(client, base_url, forms)
            
            # 9. Enterprise: Double submit cookie validation
            await self._test_double_submit_cookie(client, base_url)
            
            # 10. Enterprise: WebSocket CSRF
            await self._test_websocket_csrf(client, base_url)

            # 11. Enterprise: Multi-step workflow CSRF
            await self._test_multistep_csrf(client, base_url, forms)

        # Count high-impact findings
        high_impact_count = sum(1 for f in self.result.findings if f.severity == "CRITICAL")
        logger.info(f"✅ CSRF Enterprise scan complete: {len(self.result.findings)} findings ({high_impact_count} CRITICAL)")

        # FIX: CROSS-MODULE SHARING - Add findings to SharedFindingsStore
        # This enables other modules to target CSRF-vulnerable endpoints
        if self.result.findings:
            try:
                store = SharedFindingsStore.get_instance()
                for finding in self.result.findings:
                    store.add_finding(
                        vuln_type=StoreVulnType.CSRF,
                        module="csrf_scanner",
                        endpoint=finding.endpoint,
                        parameter=None,  # CSRF is form-level, not param-level
                        severity=finding.severity,
                        confidence=finding.confidence,
                    )
                logger.debug(f"[CSRF] Shared {len(self.result.findings)} findings with cross-module store")
            except Exception as e:
                logger.debug(f"[CSRF] Could not share findings: {e}")

        return {
            "findings": [f.to_dict() for f in self.result.findings],
            "endpoints_tested": self.result.endpoints_tested,
            "cookies_analyzed": self.result.cookies_analyzed,
            "tokens_analyzed": self.result.tokens_analyzed,
            "frameworks_detected": self.result.frameworks_detected,
        }
    
    # ========================================================================
    # HIGH-IMPACT CSRF DETECTION - Password/Email/Account/Financial
    # ========================================================================
    
    async def _test_high_impact_csrf(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        known_endpoints: list[str],
        rate_limiter: Any = None
    ) -> None:
        """
        Specifically test high-impact endpoints for CSRF.
        
        This method probes common high-impact endpoints that may not be
        in the discovered endpoints list, testing for CSRF on:
        - Password change → Account Takeover
        - Email change → Account Takeover via password reset
        - Account deletion → Data loss
        - Financial operations → Theft
        """
        # Common high-impact endpoint paths to probe
        HIGH_IMPACT_PROBE_ENDPOINTS = [
            # Password change endpoints
            "/api/user/password",
            "/api/users/password",
            "/rest/user/password",
            "/rest/users/password",
            "/api/v1/user/password",
            "/api/v1/account/password",
            "/api/v1/profile/password",
            "/user/change-password",
            "/account/password",
            "/profile/password",
            "/settings/password",
            "/api/password/change",
            "/password/update",
            
            # Email change endpoints
            "/api/user/email",
            "/api/users/email", 
            "/rest/user/email",
            "/api/v1/user/email",
            "/api/v1/account/email",
            "/user/change-email",
            "/account/email",
            "/profile/email",
            "/settings/email",
            "/api/email/change",
            
            # Account deletion endpoints
            "/api/user/delete",
            "/api/users/delete",
            "/api/v1/user",  # DELETE method
            "/api/v1/account",  # DELETE method
            "/api/account/delete",
            "/user/delete",
            "/account/delete",
            "/profile/delete",
            "/api/user/deactivate",
            
            # REST API patterns (Express/Node.js apps)
            "/rest/user/change-password",
            "/api/users",  # POST for user changes
            "/rest/user/data-export",
            "/api/security-questions",
            "/api/security-answers",
            
            # Financial/Transfer endpoints
            "/api/transfer",
            "/api/payment",
            "/api/withdraw",
            "/api/wallet/transfer",
            "/api/basket/checkout",
            "/rest/basket/checkout",
            "/api/orders",
            
            # Admin endpoints
            "/api/admin/users",
            "/admin/users",
            "/api/v1/admin",
            
            # 2FA/Security endpoints
            "/api/2fa/disable",
            "/api/mfa/disable",
            "/api/security/2fa",
            "/api/totp/disable",
        ]
        
        # Combine with known endpoints that match high-impact patterns
        all_high_impact = set(HIGH_IMPACT_PROBE_ENDPOINTS)
        
        for endpoint in known_endpoints:
            impact_type, severity, _ = self._classify_endpoint_impact(endpoint)
            if impact_type != "generic":
                all_high_impact.add(endpoint)
        
        logger.info(f"🎯 Testing {len(all_high_impact)} high-impact endpoints")
        
        for endpoint in all_high_impact:
            if rate_limiter:
                host = urlparse(base_url).hostname or ""
                await rate_limiter.acquire(host)
            
            await self._test_single_high_impact_endpoint(client, base_url, endpoint)
    
    async def _test_single_high_impact_endpoint(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        endpoint: str
    ) -> None:
        """Test a single high-impact endpoint for CSRF vulnerability."""
        url = endpoint if endpoint.startswith("http") else urljoin(base_url, endpoint)
        
        # Classify impact
        impact_type, severity, cvss_score = self._classify_endpoint_impact(endpoint, "POST")
        impact_description = self._get_impact_description(impact_type)
        
        if impact_type == "generic":
            return  # Skip non-high-impact in this method
        
        # Test payloads specific to endpoint type
        test_payloads = self._get_high_impact_test_payload(impact_type)
        
        methods_to_test = ["POST", "PUT", "PATCH"]
        if impact_type == "account_delete":
            methods_to_test.append("DELETE")
        
        for method in methods_to_test:
            try:
                # Test 1: Cross-origin request (main CSRF test)
                if method == "DELETE":
                    response = await client.request(
                        method,
                        url,
                        headers={
                            "Origin": "https://evil-attacker.com",
                            "Referer": "https://evil-attacker.com/csrf-poc.html",
                        }
                    )
                else:
                    response = await client.request(
                        method,
                        url,
                        json=test_payloads,
                        headers={
                            "Content-Type": "application/json",
                            "Origin": "https://evil-attacker.com",
                            "Referer": "https://evil-attacker.com/csrf-poc.html",
                        }
                    )
                
                self.result.endpoints_tested += 1
                
                # Analyze response
                if response.status_code in [200, 201, 202, 204, 302]:
                    # Check if it actually processed or just returned an auth error
                    is_vulnerable = False
                    side_effect_confirmed = False
                    is_spa_response = False
                    try:
                        body = response.text.lower()

                        # Not vulnerable if auth error
                        if any(x in body for x in ["unauthorized", "unauthenticated", "login required", "401"]):
                            continue
                        # Not vulnerable if CSRF error
                        if any(x in body for x in ["csrf", "token", "invalid token", "missing token"]):
                            continue

                        # SPA detection: SPAs return 200 for all routes because
                        # the client-side router handles routing. A 200 from an
                        # SPA homepage does NOT mean the action was processed.
                        content_type = response.headers.get("content-type", "").lower()
                        is_json_response = "application/json" in content_type

                        is_spa_response = self._is_spa_shell(body, content_type, url)

                        if is_spa_response:
                            # SPA returned its shell page — the server did NOT process
                            # the action, the client-side router caught the route.
                            # This is NOT evidence of CSRF. Skip entirely.
                            logger.debug(f"[CSRF] SPA shell detected for {url}, skipping (not a real CSRF)")
                            continue
                        elif is_json_response:
                            # JSON response — more likely the endpoint processed it
                            # Check for success indicators
                            if any(x in body for x in ['"success"', '"ok"', '"updated"',
                                                        '"deleted"', '"created"', '"done"']):
                                is_vulnerable = True
                                side_effect_confirmed = True
                            elif any(x in body for x in ['"error"', '"fail"', '"denied"',
                                                          '"forbidden"', '"not found"']):
                                continue  # Action was rejected
                            else:
                                # Generic JSON response — accept but not confirmed
                                is_vulnerable = True
                        elif response.status_code in [201, 204]:
                            # 201 Created or 204 No Content = strong side-effect signal
                            is_vulnerable = True
                            side_effect_confirmed = True
                        else:
                            # Generic 200 HTML — could be SPA or real processing
                            is_vulnerable = True

                    except (AttributeError, TypeError) as e:
                        # Response parsing failed - don't assume vulnerable
                        logger.debug(f"[CSRF] Response parse error: {e}")
                        is_vulnerable = False
                    
                    if is_vulnerable:
                        # Confidence based on side-effect verification:
                        # - Side-effect confirmed (JSON success, 201/204): 90%
                        # - Generic 200 (no JSON confirmation): 75%
                        # NOTE: SPA shell responses are skipped entirely above (continue)
                        if side_effect_confirmed:
                            csrf_confidence = 90.0
                            verification_note = "Side-effect confirmed (server returned action-specific response)"
                        else:
                            csrf_confidence = 75.0
                            verification_note = "Cross-origin request accepted without CSRF token"

                        self.result.findings.append(CSRFFinding(
                            url=url,
                            method=method,
                            severity=severity,
                            confidence=csrf_confidence,
                            title=f"🔴 CRITICAL CSRF: {impact_type.replace('_', ' ').title()}",
                            description=(
                                f"**HIGH-IMPACT CSRF VULNERABILITY**\n\n"
                                f"The endpoint `{endpoint}` accepts {method} requests from any origin "
                                f"without CSRF token validation.\n\n"
                                f"**Verification:** {verification_note}\n\n"
                                f"**Impact Classification:** {impact_type.upper()}\n"
                                f"**CVSS Score:** {cvss_score}\n"
                                f"**Severity:** {severity}\n\n"
                                f"**Real-World Attack Scenario:**\n{impact_description}\n\n"
                                f"**Proof of Concept:**\n"
                                f"An attacker can create a malicious page that, when visited by "
                                f"an authenticated user, will automatically perform this action "
                                f"without the user's knowledge or consent."
                            ),
                            evidence=(
                                f"Request: {method} {url}\n"
                                f"Origin: https://evil-attacker.com\n"
                                f"Response: {response.status_code}\n"
                                f"Side-effect verified: {side_effect_confirmed}\n"
                                f"Body (truncated): {response.text[:300]}"
                            ),
                            remediation=(
                                f"1. Implement CSRF token validation for this endpoint\n"
                                f"2. Use SameSite=Strict cookies\n"
                                f"3. Validate Origin/Referer headers\n"
                                f"4. For {impact_type}, consider requiring re-authentication"
                            ),
                        ))
                        logger.warning(f"🔴 CRITICAL CSRF found: {impact_type} at {url}")
                        break  # Found vulnerability, no need to test other methods
                        
            except httpx.HTTPStatusError as e:
                if e.response.status_code in [401, 403]:
                    pass  # Auth required - can't test without credentials
            except Exception as e:
                logger.debug(f"High-impact CSRF test error for {endpoint}: {e}")
    
    def _get_high_impact_test_payload(self, impact_type: str) -> dict:
        """Get test payload for high-impact endpoint type."""
        payloads = {
            "password_change": {
                "password": "csrf_test_password123",
                "new_password": "csrf_test_password123",
                "newPassword": "csrf_test_password123",
                "current_password": "current",
                "confirm_password": "csrf_test_password123",
                "repeat": "csrf_test_password123",
            },
            "email_change": {
                "email": "attacker@evil.com",
                "new_email": "attacker@evil.com",
                "newEmail": "attacker@evil.com",
            },
            "account_delete": {
                "confirm": True,
                "deleteAccount": True,
                "action": "delete",
            },
            "financial": {
                "amount": 0.01,
                "to": "attacker",
                "recipient": "attacker",
            },
            "admin_action": {
                "role": "admin",
                "action": "promote",
            },
            "security_bypass": {
                "enabled": False,
                "disable": True,
            },
            "high_impact_action": {
                "action": "csrf_test",
            },
        }
        return payloads.get(impact_type, {"test": "csrf"})

    async def _test_samesite_cookies(self, client: httpx.AsyncClient, base_url: str) -> None:
        """Test SameSite cookie attribute."""
        logger.info("🍪 Testing SameSite cookie attributes...")
        
        try:
            response = await client.get(base_url)
            
            for cookie in response.cookies.jar:
                self.result.cookies_analyzed += 1
                
                # Check if cookie has secure flag for state management
                cookie_name = cookie.name.lower()
                is_session_cookie = any(kw in cookie_name for kw in [
                    "session", "auth", "token", "jwt", "sid", "user"
                ])
                
                if not is_session_cookie:
                    continue
                
                # Get SameSite value from Set-Cookie headers
                # CRITICAL: response.headers.get() only returns FIRST header
                # We need to check ALL Set-Cookie headers for this specific cookie
                samesite = "not set"
                secure_flag = False

                # Access raw headers to get ALL Set-Cookie values
                raw_headers = response.headers.raw
                for name, value in raw_headers:
                    if name.lower() == b"set-cookie":
                        header_str = value.decode("utf-8", errors="replace")
                        # Check if this header sets our cookie
                        if header_str.startswith(f"{cookie.name}=") or f"; {cookie.name}=" in header_str:
                            # Parse SameSite (case-insensitive)
                            header_lower = header_str.lower()
                            if "samesite=strict" in header_lower:
                                samesite = "Strict"
                            elif "samesite=lax" in header_lower:
                                samesite = "Lax"
                            elif "samesite=none" in header_lower:
                                samesite = "None"
                            # Check Secure flag
                            if "; secure" in header_lower or header_lower.endswith("; secure"):
                                secure_flag = True
                            break  # Found the matching cookie header
                
                # Evaluate security
                if samesite == "not set":
                    self.result.findings.append(CSRFFinding(
                        url=base_url,
                        method="GET",
                        severity=Severity.MEDIUM,
                        title=f"Session cookie '{cookie.name}' missing SameSite",
                        description=f"The cookie '{cookie.name}' does not have SameSite attribute. "
                                   "Modern browsers default to Lax, but older browsers send it cross-site.",
                        evidence=f"Cookie: {cookie.name}, SameSite: {samesite}",
                        remediation="Set SameSite=Strict or SameSite=Lax on session cookies.",
                    ))
                elif samesite == "None":
                    # SameSite=None requires Secure flag
                    if not secure_flag:
                        self.result.findings.append(CSRFFinding(
                            url=base_url,
                            method="GET",
                            severity=Severity.HIGH,
                            title=f"Cookie '{cookie.name}' has SameSite=None without Secure",
                            description="SameSite=None cookies must have Secure flag. "
                                       "Without it, the cookie is vulnerable to CSRF.",
                            evidence=f"Cookie: {cookie.name}, SameSite: None, Secure: missing",
                            remediation="Add Secure flag to SameSite=None cookies.",
                        ))
                    else:
                        self.result.findings.append(CSRFFinding(
                            url=base_url,
                            method="GET",
                            severity=Severity.MEDIUM,
                            title=f"Cookie '{cookie.name}' uses SameSite=None",
                            description="SameSite=None allows cross-site cookie sending. "
                                       "Ensure additional CSRF protections are in place.",
                            evidence=f"Cookie: {cookie.name}, SameSite: None",
                            remediation="Use SameSite=Strict if cross-site requests aren't needed.",
                        ))
                        
        except Exception as e:
            logger.debug(f"Cookie test error: {e}")
    
    async def _test_form_csrf(self, client: httpx.AsyncClient, form: dict) -> None:
        """Test form for CSRF token with IMPACT CLASSIFICATION."""
        url = form.get("action", form.get("url", ""))
        method = form.get("method", "POST").upper()
        
        if method not in self.STATE_CHANGING_METHODS:
            return
        
        self.result.endpoints_tested += 1
        
        # === HIGH-IMPACT CLASSIFICATION ===
        impact_type, severity, cvss_score = self._classify_endpoint_impact(url, method)
        impact_description = self._get_impact_description(impact_type)
        
        # Check if form has CSRF token field
        # FIX: Crawler uses "inputs", not "fields"
        fields = form.get("inputs", form.get("fields", []))
        field_names = [f.get("name", "").lower() for f in fields if f.get("name")]
        
        has_csrf_token = any(
            csrf_name.lower() in name 
            for csrf_name in self.CSRF_TOKEN_NAMES 
            for name in field_names
        )
        
        if not has_csrf_token:
            # Create finding with IMPACT-BASED SEVERITY
            title = f"Form missing CSRF token"
            if impact_type != "generic":
                title = f"🔴 HIGH-IMPACT CSRF: {impact_type.replace('_', ' ').title()} - Form Unprotected"
            
            self.result.findings.append(CSRFFinding(
                url=url,
                method=method,
                severity=severity,  # Based on endpoint impact
                title=title,
                description=(
                    f"The form at '{url}' does not include a CSRF token field.\n\n"
                    f"**Impact Classification:** {impact_type.upper()}\n"
                    f"**CVSS Score:** {cvss_score}\n\n"
                    f"**Real-World Impact:**\n{impact_description}"
                ),
                evidence=f"Form fields: {field_names}\nEndpoint: {url}\nMethod: {method}",
                remediation="Add a CSRF token hidden field to the form. "
                           "For high-impact actions, consider requiring re-authentication.",
            ))
    
    async def _test_endpoint_csrf(
        self, 
        client: httpx.AsyncClient, 
        endpoint: str,
        base_url: str
    ) -> None:
        """Test endpoint for CSRF vulnerability with HIGH-IMPACT CLASSIFICATION."""
        # Only test POST/PUT/PATCH/DELETE
        # First, discover the method
        
        self.result.endpoints_tested += 1
        
        url = endpoint if endpoint.startswith("http") else urljoin(base_url, endpoint)
        parsed = urlparse(url)
        
        # === HIGH-IMPACT CLASSIFICATION ===
        impact_type, base_severity, cvss_score = self._classify_endpoint_impact(url, "POST")
        impact_description = self._get_impact_description(impact_type)
        is_high_impact = impact_type != "generic"
        
        try:
            # Test 1: Send POST without CSRF token
            response = await client.post(
                url,
                json={"test": "csrf_check"},
                headers={
                    "Content-Type": "application/json",
                    "Origin": "https://evil.com",  # Different origin
                }
            )
            
            # If request succeeds with foreign origin, potential CSRF
            if response.status_code in [200, 201, 202, 204]:
                # SPA detection: skip if the response is an SPA shell
                ct = response.headers.get("content-type", "")
                if self._is_spa_shell(response.text, ct, url):
                    logger.debug(f"[CSRF] SPA shell at {url}, skipping endpoint CSRF test")
                    return

                # Check if response indicates the action was performed
                # vs just returning an error in JSON
                try:
                    data = response.json()
                    if "error" not in str(data).lower() and "invalid" not in str(data).lower():
                        # Create finding with IMPACT-BASED SEVERITY
                        title = f"Endpoint accepts cross-origin POST"
                        if is_high_impact:
                            title = f"🔴 CRITICAL CSRF: {impact_type.replace('_', ' ').title()} - Cross-Origin Attack Possible"
                        
                        self.result.findings.append(CSRFFinding(
                            url=url,
                            method="POST",
                            severity=base_severity,  # Based on impact
                            title=title,
                            description=(
                                f"The endpoint '{endpoint}' accepted a POST request "
                                f"with Origin: https://evil.com without CSRF validation.\n\n"
                                f"**Impact Classification:** {impact_type.upper()}\n"
                                f"**CVSS Score:** {cvss_score}\n\n"
                                f"**Real-World Impact:**\n{impact_description}"
                            ),
                            evidence=f"Response: {response.status_code}, Body: {str(data)[:200]}",
                            remediation="Implement CSRF token validation or SameSite=Strict cookies. "
                                       "For high-impact actions, require re-authentication.",
                        ))
                except Exception:
                    pass
            
            # Test 2: Test Origin header validation
            response_no_origin = await client.post(
                url,
                json={"test": "csrf_check"},
                headers={"Content-Type": "application/json"}
            )
            
            response_null_origin = await client.post(
                url,
                json={"test": "csrf_check"},
                headers={
                    "Content-Type": "application/json",
                    "Origin": "null",
                }
            )
            
            # If null origin is accepted but other origins aren't, it's vulnerable
            if response_null_origin.status_code in [200, 201] and response.status_code >= 400:
                self.result.findings.append(CSRFFinding(
                    url=url,
                    method="POST",
                    severity=Severity.HIGH,
                    title=f"Endpoint accepts null Origin",
                    description=f"The endpoint '{endpoint}' accepts Origin: null but blocks other origins. "
                               "Attackers can exploit this with sandboxed iframes.",
                    evidence=f"null origin: {response_null_origin.status_code}, evil.com: {response.status_code}",
                    remediation="Block null origin in CORS/CSRF validation.",
                ))
            
            # Test 3: Check X-Requested-With bypass
            response_xhr = await client.post(
                url,
                json={"test": "csrf_check"},
                headers={
                    "Content-Type": "application/json",
                    "X-Requested-With": "XMLHttpRequest",
                    "Origin": "https://evil.com",
                }
            )
            
            if response_xhr.status_code in [200, 201] and response.status_code >= 400:
                self.result.findings.append(CSRFFinding(
                    url=url,
                    method="POST",
                    severity=Severity.MEDIUM,
                    title=f"X-Requested-With header bypass",
                    description=f"The endpoint '{endpoint}' can be accessed with X-Requested-With header "
                               "from any origin. This header can be set via CORS.",
                    evidence=f"With X-Requested-With: {response_xhr.status_code}",
                    remediation="Don't rely solely on X-Requested-With for CSRF protection.",
                ))
                
        except Exception as e:
            logger.debug(f"Endpoint CSRF test error for {endpoint}: {e}")

    # ========================================================================
    # ENTERPRISE METHODS - Token Entropy Analysis
    # ========================================================================
    
    def _calculate_entropy(self, token: str) -> float:
        """Calculate Shannon entropy of a token."""
        if not token:
            return 0.0
        
        # Count character frequencies
        counter = Counter(token)
        length = len(token)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        # Return bits of entropy
        return entropy * length
    
    def _detect_token_pattern(self, token: str) -> tuple[bool, str | None]:
        """Detect if token matches known framework patterns."""
        for framework, pattern in TOKEN_PATTERNS.items():
            if pattern.match(token):
                return True, framework
        return False, None
    
    def _analyze_token(self, token: str) -> TokenAnalysis:
        """Perform comprehensive token analysis."""
        entropy_bits = self._calculate_entropy(token)
        # OWASP recommends 128 bits minimum for CSRF tokens
        # 64 bits is weak against brute-force with modern hardware
        is_predictable = entropy_bits < 128
        matched, framework = self._detect_token_pattern(token)
        
        return TokenAnalysis(
            token_value=token[:20] + "..." if len(token) > 20 else token,
            entropy_bits=entropy_bits,
            is_predictable=is_predictable,
            pattern_detected=framework,
            is_bound_to_session=False,  # Determined by other tests
            is_reusable=False,  # Determined by other tests
            framework_hint=framework,
        )
    
    async def _analyze_token_entropy(self, client: httpx.AsyncClient, base_url: str) -> None:
        """Analyze CSRF token entropy and predictability."""
        logger.info("🔐 Analyzing CSRF token entropy...")
        
        try:
            # Get page with form to extract token
            response = await client.get(base_url)
            
            # Extract tokens from page
            html = response.text
            tokens_found = []
            
            # Search for tokens in hidden fields
            for token_name in self.CSRF_TOKEN_NAMES:
                pattern = rf'name=["\']?{token_name}["\']?\s+value=["\']([^"\']+)["\']'
                matches = re.findall(pattern, html, re.IGNORECASE)
                tokens_found.extend(matches)
                
                # Also check reverse order
                pattern2 = rf'value=["\']([^"\']+)["\']?\s+name=["\']?{token_name}'
                matches2 = re.findall(pattern2, html, re.IGNORECASE)
                tokens_found.extend(matches2)
            
            # Check meta tags (Rails/Phoenix style)
            meta_pattern = r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']'
            meta_tokens = re.findall(meta_pattern, html, re.IGNORECASE)
            tokens_found.extend(meta_tokens)
            
            for token in tokens_found:
                self.result.tokens_analyzed += 1
                analysis = self._analyze_token(token)
                
                if analysis.framework_hint:
                    if analysis.framework_hint not in self.result.frameworks_detected:
                        self.result.frameworks_detected.append(analysis.framework_hint)
                
                if analysis.is_predictable:
                    self.result.findings.append(CSRFFinding(
                        url=base_url,
                        method="GET",
                        severity=Severity.HIGH,
                        title="CSRF Token with Low Entropy",
                        description=f"CSRF token has only {analysis.entropy_bits:.1f} bits of entropy. "
                                   "Recommended minimum is 128 bits for cryptographic security.",
                        evidence=f"Token: {analysis.token_value}, Entropy: {analysis.entropy_bits:.1f} bits",
                        remediation="Use cryptographically secure random token generation. "
                                   "Ensure at least 128 bits of entropy.",
                        cwe_id="CWE-330",
                        vuln_type=CSRFVulnType.WEAK_TOKEN,
                        confidence=85.0,
                        cvss_score=6.5,
                    ))
                
                # Check for timestamp-based tokens
                if re.match(r'^\d{10,13}', token):
                    self.result.findings.append(CSRFFinding(
                        url=base_url,
                        method="GET",
                        severity=Severity.HIGH,
                        title="Timestamp-Based CSRF Token",
                        description="CSRF token appears to be timestamp-based, making it predictable.",
                        evidence=f"Token starts with timestamp pattern: {token[:15]}",
                        remediation="Use cryptographically secure random tokens, not timestamps.",
                        cwe_id="CWE-330",
                        vuln_type=CSRFVulnType.WEAK_TOKEN,
                        confidence=85.0,
                        cvss_score=7.5,
                    ))
                    
                # Cache token for reuse detection
                self._token_cache[token] = base_url
                
        except Exception as e:
            logger.debug(f"Token entropy analysis error: {e}")
    
    # ========================================================================
    # ENTERPRISE METHODS - JSON CSRF Testing
    # ========================================================================
    
    async def _test_json_csrf(
        self, 
        client: httpx.AsyncClient, 
        endpoint: str,
        base_url: str
    ) -> None:
        """Test for JSON-based CSRF vulnerabilities."""
        url = endpoint if endpoint.startswith("http") else urljoin(base_url, endpoint)
        
        try:
            for content_type in CONTENT_TYPE_PAYLOADS:
                for payload in JSON_CSRF_PAYLOADS:
                    # Test without CORS headers (form submission simulation)
                    response = await client.post(
                        url,
                        content=payload,
                        headers={
                            "Content-Type": content_type,
                            "Origin": "https://evil.com",
                        }
                    )
                    
                    if response.status_code in [200, 201, 202, 204]:
                        try:
                            data = response.json()
                            # Check if request was processed (not just CORS preflight)
                            if "error" not in str(data).lower():
                                self.result.findings.append(CSRFFinding(
                                    url=url,
                                    method="POST",
                                    severity=Severity.HIGH,
                                    title="JSON CSRF Vulnerability",
                                    description=f"Endpoint accepts JSON POST from cross-origin "
                                               f"with Content-Type: {content_type}",
                                    evidence=f"Content-Type: {content_type}, "
                                            f"Response: {response.status_code}",
                                    remediation="Validate CSRF token for all JSON endpoints. "
                                               "Check Origin header strictly.",
                                    cwe_id="CWE-352",
                                    vuln_type=CSRFVulnType.JSON_CSRF,
                                    confidence=85.0,
                                    cvss_score=8.0,
                                ))
                                return  # Found vulnerability, no need to continue
                        except Exception:
                            pass
                    
                    # Test text/plain with JSON body (Flash CSRF style)
                    if content_type == "text/plain":
                        # Form submission with text/plain can include JSON
                        response2 = await client.post(
                            url,
                            data=payload,
                            headers={
                                "Content-Type": "text/plain",
                            }
                        )
                        
                        if response2.status_code in [200, 201]:
                            self.result.findings.append(CSRFFinding(
                                url=url,
                                method="POST",
                                severity=Severity.MEDIUM,
                                title="JSON via text/plain CSRF",
                                description="Endpoint accepts text/plain with JSON body. "
                                           "Forms can send text/plain without CORS preflight.",
                                evidence=f"text/plain accepted: {response2.status_code}",
                                remediation="Reject requests with Content-Type: text/plain "
                                           "for JSON endpoints.",
                                cwe_id="CWE-352",
                                vuln_type=CSRFVulnType.CONTENT_TYPE_CONFUSION,
                                confidence=65.0,
                                cvss_score=6.0,
                            ))
                            
        except Exception as e:
            logger.debug(f"JSON CSRF test error: {e}")
    
    # ========================================================================
    # ENTERPRISE METHODS - Origin/Referer Bypass Testing
    # ========================================================================
    
    async def _test_origin_bypass(
        self, 
        client: httpx.AsyncClient, 
        endpoint: str,
        base_url: str
    ) -> None:
        """Test for Origin header bypass vulnerabilities."""
        url = endpoint if endpoint.startswith("http") else urljoin(base_url, endpoint)
        parsed = urlparse(base_url)
        target_host = parsed.netloc
        
        try:
            # First, get baseline with correct origin
            baseline_response = await client.post(
                url,
                json={"test": "csrf"},
                headers={
                    "Content-Type": "application/json",
                    "Origin": base_url,
                }
            )
            baseline_code = baseline_response.status_code
            
            # Test each bypass payload
            for origin_payload in ORIGIN_BYPASS_PAYLOADS:
                # Customize payloads with target domain
                payload = origin_payload.replace("target.com", target_host)
                
                response = await client.post(
                    url,
                    json={"test": "csrf"},
                    headers={
                        "Content-Type": "application/json",
                        "Origin": payload,
                    }
                )
                
                # Check for successful bypass
                if response.status_code in [200, 201, 202, 204]:
                    if payload == "null":
                        self.result.findings.append(CSRFFinding(
                            url=url,
                            method="POST",
                            severity=Severity.HIGH,
                            title="Null Origin Bypass",
                            description="Endpoint accepts requests with Origin: null. "
                                       "Attackers can exploit via sandboxed iframes.",
                            evidence=f"null origin accepted: {response.status_code}",
                            remediation="Explicitly reject null origin in CORS config.",
                            cwe_id="CWE-346",
                            vuln_type=CSRFVulnType.ORIGIN_BYPASS,
                            confidence=85.0,
                            cvss_score=7.5,
                        ))
                    elif "evil.com" in payload:
                        self.result.findings.append(CSRFFinding(
                            url=url,
                            method="POST",
                            severity=Severity.CRITICAL,
                            title="Origin Header Validation Bypass",
                            description=f"Endpoint accepts malicious origin: {payload}",
                            evidence=f"Origin: {payload}, Response: {response.status_code}",
                            remediation="Implement strict origin whitelist validation. "
                                       "Use exact domain matching, not substring.",
                            cwe_id="CWE-346",
                            vuln_type=CSRFVulnType.ORIGIN_BYPASS,
                            confidence=85.0,
                            cvss_score=9.0,
                        ))
            
            # Test Referer header bypass
            for referer in REFERER_BYPASS_PAYLOADS:
                headers = {"Content-Type": "application/json"}
                if referer:
                    headers["Referer"] = referer.replace("target.com", target_host)
                
                response = await client.post(
                    url,
                    json={"test": "csrf"},
                    headers=headers
                )
                
                if response.status_code in [200, 201, 202, 204] and "evil.com" in referer:
                    self.result.findings.append(CSRFFinding(
                        url=url,
                        method="POST",
                        severity=Severity.MEDIUM,
                        title="Referer Header Validation Bypass",
                        description="Endpoint doesn't properly validate Referer header.",
                        evidence=f"Referer: {referer[:50]}, Response: {response.status_code}",
                        remediation="Implement Referer validation as defense-in-depth, "
                                   "but rely primarily on CSRF tokens.",
                        cwe_id="CWE-346",
                        vuln_type=CSRFVulnType.REFERER_BYPASS,
                        confidence=65.0,
                        cvss_score=5.0,
                    ))
                    break
                    
        except Exception as e:
            logger.debug(f"Origin bypass test error: {e}")
    
    # ========================================================================
    # ENTERPRISE METHODS - Clickjacking Detection
    # ========================================================================
    
    async def _test_clickjacking(self, client: httpx.AsyncClient, base_url: str) -> None:
        """Test for clickjacking vulnerability (CSRF combo attack)."""
        logger.info("🖼️ Testing clickjacking protection...")
        
        try:
            response = await client.get(base_url)
            
            # Check X-Frame-Options
            xfo = response.headers.get("X-Frame-Options", "").upper()
            csp = response.headers.get("Content-Security-Policy", "")
            
            has_xfo_protection = xfo in ["DENY", "SAMEORIGIN"]
            has_csp_frame = "frame-ancestors" in csp.lower()
            
            if not has_xfo_protection and not has_csp_frame:
                self.result.findings.append(CSRFFinding(
                    url=base_url,
                    method="GET",
                    severity=Severity.MEDIUM,
                    title="Missing Clickjacking Protection",
                    description="Page lacks X-Frame-Options and CSP frame-ancestors. "
                               "Combined with CSRF, enables UI redressing attacks.",
                    evidence=f"X-Frame-Options: {xfo or 'missing'}, "
                            f"CSP frame-ancestors: {'present' if has_csp_frame else 'missing'}",
                    remediation="Add 'X-Frame-Options: DENY' or CSP 'frame-ancestors: self'.",
                    cwe_id="CWE-1021",
                    vuln_type=CSRFVulnType.CLICKJACKING,
                    confidence=85.0,
                    cvss_score=4.3,
                ))
            elif xfo == "ALLOWFROM" or "ALLOW-FROM" in xfo:
                self.result.findings.append(CSRFFinding(
                    url=base_url,
                    method="GET",
                    severity=Severity.LOW,
                    title="Deprecated X-Frame-Options ALLOW-FROM",
                    description="X-Frame-Options uses deprecated ALLOW-FROM directive. "
                               "Use CSP frame-ancestors instead.",
                    evidence=f"X-Frame-Options: {xfo}",
                    remediation="Replace with CSP frame-ancestors directive.",
                    cwe_id="CWE-16",
                    vuln_type=CSRFVulnType.CLICKJACKING,
                    confidence=85.0,
                    cvss_score=3.0,
                ))
                
        except Exception as e:
            logger.debug(f"Clickjacking test error: {e}")
    
    # ========================================================================
    # ENTERPRISE METHODS - Token Reuse Detection
    # ========================================================================
    
    async def _test_token_reuse(
        self, 
        client: httpx.AsyncClient, 
        base_url: str,
        forms: list
    ) -> None:
        """Test if CSRF tokens can be reused."""
        logger.info("♻️ Testing CSRF token reuse...")
        
        try:
            # Get fresh page twice
            response1 = await client.get(base_url)
            await asyncio.sleep(1)
            response2 = await client.get(base_url)
            
            # Extract tokens from both
            tokens1 = self._extract_tokens_from_html(response1.text)
            tokens2 = self._extract_tokens_from_html(response2.text)
            
            # Check if tokens are the same (should be different per-request)
            common_tokens = set(tokens1) & set(tokens2)
            
            if common_tokens:
                for token in common_tokens:
                    # Verify by using old token in new request
                    self.result.findings.append(CSRFFinding(
                        url=base_url,
                        method="GET",
                        severity=Severity.MEDIUM,
                        title="CSRF Token Not Rotated Per Request",
                        description="CSRF token remains the same across requests. "
                                   "Should rotate per-request for maximum security.",
                        evidence=f"Same token in consecutive requests: {token[:20]}...",
                        remediation="Implement per-request token rotation. "
                                   "At minimum, rotate tokens per session.",
                        cwe_id="CWE-352",
                        vuln_type=CSRFVulnType.TOKEN_REUSE,
                        confidence=65.0,
                        cvss_score=4.0,
                    ))
                    break
            
            # Test if token can be reused after form submission
            if forms and tokens1:
                first_form = forms[0]
                form_url = first_form.get("action", base_url)
                
                # Submit with first token
                form_data = {"csrf_token": tokens1[0] if tokens1 else ""}
                response3 = await client.post(form_url, data=form_data)
                
                # Try reusing same token
                response4 = await client.post(form_url, data=form_data)
                
                if response3.status_code == response4.status_code == 200:
                    self.result.findings.append(CSRFFinding(
                        url=form_url,
                        method="POST",
                        severity=Severity.MEDIUM,
                        title="CSRF Token Reusable After Submission",
                        description="CSRF token accepted multiple times. "
                                   "Tokens should be single-use.",
                        evidence="Same token accepted in consecutive submissions",
                        remediation="Invalidate tokens after use. Implement single-use tokens.",
                        cwe_id="CWE-352",
                        vuln_type=CSRFVulnType.TOKEN_REUSE,
                        confidence=65.0,
                        cvss_score=5.0,
                    ))
                    
        except Exception as e:
            logger.debug(f"Token reuse test error: {e}")
    
    def _extract_tokens_from_html(self, html: str) -> list[str]:
        """Extract all CSRF tokens from HTML."""
        tokens = []
        for token_name in self.CSRF_TOKEN_NAMES:
            pattern = rf'name=["\']?{token_name}["\']?\s+value=["\']([^"\']+)["\']'
            matches = re.findall(pattern, html, re.IGNORECASE)
            tokens.extend(matches)
        return tokens
    
    # ========================================================================
    # ENTERPRISE METHODS - Double Submit Cookie Validation
    # ========================================================================
    
    async def _test_double_submit_cookie(
        self, 
        client: httpx.AsyncClient, 
        base_url: str
    ) -> None:
        """Test double-submit cookie CSRF protection."""
        logger.info("🍪 Testing double-submit cookie pattern...")
        
        try:
            response = await client.get(base_url)
            
            # Look for CSRF cookie
            csrf_cookie = None
            csrf_cookie_name = None
            
            for cookie in response.cookies.jar:
                name_lower = cookie.name.lower()
                if any(csrf in name_lower for csrf in ["csrf", "xsrf", "_token"]):
                    csrf_cookie = cookie.value
                    csrf_cookie_name = cookie.name
                    break
            
            if not csrf_cookie:
                return
            
            # Test if cookie value can be used without token in body
            # (weak double-submit implementation)
            test_response = await client.post(
                base_url,
                json={"action": "test"},
                headers={
                    "Content-Type": "application/json",
                    "X-CSRF-Token": csrf_cookie,  # Use cookie value as header
                }
            )
            
            if test_response.status_code in [200, 201]:
                # Check if token in body matches cookie
                # Weak: attacker can set both cookie and header via XSS
                self.result.findings.append(CSRFFinding(
                    url=base_url,
                    method="POST",
                    severity=Severity.MEDIUM,
                    title="Double-Submit Cookie Without HMAC",
                    description="Double-submit cookie pattern used without cryptographic binding. "
                               "Attacker with XSS can set both cookie and header values.",
                    evidence=f"Cookie: {csrf_cookie_name}, Can set matching header",
                    remediation="Use HMAC to bind CSRF token to session. "
                               "Or use synchronizer token pattern.",
                    cwe_id="CWE-352",
                    vuln_type=CSRFVulnType.DOUBLE_SUBMIT_WEAK,
                    confidence=65.0,
                    cvss_score=5.5,
                ))
            
            # Test if arbitrary cookie value is accepted
            fake_token = secrets.token_hex(16)
            client.cookies.set(csrf_cookie_name, fake_token, domain=urlparse(base_url).netloc)
            
            test_response2 = await client.post(
                base_url,
                json={"action": "test"},
                headers={
                    "Content-Type": "application/json",
                    "X-CSRF-Token": fake_token,
                }
            )
            
            if test_response2.status_code in [200, 201]:
                self.result.findings.append(CSRFFinding(
                    url=base_url,
                    method="POST",
                    severity=Severity.HIGH,
                    title="Double-Submit Cookie Accepts Arbitrary Values",
                    description="Server accepts any matching cookie/header values. "
                               "Token not cryptographically bound to session.",
                    evidence="Arbitrary token value accepted when cookie matches header",
                    remediation="Validate CSRF token against server-side stored value. "
                               "Use signed tokens with session binding.",
                    cwe_id="CWE-352",
                    vuln_type=CSRFVulnType.DOUBLE_SUBMIT_WEAK,
                    confidence=85.0,
                    cvss_score=7.0,
                ))
                
        except Exception as e:
            logger.debug(f"Double-submit cookie test error: {e}")
    
    # ========================================================================
    # ENTERPRISE METHODS - WebSocket CSRF
    # ========================================================================
    
    async def _test_websocket_csrf(
        self, 
        client: httpx.AsyncClient, 
        base_url: str
    ) -> None:
        """Test for Cross-Site WebSocket Hijacking (CSWSH)."""
        logger.info("🔌 Testing WebSocket CSRF (CSWSH)...")
        
        parsed = urlparse(base_url)
        ws_endpoints = [
            f"wss://{parsed.netloc}/ws",
            f"wss://{parsed.netloc}/websocket",
            f"wss://{parsed.netloc}/socket.io/",
            f"wss://{parsed.netloc}/sockjs",
            f"ws://{parsed.netloc}/ws",
        ]
        
        try:
            # Check if WebSocket upgrade is accepted with cross-origin
            for ws_url in ws_endpoints:
                http_url = ws_url.replace("wss://", "https://").replace("ws://", "http://")
                
                response = await client.get(
                    http_url,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": base64.b64encode(secrets.token_bytes(16)).decode(),
                        "Sec-WebSocket-Version": "13",
                        "Origin": "https://evil.com",
                    }
                )
                
                # Check for WebSocket upgrade acceptance
                if response.status_code == 101:
                    self.result.findings.append(CSRFFinding(
                        url=ws_url,
                        method="GET",
                        severity=Severity.HIGH,
                        title="Cross-Site WebSocket Hijacking (CSWSH)",
                        description="WebSocket endpoint accepts connections from any origin. "
                                   "Attacker can hijack authenticated WebSocket sessions.",
                        evidence=f"WebSocket upgrade accepted with Origin: evil.com",
                        remediation="Validate Origin header on WebSocket upgrade. "
                                   "Require CSRF token in WebSocket handshake.",
                        cwe_id="CWE-352",
                        vuln_type=CSRFVulnType.WEBSOCKET_CSRF,
                        confidence=85.0,
                        cvss_score=8.0,
                    ))
                    break
                    
                # Also check if regular HTTP returns info about WebSocket
                if response.status_code == 426:  # Upgrade Required
                    # Check if origin was validated
                    if "origin" not in response.text.lower():
                        self.result.findings.append(CSRFFinding(
                            url=ws_url,
                            method="GET",
                            severity=Severity.MEDIUM,
                            title="WebSocket Endpoint Found - Origin Check Unknown",
                            description="WebSocket endpoint found. Cannot verify origin validation.",
                            evidence=f"WebSocket endpoint: {ws_url}",
                            remediation="Ensure Origin header validation on WebSocket upgrade.",
                            cwe_id="CWE-352",
                            vuln_type=CSRFVulnType.WEBSOCKET_CSRF,
                            confidence=40.0,
                            cvss_score=5.0,
                        ))
                        break
                        
        except Exception as e:
            logger.debug(f"WebSocket CSRF test error: {e}")
    
    # ========================================================================
    # ENTERPRISE METHODS - Token Leakage Detection
    # ========================================================================
    
    async def _check_token_leakage(
        self, 
        client: httpx.AsyncClient, 
        base_url: str
    ) -> None:
        """Check if CSRF tokens leak in URLs or Referer headers."""
        logger.info("🔍 Checking for CSRF token leakage...")
        
        try:
            response = await client.get(base_url)
            
            # Check for tokens in URL parameters
            parsed = urlparse(str(response.url))
            query_params = parse_qs(parsed.query)
            
            for param_name, values in query_params.items():
                if any(csrf in param_name.lower() for csrf in ["csrf", "token", "xsrf"]):
                    self.result.findings.append(CSRFFinding(
                        url=base_url,
                        method="GET",
                        severity=Severity.HIGH,
                        title="CSRF Token in URL",
                        description=f"CSRF token '{param_name}' exposed in URL. "
                                   "Tokens in URLs leak via Referer header and browser history.",
                        evidence=f"Parameter: {param_name}={values[0][:20]}...",
                        remediation="Never include CSRF tokens in URLs. "
                                   "Use hidden form fields or custom headers.",
                        cwe_id="CWE-598",
                        vuln_type=CSRFVulnType.TOKEN_LEAKAGE,
                        confidence=85.0,
                        cvss_score=6.5,
                    ))
            
            # Check HTML for tokens that might leak
            html = response.text
            
            # Check for tokens in links
            link_pattern = r'href=["\'][^"\']*[?&](csrf|token|_token)=([^"\'&]+)'
            link_matches = re.findall(link_pattern, html, re.IGNORECASE)
            
            if link_matches:
                self.result.findings.append(CSRFFinding(
                    url=base_url,
                    method="GET",
                    severity=Severity.HIGH,
                    title="CSRF Token in HTML Links",
                    description="CSRF tokens found embedded in hyperlinks. "
                               "Will leak via Referer when clicking links.",
                    evidence=f"Found {len(link_matches)} links with tokens",
                    remediation="Remove tokens from URLs. Use POST forms or JavaScript.",
                    cwe_id="CWE-598",
                    vuln_type=CSRFVulnType.TOKEN_LEAKAGE,
                    confidence=85.0,
                    cvss_score=6.5,
                ))
                
        except Exception as e:
            logger.debug(f"Token leakage check error: {e}")

    # ========================================================================
    # MULTI-STEP CSRF WORKFLOW TESTING
    # ========================================================================

    async def _test_multistep_csrf(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        forms: list[dict],
    ) -> None:
        """
        Test multi-step workflows for CSRF vulnerabilities.

        Many applications require multiple steps (e.g., confirm page before action).
        Attackers can bypass CSRF protection if intermediate steps don't validate tokens.

        Workflow patterns tested:
        1. Password change: settings → confirm → change
        2. Transfer: form → confirm → execute
        3. Delete: action → confirm → delete
        """
        logger.info("🔄 Testing multi-step CSRF workflows...")

        # Identify potential multi-step workflows
        workflows = self._identify_workflows(forms)

        for workflow in workflows:
            try:
                await self._test_workflow_csrf(client, base_url, workflow)
            except Exception as e:
                logger.debug(f"Workflow CSRF test error: {e}")

    def _identify_workflows(self, forms: list[dict]) -> list[dict]:
        """Identify potential multi-step workflows from forms and endpoints."""
        workflows = []

        # Pattern 1: Password change workflow
        password_forms = [f for f in forms if any(
            kw in f.get("action", "").lower()
            for kw in ["password", "passwd", "pw"]
        )]
        if password_forms:
            workflows.append({
                "name": "Password Change",
                "type": "password_change",
                "steps": [
                    {"action": "settings", "paths": ["/settings", "/account", "/profile"]},
                    {"action": "confirm", "paths": ["/confirm", "/verify"]},
                    {"action": "execute", "forms": password_forms},
                ],
                "impact": "CRITICAL",
            })

        # Pattern 2: Money transfer workflow
        transfer_indicators = ["transfer", "send", "pay", "withdraw", "deposit"]
        transfer_forms = [f for f in forms if any(
            kw in f.get("action", "").lower()
            for kw in transfer_indicators
        )]
        if transfer_forms:
            workflows.append({
                "name": "Money Transfer",
                "type": "financial",
                "steps": [
                    {"action": "form", "forms": transfer_forms},
                    {"action": "confirm", "paths": ["/confirm", "/review"]},
                    {"action": "execute", "paths": ["/execute", "/submit"]},
                ],
                "impact": "CRITICAL",
            })

        # Pattern 3: Delete/deactivate workflow
        delete_forms = [f for f in forms if any(
            kw in f.get("action", "").lower()
            for kw in ["delete", "remove", "deactivate", "close"]
        )]
        if delete_forms:
            workflows.append({
                "name": "Account Deletion",
                "type": "destructive",
                "steps": [
                    {"action": "initiate", "forms": delete_forms},
                    {"action": "confirm", "paths": ["/confirm", "/verify"]},
                ],
                "impact": "HIGH",
            })

        return workflows

    async def _test_workflow_csrf(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        workflow: dict,
    ) -> None:
        """Test a multi-step workflow for CSRF vulnerabilities."""
        workflow_name = workflow["name"]
        steps = workflow["steps"]

        # Track tokens across steps
        tokens_per_step: list[str | None] = []
        vulnerable_steps: list[int] = []

        for i, step in enumerate(steps):
            step_action = step.get("action", "")

            # Try to get a page/form for this step
            if "forms" in step and step["forms"]:
                # Use the first form for testing
                form = step["forms"][0]
                form_url = form.get("action", "")
                if not form_url.startswith("http"):
                    form_url = f"{base_url}{form_url}"

                # Check if this step requires a CSRF token
                fields = form.get("fields", [])
                csrf_field = None
                for field in fields:
                    if any(name in field.get("name", "").lower() for name in self.CSRF_TOKEN_NAMES):
                        csrf_field = field
                        break

                if csrf_field:
                    tokens_per_step.append(csrf_field.get("value", ""))
                else:
                    # No CSRF token in this step - potentially vulnerable
                    tokens_per_step.append(None)
                    if step_action in ("execute", "confirm"):
                        vulnerable_steps.append(i)

            elif "paths" in step:
                # Probe paths to find the step
                for path in step["paths"]:
                    try:
                        resp = await client.get(f"{base_url}{path}")
                        if resp.status_code == 200:
                            # Check for CSRF token in response
                            html = resp.text
                            has_token = any(
                                name in html.lower()
                                for name in self.CSRF_TOKEN_NAMES
                            )
                            tokens_per_step.append("found" if has_token else None)
                            if not has_token and step_action in ("execute", "confirm"):
                                vulnerable_steps.append(i)
                            break
                    except Exception:
                        pass
                else:
                    tokens_per_step.append(None)

        # Report if intermediate steps lack CSRF protection
        if vulnerable_steps:
            vulnerable_step_names = [steps[i].get("action", f"step {i}") for i in vulnerable_steps]
            self.result.findings.append(CSRFFinding(
                url=base_url,
                method="POST",
                severity=workflow.get("impact", "HIGH"),
                title=f"Multi-Step {workflow_name} Workflow Missing CSRF Protection",
                description=(
                    f"The {workflow_name} workflow has {len(steps)} steps, but "
                    f"step(s) {vulnerable_step_names} lack CSRF token validation. "
                    "An attacker can skip directly to the vulnerable step, bypassing "
                    "any CSRF protection on earlier steps."
                ),
                evidence=(
                    f"Workflow: {workflow_name}\n"
                    f"Steps: {len(steps)}\n"
                    f"Vulnerable steps: {vulnerable_step_names}\n"
                    f"Token presence: {tokens_per_step}"
                ),
                remediation=(
                    "Validate CSRF tokens on EVERY step of multi-step workflows. "
                    "Bind workflow state to the session to prevent step-skipping. "
                    "Use unique tokens per step for sensitive operations."
                ),
                cwe_id="CWE-352",
                vuln_type=CSRFVulnType.WORKFLOW_BYPASS,
                confidence=80.0,
                cvss_score=8.0 if workflow.get("impact") == "CRITICAL" else 6.5,
            ))


async def scan_csrf(
    host: str,
    asset_data: dict,
    settings: Any = None
) -> dict:
    """Convenience function to run CSRF scan."""
    scanner = CSRFScanner(settings)
    return await scanner.scan(host, asset_data)
