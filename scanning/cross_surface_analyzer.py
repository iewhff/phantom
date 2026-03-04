"""
PHANTOM AI - Cross-Surface Analyzer

Strengthens cross-surface analysis by correlating vulnerabilities across:
1. UI (web frontend) - Forms, JavaScript, client-side validation
2. API (REST, GraphQL, WebSocket) - Backend endpoints
3. Background Jobs (async, queues, workers) - Deferred processing
4. Integrations (OAuth, webhooks, SSO) - Third-party connections

Real attackers don't limit themselves to a single interface. This module:
- Discovers all attack surfaces from a single target
- Correlates findings across surfaces
- Tests cross-surface attack patterns
- Chains vulnerabilities that span multiple surfaces

Key Attack Patterns:
- API bypasses UI validation → inject values client blocks
- Hidden API fields not in UI → discover admin flags
- OAuth redirect manipulation → account takeover
- Webhook signature bypass → unauthorized actions
- Job injection via async endpoints → bypass rate limits
- Cross-surface IDOR → use IDs from one surface on another
"""

from __future__ import annotations

import asyncio
import json
import re
import ssl
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp

from scanning.findings import Finding, VulnType, Severity
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.shared_findings_store import SharedFindingsStore

logger = get_logger(__name__)

# Public API exports
__all__ = [
    "CrossSurfaceAnalyzer",
    "SurfaceType",
    "DiscoveredSurface",
    "CrossSurfaceCorrelation",
    "SURFACE_PATTERNS",
]

# ============================================================================
# Constants (H5 FIX)
# ============================================================================
DEFAULT_TIMEOUT = 15.0
MIN_RESPONSE_LENGTH_SMALL = 50
MIN_RESPONSE_LENGTH_MEDIUM = 100
MAX_BYPASS_LENGTH_ADDITION = 100
MAX_IDS_TO_TEST = 3
MAX_SENSITIVE_TYPES_TO_QUERY = 3
MAX_SURFACES = 500
MAX_CORRELATIONS = 1000
EXIST_STATUS_CODES = frozenset({200, 401, 403, 405})
SUCCESS_STATUS_CODES = frozenset({200, 201, 202})

# SSL context cache (C2 FIX: configurable SSL verification)
_SSL_CONTEXTS: dict[bool, ssl.SSLContext] = {}


def _get_ssl_context(verify: bool = False) -> ssl.SSLContext:
    """Get SSL context with optional certificate verification.

    Args:
        verify: If True, verify SSL certificates. If False, skip verification.

    Returns:
        SSL context configured for the verification mode.
    """
    if verify not in _SSL_CONTEXTS:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        _SSL_CONTEXTS[verify] = ctx
    return _SSL_CONTEXTS[verify]


class SurfaceType(Enum):
    """Types of attack surfaces."""
    UI = auto()              # Web frontend (HTML forms, JS)
    API_REST = auto()        # REST API endpoints
    API_GRAPHQL = auto()     # GraphQL endpoint
    API_WEBSOCKET = auto()   # WebSocket endpoints
    OAUTH = auto()           # OAuth/OIDC endpoints
    WEBHOOK = auto()         # Webhook receivers
    SSO = auto()             # SAML/SSO endpoints
    ASYNC_JOB = auto()       # Background job endpoints
    ADMIN = auto()           # Admin/internal endpoints
    UNKNOWN = auto()


@dataclass
class DiscoveredSurface:
    """A discovered attack surface."""
    surface_type: SurfaceType
    url: str
    method: str = "GET"
    parameters: list[str] = field(default_factory=list)
    response_fields: list[str] = field(default_factory=list)
    requires_auth: bool = False
    related_surfaces: list[str] = field(default_factory=list)  # URLs of related surfaces
    metadata: dict = field(default_factory=dict)


@dataclass
class CrossSurfaceCorrelation:
    """A correlation between two surfaces."""
    surface_a: DiscoveredSurface
    surface_b: DiscoveredSurface
    correlation_type: str  # "same_resource", "ui_api_pair", "oauth_callback", etc.
    shared_parameters: list[str] = field(default_factory=list)
    confidence: float = 0.0


# Patterns for surface type detection
SURFACE_PATTERNS = {
    SurfaceType.API_REST: [
        r"/api/", r"/rest/", r"/v\d+/", r"/graphql",
        r"\.json$", r"\.xml$",
    ],
    SurfaceType.API_GRAPHQL: [
        r"/graphql", r"/gql", r"/query",
    ],
    SurfaceType.OAUTH: [
        r"/oauth", r"/auth/callback", r"/login/callback",
        r"/connect/", r"state=", r"code=", r"access_token=",
        r"/authorize", r"/token", r"/.well-known/openid",
    ],
    SurfaceType.WEBHOOK: [
        r"/webhook", r"/hook", r"/callback", r"/notify",
        r"/events", r"/ingest", r"/receive",
    ],
    SurfaceType.SSO: [
        r"/saml", r"/sso", r"/adfs", r"/simplesaml",
        r"/auth/saml", r"SAMLRequest", r"SAMLResponse",
    ],
    SurfaceType.ASYNC_JOB: [
        r"/job", r"/task", r"/queue", r"/worker",
        r"/async", r"/background", r"/status/",
        r"/poll", r"/progress",
    ],
    SurfaceType.ADMIN: [
        r"/admin", r"/manage", r"/internal", r"/console",
        r"/dashboard", r"/_", r"/debug",
    ],
}

# Fields that indicate hidden/sensitive data in API responses
HIDDEN_FIELD_PATTERNS = [
    r'"is_?admin"', r'"role"', r'"permissions?"', r'"privileges?"',
    r'"internal_?id"', r'"secret"', r'"api_?key"', r'"token"',
    r'"password_?hash"', r'"salt"', r'"private_?key"',
    r'"ssn"', r'"credit_?card"', r'"account_?number"',
    r'"internal_?notes?"', r'"debug"', r'"_id"', r'"__',
]

# UI validation patterns (client-side restrictions to bypass)
UI_VALIDATION_PATTERNS = {
    "maxlength": r'maxlength=["\']?(\d+)',
    "min": r'min=["\']?([0-9.-]+)',
    "max": r'max=["\']?([0-9.-]+)',
    "pattern": r'pattern=["\']([^"\']+)',
    "required": r'required(?:\s|>|/)',
    "disabled": r'disabled(?:\s|>|/)',
    "readonly": r'readonly(?:\s|>|/)',
    "type_number": r'type=["\']number["\']',
    "type_email": r'type=["\']email["\']',
}

# OAuth security test patterns
OAUTH_ATTACK_PATTERNS = {
    "open_redirect": [
        "redirect_uri=https://evil.example.com",
        "redirect_uri=https://target.com@evil.example.com",
        "redirect_uri=https://target.com.evil.example.com",
        "redirect_uri=//evil.example.com",
        "redirect_uri=https://target.com/callback/../../../evil",
    ],
    "state_manipulation": [
        "state=",  # Empty state
        "state=attacker_controlled",
    ],
    "scope_escalation": [
        "scope=admin",
        "scope=openid profile email admin",
        "scope=*",
    ],
}

# Webhook security test patterns
WEBHOOK_ATTACK_PATTERNS = {
    "signature_bypass": [
        ("X-Hub-Signature", ""),
        ("X-Hub-Signature-256", "sha256=invalid"),
        ("X-Webhook-Signature", ""),
        ("Stripe-Signature", "t=0,v1=invalid"),
    ],
    "replay": [
        ("X-Request-Timestamp", "0"),
        ("X-Timestamp", "1000000000"),
    ],
    "ssrf_callback": [
        "callback_url=http://169.254.169.254/latest/meta-data/",
        "webhook_url=http://localhost:6379/",
        "notify_url=http://127.0.0.1:8080/admin",
    ],
}


class CrossSurfaceAnalyzer(ScanModule):
    """
    Analyzes vulnerabilities across multiple attack surfaces.

    Discovers UI, API, OAuth, webhooks, and async job surfaces,
    then tests cross-surface attack patterns that span multiple interfaces.
    """

    name = "cross_surface"
    description = "Cross-surface vulnerability analysis"

    def __init__(self, settings: Any = None) -> None:
        super().__init__(settings)
        # Thread safety locks (C1 FIX)
        self._lock = asyncio.Lock()
        self._sync_lock = threading.Lock()

        # State
        self._base_url = ""
        self._surfaces: list[DiscoveredSurface] = []
        self._correlations: list[CrossSurfaceCorrelation] = []
        self._auth_headers: dict[str, str] = {}
        self._rate_limiter: Any = None
        self._timeout = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)
        self._ui_baseline: str = ""
        self._api_responses: dict[str, dict] = {}  # url -> {fields, status, body_sample}
        self._verify_ssl: bool = False  # C2 FIX: configurable

        # Initialize metrics (H2 FIX)
        self._init_metrics()

    def _init_metrics(self) -> None:
        """Initialize metrics tracking."""
        self._metrics = {
            "surfaces_discovered": 0,
            "correlations_found": 0,
            "tests_run": 0,
            "findings_generated": 0,
            "by_surface_type": defaultdict(int),
            "by_test_type": defaultdict(int),
            "probes_attempted": 0,
            "probes_succeeded": 0,
        }

    def get_metrics(self) -> dict:
        """Get current metrics.

        Returns:
            Dictionary with all tracked metrics.
        """
        with self._sync_lock:
            metrics = dict(self._metrics)
            metrics["by_surface_type"] = dict(metrics["by_surface_type"])
            metrics["by_test_type"] = dict(metrics["by_test_type"])
            metrics["surfaces_count"] = len(self._surfaces)
            metrics["correlations_count"] = len(self._correlations)
            return metrics

    def reset_metrics(self) -> None:
        """Reset all metrics to initial values."""
        with self._sync_lock:
            self._init_metrics()

    async def _add_surface(self, surface: DiscoveredSurface) -> bool:
        """Add a surface with limit checking (H3 FIX).

        Args:
            surface: The surface to add.

        Returns:
            True if added, False if limit reached.
        """
        async with self._lock:
            if len(self._surfaces) >= MAX_SURFACES:
                logger.warning(f"[CROSS-SURFACE] Surface limit reached ({MAX_SURFACES})")
                return False
            self._surfaces.append(surface)
            self._metrics["surfaces_discovered"] += 1
            self._metrics["by_surface_type"][surface.surface_type.name] += 1
            return True

    async def _add_correlation(self, correlation: CrossSurfaceCorrelation) -> bool:
        """Add a correlation with limit checking (H3 FIX).

        Args:
            correlation: The correlation to add.

        Returns:
            True if added, False if limit reached.
        """
        async with self._lock:
            if len(self._correlations) >= MAX_CORRELATIONS:
                logger.warning(f"[CROSS-SURFACE] Correlation limit reached ({MAX_CORRELATIONS})")
                return False
            self._correlations.append(correlation)
            self._metrics["correlations_found"] += 1
            return True

    async def scan(
        self,
        host: str,
        port: int | None = None,
        extra_params: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Main entry point for cross-surface analysis.

        Args:
            host: Target host or URL.
            port: Optional port number.
            extra_params: Additional parameters including auth_context, rate_limiter,
                         endpoints, verify_ssl.

        Returns:
            List of discovered findings.
        """
        extra_params = extra_params or {}
        self._base_url = self._resolve_base_url(host, port)

        findings: list[Finding] = []

        # Get auth context
        auth_context = extra_params.get("auth_context")
        if auth_context:
            if hasattr(auth_context, "auth_headers"):
                self._auth_headers = auth_context.auth_headers
            elif hasattr(auth_context, "token") and auth_context.token:
                self._auth_headers["Authorization"] = f"Bearer {auth_context.token}"

        # Get rate limiter
        self._rate_limiter = extra_params.get("rate_limiter")

        # Get SSL verification setting (C2 FIX)
        self._verify_ssl = extra_params.get("verify_ssl", False)

        # Get discovered endpoints from other modules
        endpoints = extra_params.get("endpoints", [])

        logger.info(f"[CROSS-SURFACE] Starting analysis for {self._base_url}")

        # Phase 1: Discover all attack surfaces
        await self._discover_surfaces(endpoints)
        logger.info(f"[CROSS-SURFACE] Discovered {len(self._surfaces)} surfaces")

        # Phase 2: Fetch UI baseline for comparison
        await self._fetch_ui_baseline()

        # Phase 3: Correlate surfaces (find UI-API pairs, etc.)
        await self._correlate_surfaces()
        logger.info(f"[CROSS-SURFACE] Found {len(self._correlations)} correlations")

        # Phase 4: Test cross-surface attacks

        # 4.1: UI/API Validation Bypass
        self._metrics["tests_run"] += 1
        bypass_findings = await self._test_ui_api_bypass()
        findings.extend(bypass_findings)
        self._metrics["by_test_type"]["ui_api_bypass"] += len(bypass_findings)

        # 4.2: Hidden API Fields
        self._metrics["tests_run"] += 1
        hidden_findings = await self._test_hidden_fields()
        findings.extend(hidden_findings)
        self._metrics["by_test_type"]["hidden_fields"] += len(hidden_findings)

        # 4.3: OAuth Security
        self._metrics["tests_run"] += 1
        oauth_findings = await self._test_oauth_security()
        findings.extend(oauth_findings)
        self._metrics["by_test_type"]["oauth"] += len(oauth_findings)

        # 4.4: Webhook Security
        self._metrics["tests_run"] += 1
        webhook_findings = await self._test_webhook_security()
        findings.extend(webhook_findings)
        self._metrics["by_test_type"]["webhook"] += len(webhook_findings)

        # 4.5: Async Job Abuse
        self._metrics["tests_run"] += 1
        job_findings = await self._test_async_job_abuse()
        findings.extend(job_findings)
        self._metrics["by_test_type"]["async_job"] += len(job_findings)

        # 4.6: Cross-Surface IDOR
        self._metrics["tests_run"] += 1
        idor_findings = await self._test_cross_surface_idor()
        findings.extend(idor_findings)
        self._metrics["by_test_type"]["idor"] += len(idor_findings)

        # 4.7: GraphQL Cross-Surface
        self._metrics["tests_run"] += 1
        graphql_findings = await self._test_graphql_cross_surface()
        findings.extend(graphql_findings)
        self._metrics["by_test_type"]["graphql"] += len(graphql_findings)

        # Deduplicate
        findings = self._deduplicate(findings)

        # Update metrics
        self._metrics["findings_generated"] = len(findings)

        # M4 FIX: Share HIGH+ findings for cross-module chaining
        self._share_high_findings(findings)

        logger.info(f"[CROSS-SURFACE] Complete: {len(findings)} findings")
        return findings

    def _share_high_findings(self, findings: list[Finding]) -> None:
        """Share HIGH+ findings with SharedFindingsStore for cross-module chaining.

        This enables other modules to chain with cross-surface findings,
        e.g., OAuth redirect manipulation + XSS = account takeover.

        Args:
            findings: List of findings to potentially share.
        """
        try:
            store = SharedFindingsStore()
            shared_count = 0
            for finding in findings:
                severity = getattr(finding, "severity", "").upper()
                if severity in ("HIGH", "CRITICAL"):
                    store.add_finding(finding)
                    shared_count += 1
            if shared_count > 0:
                logger.debug(f"[CROSS-SURFACE] Shared {shared_count} HIGH+ findings for chaining")
        except Exception as e:
            logger.debug(f"[CROSS-SURFACE] Could not share findings: {e}")

    def _resolve_base_url(self, host: str, port: int | None) -> str:
        """Resolve base URL from host and port."""
        if host.startswith(("http://", "https://")):
            return host.rstrip("/")

        if port in (443, 8443):
            protocol = "https"
        else:
            protocol = "http"

        if port and port not in (80, 443):
            return f"{protocol}://{host}:{port}"
        return f"{protocol}://{host}"

    async def _discover_surfaces(self, endpoints: list) -> None:
        """Discover all attack surfaces from endpoints."""
        for ep in endpoints:
            url = getattr(ep, "url", "") or getattr(ep, "path", "")
            method = getattr(ep, "method", "GET")

            if not url:
                continue

            if not url.startswith("http"):
                url = urljoin(self._base_url, url)

            surface_type = self._classify_surface(url)

            surface = DiscoveredSurface(
                surface_type=surface_type,
                url=url,
                method=method,
                parameters=getattr(ep, "parameters", []) or [],
                requires_auth=getattr(ep, "requires_auth", False),
            )

            # Use limit-checked method (H3 FIX)
            if not await self._add_surface(surface):
                break  # Limit reached

        # Also probe for common integration endpoints
        await self._probe_integration_endpoints()

    def _classify_surface(self, url: str) -> SurfaceType:
        """Classify URL into surface type."""
        url_lower = url.lower()

        for surface_type, patterns in SURFACE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, url_lower, re.IGNORECASE):
                    return surface_type

        # Default: if it looks like API, it's API_REST
        if any(kw in url_lower for kw in ["/api/", "/rest/", "/v1/", "/v2/"]):
            return SurfaceType.API_REST

        return SurfaceType.UI

    async def _probe_integration_endpoints(self) -> None:
        """Probe for common integration endpoints."""
        integration_paths = [
            # OAuth
            ("/oauth/authorize", SurfaceType.OAUTH),
            ("/oauth/token", SurfaceType.OAUTH),
            ("/oauth/callback", SurfaceType.OAUTH),
            ("/auth/callback", SurfaceType.OAUTH),
            ("/.well-known/openid-configuration", SurfaceType.OAUTH),

            # Webhooks
            ("/webhook", SurfaceType.WEBHOOK),
            ("/webhooks", SurfaceType.WEBHOOK),
            ("/api/webhook", SurfaceType.WEBHOOK),
            ("/hooks", SurfaceType.WEBHOOK),

            # SSO
            ("/saml/acs", SurfaceType.SSO),
            ("/saml/login", SurfaceType.SSO),
            ("/sso/callback", SurfaceType.SSO),

            # Async/Jobs
            ("/api/jobs", SurfaceType.ASYNC_JOB),
            ("/api/tasks", SurfaceType.ASYNC_JOB),
            ("/api/queue", SurfaceType.ASYNC_JOB),

            # GraphQL
            ("/graphql", SurfaceType.API_GRAPHQL),
            ("/api/graphql", SurfaceType.API_GRAPHQL),
        ]

        ssl_ctx = _get_ssl_context(self._verify_ssl)

        async with aiohttp.ClientSession(timeout=self._timeout) as session:
            for path, surface_type in integration_paths:
                url = urljoin(self._base_url, path)

                # Skip if already discovered
                if any(s.url == url for s in self._surfaces):
                    continue

                self._metrics["probes_attempted"] += 1

                try:
                    if self._rate_limiter:
                        await self._rate_limiter.acquire()

                    async with session.get(
                        url, headers=self._auth_headers, ssl=ssl_ctx
                    ) as resp:
                        if resp.status in EXIST_STATUS_CODES:
                            # Endpoint exists (even if protected)
                            surface = DiscoveredSurface(
                                surface_type=surface_type,
                                url=url,
                                method="GET",
                                requires_auth=(resp.status in (401, 403)),
                                metadata={"probed": True},
                            )
                            if await self._add_surface(surface):
                                self._metrics["probes_succeeded"] += 1
                                logger.debug(f"[CROSS-SURFACE] Probed: {path} ({surface_type.name})")
                            else:
                                break  # Limit reached

                except aiohttp.ClientError as e:
                    logger.debug(f"[CROSS-SURFACE] Connection error for {path}: {e}")
                except asyncio.TimeoutError:
                    logger.debug(f"[CROSS-SURFACE] Timeout for {path}")
                except Exception as e:
                    logger.debug(f"[CROSS-SURFACE] Probe failed for {path}: {e}")

    async def _fetch_ui_baseline(self) -> None:
        """Fetch UI baseline for form analysis."""
        ssl_ctx = _get_ssl_context(self._verify_ssl)

        try:
            async with aiohttp.ClientSession(timeout=self._timeout) as session:
                async with session.get(
                    self._base_url, headers=self._auth_headers, ssl=ssl_ctx
                ) as resp:
                    if resp.status == 200:
                        self._ui_baseline = await resp.text()
        except aiohttp.ClientError as e:
            logger.debug(f"[CROSS-SURFACE] Connection error fetching UI baseline: {e}")
        except asyncio.TimeoutError:
            logger.debug("[CROSS-SURFACE] Timeout fetching UI baseline")
        except Exception as e:
            logger.debug(f"[CROSS-SURFACE] Failed to fetch UI baseline: {e}")

    async def _correlate_surfaces(self) -> None:
        """Find correlations between surfaces."""
        # Group by resource patterns
        api_surfaces = [s for s in self._surfaces if s.surface_type in (
            SurfaceType.API_REST, SurfaceType.API_GRAPHQL
        )]
        ui_surfaces = [s for s in self._surfaces if s.surface_type == SurfaceType.UI]

        # Find UI-API pairs (same resource, different surface)
        for api in api_surfaces:
            api_resource = self._extract_resource_name(api.url)
            if not api_resource:
                continue

            for ui in ui_surfaces:
                ui_resource = self._extract_resource_name(ui.url)
                if api_resource == ui_resource:
                    correlation = CrossSurfaceCorrelation(
                        surface_a=api,
                        surface_b=ui,
                        correlation_type="ui_api_pair",
                        shared_parameters=list(
                            set(api.parameters) & set(ui.parameters)
                        ),
                        confidence_score=0.8,
                    )
                    if not await self._add_correlation(correlation):
                        return  # Limit reached

        # Find OAuth callback pairs
        oauth_surfaces = [s for s in self._surfaces if s.surface_type == SurfaceType.OAUTH]
        for oauth in oauth_surfaces:
            if "callback" in oauth.url.lower() or "redirect" in oauth.url.lower():
                # Find corresponding authorize endpoint
                for other in oauth_surfaces:
                    if "authorize" in other.url.lower():
                        correlation = CrossSurfaceCorrelation(
                            surface_a=other,
                            surface_b=oauth,
                            correlation_type="oauth_flow",
                            confidence_score=0.9,
                        )
                        if not await self._add_correlation(correlation):
                            return  # Limit reached

    def _extract_resource_name(self, url: str) -> str:
        """Extract resource name from URL path."""
        parsed = urlparse(url)
        path_parts = [p for p in parsed.path.split("/") if p]

        # Skip common prefixes
        skip = {"api", "rest", "v1", "v2", "v3"}
        for part in path_parts:
            if part.lower() not in skip and not part.isdigit():
                return part.lower()

        return ""

    async def _test_ui_api_bypass(self) -> list[Finding]:
        """Test if API accepts values that UI would block."""
        findings: list[Finding] = []
        ssl_ctx = _get_ssl_context(self._verify_ssl)

        # Extract UI validation rules from baseline
        ui_validations = self._extract_ui_validations(self._ui_baseline)

        if not ui_validations:
            return findings

        # Find API endpoints for same resources
        for field_name, validation in ui_validations.items():
            # Find API endpoints that might accept this field
            for surface in self._surfaces:
                if surface.surface_type not in (SurfaceType.API_REST,):
                    continue

                # Try to bypass the validation via API
                bypass_value = self._generate_bypass_value(validation)
                if not bypass_value:
                    continue

                try:
                    if self._rate_limiter:
                        await self._rate_limiter.acquire()

                    body = {field_name: bypass_value}

                    async with aiohttp.ClientSession(timeout=self._timeout) as session:
                        async with session.post(
                            surface.url,
                            json=body,
                            headers=self._auth_headers,
                            ssl=ssl_ctx,
                        ) as resp:
                            if resp.status in SUCCESS_STATUS_CODES:
                                text = await resp.text()

                                # Check if bypass value was accepted
                                if (str(bypass_value) in text or
                                    f'"{field_name}"' in text.lower()):
                                    findings.append(Finding(
                                        name=f"UI Validation Bypass: {field_name}",
                                        severity=Severity.MEDIUM,
                                        confidence_score=80,
                                        vuln_type=VulnType.LOGIC_FLAW,
                                        scanner="cross_surface",
                                        description=(
                                            f"API endpoint accepts values that UI validation "
                                            f"would block for field '{field_name}'. "
                                            f"UI rule: {validation['type']}={validation['value']}, "
                                            f"Bypass value: {bypass_value}"
                                        ),
                                        endpoint=surface.url,
                                        evidence=[
                                            f"UI validation: {validation}",
                                            f"API accepted: {bypass_value}",
                                            f"Response status: {resp.status}",
                                        ],
                                        metadata={
                                            "field": field_name,
                                            "validation": validation,
                                            "bypass_value": str(bypass_value),
                                            "test_type": "ui_api_bypass",
                                        },
                                    ))
                                    break  # One finding per field

                except aiohttp.ClientError as e:
                    logger.debug(f"[CROSS-SURFACE] Connection error in UI bypass test: {e}")
                except asyncio.TimeoutError:
                    logger.debug("[CROSS-SURFACE] Timeout in UI bypass test")
                except Exception as e:
                    logger.debug(f"[CROSS-SURFACE] UI bypass test failed: {e}")

        return findings

    def _extract_ui_validations(self, html: str) -> dict[str, dict]:
        """Extract validation rules from HTML forms."""
        validations = {}

        if not html:
            return validations

        # Find input fields with validation attributes
        input_pattern = r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>'

        for match in re.finditer(input_pattern, html, re.IGNORECASE):
            full_tag = match.group(0)
            field_name = match.group(1)

            for val_type, val_pattern in UI_VALIDATION_PATTERNS.items():
                val_match = re.search(val_pattern, full_tag, re.IGNORECASE)
                if val_match:
                    validations[field_name] = {
                        "type": val_type,
                        "value": val_match.group(1) if val_match.lastindex else True,
                    }
                    break

        return validations

    def _generate_bypass_value(self, validation: dict) -> Any:
        """Generate a value that bypasses the validation."""
        val_type = validation.get("type", "")
        val_value = validation.get("value")

        if val_type == "maxlength" and val_value:
            # Exceed max length
            return "A" * (int(val_value) + 100)

        elif val_type == "min" and val_value:
            # Go below minimum
            return float(val_value) - 1000

        elif val_type == "max" and val_value:
            # Go above maximum
            return float(val_value) + 1000

        elif val_type == "type_number":
            # Send non-numeric
            return "not_a_number"

        elif val_type == "type_email":
            # Send invalid email
            return "not_an_email"

        elif val_type == "pattern":
            # Try to bypass pattern
            return "AAAA<script>alert(1)</script>"

        elif val_type in ("disabled", "readonly"):
            # Send value for disabled/readonly field
            return "attacker_controlled"

        return None

    async def _test_hidden_fields(self) -> list[Finding]:
        """Test for hidden fields in API responses not shown in UI."""
        findings: list[Finding] = []
        ssl_ctx = _get_ssl_context(self._verify_ssl)

        # Fetch API responses and analyze fields
        for surface in self._surfaces:
            if surface.surface_type not in (SurfaceType.API_REST,):
                continue

            try:
                if self._rate_limiter:
                    await self._rate_limiter.acquire()

                async with aiohttp.ClientSession(timeout=self._timeout) as session:
                    async with session.get(
                        surface.url, headers=self._auth_headers, ssl=ssl_ctx
                    ) as resp:
                        if resp.status != 200:
                            continue

                        text = await resp.text()

                        # Check for hidden/sensitive fields
                        for pattern in HIDDEN_FIELD_PATTERNS:
                            if re.search(pattern, text, re.IGNORECASE):
                                field_match = re.search(pattern, text, re.IGNORECASE)
                                if field_match:
                                    field_name = field_match.group(0).strip('"\'')

                                    # Check if field appears in UI
                                    if field_name not in self._ui_baseline.lower():
                                        findings.append(Finding(
                                            name=f"Hidden API Field: {field_name}",
                                            severity=Severity.LOW if "debug" in field_name.lower() else Severity.MEDIUM,
                                            confidence_score=75.0,
                                            vuln_type=VulnType.INFO_DISCLOSURE,
                                            scanner="cross_surface",
                                            description=(
                                                f"API response contains field '{field_name}' that "
                                                f"is not visible in the UI. This may expose internal "
                                                f"data or admin functionality."
                                            ),
                                            endpoint=surface.url,
                                            evidence=[
                                                f"Hidden field: {field_name}",
                                                f"Found in API but not UI",
                                            ],
                                            metadata={
                                                "field": field_name,
                                                "test_type": "hidden_field",
                                            },
                                        ))
                                        break  # One finding per endpoint

            except aiohttp.ClientError as e:
                logger.debug(f"[CROSS-SURFACE] Connection error in hidden field test: {e}")
            except asyncio.TimeoutError:
                logger.debug("[CROSS-SURFACE] Timeout in hidden field test")
            except Exception as e:
                logger.debug(f"[CROSS-SURFACE] Hidden field test failed: {e}")

        return findings

    async def _test_oauth_security(self) -> list[Finding]:
        """Test OAuth endpoints for security issues."""
        findings: list[Finding] = []
        ssl_ctx = _get_ssl_context(self._verify_ssl)

        oauth_surfaces = [
            s for s in self._surfaces if s.surface_type == SurfaceType.OAUTH
        ]

        if not oauth_surfaces:
            return findings

        for surface in oauth_surfaces:
            # Test open redirect
            if "authorize" in surface.url.lower():
                for payload in OAUTH_ATTACK_PATTERNS["open_redirect"]:
                    try:
                        if self._rate_limiter:
                            await self._rate_limiter.acquire()

                        test_url = f"{surface.url}?{payload}&response_type=code&client_id=test"

                        async with aiohttp.ClientSession(timeout=self._timeout) as session:
                            async with session.get(
                                test_url,
                                headers=self._auth_headers,
                                ssl=ssl_ctx,
                                allow_redirects=False,
                            ) as resp:
                                # Check if evil domain appears in redirect
                                location = resp.headers.get("Location", "")
                                if "evil.example.com" in location:
                                    findings.append(Finding(
                                        name="OAuth Open Redirect",
                                        severity=Severity.HIGH,
                                        confidence_score=90.0,
                                        vuln_type=VulnType.OPEN_REDIRECT,
                                        scanner="cross_surface",
                                        description=(
                                            "OAuth authorization endpoint is vulnerable to open "
                                            "redirect via redirect_uri manipulation. Attackers can "
                                            "steal authorization codes by redirecting to malicious sites."
                                        ),
                                        endpoint=surface.url,
                                        evidence=[
                                            f"Payload: {payload}",
                                            f"Redirect to: {location}",
                                        ],
                                        metadata={
                                            "payload": payload,
                                            "redirect": location,
                                            "test_type": "oauth_open_redirect",
                                        },
                                    ))
                                    break

                    except aiohttp.ClientError as e:
                        logger.debug(f"[CROSS-SURFACE] Connection error in OAuth test: {e}")
                    except asyncio.TimeoutError:
                        logger.debug("[CROSS-SURFACE] Timeout in OAuth test")
                    except Exception as e:
                        logger.debug(f"[CROSS-SURFACE] OAuth test failed: {e}")

            # Test missing state parameter
            if "callback" in surface.url.lower():
                try:
                    if self._rate_limiter:
                        await self._rate_limiter.acquire()

                    # Check if callback accepts requests without state
                    test_url = f"{surface.url}?code=test_code"

                    async with aiohttp.ClientSession(timeout=self._timeout) as session:
                        async with session.get(
                            test_url, headers=self._auth_headers, ssl=ssl_ctx
                        ) as resp:
                            # If we don't get a state validation error, it's vulnerable
                            text = await resp.text()
                            if resp.status in (200, 302) and "state" not in text.lower():
                                findings.append(Finding(
                                    name="OAuth Missing State Validation",
                                    severity=Severity.MEDIUM,
                                    confidence_score=70.0,
                                    vuln_type=VulnType.CSRF,
                                    scanner="cross_surface",
                                    description=(
                                        "OAuth callback endpoint does not validate the state "
                                        "parameter. This makes the OAuth flow vulnerable to CSRF "
                                        "attacks."
                                    ),
                                    endpoint=surface.url,
                                    evidence=[
                                        "Callback accepted without state parameter",
                                        f"Response status: {resp.status}",
                                    ],
                                    metadata={
                                        "test_type": "oauth_csrf",
                                    },
                                ))

                except aiohttp.ClientError as e:
                    logger.debug(f"[CROSS-SURFACE] Connection error in OAuth state test: {e}")
                except asyncio.TimeoutError:
                    logger.debug("[CROSS-SURFACE] Timeout in OAuth state test")
                except Exception as e:
                    logger.debug(f"[CROSS-SURFACE] OAuth state test failed: {e}")

        return findings

    async def _test_webhook_security(self) -> list[Finding]:
        """Test webhook endpoints for security issues."""
        findings: list[Finding] = []
        ssl_ctx = _get_ssl_context(self._verify_ssl)

        webhook_surfaces = [
            s for s in self._surfaces if s.surface_type == SurfaceType.WEBHOOK
        ]

        if not webhook_surfaces:
            return findings

        for surface in webhook_surfaces:
            # Test signature bypass
            for header_name, header_value in WEBHOOK_ATTACK_PATTERNS["signature_bypass"]:
                try:
                    if self._rate_limiter:
                        await self._rate_limiter.acquire()

                    headers = {**self._auth_headers, header_name: header_value}
                    body = {"event": "test", "data": {"id": 1}}

                    async with aiohttp.ClientSession(timeout=self._timeout) as session:
                        async with session.post(
                            surface.url,
                            json=body,
                            headers=headers,
                            ssl=ssl_ctx,
                        ) as resp:
                            if resp.status in SUCCESS_STATUS_CODES:
                                text = await resp.text()

                                # Check if webhook was processed
                                if "error" not in text.lower() and "signature" not in text.lower():
                                    findings.append(Finding(
                                        name="Webhook Signature Bypass",
                                        severity=Severity.HIGH,
                                        confidence_score=85.0,
                                        vuln_type=VulnType.AUTH_BYPASS,
                                        scanner="cross_surface",
                                        description=(
                                            f"Webhook endpoint accepts requests without valid "
                                            f"signature verification ({header_name}). Attackers can "
                                            f"forge webhook events."
                                        ),
                                        endpoint=surface.url,
                                        evidence=[
                                            f"Invalid signature accepted: {header_name}={header_value}",
                                            f"Response status: {resp.status}",
                                        ],
                                        metadata={
                                            "header": header_name,
                                            "test_type": "webhook_signature_bypass",
                                        },
                                    ))
                                    break

                except aiohttp.ClientError as e:
                    logger.debug(f"[CROSS-SURFACE] Connection error in webhook test: {e}")
                except asyncio.TimeoutError:
                    logger.debug("[CROSS-SURFACE] Timeout in webhook test")
                except Exception as e:
                    logger.debug(f"[CROSS-SURFACE] Webhook test failed: {e}")

            # Test SSRF via callback URL
            for payload in WEBHOOK_ATTACK_PATTERNS["ssrf_callback"]:
                param_name, param_value = payload.split("=", 1)
                try:
                    if self._rate_limiter:
                        await self._rate_limiter.acquire()

                    body = {param_name: param_value, "event": "test"}

                    async with aiohttp.ClientSession(timeout=self._timeout) as session:
                        async with session.post(
                            surface.url,
                            json=body,
                            headers=self._auth_headers,
                            ssl=ssl_ctx,
                        ) as resp:
                            if resp.status in SUCCESS_STATUS_CODES:
                                text = await resp.text()

                                # Check for SSRF indicators
                                ssrf_indicators = ["169.254", "metadata", "localhost", "127.0.0.1"]
                                if any(ind in text for ind in ssrf_indicators):
                                    findings.append(Finding(
                                        name="Webhook SSRF",
                                        severity=Severity.HIGH,
                                        confidence_score=80.0,
                                        vuln_type=VulnType.SSRF,
                                        scanner="cross_surface",
                                        description=(
                                            f"Webhook endpoint is vulnerable to SSRF via "
                                            f"callback URL parameter ({param_name})."
                                        ),
                                        endpoint=surface.url,
                                        evidence=[
                                            f"Payload: {payload}",
                                            f"Response contained internal data",
                                        ],
                                        metadata={
                                            "parameter": param_name,
                                            "payload": param_value,
                                            "test_type": "webhook_ssrf",
                                        },
                                    ))
                                    break

                except aiohttp.ClientError as e:
                    logger.debug(f"[CROSS-SURFACE] Connection error in webhook SSRF test: {e}")
                except asyncio.TimeoutError:
                    logger.debug("[CROSS-SURFACE] Timeout in webhook SSRF test")
                except Exception as e:
                    logger.debug(f"[CROSS-SURFACE] Webhook SSRF test failed: {e}")

        return findings

    async def _test_async_job_abuse(self) -> list[Finding]:
        """Test async/job endpoints for abuse."""
        findings: list[Finding] = []
        ssl_ctx = _get_ssl_context(self._verify_ssl)

        job_surfaces = [
            s for s in self._surfaces if s.surface_type == SurfaceType.ASYNC_JOB
        ]

        if not job_surfaces:
            return findings

        for surface in job_surfaces:
            # Test job enumeration
            try:
                if self._rate_limiter:
                    await self._rate_limiter.acquire()

                # Try to access other users' jobs
                test_ids = ["1", "0", "999", "admin"]

                for test_id in test_ids:
                    test_url = f"{surface.url}/{test_id}"

                    async with aiohttp.ClientSession(timeout=self._timeout) as session:
                        async with session.get(
                            test_url, headers=self._auth_headers, ssl=ssl_ctx
                        ) as resp:
                            if resp.status == 200:
                                text = await resp.text()

                                if len(text) > MIN_RESPONSE_LENGTH_SMALL and "error" not in text.lower():
                                    findings.append(Finding(
                                        name="Job Enumeration",
                                        severity=Severity.MEDIUM,
                                        confidence_score=70.0,
                                        vuln_type=VulnType.IDOR,
                                        scanner="cross_surface",
                                        description=(
                                            f"Async job endpoint allows enumeration of jobs. "
                                            f"Attacker can access job {test_id} which may belong "
                                            f"to other users."
                                        ),
                                        endpoint=test_url,
                                        evidence=[
                                            f"Accessible job ID: {test_id}",
                                            f"Response status: {resp.status}",
                                        ],
                                        metadata={
                                            "job_id": test_id,
                                            "test_type": "job_enumeration",
                                        },
                                    ))
                                    break

            except aiohttp.ClientError as e:
                logger.debug(f"[CROSS-SURFACE] Connection error in job enumeration test: {e}")
            except asyncio.TimeoutError:
                logger.debug("[CROSS-SURFACE] Timeout in job enumeration test")
            except Exception as e:
                logger.debug(f"[CROSS-SURFACE] Job enumeration test failed: {e}")

            # Test job injection
            try:
                if self._rate_limiter:
                    await self._rate_limiter.acquire()

                body = {
                    "type": "admin_task",
                    "command": "id",
                    "callback": "http://169.254.169.254/",
                    "priority": 9999,
                }

                async with aiohttp.ClientSession(timeout=self._timeout) as session:
                    async with session.post(
                        surface.url,
                        json=body,
                        headers=self._auth_headers,
                        ssl=ssl_ctx,
                    ) as resp:
                        if resp.status in SUCCESS_STATUS_CODES:
                            text = await resp.text()

                            # Check if job was queued
                            if any(kw in text.lower() for kw in ["queued", "created", "job_id", "task_id"]):
                                findings.append(Finding(
                                    name="Job Injection",
                                    severity=Severity.HIGH,
                                    confidence_score=75.0,
                                    vuln_type=VulnType.LOGIC_FLAW,
                                    scanner="cross_surface",
                                    description=(
                                        "Async job endpoint accepts arbitrary job parameters. "
                                        "Attacker can inject admin tasks, commands, or SSRF "
                                        "callbacks into the job queue."
                                    ),
                                    endpoint=surface.url,
                                    evidence=[
                                        "Injected job accepted",
                                        f"Response status: {resp.status}",
                                    ],
                                    metadata={
                                        "injected_params": list(body.keys()),
                                        "test_type": "job_injection",
                                    },
                                ))

            except aiohttp.ClientError as e:
                logger.debug(f"[CROSS-SURFACE] Connection error in job injection test: {e}")
            except asyncio.TimeoutError:
                logger.debug("[CROSS-SURFACE] Timeout in job injection test")
            except Exception as e:
                logger.debug(f"[CROSS-SURFACE] Job injection test failed: {e}")

        return findings

    async def _test_cross_surface_idor(self) -> list[Finding]:
        """Test for IDOR by using IDs discovered on one surface to attack another."""
        findings: list[Finding] = []
        ssl_ctx = _get_ssl_context(self._verify_ssl)

        # Collect IDs from API responses
        discovered_ids: dict[str, list[str]] = {}  # resource_type -> [ids]

        for surface in self._surfaces:
            if surface.surface_type not in (SurfaceType.API_REST,):
                continue

            try:
                if self._rate_limiter:
                    await self._rate_limiter.acquire()

                async with aiohttp.ClientSession(timeout=self._timeout) as session:
                    async with session.get(
                        surface.url, headers=self._auth_headers, ssl=ssl_ctx
                    ) as resp:
                        if resp.status == 200:
                            text = await resp.text()

                            # Extract IDs from response
                            id_patterns = [
                                (r'"id"\s*:\s*"?(\d+)', "generic"),
                                (r'"user_?id"\s*:\s*"?(\d+)', "user"),
                                (r'"order_?id"\s*:\s*"?(\d+)', "order"),
                                (r'"account_?id"\s*:\s*"?(\d+)', "account"),
                            ]

                            for pattern, resource_type in id_patterns:
                                for match in re.finditer(pattern, text, re.IGNORECASE):
                                    id_value = match.group(1)
                                    if resource_type not in discovered_ids:
                                        discovered_ids[resource_type] = []
                                    if id_value not in discovered_ids[resource_type]:
                                        discovered_ids[resource_type].append(id_value)

            except aiohttp.ClientError as e:
                logger.debug(f"[CROSS-SURFACE] Connection error in ID discovery: {e}")
            except asyncio.TimeoutError:
                logger.debug("[CROSS-SURFACE] Timeout in ID discovery")
            except Exception as e:
                logger.debug(f"[CROSS-SURFACE] ID discovery failed: {e}")

        if not discovered_ids:
            return findings

        # Try to use discovered IDs on other surfaces
        for surface in self._surfaces:
            if surface.surface_type not in (SurfaceType.API_REST, SurfaceType.UI):
                continue

            resource_name = self._extract_resource_name(surface.url)

            for resource_type, ids in discovered_ids.items():
                # Skip if same resource type (not cross-surface)
                if resource_type == resource_name:
                    continue

                for id_value in ids[:MAX_IDS_TO_TEST]:  # Test first N IDs
                    try:
                        # Try adding ID as path parameter
                        test_url = f"{surface.url}/{id_value}"

                        if self._rate_limiter:
                            await self._rate_limiter.acquire()

                        async with aiohttp.ClientSession(timeout=self._timeout) as session:
                            async with session.get(
                                test_url, headers=self._auth_headers, ssl=ssl_ctx
                            ) as resp:
                                if resp.status == 200:
                                    text = await resp.text()

                                    if len(text) > MIN_RESPONSE_LENGTH_MEDIUM and "error" not in text.lower():
                                        findings.append(Finding(
                                            name=f"Cross-Surface IDOR: {resource_type}",
                                            severity=Severity.HIGH,
                                            confidence_score=80.0,
                                            vuln_type=VulnType.IDOR,
                                            scanner="cross_surface",
                                            description=(
                                                f"ID from {resource_type} resource can be used to "
                                                f"access data on {resource_name} endpoint. This "
                                                f"cross-surface IDOR allows accessing other users' data."
                                            ),
                                            endpoint=test_url,
                                            evidence=[
                                                f"Source: {resource_type} ID={id_value}",
                                                f"Target: {surface.url}",
                                                "Data accessible",
                                            ],
                                            metadata={
                                                "source_resource": resource_type,
                                                "target_resource": resource_name,
                                                "id_used": id_value,
                                                "test_type": "cross_surface_idor",
                                            },
                                        ))
                                        break

                    except aiohttp.ClientError as e:
                        logger.debug(f"[CROSS-SURFACE] Connection error in cross-surface ID test: {e}")
                    except asyncio.TimeoutError:
                        logger.debug("[CROSS-SURFACE] Timeout in cross-surface ID test")
                    except Exception as e:
                        logger.debug(f"[CROSS-SURFACE] Cross-surface ID test failed: {e}")

        return findings

    async def _test_graphql_cross_surface(self) -> list[Finding]:
        """Test GraphQL endpoint for cross-surface attacks."""
        findings: list[Finding] = []
        ssl_ctx = _get_ssl_context(self._verify_ssl)

        graphql_surfaces = [
            s for s in self._surfaces if s.surface_type == SurfaceType.API_GRAPHQL
        ]

        if not graphql_surfaces:
            return findings

        for surface in graphql_surfaces:
            # Test introspection to discover types
            introspection_query = {
                "query": """
                    query IntrospectionQuery {
                        __schema {
                            types {
                                name
                                fields {
                                    name
                                    type { name }
                                }
                            }
                        }
                    }
                """
            }

            try:
                if self._rate_limiter:
                    await self._rate_limiter.acquire()

                async with aiohttp.ClientSession(timeout=self._timeout) as session:
                    async with session.post(
                        surface.url,
                        json=introspection_query,
                        headers={**self._auth_headers, "Content-Type": "application/json"},
                        ssl=ssl_ctx,
                    ) as resp:
                        if resp.status == 200:
                            text = await resp.text()

                            # Check if introspection is enabled
                            if "__schema" in text and "types" in text:
                                # Parse types to find sensitive ones
                                try:
                                    data = json.loads(text)
                                    types = []
                                    if isinstance(data, dict):
                                        types = data.get("data", {}).get("__schema", {}).get("types", [])

                                    sensitive_types = []
                                    for t in types:
                                        name = t.get("name", "").lower()
                                        if any(kw in name for kw in ["admin", "user", "secret", "config", "internal"]):
                                            sensitive_types.append(t.get("name"))

                                    if sensitive_types:
                                        findings.append(Finding(
                                            name="GraphQL Introspection Exposes Sensitive Types",
                                            severity=Severity.MEDIUM,
                                            confidence_score=85.0,
                                            vuln_type=VulnType.INFO_DISCLOSURE,
                                            scanner="cross_surface",
                                            description=(
                                                "GraphQL introspection is enabled and exposes "
                                                "potentially sensitive types. These can be used to "
                                                "attack REST endpoints or discover admin functionality."
                                            ),
                                            endpoint=surface.url,
                                            evidence=[
                                                f"Sensitive types: {sensitive_types[:5]}",
                                                "Introspection enabled",
                                            ],
                                            metadata={
                                                "sensitive_types": sensitive_types[:10],
                                                "test_type": "graphql_introspection",
                                            },
                                        ))

                                        # Try to query sensitive types (M2 FIX: rate limiter check)
                                        for sensitive_type in sensitive_types[:MAX_SENSITIVE_TYPES_TO_QUERY]:
                                            if self._rate_limiter:
                                                await self._rate_limiter.acquire()

                                            sensitive_query = {
                                                "query": f"{{ {sensitive_type.lower()}s {{ id }} }}"
                                            }

                                            async with session.post(
                                                surface.url,
                                                json=sensitive_query,
                                                headers={**self._auth_headers, "Content-Type": "application/json"},
                                                ssl=ssl_ctx,
                                            ) as resp2:
                                                if resp2.status == 200:
                                                    text2 = await resp2.text()
                                                    if "id" in text2 and "error" not in text2.lower():
                                                        findings.append(Finding(
                                                            name=f"GraphQL Exposes {sensitive_type}",
                                                            severity=Severity.HIGH,
                                                            confidence_score=90.0,
                                                            vuln_type=VulnType.INFO_DISCLOSURE,
                                                            scanner="cross_surface",
                                                            description=(
                                                                f"GraphQL allows querying sensitive type "
                                                                f"'{sensitive_type}' which may expose "
                                                                f"admin or internal data."
                                                            ),
                                                            endpoint=surface.url,
                                                            evidence=[
                                                                f"Query: {sensitive_type.lower()}s",
                                                                "Data returned",
                                                            ],
                                                            metadata={
                                                                "type": sensitive_type,
                                                                "test_type": "graphql_sensitive_data",
                                                            },
                                                        ))
                                                        break

                                except json.JSONDecodeError:
                                    pass

            except aiohttp.ClientError as e:
                logger.debug(f"[CROSS-SURFACE] Connection error in GraphQL test: {e}")
            except asyncio.TimeoutError:
                logger.debug("[CROSS-SURFACE] Timeout in GraphQL test")
            except Exception as e:
                logger.debug(f"[CROSS-SURFACE] GraphQL test failed: {e}")

        return findings

    def _deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Deduplicate findings by (name, matched_at)."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.name, f.matched_at or "")
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
