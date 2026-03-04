"""
CORS misconfiguration checker v2.0 - Enhanced Bypass Testing
Tests for Cross-Origin Resource Sharing vulnerabilities including bypass techniques.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import aiohttp

from scanning.findings import Finding, VulnType, VulnCategory, Severity
from scanning.vuln_scanner import ScanModule
from scanning.scan_context import ScanContext
from utils.logger import get_logger
from utils.shared_findings_store import SharedFindingsStore

if TYPE_CHECKING:
    from core.config_manager import Settings
    from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


# =============================================================================
# SENSITIVE DATA DETECTION (FP Reduction)
# =============================================================================

# Patterns indicating sensitive data in response
# FIX 2026-02-19: Added camelCase variants, JWT patterns, and prefix/suffix variants
# Audit found: "isAdmin" (camelCase) not detected, JWT tokens in short responses skipped
SENSITIVE_DATA_PATTERNS = [
    # PII / User data
    r'"email"\s*:\s*"[^"]+@[^"]+"',  # Email in JSON
    r'"password"\s*:\s*"',            # Password field
    r'"phone"\s*:\s*"[\d\-\+]+"',     # Phone number
    r'"ssn"\s*:\s*"[\d\-]+"',         # SSN
    r'"credit_card"\s*:\s*"',         # Credit card
    r'"card_number"\s*:\s*"',
    r'"cvv"\s*:\s*"',
    r'"dob"\s*:\s*"',                 # Date of birth
    r'"date_of_birth"\s*:\s*"',
    r'"dateOfBirth"\s*:\s*"',         # FIX: camelCase
    r'"address"\s*:\s*"',

    # Auth tokens / secrets
    r'"token"\s*:\s*"[a-zA-Z0-9\-_\.]+',
    r'"access_token"\s*:\s*"',
    r'"accessToken"\s*:\s*"',         # FIX: camelCase
    r'"refresh_token"\s*:\s*"',
    r'"refreshToken"\s*:\s*"',        # FIX: camelCase
    r'"api_key"\s*:\s*"',
    r'"apiKey"\s*:\s*"',
    r'"secret"\s*:\s*"',
    r'"session_id"\s*:\s*"',
    r'"sessionId"\s*:\s*"',           # FIX: camelCase
    r'"csrf"\s*:\s*"',
    r'"csrfToken"\s*:\s*"',           # FIX: variant
    r'Bearer\s+[a-zA-Z0-9\-_\.]+',

    # FIX: JWT token detection (Audit: short JWT responses were skipped)
    r'eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.',  # JWT format: eyJ...eyJ...
    r'"jwt"\s*:\s*"',
    r'"id_token"\s*:\s*"',
    r'"idToken"\s*:\s*"',

    # Financial data
    r'"balance"\s*:\s*[\d\.]+',
    r'"amount"\s*:\s*[\d\.]+',
    r'"account_number"\s*:\s*"',
    r'"accountNumber"\s*:\s*"',       # FIX: camelCase
    r'"routing_number"\s*:\s*"',
    r'"routingNumber"\s*:\s*"',       # FIX: camelCase
    r'"iban"\s*:\s*"',
    r'"accountBalance"\s*:\s*',       # FIX: variant

    # User IDs / Admin data - FIX: Added all variants
    r'"user_id"\s*:\s*\d+',
    r'"userId"\s*:\s*\d+',
    r'"[a-z_]*user[_-]?id"\s*:\s*\d+',  # FIX: Prefix variants (current_user_id, etc.)
    r'"admin"\s*:\s*true',
    r'"isAdmin"\s*:\s*true',           # FIX: camelCase (Audit found this missing)
    r'"is_admin"\s*:\s*true',
    r'"isAdministrator"\s*:\s*true',   # FIX: variant
    r'"role"\s*:\s*"admin"',
    r'"userRole"\s*:\s*"admin"',       # FIX: variant
    r'"permissions"\s*:\s*\[',
    r'"scopes"\s*:\s*\[',              # FIX: OAuth scopes

    # Private user data
    r'"username"\s*:\s*"',
    r'"userName"\s*:\s*"',             # FIX: camelCase
    r'"first_name"\s*:\s*"',
    r'"firstName"\s*:\s*"',            # FIX: camelCase
    r'"last_name"\s*:\s*"',
    r'"lastName"\s*:\s*"',             # FIX: camelCase
    r'"full_name"\s*:\s*"',
    r'"fullName"\s*:\s*"',             # FIX: camelCase
    r'"profile"\s*:\s*\{',
    r'"settings"\s*:\s*\{',
    r'"preferences"\s*:\s*\{',         # FIX: variant
]

# Patterns indicating public/non-sensitive data (reduce FP)
PUBLIC_DATA_PATTERNS = [
    r'<html.*?>.*?<title>',           # HTML page (usually public)
    r'"version"\s*:\s*"[\d\.]+"',     # Version info
    r'"status"\s*:\s*"(ok|healthy)"', # Health checks
    r'"message"\s*:\s*"success"',     # Generic success
    r'"data"\s*:\s*\[\]',             # Empty array
    r'"items"\s*:\s*\[\]',
    r'^\s*\{\s*\}\s*$',               # Empty JSON object
    r'"public"\s*:\s*true',
]


def contains_sensitive_data(response_body: str) -> tuple[bool, list[str]]:
    """
    Check if response contains sensitive data worth protecting via CORS.

    Returns:
        Tuple of (has_sensitive_data, list_of_matched_patterns)
    """
    if not response_body:
        return False, []

    matched_patterns = []

    # Check for sensitive patterns
    for pattern in SENSITIVE_DATA_PATTERNS:
        if re.search(pattern, response_body, re.I):
            matched_patterns.append(pattern)

    # If we found sensitive data, return True
    if matched_patterns:
        return True, matched_patterns

    return False, []


# Patterns indicating critical auth/admin data (warrants severity upgrade)
_CRITICAL_PATTERNS = {
    r'"access_token"\s*:\s*"', r'"accessToken"\s*:\s*"',
    r'"refresh_token"\s*:\s*"', r'"refreshToken"\s*:\s*"',
    r'"api_key"\s*:\s*"', r'"apiKey"\s*:\s*"',
    r'"secret"\s*:\s*"',
    r'"admin"\s*:\s*true', r'"isAdmin"\s*:\s*true',
    r'"is_admin"\s*:\s*true', r'"isAdministrator"\s*:\s*true',
    r'"role"\s*:\s*"admin"', r'"userRole"\s*:\s*"admin"',
    r'eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.',
    r'"password"\s*:\s*"',
    r'"ssn"\s*:\s*"[\d\-]+"', r'"credit_card"\s*:\s*"',
    r'"card_number"\s*:\s*"', r'"cvv"\s*:\s*"',
    r'Bearer\s+[a-zA-Z0-9\-_\.]+',
}


def has_critical_sensitive_data(matched_patterns: list[str]) -> bool:
    """Check if matched patterns include critical auth/admin data."""
    return any(p in _CRITICAL_PATTERNS for p in matched_patterns)


def is_public_endpoint(response_body: str, url: str) -> bool:
    """
    Detect if endpoint returns only public data.

    Public endpoints with CORS issues are low-risk FPs.
    """
    # FIX 2026-02-19: Never skip auth-protected endpoint patterns
    # Audit found: /api/user/1/preferences returning empty [] was skipped
    protected_url_patterns = [
        r'/user[s]?/',
        r'/account[s]?/',
        r'/profile[s]?/',
        r'/auth/',
        r'/admin/',
        r'/token',
        r'/session',
        r'/me\b',
        r'/private/',
        r'/settings/',
        r'/preferences/',
        r'/payment[s]?/',
        r'/order[s]?/',
        r'/transaction[s]?/',
    ]

    for pattern in protected_url_patterns:
        if re.search(pattern, url, re.I):
            # Never assume protected endpoints are "public"
            return False

    # Check URL patterns for public endpoints
    public_url_patterns = [
        r'/public/',
        r'/static/',
        r'/assets/',
        r'/health',
        r'/status',
        r'/version',
        r'/ping',
        r'/favicon',
        r'\.css$',
        r'\.js$',
        r'\.png$',
        r'\.jpg$',
        r'\.svg$',
    ]

    for pattern in public_url_patterns:
        if re.search(pattern, url, re.I):
            return True

    # Check response content for public data patterns
    public_matches = 0
    for pattern in PUBLIC_DATA_PATTERNS:
        if re.search(pattern, response_body, re.I | re.S):
            public_matches += 1

    # If multiple public patterns match and no sensitive data, likely public
    if public_matches >= 2:
        has_sensitive, _ = contains_sensitive_data(response_body)
        if not has_sensitive:
            return True

    # FIX 2026-02-19: Relaxed short response assumption
    # Audit found: JWT tokens (45 bytes) were being skipped
    # Solution: Only assume public if short AND no token-like patterns
    if len(response_body.strip()) < 50:
        # Check for JWT or token patterns even in short responses
        if re.search(r'eyJ[a-zA-Z0-9\-_]+\.eyJ', response_body):
            # JWT token detected - NOT public
            return False
        if re.search(r'"(token|key|secret|jwt)"', response_body, re.I):
            # Token-related field - NOT public
            return False
        # Truly minimal response with no sensitive indicators
        return True

    return False


class CORSChecker(ScanModule):
    """
    CORS misconfiguration scanner v2.0 - Enterprise Edition.

    Advanced Checks:
    - Wildcard origin reflection
    - Null origin acceptance
    - Origin reflection
    - Credential exposure
    - Subdomain bypass (attacker.target.com)
    - Suffix bypass (target.com.attacker.example.com)
    - Prefix bypass (attacker-target.com)
    - Protocol downgrade (https → http)
    - Preflight bypass techniques
    - Cloudflare/CDN bypass patterns
    """

    name = "cors"
    version = "2.0.0"

    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)

        # Base test origins (will be expanded per-target)
        # BUG-FIX: Handle both dict and object settings
        module_config = settings.scanning.modules.get("cors", {}) if hasattr(settings, 'scanning') else {}
        self.base_origins = module_config.get(
            "test_origins",
            ["null", "https://attacker.example.com", "https://test.example.com"]
        )

    def _generate_bypass_origins(self, target: str) -> list[dict[str, Any]]:
        """Generate bypass origins based on target domain."""
        parsed = urlparse(target)
        domain = parsed.netloc.split(':')[0]  # Remove port if present
        scheme = parsed.scheme

        # Extract base domain (e.g., example.com from www.example.com)
        parts = domain.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
        else:
            base_domain = domain

        origins = [
            # Standard attacks
            {"origin": "null", "type": "null_origin", "description": "Null origin (sandboxed iframe)"},
            {"origin": "https://attacker.example.com", "type": "arbitrary", "description": "Arbitrary external origin"},

            # Subdomain bypass - pretend to be a subdomain
            {"origin": f"https://attacker.{base_domain}", "type": "subdomain_inject",
             "description": f"Subdomain injection: attacker.{base_domain}"},
            {"origin": f"https://test.{base_domain}", "type": "subdomain_inject",
             "description": f"Test subdomain: test.{base_domain}"},

            # Suffix bypass - target.com.attacker.example.com
            {"origin": f"https://{base_domain}.attacker.example.com", "type": "suffix_bypass",
             "description": f"Suffix bypass: {base_domain}.attacker.example.com"},

            # Prefix bypass - attacker-target.com
            {"origin": f"https://attacker-{base_domain}", "type": "prefix_bypass",
             "description": f"Prefix bypass: attacker-{base_domain}"},

            # Protocol downgrade
            {"origin": f"http://{domain}", "type": "protocol_downgrade",
             "description": "HTTP protocol downgrade"},

            # Regex bypass with special chars
            {"origin": f"https://{base_domain}%60.attacker.example.com", "type": "regex_bypass",
             "description": "Regex bypass with backtick"},
            {"origin": f"https://{base_domain}%00.attacker.example.com", "type": "null_byte",
             "description": "Null byte injection"},

            # Underscore/hyphen variations
            {"origin": f"https://{base_domain.replace('.', '_')}.attacker.example.com", "type": "underscore_bypass",
             "description": "Underscore domain bypass"},

            # Cloudflare bypass patterns
            {"origin": "https://cloudflare.com", "type": "cdn_trust",
             "description": "CDN trust exploitation"},

            # Localhost variations
            {"origin": "http://localhost", "type": "localhost",
             "description": "Localhost origin"},
            {"origin": "http://127.0.0.1", "type": "localhost_ip",
             "description": "Localhost IP origin"},
        ]

        return origins
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Check for CORS misconfigurations with advanced bypass testing."""
        logger.info(f"[cors] Checking CORS on {host}")

        findings = []
        info_items = []

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._ctx.log_context_status()
        self._auth_headers = self._ctx.auth_headers
        if self._ctx.has_auth:
            logger.info(f"[CORS] Using authenticated session ({self._ctx.auth_method})")

        # Build URL
        url = host if host.startswith(('http://', 'https://')) else f"https://{host}"

        # Generate target-specific bypass origins
        bypass_origins = self._generate_bypass_origins(url)

        # Get URLs to test — order matters: test highest-value first
        # FIX 2026-03-02: Use ordered dedup (not set()) to preserve priority.
        # Previous code used set() which randomized order, causing the base URL
        # and authenticated endpoints to be tested inconsistently across scans.
        max_cors_endpoints = 30

        # Priority 1: Base URL (always test — CORS policy applies globally)
        priority_urls = [url]

        # Priority 2: Authenticated/sensitive endpoints (highest CORS impact)
        if isinstance(asset_data, dict):
            all_endpoints = asset_data.get("endpoints", [])
        else:
            all_endpoints = []
        auth_patterns = ["/user", "/account", "/profile", "/admin", "/auth", "/me", "/session"]
        for u in all_endpoints:
            if isinstance(u, str) and any(p in u.lower() for p in auth_patterns):
                priority_urls.append(u)

        # Priority 3: API endpoints from discovery
        api_patterns = ["/api", "/v1", "/v2", "/v3", "/graphql", "/rest", "/data", "/json"]
        for u in all_endpoints:
            if isinstance(u, str) and any(p in u.lower() for p in api_patterns):
                priority_urls.append(u)

        # Priority 4: URLs from recon
        if isinstance(asset_data, dict):
            urls_from_recon = asset_data.get("urls", [])
        else:
            urls_from_recon = []
        for u in urls_from_recon:
            if isinstance(u, str) and any(p in u.lower() for p in api_patterns):
                priority_urls.append(u)

        # Priority 5: SPA-discovered API endpoints
        if isinstance(asset_data, dict):
            spa_endpoints = asset_data.get("spa_analysis", {}).get("api_endpoints", [])
        else:
            spa_endpoints = []
        for ep in spa_endpoints:
            if isinstance(ep, dict):
                priority_urls.append(ep.get("url", ""))
            elif isinstance(ep, str):
                priority_urls.append(ep)

        # Ordered dedup: preserve priority order, remove duplicates
        seen: set[str] = set()
        test_urls: list[str] = []
        for u in priority_urls:
            if u and u not in seen:
                seen.add(u)
                test_urls.append(u)
                if len(test_urls) >= max_cors_endpoints:
                    break

        logger.info(f"[CORS] Testing {len(test_urls)} endpoints for CORS misconfigurations")

        for test_url in test_urls:
            try:
                # Collect ALL test evidence for this URL so the report
                # can show real captured data for every step (arbitrary,
                # null, preflight) — not just the single finding that won
                # deduplication.
                url_evidence_map: dict[str, dict] = {}

                # Capture baseline: request WITHOUT Origin header.
                # This proves CORS headers only appear when Origin is sent
                # (i.e., they are reflection-based, not always-present).
                await rate_limiter.acquire()
                baseline_ev = await self._capture_baseline(test_url)
                if baseline_ev:
                    url_evidence_map["baseline"] = baseline_ev

                # Test each bypass origin
                for origin_config in bypass_origins:
                    await rate_limiter.acquire()

                    result = await self._test_origin_advanced(
                        test_url,
                        origin_config["origin"],
                        origin_config["type"],
                        origin_config["description"]
                    )

                    if result:
                        # Stash this test's evidence keyed by attack type
                        ev = (result.metadata or {}).get("http_evidence")
                        if ev:
                            url_evidence_map[origin_config["type"]] = ev
                        findings.append(result)

                # Test preflight bypass
                await rate_limiter.acquire()
                preflight_result = await self._test_preflight_bypass(test_url)
                if preflight_result:
                    ev = (preflight_result.metadata or {}).get("http_evidence")
                    if ev:
                        url_evidence_map["preflight"] = ev
                    findings.append(preflight_result)

                # Enrich ALL findings for this URL with the full evidence map.
                # This way, whichever finding survives deduplication still
                # carries evidence from every test type.
                if url_evidence_map:
                    for f in findings:
                        if f.endpoint == test_url and f.metadata is not None:
                            f.metadata["all_cors_evidence"] = url_evidence_map

            except Exception as e:
                logger.debug(f"[cors] Error testing {test_url}: {e}")
        
        # Deduplicate findings by type
        unique_findings = self._deduplicate_findings(findings, host)

        # ====================================================================
        # CROSS-MODULE SHARING: Add findings to SharedFindingsStore
        # CORS findings enable chains: XSS + CORS → ATO, CORS + Session → Data Theft
        # ====================================================================
        try:
            store = SharedFindingsStore.get_instance()
            for f in unique_findings:
                await store.add_finding(
                    {
                        "type": f.vuln_type.value,
                        "endpoint": f.endpoint,
                        "severity": f.severity.value,
                        "metadata": f.metadata or {},
                    },
                    module="cors",
                )
        except Exception as e:
            logger.debug(f"[CORS] SharedFindingsStore error: {e}")

        logger.info(f"[cors] Found {len(unique_findings)} issues on {host}")
        return {"findings": [f.to_dict() for f in unique_findings], "info": info_items}
    
    async def _test_origin_advanced(
        self,
        url: str,
        origin: str,
        attack_type: str,
        description: str
    ) -> Finding | None:
        """Test a specific origin with advanced bypass detection."""
        timeout = aiohttp.ClientTimeout(total=10)
        headers = {"Origin": origin}
        # Merge auth headers if available
        if hasattr(self, "_auth_headers") and self._auth_headers:
            headers.update(self._auth_headers)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    url,
                    headers=headers,
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                    acam = resp.headers.get("Access-Control-Allow-Methods", "")
                    acah = resp.headers.get("Access-Control-Allow-Headers", "")

                    # Capture full HTTP evidence for report generation
                    status_code = resp.status
                    all_response_headers = dict(resp.headers)
                    try:
                        body_bytes = await resp.read()
                        body_preview = body_bytes[:4096].decode("utf-8", errors="replace")
                    except Exception:
                        body_preview = ""

                    http_evidence = {
                        "request": {"method": "GET", "url": url, "headers": {"Origin": origin}},
                        "response": {
                            "status_code": status_code,
                            "headers": all_response_headers,
                            "body_preview": body_preview,
                        },
                        "target_domain": urlparse(url).netloc,
                        "test_origin": origin,
                    }

                    # FP REDUCTION: Check if endpoint returns sensitive data
                    has_sensitive, sensitive_patterns = contains_sensitive_data(body_preview)
                    is_public = is_public_endpoint(body_preview, url)

                    # FIX 2026-03-02: Never skip the base URL (target root).
                    # SPA HTML shells match PUBLIC_DATA_PATTERNS (e.g. <html><title>)
                    # but the CORS policy on the base URL is always worth reporting.
                    parsed_url = urlparse(url)
                    is_base_url = parsed_url.path in ("", "/")

                    # Skip public endpoints entirely (major FP reduction)
                    # BUT never skip the base URL — its CORS policy applies globally
                    if is_public and not has_sensitive and not is_base_url:
                        logger.debug(f"[CORS] Skipping public endpoint: {url}")
                        return None

                    # Check for vulnerabilities
                    if acao == "*":
                        # Adjust severity based on sensitive data presence
                        # HIGH = critical auth/admin data exposed (tokens, admin role, passwords)
                        # MEDIUM = sensitive data present (PII, emails, user data)
                        # LOW = no sensitive data detected
                        is_critical = has_sensitive and has_critical_sensitive_data(sensitive_patterns)
                        if is_critical:
                            wildcard_severity = "HIGH"
                            wildcard_cvss = 7.5
                            wildcard_confidence = 98
                        elif has_sensitive:
                            wildcard_severity = "MEDIUM"
                            wildcard_cvss = 5.0
                            wildcard_confidence = 95
                        else:
                            wildcard_severity = "LOW"
                            wildcard_cvss = 2.0
                            wildcard_confidence = 60

                        # Add sensitive data info to evidence
                        evidence_list = [
                            f"Origin sent: {origin}",
                            f"Access-Control-Allow-Origin: {acao}",
                            f"Attack type: {attack_type}",
                        ]
                        if has_sensitive:
                            evidence_list.append(f"Sensitive data detected: {len(sensitive_patterns)} patterns")
                        else:
                            evidence_list.append("No sensitive data detected in response")

                        return Finding(
                            vuln_type=VulnType.CORS_MISCONFIGURATION,
                            category=VulnCategory.CONFIGURATION,
                            name="CORS Wildcard Origin",
                            severity=Severity(wildcard_severity),
                            description="Server allows any origin to access resources. "
                                       + ("Critical auth/admin data exposed — any website can steal tokens, credentials, or admin status via CORS." if is_critical
                                          else "This enables data theft from any website via CORS." if has_sensitive
                                          else "Impact is limited as no sensitive data was detected in response."),
                            host=url,
                            endpoint=url,
                            evidence=evidence_list,
                            cvss_score=wildcard_cvss,
                            cwe_id="CWE-346",
                            confidence_score=float(wildcard_confidence),
                            remediation="Restrict CORS to specific trusted origins. Never use '*' in production.",
                            scanner="cors",
                            metadata={"http_evidence": http_evidence, "has_sensitive_data": has_sensitive},
                        )

                    # Origin reflection (most dangerous)
                    if acao == origin and origin != "null":
                        has_credentials = acac.lower() == "true"

                        # FP REDUCTION: Adjust severity based on credentials AND sensitive data
                        # CRITICAL = credentials + sensitive data
                        # HIGH = credentials OR sensitive data
                        # MEDIUM = neither (still a misconfiguration, but low impact)
                        if has_credentials and has_sensitive:
                            severity = "CRITICAL"
                            cvss = 9.0
                            confidence = 100
                        elif has_credentials or has_sensitive:
                            severity = "HIGH"
                            cvss = 7.0
                            confidence = 95
                        else:
                            # No credentials, no sensitive data = lower severity
                            severity = "MEDIUM"
                            cvss = 4.0
                            confidence = 70

                        evidence_list = [
                            f"Origin sent: {origin}",
                            f"Access-Control-Allow-Origin: {acao}",
                            f"Access-Control-Allow-Credentials: {acac}",
                            f"Access-Control-Allow-Methods: {acam}",
                            f"Bypass technique: {attack_type}",
                        ]
                        if has_sensitive:
                            evidence_list.append(f"Sensitive data detected: {len(sensitive_patterns)} patterns")
                        if not has_sensitive and not has_credentials:
                            evidence_list.append("No sensitive data or credentials detected")

                        impact_desc = []
                        if has_credentials:
                            impact_desc.append("WITH CREDENTIALS - can steal authenticated data!")
                        if has_sensitive:
                            impact_desc.append(f"Response contains sensitive data ({len(sensitive_patterns)} patterns)")

                        return Finding(
                            vuln_type=VulnType.CORS_MISCONFIGURATION,
                            category=VulnCategory.CONFIGURATION,
                            name=f"CORS Bypass via {attack_type.replace('_', ' ').title()}",
                            severity=Severity(severity),
                            description=(
                                f"Server reflects arbitrary origin: {description}. "
                                f"{' '.join(impact_desc) if impact_desc else 'Attacker can read responses via CORS.'}"
                            ),
                            host=url,
                            endpoint=url,
                            evidence=evidence_list,
                            cvss_score=cvss,
                            cwe_id="CWE-346",
                            confidence_score=float(confidence),
                            remediation=(
                                "1. Validate origins against a strict whitelist\n"
                                "2. Never reflect the Origin header directly\n"
                                "3. Use exact string matching, not regex\n"
                                "4. Be careful with subdomain wildcards\n"
                                "5. Review: https://portswigger.net/research/exploiting-cors-misconfigurations"
                            ),
                            scanner="cors",
                            metadata={"http_evidence": http_evidence, "has_sensitive_data": has_sensitive, "has_credentials": has_credentials, "attack_type": attack_type},
                        )

                    # Null origin acceptance
                    if acao == "null" and origin == "null":
                        has_credentials = acac.lower() == "true"

                        # FP REDUCTION: Adjust severity based on credentials AND sensitive data
                        if has_credentials and has_sensitive:
                            null_severity = "HIGH"
                            null_cvss = 7.0
                            null_confidence = 95
                        elif has_credentials or has_sensitive:
                            null_severity = "MEDIUM"
                            null_cvss = 5.0
                            null_confidence = 85
                        else:
                            null_severity = "LOW"
                            null_cvss = 3.0
                            null_confidence = 60

                        evidence_list = [
                            f"Origin: {origin}",
                            f"Access-Control-Allow-Origin: {acao}",
                            f"Access-Control-Allow-Credentials: {acac}",
                        ]
                        if has_sensitive:
                            evidence_list.append(f"Sensitive data detected: {len(sensitive_patterns)} patterns")

                        return Finding(
                            vuln_type=VulnType.CORS_MISCONFIGURATION,
                            category=VulnCategory.CONFIGURATION,
                            name="CORS Null Origin Accepted",
                            severity=Severity(null_severity),
                            description=(
                                "Server accepts null origin. Exploitable via:\n"
                                "- Sandboxed iframes\n"
                                "- data: URLs\n"
                                "- Local file access\n"
                                "- Redirects from other origins"
                                + (f"\nResponse contains sensitive data." if has_sensitive else "")
                            ),
                            host=url,
                            endpoint=url,
                            evidence=evidence_list,
                            cvss_score=null_cvss,
                            cwe_id="CWE-346",
                            confidence_score=float(null_confidence),
                            remediation="Reject null origins. Add explicit check: if (origin === 'null') return;",
                            scanner="cors",
                            metadata={"http_evidence": http_evidence, "has_sensitive_data": has_sensitive},
                        )

        except Exception as e:
            # FIX 2026-02-12: Log suppressed errors for audit trail
            logger.warning(f"[CORS] Error testing null origin: {e}")

        return None

    async def _test_preflight_bypass(self, url: str) -> Finding | None:
        """
        Test preflight (OPTIONS) to capture evidence of allowed methods/headers.

        Does NOT produce a standalone finding (preflight alone is not exploitable).
        Instead, captures the evidence into metadata so the report generator can
        embed real preflight data in reproduction steps.
        """
        timeout = aiohttp.ClientTimeout(total=10)
        origin = "https://attacker.example.com"
        headers = {
            "Origin": origin,
            "Access-Control-Request-Method": "DELETE",
        }
        # Merge auth headers if available
        if hasattr(self, "_auth_headers") and self._auth_headers:
            headers.update(self._auth_headers)

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.options(
                    url,
                    headers=headers,
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                    acam = resp.headers.get("Access-Control-Allow-Methods", "")

                    status_code = resp.status
                    all_response_headers = dict(resp.headers)
                    try:
                        body_bytes = await resp.read()
                        body_preview = body_bytes[:4096].decode("utf-8", errors="replace")
                    except Exception:
                        body_preview = ""

                    http_evidence = {
                        "request": {
                            "method": "OPTIONS",
                            "url": url,
                            "headers": {
                                "Origin": origin,
                                "Access-Control-Request-Method": "DELETE",
                            },
                        },
                        "response": {
                            "status_code": status_code,
                            "headers": all_response_headers,
                            "body_preview": body_preview,
                        },
                        "target_domain": urlparse(url).netloc,
                        "test_origin": origin,
                    }

                    # Only return a "finding" if the server reflects the origin
                    # AND allows dangerous methods — purely to carry evidence.
                    # Severity is set low; the real finding is the origin reflection.
                    if acao in (origin, "*") and acam and "DELETE" in acam.upper():
                        return Finding(
                            vuln_type=VulnType.CORS_MISCONFIGURATION,
                            category=VulnCategory.CONFIGURATION,
                            name="CORS Preflight Allows Dangerous Methods",
                            severity=Severity.INFO,
                            description=(
                                f"Preflight response allows {acam} from arbitrary origins."
                            ),
                            host=url,
                            endpoint=url,
                            evidence=[
                                f"Origin sent: {origin}",
                                f"Access-Control-Allow-Origin: {acao}",
                                f"Access-Control-Allow-Methods: {acam}",
                                f"Access-Control-Allow-Credentials: {acac}",
                            ],
                            cvss_score=0.0,
                            cwe_id="CWE-346",
                            confidence_score=80.0,
                            remediation="Restrict allowed methods in preflight responses.",
                            scanner="cors",
                            metadata={"http_evidence": http_evidence},
                        )
        except Exception as e:
            # FIX 2026-02-12: Log suppressed errors for audit trail
            logger.warning(f"[CORS] Error testing preflight bypass: {e}")

        return None

    async def _capture_baseline(self, url: str) -> dict | None:
        """
        Capture a baseline response WITHOUT any Origin header.

        This proves that CORS headers are only added when an Origin is present
        (reflection-based), strengthening the evidence that the misconfiguration
        is real and not just always-present headers.
        """
        timeout = aiohttp.ClientTimeout(total=10)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=False, allow_redirects=True) as resp:
                    status_code = resp.status
                    all_headers = dict(resp.headers)
                    try:
                        body_bytes = await resp.read()
                        body_preview = body_bytes[:4096].decode("utf-8", errors="replace")
                    except Exception:
                        body_preview = ""

                    return {
                        "request": {
                            "method": "GET",
                            "url": url,
                            "headers": {},  # No Origin header
                        },
                        "response": {
                            "status_code": status_code,
                            "headers": all_headers,
                            "body_preview": body_preview,
                        },
                        "target_domain": urlparse(url).netloc,
                        "test_origin": "(none — baseline)",
                    }
        except Exception:
            return None

    async def _test_origin(self, url: str, origin: str) -> Finding | None:
        """Legacy method - use _test_origin_advanced instead."""
        return await self._test_origin_advanced(url, origin, "legacy", "Legacy origin test")
    
    def _deduplicate_findings(
        self,
        findings: list[Finding],
        host: str,
    ) -> list[Finding]:
        """Deduplicate findings by vulnerability name, keeping highest severity."""
        _SEV_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        best: dict[str, Finding] = {}

        for finding in findings:
            key = finding.name
            existing = best.get(key)
            if existing is None:
                finding.host = host
                best[key] = finding
            else:
                # Keep the finding with highest severity
                new_rank = _SEV_RANK.get(finding.severity.value, 0)
                old_rank = _SEV_RANK.get(existing.severity.value, 0)
                if new_rank > old_rank:
                    finding.host = host
                    best[key] = finding

        return list(best.values())
