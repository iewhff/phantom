"""
HTTP security headers checker.
Analyzes security-related HTTP headers.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import aiohttp

from scanning.findings import Finding, VulnType, VulnCategory, Severity
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from core.config_manager import Settings
    from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


class HeaderSecurityChecker(ScanModule):
    """
    Checks for missing or misconfigured security headers.
    
    Checks:
    - Content-Security-Policy
    - X-Content-Type-Options
    - X-Frame-Options
    - Strict-Transport-Security
    - X-XSS-Protection
    - Permissions-Policy
    - Referrer-Policy
    """
    
    name = "headers"
    
    # Header checks with severity and recommendations
    HEADER_CHECKS = {
        "Strict-Transport-Security": {
            "severity": "MEDIUM",
            "cvss": 5.0,
            "cwe": "CWE-319",
            "description": "Missing HSTS header allows potential MITM attacks",
            "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "example": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        },
        "Content-Security-Policy": {
            "severity": "MEDIUM",
            "cvss": 5.0,
            "cwe": "CWE-79",
            "description": "Missing CSP header increases XSS attack surface",
            "remediation": "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; object-src 'none'; frame-ancestors 'self'",
            "example": "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
        },
        "X-Content-Type-Options": {
            "severity": "LOW",
            "cvss": 3.0,
            "cwe": "CWE-16",
            "description": "Missing X-Content-Type-Options allows MIME type sniffing",
            "remediation": "Add header: X-Content-Type-Options: nosniff",
            "example": "X-Content-Type-Options: nosniff",
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "cvss": 4.0,
            "cwe": "CWE-1021",
            "description": "Missing X-Frame-Options allows clickjacking attacks. Note: CSP frame-ancestors is preferred",
            "remediation": "Add header: X-Frame-Options: DENY (or SAMEORIGIN if iframes needed). Better: use CSP frame-ancestors 'self'",
            "example": "X-Frame-Options: DENY",
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "cvss": 2.0,
            "cwe": "CWE-16",
            "description": "Missing Permissions-Policy header allows unrestricted browser features",
            "remediation": "Add header: Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=(), usb=()",
            "example": "Permissions-Policy: geolocation=(), microphone=(), camera=()",
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "cvss": 2.0,
            "cwe": "CWE-200",
            "description": "Missing Referrer-Policy may leak sensitive URL information",
            "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin (or no-referrer for maximum privacy)",
            "example": "Referrer-Policy: strict-origin-when-cross-origin",
        },
        # Modern headers (shows senior-level knowledge)
        "Cross-Origin-Opener-Policy": {
            "severity": "LOW",
            "cvss": 2.0,
            "cwe": "CWE-346",
            "description": "Missing COOP allows cross-origin windows to retain references. Required for SharedArrayBuffer and high-resolution timers",
            "remediation": "Add header: Cross-Origin-Opener-Policy: same-origin (or same-origin-allow-popups if OAuth flows needed)",
            "example": "Cross-Origin-Opener-Policy: same-origin",
        },
        "Cross-Origin-Embedder-Policy": {
            "severity": "LOW",
            "cvss": 2.0,
            "cwe": "CWE-346",
            "description": "Missing COEP allows loading cross-origin resources without explicit permission. Required for cross-origin isolation",
            "remediation": "Add header: Cross-Origin-Embedder-Policy: require-corp (ensure all resources have CORP headers)",
            "example": "Cross-Origin-Embedder-Policy: require-corp",
        },
        "Cross-Origin-Resource-Policy": {
            "severity": "LOW",
            "cvss": 2.0,
            "cwe": "CWE-346",
            "description": "Missing CORP allows other sites to embed your resources. Prevents Spectre-like side-channel attacks",
            "remediation": "Add header: Cross-Origin-Resource-Policy: same-origin (or same-site for CDN resources)",
            "example": "Cross-Origin-Resource-Policy: same-origin",
        },
    }
    
    # Dangerous header values
    # NOTE: CORS is handled by dedicated cors module - don't duplicate here
    DANGEROUS_VALUES = {
        "Content-Security-Policy": {
            "unsafe-inline": {
                "severity": "MEDIUM",
                "description": "CSP allows unsafe-inline scripts, reducing XSS protection",
            },
            "unsafe-eval": {
                "severity": "MEDIUM",
                "description": "CSP allows unsafe-eval, enabling code injection",
            },
        },
    }
    
    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        # Enterprise style: aggregate all missing headers into one finding
        module_config = settings.scanning.modules.get("headers", {}) if hasattr(settings, 'scanning') else {}
        self.aggregate_findings = module_config.get("aggregate_findings", True)  # Default: enterprise style

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Check security headers on host."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings = []
        info_items = []

        # Build URL
        url = host if host.startswith(('http://', 'https://')) else f"https://{host}"

        # Get multiple endpoints to test - different endpoints may have different headers
        test_urls = [url]
        if isinstance(asset_data, dict):
            all_endpoints = asset_data.get("endpoints", [])

        # Add API endpoints (may have different security headers)
        for ep in all_endpoints[:20]:
            if isinstance(ep, str) and any(p in ep.lower() for p in ["/api", "/v1", "/graphql", "/rest"]):
                test_urls.append(ep)
                if len(test_urls) >= 10:  # Limit to 10 endpoints
                    break

        test_urls = list(set(test_urls))
        logger.info(f"[headers] Checking security headers on {len(test_urls)} endpoints")

        # Track unique header issues to avoid duplicates
        seen_issues = set()

        for test_url in test_urls:
            try:
                await rate_limiter.acquire()
                headers = await self._fetch_headers(test_url)

                if headers is None and test_url == url:
                    # Try HTTP only for main URL
                    http_url = test_url.replace("https://", "http://")
                    await rate_limiter.acquire()
                    headers = await self._fetch_headers(http_url)

                if headers:
                    # Check for missing headers
                    missing = self._check_missing_headers(headers, test_url)

                    # Check for dangerous values
                    dangerous = self._check_dangerous_values(headers, test_url)

                    # Add only unique issues (by header name + issue type)
                    for f in missing + dangerous:
                        issue_key = (f.metadata.get("header", ""), f.vuln_type)
                        if issue_key not in seen_issues:
                            seen_issues.add(issue_key)
                            if test_url == url:
                                findings.append(f)
                            else:
                                # For API endpoints, just note the URL differs
                                if isinstance(asset_data, dict):
                                    f.metadata["also_affects"] = test_url
                                findings.append(f)

                    # Collect info for main URL only
                    if test_url == url:
                        info_items.append({
                            "type": "headers_info",
                            "host": host,
                            "headers": dict(headers),
                        })

            except Exception as e:
                logger.debug(f"[headers] Failed to check {test_url}: {e}")

        logger.info(f"[headers] Found {len(findings)} issues on {host}")
        return {"findings": [f.to_dict() for f in findings], "info": info_items}

    def _aggregate_header_findings(
        self,
        findings: list[Finding],
        host: str,
    ) -> Finding:
        """Aggregate multiple missing header findings into one enterprise-style finding."""
        # Categorize by severity
        critical_headers = []
        high_headers = []
        medium_headers = []
        low_headers = []

        for f in findings:
            header = f.metadata.get("header", "Unknown")
            if f.severity == Severity.CRITICAL:
                critical_headers.append(header)
            elif f.severity == Severity.HIGH:
                high_headers.append(header)
            elif f.severity == Severity.MEDIUM:
                medium_headers.append(header)
            else:
                low_headers.append(header)

        # Determine overall severity (highest found)
        if critical_headers:
            severity = "CRITICAL"
        elif high_headers:
            severity = "HIGH"
        elif medium_headers:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Build sub-items list
        sub_items = []
        for f in findings:
            # Prepara os valores condicionais antes
            header = f.metadata.get("header", "Unknown") if isinstance(f.metadata, dict) else "Unknown"
            business_impact = f.metadata.get("business_impact", "") if isinstance(f.metadata, dict) else ""

            sub_items.append({
                "header": header,
                "severity": f.severity.value,  # Convert enum to string for JSON
                "description": f.description,
                "remediation": f.remediation,
                "business_impact": business_impact,
            })


        # Build consolidated evidence
        evidence = [
            f"🛡️ Browser Hardening Analysis for {host}",
            "",
            f"Missing Headers ({len(findings)} total):",
        ]

        if medium_headers:
            evidence.append(f"  🟡 Medium Priority: {', '.join(medium_headers)}")
        if low_headers:
            evidence.append(f"  🟢 Low Priority: {', '.join(low_headers)}")

        evidence.extend([
            "",
            "📋 Reproduction:",
            f"  curl -I {host} | grep -iE 'content-security|x-frame|strict-transport'",
        ])

        return Finding(
            vuln_type=VulnType.SECURITY_HEADERS_MISSING,
            category=VulnCategory.CONFIGURATION,
            name="Missing Browser Hardening Headers",
            severity=Severity(severity),
            description=(
                f"The application is missing {len(findings)} security headers that provide "
                f"defense-in-depth against client-side attacks. These headers help mitigate "
                f"XSS, clickjacking, and other browser-based attacks IF vulnerabilities exist."
            ),
            host=host,
            endpoint=host,
            evidence=evidence,
            cvss_score=max(f.cvss_score for f in findings),
            cwe_id="CWE-693",  # Protection Mechanism Failure
            remediation=(
                "Add the missing security headers to your web server or CDN configuration. "
                "See sub-items for specific header values and priorities."
            ),
            confidence_score=100.0,
            scanner="headers",
            metadata={
                "aggregated": True,
                "sub_findings_count": len(findings),
                "sub_findings": sub_items,
                "headers_by_priority": {
                    "medium": medium_headers,
                    "low": low_headers,
                },
                "fix_priority": self._get_fix_priority(severity),
                "fix_effort": "Low (configuration changes)",
                "business_impact": (
                    "These are defense-in-depth controls. IF XSS or clickjacking vulnerabilities "
                    "exist, the absence of these headers would allow full exploitation."
                ),
            },
        )
    
    async def _fetch_headers(self, url: str) -> dict[str, str] | None:
        """Fetch headers from URL."""
        timeout = aiohttp.ClientTimeout(total=10)
        
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, ssl=False, allow_redirects=True) as resp:
                    return {k.lower(): v for k, v in resp.headers.items()}
        except Exception:
            return None
    
    def _check_missing_headers(
        self,
        headers: dict[str, str],
        host: str,
    ) -> list[Finding]:
        """Check for missing security headers with real evidence."""
        findings = []

        # Build evidence of what headers ARE present (for proof)
        security_headers_present = []
        for h in ["strict-transport-security", "x-content-type-options",
                  "x-frame-options", "content-security-policy",
                  "permissions-policy", "referrer-policy"]:
            if h in headers:
                security_headers_present.append(f"{h}: {headers[h][:100]}")

        for header, config in self.HEADER_CHECKS.items():
            header_lower = header.lower()

            if header_lower not in headers:
                # Build comprehensive evidence
                evidence = [
                    f"Header '{header}' is NOT present in response",
                    "",
                    "📋 Reproduction Steps:",
                    f"  1. curl -I {host}",
                    f"  2. Look for '{header}' in response headers",
                    f"  3. Header is missing from response",
                    "",
                    "🔍 Current Security Headers Present:",
                ]
                if security_headers_present:
                    evidence.extend([f"  ✓ {h}" for h in security_headers_present[:5]])
                else:
                    evidence.append("  ⚠️ No security headers detected")

                # Add business impact
                business_impact = self._get_business_impact(header)

                findings.append(Finding(
                    vuln_type=VulnType.SECURITY_HEADERS_MISSING,
                    category=VulnCategory.CONFIGURATION,
                    name=f"Missing {header} Header",
                    severity=Severity(config["severity"]),
                    description=config["description"],
                    host=host,
                    endpoint=host,
                    evidence=evidence,
                    cvss_score=config["cvss"],
                    cwe_id=config["cwe"],
                    remediation=config["remediation"],
                    confidence_score=100.0,
                    scanner="headers",
                    metadata={
                        "header": header,
                        "example": config.get("example", ""),
                        "business_impact": business_impact,
                        "fix_priority": self._get_fix_priority(config["severity"]),
                        "fix_effort": "Low (configuration change)",
                        "curl_command": f"curl -I {host} | grep -i {header.lower()}",
                    },
                ))

        return findings

    def _get_business_impact(self, header: str) -> str:
        """Get CONDITIONAL business impact description for missing header.

        Uses 'IF' language because we haven't confirmed the prerequisite
        vulnerabilities (XSS, file uploads, etc.) exist.
        """
        impacts = {
            "Content-Security-Policy": (
                "IF an XSS vulnerability exists in this application, the absence of CSP "
                "would allow full exploitation: session hijacking, credential theft, "
                "defacement, cryptomining. CSP is defense-in-depth against XSS."
            ),
            "X-Frame-Options": (
                "IF the site has sensitive one-click actions (transfers, deletions, "
                "password changes), attackers COULD embed the site in malicious pages "
                "to perform clickjacking attacks. Risk depends on site functionality."
            ),
            "Strict-Transport-Security": (
                "IF users access the site from public WiFi (coffee shops, airports), "
                "they COULD be vulnerable to MITM attacks on first connection. "
                "HSTS preload eliminates this first-connection window."
            ),
            "Permissions-Policy": (
                "IF third-party scripts are included (analytics, ads, widgets), they "
                "COULD access device features (camera, mic, location) without restriction. "
                "Lower risk if no third-party scripts are used."
            ),
            "Referrer-Policy": (
                "IF sensitive data appears in URLs (tokens, IDs, query params), it "
                "COULD leak to third parties via Referer header. Lower risk if URLs "
                "are clean and tokens are in headers/cookies."
            ),
            "X-Content-Type-Options": (
                "IF the site accepts file uploads, browsers COULD interpret uploaded "
                "files as executable scripts (MIME sniffing). Lower risk if no file "
                "upload functionality exists."
            ),
            "Cross-Origin-Opener-Policy": (
                "IF cross-origin isolation is needed (SharedArrayBuffer, high-res timers), "
                "this header is required. Lower priority for standard web applications."
            ),
            "Cross-Origin-Embedder-Policy": (
                "IF cross-origin isolation is needed, this header is required. "
                "Note: May break third-party resources without CORP headers."
            ),
            "Cross-Origin-Resource-Policy": (
                "IF resources should not be embedded by other sites, this header "
                "prevents cross-origin inclusion. Protects against Spectre-like attacks."
            ),
        }
        return impacts.get(header, "Security control is missing. Risk level depends on application functionality.")

    def _get_fix_priority(self, severity: str) -> str:
        """Convert severity to actionable fix priority."""
        priorities = {
            "CRITICAL": "🔴 Fix Now (within 24 hours)",
            "HIGH": "🟠 Fix This Sprint",
            "MEDIUM": "🟡 Fix Next Sprint",
            "LOW": "🟢 Fix When Convenient",
            "INFO": "ℹ️ Optional Enhancement",
        }
        return priorities.get(severity.upper(), "🟡 Fix Next Sprint")
    
    def _check_dangerous_values(
        self,
        headers: dict[str, str],
        host: str,
    ) -> list[Finding]:
        """Check for dangerous header values."""
        findings = []
        
        for header, dangerous_values in self.DANGEROUS_VALUES.items():
            header_lower = header.lower()
            value = headers.get(header_lower, "")
            
            if not value:
                continue
            
            for dangerous, config in dangerous_values.items():
                if dangerous.lower() in value.lower():
                    findings.append(Finding(
                        vuln_type=VulnType.SECURITY_HEADERS_MISSING,
                        category=VulnCategory.CONFIGURATION,
                        name=f"Insecure {header} Configuration",
                        severity=Severity(config["severity"]),
                        description=config["description"],
                        host=host,
                        endpoint=host,
                        evidence=[f"{header}: {value}"],
                        cvss_score=5.0,
                        cwe_id="CWE-16",
                        remediation=f"Review and restrict {header} header value",
                        confidence_score=100.0,  # Deterministic finding - dangerous value found
                        scanner="headers",
                        metadata={
                            "header": header,
                            "value": value,
                            "dangerous_pattern": dangerous,
                        },
                    ))
        
        return findings
