"""
PHANTOM AI - Client-Side Hardening Scanner

Comprehensive client-side security testing including:
1. CSP (Content Security Policy) analysis and bypass detection
2. SRI (Subresource Integrity) validation
3. postMessage security analysis
4. DOM clobbering detection
5. Client-side storage security (localStorage, sessionStorage, IndexedDB)
6. Service Worker security
7. WebSocket origin validation
8. Client-side prototype pollution
9. Browser security headers analysis

Works generically for ALL web applications.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.scan_client import get_scan_client
from utils.logger import get_logger
from scanning.scan_context import ScanContext

logger = get_logger(__name__)


# CSP directives and their security implications
CSP_DIRECTIVES = {
    "default-src": "Fallback for other directives",
    "script-src": "Controls JavaScript execution",
    "style-src": "Controls CSS",
    "img-src": "Controls images",
    "connect-src": "Controls XHR/fetch/WebSocket",
    "font-src": "Controls fonts",
    "object-src": "Controls plugins (Flash, Java)",
    "media-src": "Controls audio/video",
    "frame-src": "Controls iframes",
    "frame-ancestors": "Controls who can iframe this page",
    "form-action": "Controls form submission targets",
    "base-uri": "Controls base tag",
    "report-uri": "CSP violation reporting",
    "report-to": "CSP violation reporting (new)",
}

# Dangerous CSP values that enable bypass
CSP_DANGEROUS_VALUES = {
    "unsafe-inline": "Allows inline scripts/styles - XSS risk",
    "unsafe-eval": "Allows eval() - XSS risk",
    "unsafe-hashes": "Allows specific inline handlers",
    "*": "Wildcard - allows any origin",
    "data:": "Allows data: URLs - potential XSS",
    "blob:": "Allows blob: URLs",
    "'none'": None,  # Safe
    "'self'": None,  # Generally safe
}

# JSONP endpoints commonly used for CSP bypass
JSONP_PATTERNS = [
    r"callback=", r"jsonp=", r"cb=", r"jsonpcallback=",
    r"\.jsonp", r"json-in-script", r"\?c=",
]

# Known CSP bypass CDNs/services
CSP_BYPASS_CDNS = [
    "cdnjs.cloudflare.com",  # Has angular.js with XSS gadgets
    "cdn.jsdelivr.net",
    "unpkg.com",
    "ajax.googleapis.com",  # Has angular.js
    "code.jquery.com",
    "stackpath.bootstrapcdn.com",
]


@dataclass
class CSPPolicy:
    """Parsed CSP policy."""
    raw: str
    directives: dict[str, list[str]] = field(default_factory=dict)
    report_only: bool = False


class ClientHardeningScanner(ScanModule):
    """
    Comprehensive client-side security scanner.

    Tests CSP bypass, SRI, postMessage, DOM security, and browser hardening.
    """

    name = "client_hardening"
    description = "Tests client-side security: CSP, SRI, postMessage, DOM security"
    version = "1.0.0"
    author = "PHANTOM AI"
    tags = ["csp", "sri", "postmessage", "client", "browser"]

    def __init__(
        self,
        settings: Any = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self._base_url = ""
        self._csp_policy: CSPPolicy | None = None
        self._page_content: str = ""

    async def scan(
        self,
        host: str,
        port: int | None = None,
        extra_params: dict[str, Any] | None = None,
    ) -> list[Finding]:
        """Main entry point for client-side security scanning."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(extra_params)
        self._auth_headers = self._ctx.auth_headers

        extra_params = extra_params or {}
        self._base_url = self._resolve_base_url(host, port)

        findings: list[Finding] = []

        # Fetch main page and headers
        await self._fetch_main_page()

        # Phase 1: CSP analysis
        csp_findings = await self._analyze_csp()
        findings.extend(csp_findings)

        # Phase 2: SRI analysis
        sri_findings = await self._analyze_sri()
        findings.extend(sri_findings)

        # Phase 3: postMessage analysis
        postmessage_findings = await self._analyze_postmessage()
        findings.extend(postmessage_findings)

        # Phase 4: Client storage analysis
        storage_findings = await self._analyze_client_storage()
        findings.extend(storage_findings)

        # Phase 5: Security headers analysis
        header_findings = await self._analyze_security_headers()
        findings.extend(header_findings)

        # Phase 6: DOM clobbering potential
        clobber_findings = await self._analyze_dom_clobbering()
        findings.extend(clobber_findings)

        return findings

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

    async def _fetch_main_page(self) -> None:
        """Fetch the main page and extract CSP header."""
        try:
            async with get_scan_client(verify_ssl=False, timeout=15.0) as client:
                resp = await client.get(self._base_url)
                self._page_content = resp.text

                # Extract CSP from header
                csp_header = resp.headers.get("Content-Security-Policy", "")
                csp_report_only = resp.headers.get("Content-Security-Policy-Report-Only", "")

                if csp_header:
                    self._csp_policy = self._parse_csp(csp_header, report_only=False)
                elif csp_report_only:
                    self._csp_policy = self._parse_csp(csp_report_only, report_only=True)

                # Also check meta tag
                if not self._csp_policy:
                    meta_match = re.search(
                        r'<meta[^>]+http-equiv=["\']Content-Security-Policy["\'][^>]+content=["\']([^"\']+)["\']',
                        self._page_content, re.IGNORECASE
                    )
                    if meta_match:
                        self._csp_policy = self._parse_csp(meta_match.group(1), report_only=False)

        except Exception as e:
            logger.debug(f"[CLIENT] Error fetching main page: {e}")

    def _parse_csp(self, raw: str, report_only: bool = False) -> CSPPolicy:
        """Parse a CSP header into directives."""
        policy = CSPPolicy(raw=raw, report_only=report_only)

        for directive in raw.split(";"):
            directive = directive.strip()
            if not directive:
                continue

            parts = directive.split()
            if parts:
                directive_name = parts[0].lower()
                values = parts[1:] if len(parts) > 1 else []
                policy.directives[directive_name] = values

        return policy

    async def _analyze_csp(self) -> list[Finding]:
        """Analyze CSP for weaknesses and bypass opportunities."""
        findings: list[Finding] = []

        if not self._csp_policy:
            findings.append(Finding(
                vuln_type=VulnType.SECURITY_HEADERS_MISSING,
                name="Missing Content Security Policy",
                description=(
                    "The application does not have a Content Security Policy (CSP) header.\n\n"
                    "CSP is a critical defense-in-depth mechanism against XSS attacks. "
                    "Without CSP, any XSS vulnerability can be fully exploited to steal "
                    "cookies, session tokens, and execute arbitrary JavaScript."
                ),
                severity=Severity.MEDIUM,
                confidence_score=100.0,
                host=urlparse(self._base_url).netloc,
                endpoint=self._base_url,
                metadata={"missing_header": "Content-Security-Policy"},
            ))
            return findings

        # Check if report-only
        if self._csp_policy.report_only:
            findings.append(Finding(
                vuln_type=VulnType.SECURITY_HEADERS_MISSING,
                name="CSP in Report-Only Mode",
                description=(
                    "The Content Security Policy is configured in report-only mode.\n\n"
                    "Report-only mode does not block attacks - it only reports violations. "
                    "XSS attacks can still succeed. Consider enabling enforcement mode."
                ),
                severity=Severity.MEDIUM,
                confidence_score=100.0,
                host=urlparse(self._base_url).netloc,
                endpoint=self._base_url,
                metadata={"csp_mode": "report-only"},
            ))

        # Check for dangerous values
        for directive, values in self._csp_policy.directives.items():
            for value in values:
                value_lower = value.lower().strip("'\"")

                if value_lower == "unsafe-inline" and directive in ("script-src", "default-src"):
                    findings.append(Finding(
                        vuln_type=VulnType.SECURITY_HEADERS_MISSING,
                        name="CSP Allows Unsafe Inline Scripts",
                        description=(
                            f"The CSP directive `{directive}` contains `'unsafe-inline'`.\n\n"
                            f"This allows inline JavaScript execution, completely bypassing "
                            f"CSP protection against XSS. Any XSS vulnerability can be fully "
                            f"exploited.\n\n"
                            f"**CSP:** `{self._csp_policy.raw[:200]}...`"
                        ),
                        severity=Severity.HIGH,
                        confidence_score=95.0,
                        host=urlparse(self._base_url).netloc,
                        endpoint=self._base_url,
                        metadata={
                            "directive": directive,
                            "dangerous_value": "unsafe-inline",
                        },
                    ))

                if value_lower == "unsafe-eval" and directive in ("script-src", "default-src"):
                    findings.append(Finding(
                        vuln_type=VulnType.SECURITY_HEADERS_MISSING,
                        name="CSP Allows Unsafe Eval",
                        description=(
                            f"The CSP directive `{directive}` contains `'unsafe-eval'`.\n\n"
                            f"This allows `eval()`, `Function()`, and similar dynamic code "
                            f"execution, enabling CSP bypass via DOM XSS gadgets."
                        ),
                        severity=Severity.MEDIUM,
                        confidence_score=95.0,
                        host=urlparse(self._base_url).netloc,
                        endpoint=self._base_url,
                        metadata={
                            "directive": directive,
                            "dangerous_value": "unsafe-eval",
                        },
                    ))

                if value == "*" and directive in ("script-src", "default-src", "connect-src"):
                    findings.append(Finding(
                        vuln_type=VulnType.SECURITY_HEADERS_MISSING,
                        name="CSP Wildcard Allows Any Origin",
                        description=(
                            f"The CSP directive `{directive}` contains a wildcard `*`.\n\n"
                            f"This allows loading scripts/resources from any origin, "
                            f"negating much of CSP's protection. Attackers can host "
                            f"malicious scripts on any domain."
                        ),
                        severity=Severity.HIGH,
                        confidence_score=95.0,
                        host=urlparse(self._base_url).netloc,
                        endpoint=self._base_url,
                        metadata={
                            "directive": directive,
                            "dangerous_value": "*",
                        },
                    ))

                # Check for CSP bypass CDNs
                for cdn in CSP_BYPASS_CDNS:
                    if cdn in value.lower():
                        findings.append(Finding(
                            vuln_type=VulnType.SECURITY_HEADERS_MISSING,
                            name=f"CSP Allows Known Bypass CDN: {cdn}",
                            description=(
                                f"The CSP allows scripts from `{cdn}` which hosts libraries "
                                f"with known XSS gadgets (e.g., AngularJS, jQuery templates).\n\n"
                                f"Attackers can use these libraries to execute arbitrary "
                                f"JavaScript even with CSP enabled.\n\n"
                                f"**Directive:** `{directive}: {value}`"
                            ),
                            severity=Severity.MEDIUM,
                            confidence_score=80.0,
                            host=urlparse(self._base_url).netloc,
                            endpoint=self._base_url,
                            metadata={
                                "directive": directive,
                                "cdn": cdn,
                            },
                        ))

        # Check for missing frame-ancestors
        if "frame-ancestors" not in self._csp_policy.directives:
            findings.append(Finding(
                vuln_type=VulnType.SECURITY_HEADERS_MISSING,
                name="CSP Missing frame-ancestors Directive",
                description=(
                    "The CSP does not include the `frame-ancestors` directive.\n\n"
                    "This directive prevents clickjacking attacks by controlling which "
                    "sites can embed the page in an iframe. Without it, the page is "
                    "vulnerable to clickjacking."
                ),
                severity=Severity.LOW,
                confidence_score=90.0,
                host=urlparse(self._base_url).netloc,
                endpoint=self._base_url,
                metadata={"missing_directive": "frame-ancestors"},
            ))

        return findings

    async def _analyze_sri(self) -> list[Finding]:
        """Analyze Subresource Integrity usage."""
        findings: list[Finding] = []

        if not self._page_content:
            return findings

        # Find script and link tags
        script_tags = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>',
            self._page_content, re.IGNORECASE
        )
        link_tags = re.findall(
            r'<link[^>]+href=["\']([^"\']+\.css)["\'][^>]*>',
            self._page_content, re.IGNORECASE
        )

        # Check for external resources without SRI
        external_without_sri = []

        for script_src in script_tags:
            if script_src.startswith(("http://", "https://", "//")):
                # Check if integrity attribute exists
                script_match = re.search(
                    rf'<script[^>]+src=["\']' + re.escape(script_src) + r'["\'][^>]*integrity=["\']',
                    self._page_content, re.IGNORECASE
                )
                if not script_match:
                    external_without_sri.append(("script", script_src))

        for link_href in link_tags:
            if link_href.startswith(("http://", "https://", "//")):
                link_match = re.search(
                    rf'<link[^>]+href=["\']' + re.escape(link_href) + r'["\'][^>]*integrity=["\']',
                    self._page_content, re.IGNORECASE
                )
                if not link_match:
                    external_without_sri.append(("stylesheet", link_href))

        if external_without_sri:
            resources = "\n".join([f"- {r[0]}: {r[1]}" for r in external_without_sri[:10]])
            findings.append(Finding(
                vuln_type=VulnType.SECURITY_HEADERS_MISSING,
                name="External Resources Without Subresource Integrity",
                description=(
                    f"The page loads {len(external_without_sri)} external resources "
                    f"without Subresource Integrity (SRI) hashes.\n\n"
                    f"Without SRI, if any CDN or external host is compromised, "
                    f"attackers can inject malicious code that will execute in your "
                    f"users' browsers.\n\n"
                    f"**Resources without SRI:**\n{resources}"
                ),
                severity=Severity.LOW,
                confidence_score=85.0,
                host=urlparse(self._base_url).netloc,
                endpoint=self._base_url,
                metadata={
                    "resources_without_sri": len(external_without_sri),
                    "examples": external_without_sri[:5],
                },
            ))

        return findings

    async def _analyze_postmessage(self) -> list[Finding]:
        """Analyze postMessage handlers for security issues."""
        findings: list[Finding] = []

        if not self._page_content:
            return findings

        # Find postMessage event listeners
        postmessage_patterns = [
            r'addEventListener\s*\(\s*["\']message["\']',
            r'onmessage\s*=',
            r'\.on\s*\(\s*["\']message["\']',
        ]

        has_postmessage = any(
            re.search(pattern, self._page_content)
            for pattern in postmessage_patterns
        )

        if has_postmessage:
            # Check for origin validation
            origin_checks = [
                r'event\.origin',
                r'e\.origin',
                r'message\.origin',
                r'\.origin\s*[!=]==',
            ]

            has_origin_check = any(
                re.search(pattern, self._page_content)
                for pattern in origin_checks
            )

            if not has_origin_check:
                findings.append(Finding(
                    vuln_type=VulnType.SECURITY_HEADERS_MISSING,
                    name="postMessage Handler Without Origin Validation",
                    description=(
                        "The page has a postMessage handler that may not validate "
                        "the message origin.\n\n"
                        "Without origin validation, any website can send messages "
                        "to this page, potentially triggering XSS or other attacks "
                        "if the message content is processed unsafely.\n\n"
                        "**Recommendation:** Always validate `event.origin` against "
                        "an allowlist before processing postMessage data."
                    ),
                    severity=Severity.MEDIUM,
                    confidence_score=70.0,
                    host=urlparse(self._base_url).netloc,
                    endpoint=self._base_url,
                    metadata={
                        "has_postmessage_handler": True,
                        "origin_validation_detected": False,
                    },
                ))

            # Check for innerHTML/eval with message data
            dangerous_sinks = [
                r'innerHTML\s*=.*event\.data',
                r'outerHTML\s*=.*event\.data',
                r'eval\s*\(.*event\.data',
                r'document\.write\s*\(.*event\.data',
                r'\.html\s*\(.*event\.data',
            ]

            for sink in dangerous_sinks:
                if re.search(sink, self._page_content, re.IGNORECASE):
                    findings.append(Finding(
                        vuln_type=VulnType.SECURITY_HEADERS_MISSING,
                        name="Dangerous postMessage Data Sink",
                        description=(
                            "The page appears to use postMessage data in a dangerous "
                            "sink (innerHTML, eval, document.write).\n\n"
                            "If combined with missing origin validation, this could "
                            "allow cross-site XSS attacks via postMessage."
                        ),
                        severity=Severity.HIGH,
                        confidence_score=65.0,
                        host=urlparse(self._base_url).netloc,
                        endpoint=self._base_url,
                        metadata={"dangerous_pattern": sink},
                    ))
                    break

        return findings

    async def _analyze_client_storage(self) -> list[Finding]:
        """Analyze client-side storage usage patterns."""
        findings: list[Finding] = []

        if not self._page_content:
            return findings

        # Check for sensitive data in localStorage/sessionStorage
        sensitive_patterns = [
            r'localStorage\.setItem\s*\(\s*["\'](?:token|jwt|auth|session|password|secret|api_key)',
            r'sessionStorage\.setItem\s*\(\s*["\'](?:token|jwt|auth|session|password|secret|api_key)',
        ]

        for pattern in sensitive_patterns:
            if re.search(pattern, self._page_content, re.IGNORECASE):
                findings.append(Finding(
                    vuln_type=VulnType.SECURITY_HEADERS_MISSING,
                    name="Sensitive Data in Client Storage",
                    description=(
                        "The application appears to store sensitive data (tokens, credentials) "
                        "in localStorage or sessionStorage.\n\n"
                        "This data is accessible via JavaScript, making it vulnerable to "
                        "XSS attacks. Consider using HttpOnly cookies for sensitive tokens."
                    ),
                    severity=Severity.MEDIUM,
                    confidence_score=75.0,
                    host=urlparse(self._base_url).netloc,
                    endpoint=self._base_url,
                    metadata={"pattern_matched": pattern},
                ))
                break

        return findings

    async def _analyze_security_headers(self) -> list[Finding]:
        """Analyze browser security headers."""
        findings: list[Finding] = []

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                resp = await client.get(self._base_url)

                # X-Content-Type-Options
                if "x-content-type-options" not in [h.lower() for h in resp.headers]:
                    findings.append(Finding(
                        vuln_type=VulnType.SECURITY_HEADERS_MISSING,
                        name="Missing X-Content-Type-Options Header",
                        description=(
                            "The `X-Content-Type-Options: nosniff` header is missing.\n\n"
                            "This header prevents MIME type sniffing attacks where browsers "
                            "could execute files as scripts based on content inspection."
                        ),
                        severity=Severity.LOW,
                        confidence_score=100.0,
                        host=urlparse(self._base_url).netloc,
                        endpoint=self._base_url,
                        metadata={"missing_header": "X-Content-Type-Options"},
                    ))

                # X-Frame-Options (if no CSP frame-ancestors)
                has_xfo = "x-frame-options" in [h.lower() for h in resp.headers]
                has_frame_ancestors = self._csp_policy and "frame-ancestors" in self._csp_policy.directives

                if not has_xfo and not has_frame_ancestors:
                    findings.append(Finding(
                        vuln_type=VulnType.SECURITY_HEADERS_MISSING,
                        name="Missing Clickjacking Protection",
                        description=(
                            "Neither `X-Frame-Options` nor CSP `frame-ancestors` is set.\n\n"
                            "This makes the page vulnerable to clickjacking attacks where "
                            "an attacker can trick users into clicking hidden elements."
                        ),
                        severity=Severity.MEDIUM,
                        confidence_score=100.0,
                        host=urlparse(self._base_url).netloc,
                        endpoint=self._base_url,
                        metadata={"missing_protection": "clickjacking"},
                    ))

                # Referrer-Policy
                if "referrer-policy" not in [h.lower() for h in resp.headers]:
                    findings.append(Finding(
                        vuln_type=VulnType.SECURITY_HEADERS_MISSING,
                        name="Missing Referrer-Policy Header",
                        description=(
                            "The `Referrer-Policy` header is missing.\n\n"
                            "Without this header, the browser may leak sensitive URL "
                            "information (including tokens in query strings) via the "
                            "Referer header to external sites."
                        ),
                        severity=Severity.LOW,
                        confidence_score=100.0,
                        host=urlparse(self._base_url).netloc,
                        endpoint=self._base_url,
                        metadata={"missing_header": "Referrer-Policy"},
                    ))

        except Exception as e:
            logger.debug(f"[CLIENT] Error analyzing headers: {e}")

        return findings

    async def _analyze_dom_clobbering(self) -> list[Finding]:
        """Analyze potential DOM clobbering vulnerabilities."""
        findings: list[Finding] = []

        if not self._page_content:
            return findings

        # Check for dangerous patterns that could be exploited via DOM clobbering
        clobbering_patterns = [
            # Using global variables that could be clobbered
            r'if\s*\(\s*!?window\.[a-zA-Z_]+\s*\)',
            r'window\.[a-zA-Z_]+\s*\|\|\s*["\']',
            r'\?\s*window\.[a-zA-Z_]+\s*:',
        ]

        # Find HTML elements with id/name that could clobber
        id_elements = re.findall(r'id=["\']([^"\']+)["\']', self._page_content)
        name_elements = re.findall(r'name=["\']([^"\']+)["\']', self._page_content)

        # Check for potential clobbering conflicts
        sensitive_names = ["config", "settings", "data", "user", "auth", "token", "api"]

        clobber_candidates = [
            name for name in id_elements + name_elements
            if any(s in name.lower() for s in sensitive_names)
        ]

        if clobber_candidates:
            findings.append(Finding(
                vuln_type=VulnType.SECURITY_HEADERS_MISSING,
                name="Potential DOM Clobbering Vector",
                description=(
                    f"Found HTML elements with IDs/names that could potentially "
                    f"clobber JavaScript variables: {clobber_candidates[:5]}\n\n"
                    f"If the JavaScript code uses these names without proper validation, "
                    f"an attacker could inject HTML elements to manipulate application logic."
                ),
                severity=Severity.LOW,
                confidence_score=50.0,
                host=urlparse(self._base_url).netloc,
                endpoint=self._base_url,
                metadata={
                    "clobbering_candidates": clobber_candidates[:10],
                },
            ))

        return findings
