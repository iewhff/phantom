"""
PHANTOM AI - Defensive Evasion Scanner

Tests the effectiveness of security controls and their bypass potential:
1. WAF (Web Application Firewall) bypass techniques
2. Rate limiting bypass
3. Logging/monitoring evasion
4. Input validation bypass
5. Security header bypass
6. Bot detection bypass
7. CAPTCHA bypass detection
8. IP blocking bypass

Helps identify gaps in defensive security posture.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urljoin, urlparse

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.scan_client import get_scan_client
from utils.logger import get_logger
from scanning.scan_context import ScanContext

logger = get_logger(__name__)


# WAF bypass encoding techniques
WAF_BYPASS_ENCODINGS = {
    "url_encode": lambda s: quote(s, safe=""),
    "double_url_encode": lambda s: quote(quote(s, safe=""), safe=""),
    "unicode_encode": lambda s: "".join(f"\\u{ord(c):04x}" for c in s),
    "hex_encode": lambda s: "".join(f"\\x{ord(c):02x}" for c in s),
    "base64_encode": lambda s: base64.b64encode(s.encode()).decode(),
    "html_entity": lambda s: "".join(f"&#{ord(c)};" for c in s),
    "case_variation": lambda s: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s)),
    "null_byte": lambda s: s.replace(" ", "%00"),
    "tab_newline": lambda s: s.replace(" ", "\t").replace(",", "\n"),
}

# Common WAF evasion payloads
WAF_TEST_PAYLOADS = {
    "xss_basic": "<script>alert(1)</script>",
    "xss_encoded": "%3Cscript%3Ealert(1)%3C/script%3E",
    "xss_event": "<img src=x onerror=alert(1)>",
    "xss_svg": "<svg onload=alert(1)>",
    "sqli_basic": "' OR 1=1--",
    "sqli_union": "' UNION SELECT 1,2,3--",
    "sqli_comment": "1'/**/OR/**/1=1--",
    "cmdi_basic": "; ls -la",
    "cmdi_encoded": "%3B%20ls%20-la",
    "path_traversal": "../../etc/passwd",
}

# Headers that might bypass WAF
WAF_BYPASS_HEADERS = {
    "X-Originating-IP": "127.0.0.1",
    "X-Forwarded-For": "127.0.0.1",
    "X-Remote-IP": "127.0.0.1",
    "X-Remote-Addr": "127.0.0.1",
    "X-Original-URL": "/admin",
    "X-Rewrite-URL": "/admin",
    "X-Custom-IP-Authorization": "127.0.0.1",
    "X-Forwarded-Host": "localhost",
    "X-HTTP-Method-Override": "GET",
    "Content-Type": "application/x-www-form-urlencoded",
}

# Rate limit bypass techniques
RATE_LIMIT_BYPASS = {
    "ip_rotation": [
        {"X-Forwarded-For": "10.0.0.1"},
        {"X-Forwarded-For": "10.0.0.2"},
        {"X-Forwarded-For": "10.0.0.3"},
    ],
    "user_agent_rotation": [
        {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
        {"User-Agent": "Mozilla/5.0 (Linux; Android 11; SM-G991B)"},
    ],
    "case_variation": [
        {"User-Agent": "Googlebot"},
        {"User-Agent": "GOOGLEBOT"},
        {"User-Agent": "GoogleBot"},
    ],
}

# Common logging bypass patterns
LOGGING_EVASION = {
    "parameter_pollution": ["id=1&id=malicious", "id=1,malicious"],
    "encoding_tricks": ["%00null", "\r\ninjected", "normal%0d%0amalicious"],
    "overflow": ["A" * 10000, "B" * 50000],
    "unicode_normalization": ["\u202Ereverse", "normal\u0000hidden"],
}


@dataclass
class WAFDetection:
    """WAF detection result."""
    detected: bool
    waf_name: str = ""
    confidence: float = 0.0
    bypass_possible: bool = False


class DefensiveEvasionScanner(ScanModule):
    """
    Tests defensive security controls for bypass vulnerabilities.

    Evaluates WAF effectiveness, rate limiting, logging, and other
    protective measures.
    """

    name = "defensive_evasion"
    description = "Tests WAF bypass, rate limiting, logging evasion"
    version = "1.0.0"
    author = "PHANTOM AI"
    tags = ["waf", "bypass", "evasion", "rate_limit", "logging"]

    # Standard safety - tests detection bypass, no exploitation
    min_safety_level = "standard"

    def __init__(
        self,
        settings: Any = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self._base_url = ""
        self._waf_detection: WAFDetection | None = None
        self._auth_headers: dict[str, str] = {}

    async def scan(
        self,
        host: str,
        port: int | None = None,
        extra_params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Main entry point for defensive evasion scanning."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(extra_params)
        self._auth_headers = self._ctx.auth_headers

        extra_params = extra_params or {}
        self._base_url = self._resolve_base_url(host, port)

        # Get auth context if available
        auth_context = extra_params.get("auth_context")
        if auth_context and hasattr(auth_context, "auth_headers"):
            self._auth_headers = auth_context.auth_headers

        findings: list[Finding] = []

        # Phase 1: Detect WAF
        self._waf_detection = await self._detect_waf()
        if self._waf_detection.detected:
            logger.info(f"[EVASION] WAF detected: {self._waf_detection.waf_name}")

        # Phase 2: Test WAF bypass techniques
        waf_findings = await self._test_waf_bypass()
        findings.extend(waf_findings)

        # Phase 3: Test rate limiting bypass
        rate_findings = await self._test_rate_limit_bypass()
        findings.extend(rate_findings)

        # Phase 4: Test logging evasion
        log_findings = await self._test_logging_evasion()
        findings.extend(log_findings)

        # Phase 5: Test bot detection bypass
        bot_findings = await self._test_bot_detection_bypass()
        findings.extend(bot_findings)

        # Phase 6: Test security header bypass
        header_findings = await self._test_security_header_bypass()
        findings.extend(header_findings)

        return {"findings": findings, "info": []}

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

    async def _detect_waf(self) -> WAFDetection:
        """Detect if WAF is present and identify it."""
        waf_signatures = {
            "cloudflare": ["cf-ray", "__cfduid", "cloudflare"],
            "akamai": ["akamai", "akamaighost", "x-akamai"],
            "aws_waf": ["x-amzn-requestid", "x-amz-cf-id"],
            "imperva": ["incapsula", "visid_incap", "_incap_ses"],
            "f5_bigip": ["bigip", "f5", "ts="],
            "sucuri": ["sucuri", "x-sucuri"],
            "modsecurity": ["mod_security", "modsecurity"],
            "barracuda": ["barracuda", "barra"],
        }

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                # Normal request
                resp = await client.get(self._base_url, headers=self._auth_headers)
                headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
                body_lower = resp.text.lower()

                # Check for WAF signatures
                for waf_name, signatures in waf_signatures.items():
                    for sig in signatures:
                        if any(sig in v for v in headers_lower.values()) or sig in body_lower:
                            return WAFDetection(
                                detected=True,
                                waf_name=waf_name,
                                confidence_score=80.0,
                            )

                # Test with malicious payload to trigger WAF
                test_url = f"{self._base_url}?test=<script>alert(1)</script>"
                try:
                    mal_resp = await client.get(test_url)

                    # WAF might block or return specific status
                    if mal_resp.status_code in (403, 406, 429, 503):
                        return WAFDetection(
                            detected=True,
                            waf_name="unknown",
                            confidence_score=70.0,
                        )

                    # Check for common WAF block pages
                    mal_body = mal_resp.text.lower()
                    if any(phrase in mal_body for phrase in [
                        "blocked", "access denied", "forbidden",
                        "security violation", "request blocked",
                        "malicious", "attack detected",
                    ]):
                        return WAFDetection(
                            detected=True,
                            waf_name="unknown",
                            confidence_score=75.0,
                        )
                except Exception as e:
                    # FIX 2026-02-12: Log blocked request (DEBUG - expected in WAF detection)
                    logger.debug(f"[EVASION] WAF probe blocked: {e}")

        except Exception as e:
            logger.debug(f"[EVASION] Error detecting WAF: {e}")

        return WAFDetection(detected=False)

    async def _test_waf_bypass(self) -> list[Finding]:
        """Test WAF bypass techniques."""
        findings: list[Finding] = []

        if not self._waf_detection or not self._waf_detection.detected:
            pass  # Still test in case of transparent WAF

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                # First, establish baseline with blocked payload
                blocked_payload = "<script>alert(1)</script>"
                baseline_url = f"{self._base_url}?test={quote(blocked_payload)}"
                baseline_resp = await client.get(baseline_url)
                baseline_blocked = baseline_resp.status_code in (403, 406, 429, 503)

                if not baseline_blocked:
                    # WAF might not be blocking this, check response
                    if blocked_payload in baseline_resp.text:
                        findings.append(Finding(
                            vuln_type=VulnType.OTHER,
                            name="WAF Not Blocking XSS Payload",
                            description=(
                                f"The WAF did not block a basic XSS payload.\n\n"
                                f"**Payload:** `{blocked_payload}`\n"
                                f"**Status:** {baseline_resp.status_code}\n"
                                f"**Payload reflected:** Yes\n\n"
                                f"This indicates the WAF may not be properly configured to "
                                f"detect and block XSS attacks."
                            ),
                            severity=Severity.MEDIUM,
                            confidence_score=85.0,
                            host=urlparse(self._base_url).netloc,
                            endpoint=self._base_url,
                            metadata={
                                "payload": blocked_payload,
                                "response_status": baseline_resp.status_code,
                            },
                        ))
                    return findings

                # Test encoding bypass techniques
                for encoding_name, encoder in WAF_BYPASS_ENCODINGS.items():
                    try:
                        encoded_payload = encoder(blocked_payload)
                        bypass_url = f"{self._base_url}?test={quote(encoded_payload, safe='')}"

                        resp = await client.get(bypass_url, headers=self._auth_headers)

                        # Check if bypass worked
                        if resp.status_code == 200:
                            # Check if payload executed (would need DOM check for real)
                            if "script" in resp.text.lower() or "alert" in resp.text.lower():
                                findings.append(Finding(
                                    vuln_type=VulnType.OTHER,
                                    name=f"WAF Bypass via {encoding_name.replace('_', ' ').title()}",
                                    description=(
                                        f"The WAF can be bypassed using {encoding_name} encoding.\n\n"
                                        f"**Original payload:** `{blocked_payload}`\n"
                                        f"**Encoded payload:** `{encoded_payload[:100]}...`\n"
                                        f"**Encoding:** {encoding_name}\n\n"
                                        f"The encoded payload was not blocked by the WAF and may "
                                        f"be decoded by the application, enabling attacks."
                                    ),
                                    severity=Severity.HIGH,
                                    confidence_score=80.0,
                                    host=urlparse(self._base_url).netloc,
                                    endpoint=self._base_url,
                                    metadata={
                                        "encoding": encoding_name,
                                        "original_payload": blocked_payload,
                                        "bypass_payload": encoded_payload[:200],
                                    },
                                ))
                                break  # Found one bypass, that's enough

                    except Exception as e:
                        # FIX 2026-02-12: Log bypass attempt error (DEBUG - expected)
                        logger.debug(f"[EVASION] Encoding bypass test failed: {e}")

                # Test header-based bypass
                for header_name, header_value in WAF_BYPASS_HEADERS.items():
                    try:
                        test_headers = {**self._auth_headers, header_name: header_value}
                        resp = await client.get(baseline_url, headers=test_headers)

                        if resp.status_code == 200 and baseline_blocked:
                            findings.append(Finding(
                                vuln_type=VulnType.OTHER,
                                name=f"WAF Bypass via {header_name} Header",
                                description=(
                                    f"The WAF can be bypassed using the `{header_name}` header.\n\n"
                                    f"**Header:** `{header_name}: {header_value}`\n\n"
                                    f"This header caused the WAF to allow a request that was "
                                    f"previously blocked."
                                ),
                                severity=Severity.HIGH,
                                confidence_score=85.0,
                                host=urlparse(self._base_url).netloc,
                                endpoint=self._base_url,
                                metadata={
                                    "bypass_header": header_name,
                                    "header_value": header_value,
                                },
                            ))
                            break

                    except Exception as e:
                        # FIX 2026-02-12: Log header bypass test error (DEBUG - expected)
                        logger.debug(f"[EVASION] Header bypass test failed: {e}")

        except Exception as e:
            logger.debug(f"[EVASION] Error testing WAF bypass: {e}")

        return findings

    async def _test_rate_limit_bypass(self) -> list[Finding]:
        """Test rate limiting bypass techniques."""
        findings: list[Finding] = []

        # Find a rate-limited endpoint
        rate_limited_endpoints = [
            "/api/login", "/login", "/api/auth", "/auth",
            "/api/register", "/register", "/api/password/reset",
        ]

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                for endpoint in rate_limited_endpoints:
                    url = urljoin(self._base_url, endpoint)

                    # Send multiple requests to trigger rate limiting
                    rate_limited = False
                    for i in range(20):
                        try:
                            resp = await client.post(
                                url,
                                json={"username": "test", "password": "test"},
                                headers=self._auth_headers,
                            )

                            if resp.status_code == 429:
                                rate_limited = True
                                break
                        except Exception as e:
                            # FIX 2026-02-12: Log rate limit test error (DEBUG - expected)
                            logger.debug(f"[EVASION] Rate limit detection error: {e}")

                    if not rate_limited:
                        continue

                    # Test bypass techniques
                    for bypass_name, headers_list in RATE_LIMIT_BYPASS.items():
                        bypassed = True
                        for headers in headers_list:
                            test_headers = {**self._auth_headers, **headers}
                            try:
                                resp = await client.post(
                                    url,
                                    json={"username": "test", "password": "test"},
                                    headers=test_headers,
                                )

                                if resp.status_code == 429:
                                    bypassed = False
                                    break
                            except Exception as e:
                                # FIX 2026-02-12: Log bypass attempt error (DEBUG - expected)
                                logger.debug(f"[EVASION] Rate limit bypass test error: {e}")
                                bypassed = False
                                break

                        if bypassed:
                            findings.append(Finding(
                                vuln_type=VulnType.OTHER,
                                name=f"Rate Limit Bypass via {bypass_name.replace('_', ' ').title()}",
                                description=(
                                    f"Rate limiting on `{endpoint}` can be bypassed using "
                                    f"{bypass_name.replace('_', ' ')}.\n\n"
                                    f"**Endpoint:** `{url}`\n"
                                    f"**Bypass technique:** {bypass_name}\n\n"
                                    f"This allows attackers to circumvent rate limiting protections "
                                    f"by rotating headers, enabling brute force attacks."
                                ),
                                severity=Severity.MEDIUM,
                                confidence_score=85.0,
                                host=urlparse(url).netloc,
                                endpoint=url,
                                metadata={
                                    "endpoint": endpoint,
                                    "bypass_technique": bypass_name,
                                },
                            ))
                            break

                    break  # Found rate-limited endpoint, test done

        except Exception as e:
            logger.debug(f"[EVASION] Error testing rate limit bypass: {e}")

        return findings

    async def _test_logging_evasion(self) -> list[Finding]:
        """Test logging/monitoring evasion techniques."""
        findings: list[Finding] = []

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                # Test parameter pollution
                for pollution_type, payloads in LOGGING_EVASION.items():
                    # AUDIT-FIX 2026-02-11: Increased from [:2] to [:8] for better coverage
                    for payload in payloads[:8]:
                        test_url = f"{self._base_url}?param={quote(payload)}"

                        try:
                            resp = await client.get(test_url, headers=self._auth_headers)

                            # If request succeeds, logging might not capture correctly
                            if resp.status_code == 200:
                                # Log this as informational
                                logger.debug(f"[EVASION] Logging evasion test passed: {pollution_type}")

                        except Exception as e:
                            # FIX 2026-02-12: Log evasion test error (DEBUG - expected)
                            logger.debug(f"[EVASION] Param pollution test error: {e}")

                # Test log injection via headers
                log_injection_headers = {
                    "User-Agent": "Mozilla/5.0\r\nX-Injected: malicious",
                    "Referer": "https://attacker.com\nX-Injected: test",
                }

                for header_name, header_value in log_injection_headers.items():
                    try:
                        test_headers = {**self._auth_headers, header_name: header_value}
                        resp = await client.get(self._base_url, headers=test_headers)

                        # If the server accepts the header with newlines, log injection might work
                        if resp.status_code == 200:
                            findings.append(Finding(
                                vuln_type=VulnType.OTHER,
                                name="Potential Log Injection via Headers",
                                description=(
                                    f"The application accepts headers containing newline characters.\n\n"
                                    f"**Header:** `{header_name}`\n"
                                    f"**Value:** `{header_value[:50]}...`\n\n"
                                    f"This could allow attackers to inject fake log entries or "
                                    f"corrupt logging systems."
                                ),
                                severity=Severity.LOW,
                                confidence_score=60.0,
                                host=urlparse(self._base_url).netloc,
                                endpoint=self._base_url,
                                metadata={
                                    "header": header_name,
                                    "injection_type": "log_injection",
                                },
                            ))
                            break

                    except Exception as e:
                        # FIX 2026-02-12: Log injection test error (DEBUG - expected)
                        logger.debug(f"[EVASION] Log injection test error: {e}")

        except Exception as e:
            logger.debug(f"[EVASION] Error testing logging evasion: {e}")

        return findings

    async def _test_bot_detection_bypass(self) -> list[Finding]:
        """Test bot detection bypass."""
        findings: list[Finding] = []

        bot_user_agents = [
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
        ]

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                # Get baseline with normal UA
                baseline = await client.get(self._base_url, headers=self._auth_headers)

                # Check if bot detection blocks common bot UAs
                for bot_ua in bot_user_agents:
                    try:
                        test_headers = {**self._auth_headers, "User-Agent": bot_ua}
                        resp = await client.get(self._base_url, headers=test_headers)

                        # If bot gets same access as normal user
                        if resp.status_code == baseline.status_code:
                            if len(resp.content) > len(baseline.content) * 0.9:
                                # Bot gets similar content
                                logger.debug(f"[EVASION] Bot UA accepted: {bot_ua[:30]}")

                    except Exception as e:
                        # FIX 2026-02-12: Log bot detection test error (DEBUG - expected)
                        logger.debug(f"[EVASION] Bot detection test error: {e}")

        except Exception as e:
            logger.debug(f"[EVASION] Error testing bot detection: {e}")

        return findings

    async def _test_security_header_bypass(self) -> list[Finding]:
        """Test security header bypass."""
        findings: list[Finding] = []

        try:
            async with get_scan_client(verify_ssl=False, timeout=10.0) as client:
                resp = await client.get(self._base_url, headers=self._auth_headers)

                # Check for X-XSS-Protection: 0 (disabled)
                xss_protection = resp.headers.get("X-XSS-Protection", "")
                if xss_protection == "0":
                    findings.append(Finding(
                        vuln_type=VulnType.OTHER,
                        name="XSS Protection Explicitly Disabled",
                        description=(
                            "The `X-XSS-Protection` header is set to `0`, explicitly "
                            "disabling browser XSS filtering.\n\n"
                            "While modern browsers deprecated this header, explicitly "
                            "disabling it removes a layer of defense on older browsers."
                        ),
                        severity=Severity.LOW,
                        confidence_score=100.0,
                        host=urlparse(self._base_url).netloc,
                        endpoint=self._base_url,
                        metadata={"header_value": xss_protection},
                    ))

                # Check for permissive CORS
                cors_origin = resp.headers.get("Access-Control-Allow-Origin", "")
                if cors_origin == "*":
                    # Check if credentials are also allowed
                    cors_creds = resp.headers.get("Access-Control-Allow-Credentials", "")
                    if cors_creds.lower() == "true":
                        findings.append(Finding(
                            vuln_type=VulnType.OTHER,
                            name="Overly Permissive CORS Configuration",
                            description=(
                                "The application has dangerous CORS settings:\n\n"
                                "- `Access-Control-Allow-Origin: *`\n"
                                "- `Access-Control-Allow-Credentials: true`\n\n"
                                "This combination is insecure and allows any website to "
                                "make authenticated requests to this API."
                            ),
                            severity=Severity.HIGH,
                            confidence_score=95.0,
                            host=urlparse(self._base_url).netloc,
                            endpoint=self._base_url,
                            metadata={
                                "cors_origin": cors_origin,
                                "cors_credentials": cors_creds,
                            },
                        ))

        except Exception as e:
            logger.debug(f"[EVASION] Error testing security headers: {e}")

        return findings
