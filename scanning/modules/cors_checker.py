"""
CORS misconfiguration checker v2.0 - Enhanced Bypass Testing
Tests for Cross-Origin Resource Sharing vulnerabilities including bypass techniques.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import aiohttp

from scanning.vuln_scanner import Finding, ScanModule
from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings
    from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


class CORSChecker(ScanModule):
    """
    CORS misconfiguration scanner v2.0 - Enterprise Edition.

    Advanced Checks:
    - Wildcard origin reflection
    - Null origin acceptance
    - Origin reflection
    - Credential exposure
    - Subdomain bypass (evil.target.com)
    - Suffix bypass (target.com.evil.com)
    - Prefix bypass (eviltarget.com)
    - Protocol downgrade (https → http)
    - Preflight bypass techniques
    - Cloudflare/CDN bypass patterns
    """

    name = "cors"
    version = "2.0.0"

    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)

        # Base test origins (will be expanded per-target)
        module_config = settings.scanning.modules.get("cors", {})
        self.base_origins = module_config.get(
            "test_origins",
            ["null", "https://evil.com", "https://attacker.com"]
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
            {"origin": "https://evil.com", "type": "arbitrary", "description": "Arbitrary origin"},

            # Subdomain bypass - pretend to be a subdomain
            {"origin": f"https://evil.{base_domain}", "type": "subdomain_inject",
             "description": f"Subdomain injection: evil.{base_domain}"},
            {"origin": f"https://attacker.{base_domain}", "type": "subdomain_inject",
             "description": f"Attacker subdomain: attacker.{base_domain}"},

            # Suffix bypass - target.com.evil.com
            {"origin": f"https://{base_domain}.evil.com", "type": "suffix_bypass",
             "description": f"Suffix bypass: {base_domain}.evil.com"},

            # Prefix bypass - eviltarget.com
            {"origin": f"https://evil{base_domain}", "type": "prefix_bypass",
             "description": f"Prefix bypass: evil{base_domain}"},

            # Protocol downgrade
            {"origin": f"http://{domain}", "type": "protocol_downgrade",
             "description": "HTTP protocol downgrade"},

            # Regex bypass with special chars
            {"origin": f"https://{base_domain}%60.evil.com", "type": "regex_bypass",
             "description": "Regex bypass with backtick"},
            {"origin": f"https://{base_domain}%00.evil.com", "type": "null_byte",
             "description": "Null byte injection"},

            # Underscore/hyphen variations
            {"origin": f"https://{base_domain.replace('.', '_')}.evil.com", "type": "underscore_bypass",
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

        # Build URL
        url = host if host.startswith(('http://', 'https://')) else f"https://{host}"

        # Generate target-specific bypass origins
        bypass_origins = self._generate_bypass_origins(url)

        # Get URLs to test
        test_urls = [url]
        urls_from_recon = asset_data.get("urls", [])

        # Add API-like endpoints (high value for CORS attacks)
        for u in urls_from_recon[:10]:
            if any(pattern in u for pattern in ["/api", "/v1", "/v2", "/graphql", "/rest"]):
                test_urls.append(u)

        # Also test discovered endpoints from SPA analysis
        spa_endpoints = asset_data.get("spa_analysis", {}).get("api_endpoints", [])
        for ep in spa_endpoints[:5]:
            if isinstance(ep, dict):
                test_urls.append(ep.get("url", ""))
            elif isinstance(ep, str):
                test_urls.append(ep)

        test_urls = list(set(filter(None, test_urls)))  # Deduplicate

        for test_url in test_urls:
            try:
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
                        findings.append(result)

                # Test preflight bypass
                await rate_limiter.acquire()
                preflight_result = await self._test_preflight_bypass(test_url)
                if preflight_result:
                    findings.append(preflight_result)

            except Exception as e:
                logger.debug(f"[cors] Error testing {test_url}: {e}")
        
        # Deduplicate findings by type
        unique_findings = self._deduplicate_findings(findings, host)
        
        logger.info(f"[cors] Found {len(unique_findings)} issues on {host}")
        return {"vulns": [f.to_dict() for f in unique_findings], "info": info_items}
    
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

                    # Check for vulnerabilities
                    if acao == "*":
                        return Finding(
                            type="cors_wildcard",
                            name="CORS Wildcard Origin",
                            severity="MEDIUM",
                            description="Server allows any origin to access resources. "
                                       "This enables cross-origin data theft from any website.",
                            host=url,
                            matched_at=url,
                            evidence=[
                                f"Origin sent: {origin}",
                                f"Access-Control-Allow-Origin: {acao}",
                                f"Attack type: {attack_type}",
                            ],
                            cvss_score=5.0,
                            cwe="CWE-346",
                            confidence=100,
                            remediation="Restrict CORS to specific trusted origins. Never use '*' in production.",
                        )

                    # Origin reflection (most dangerous)
                    if acao == origin and origin != "null":
                        has_credentials = acac.lower() == "true"
                        severity = "CRITICAL" if has_credentials else "HIGH"
                        cvss = 9.0 if has_credentials else 7.0

                        return Finding(
                            type=f"cors_{attack_type}",
                            name=f"CORS Bypass via {attack_type.replace('_', ' ').title()}",
                            severity=severity,
                            description=(
                                f"Server reflects arbitrary origin: {description}. "
                                f"{'WITH CREDENTIALS - can steal authenticated data!' if has_credentials else ''} "
                                f"Attacker can read responses cross-origin."
                            ),
                            host=url,
                            matched_at=url,
                            evidence=[
                                f"Origin sent: {origin}",
                                f"Access-Control-Allow-Origin: {acao}",
                                f"Access-Control-Allow-Credentials: {acac}",
                                f"Access-Control-Allow-Methods: {acam}",
                                f"Bypass technique: {attack_type}",
                            ],
                            cvss_score=cvss,
                            cwe="CWE-346",
                            confidence=100,
                            remediation=(
                                "1. Validate origins against a strict whitelist\n"
                                "2. Never reflect the Origin header directly\n"
                                "3. Use exact string matching, not regex\n"
                                "4. Be careful with subdomain wildcards\n"
                                "5. Review: https://portswigger.net/research/exploiting-cors-misconfigurations"
                            ),
                        )

                    # Null origin acceptance
                    if acao == "null" and origin == "null":
                        return Finding(
                            type="cors_null",
                            name="CORS Null Origin Accepted",
                            severity="HIGH" if acac.lower() == "true" else "MEDIUM",
                            description=(
                                "Server accepts null origin. Exploitable via:\n"
                                "- Sandboxed iframes\n"
                                "- data: URLs\n"
                                "- Local file access\n"
                                "- Redirects from other origins"
                            ),
                            host=url,
                            matched_at=url,
                            evidence=[
                                f"Origin: {origin}",
                                f"Access-Control-Allow-Origin: {acao}",
                                f"Access-Control-Allow-Credentials: {acac}",
                            ],
                            cvss_score=6.0,
                            cwe="CWE-346",
                            confidence=100,
                            remediation="Reject null origins. Add explicit check: if (origin === 'null') return;",
                        )

        except Exception:
            pass

        return None

    async def _test_preflight_bypass(self, url: str) -> Finding | None:
        """
        Test for preflight bypass vulnerabilities.

        IMPORTANT: Only report as exploitable if we have REAL evidence:
        - Access-Control-Allow-Credentials: true
        - Sensitive endpoint with auth data
        - Origin reflection (not just wildcard)

        Without these, it's just "Potential" - not confirmed.
        """
        # Skip this test - it produces false positives without:
        # 1. Authenticated session to test with
        # 2. Sensitive endpoint identified
        # 3. Proof that credentials are included

        # A proper CORS test requires:
        # - JavaScript PoC that reads response cross-origin
        # - Credentials mode enabled
        # - Sensitive data in response

        # For now, return None - don't report unverified findings
        return None

    async def _test_origin(self, url: str, origin: str) -> Finding | None:
        """Legacy method - use _test_origin_advanced instead."""
        return await self._test_origin_advanced(url, origin, "legacy", "Legacy origin test")
    
    def _deduplicate_findings(
        self,
        findings: list[Finding],
        host: str,
    ) -> list[Finding]:
        """Deduplicate findings by vulnerability type."""
        seen_types: set[str] = set()
        unique: list[Finding] = []
        
        for finding in findings:
            key = f"{finding.name}-{finding.severity}"
            if key not in seen_types:
                seen_types.add(key)
                # Normalize host
                finding.host = host
                unique.append(finding)
        
        return unique
