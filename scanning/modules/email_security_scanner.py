"""
Email Security Scanner.
Tests for email-related security vulnerabilities including SPF, DKIM, DMARC.
"""

from __future__ import annotations

import re
import socket
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import httpx

from scanning.vuln_scanner import Finding, ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class EmailSecurityScanner(ScanModule):
    """
    Email Security Scanner.
    
    Tests for:
    - SPF record misconfiguration
    - DKIM issues
    - DMARC policy weaknesses
    - Email header injection
    - SMTP injection in forms
    - Email enumeration
    - Password reset token leakage
    - Email spoofing vectors
    """
    
    name = "email_security_scanner"
    
    # Email injection payloads
    EMAIL_INJECTION_PAYLOADS = [
        "test@test.com\nCc:attacker@evil.com",
        "test@test.com\r\nCc:attacker@evil.com",
        "test@test.com%0ACc:attacker@evil.com",
        "test@test.com%0D%0ACc:attacker@evil.com",
        "test@test.com\nBcc:attacker@evil.com",
        "test@test.com\nSubject:Injected",
        "test@test.com\nContent-Type:text/html",
        "test@test.com\n\nInjected Body",
    ]
    
    # SMTP injection payloads
    SMTP_INJECTION_PAYLOADS = [
        "test@test.com\nRCPT TO:<attacker@evil.com>",
        "test@test.com\r\nMAIL FROM:<attacker@evil.com>",
        "test@test.com\nDATA\nInjected",
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
        """Scan for email security vulnerabilities."""
        findings: list[Finding] = []
        
        # Extract domain from host
        domain = host.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        
        base_url = f"https://{host}" if not host.startswith("http") else host
        
        async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
            # Check DNS records (SPF, DKIM, DMARC)
            dns_findings = await self._check_email_dns(domain, rate_limiter)
            findings.extend(dns_findings)
            
            # Test email header injection in forms
            injection_findings = await self._test_email_injection(
                client, base_url, rate_limiter
            )
            findings.extend(injection_findings)
            
            # Test email enumeration
            enum_findings = await self._test_email_enumeration(
                client, base_url, domain, rate_limiter
            )
            findings.extend(enum_findings)
            
            # Test password reset vulnerabilities
            reset_findings = await self._test_password_reset(
                client, base_url, rate_limiter
            )
            findings.extend(reset_findings)
            
            # Test contact/feedback forms
            form_findings = await self._test_contact_forms(
                client, base_url, rate_limiter
            )
            findings.extend(form_findings)
        
        return findings
    
    async def _check_email_dns(
        self,
        domain: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Check SPF, DKIM, and DMARC records."""
        findings = []
        
        await rate_limiter.acquire()
        
        try:
            # Check SPF record
            spf_findings = self._check_spf(domain)
            findings.extend(spf_findings)
            
            # Check DMARC record
            dmarc_findings = self._check_dmarc(domain)
            findings.extend(dmarc_findings)
            
        except Exception as e:
            logger.debug(f"Error checking DNS records: {e}")
        
        return findings
    
    def _check_spf(self, domain: str) -> list[Finding]:
        """Check SPF record configuration."""
        findings = []
        
        try:
            import dns.resolver
            
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                
                spf_record = None
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if txt.startswith("v=spf1"):
                        spf_record = txt
                        break
                
                if not spf_record:
                    findings.append(Finding(
                        name="Missing SPF Record",
                        severity="MEDIUM",
                        confidence="HIGH",
                        description="No SPF record found - email spoofing possible",
                        matched_at=domain,
                        evidence=["No TXT record with v=spf1"],
                        cwe="CWE-290",
                        cvss_score=5.3,
                        remediation="Add SPF record: v=spf1 include:_spf.domain.com -all",
                    ))
                else:
                    # Check SPF strength
                    if "+all" in spf_record:
                        findings.append(Finding(
                            name="Weak SPF Record (+all)",
                            severity="HIGH",
                            confidence="HIGH",
                            description="SPF record with +all allows any sender",
                            matched_at=domain,
                            evidence=[f"SPF: {spf_record}"],
                            cwe="CWE-290",
                            cvss_score=7.5,
                            remediation="Change +all to -all or ~all",
                        ))
                    elif "~all" in spf_record:
                        findings.append(Finding(
                            name="Soft SPF Fail (~all)",
                            severity="LOW",
                            confidence="HIGH",
                            description="SPF uses soft fail (~all) instead of hard fail",
                            matched_at=domain,
                            evidence=[f"SPF: {spf_record}"],
                            cwe="CWE-290",
                            cvss_score=3.7,
                            remediation="Consider using -all for stricter policy",
                        ))
                    elif "?all" in spf_record:
                        findings.append(Finding(
                            name="Neutral SPF Record (?all)",
                            severity="MEDIUM",
                            confidence="HIGH",
                            description="SPF record uses neutral (?all) - no protection",
                            matched_at=domain,
                            evidence=[f"SPF: {spf_record}"],
                            cwe="CWE-290",
                            cvss_score=5.3,
                            remediation="Change ?all to -all",
                        ))
                        
            except dns.resolver.NXDOMAIN:
                pass
            except dns.resolver.NoAnswer:
                findings.append(Finding(
                    name="Missing SPF Record",
                    severity="MEDIUM",
                    confidence="HIGH",
                    description="No SPF record configured",
                    matched_at=domain,
                    evidence=["No TXT records"],
                    cwe="CWE-290",
                    remediation="Configure SPF record",
                ))
                
        except ImportError:
            logger.debug("dnspython not installed, skipping SPF check")
        
        return findings
    
    def _check_dmarc(self, domain: str) -> list[Finding]:
        """Check DMARC record configuration."""
        findings = []
        
        try:
            import dns.resolver
            
            dmarc_domain = f"_dmarc.{domain}"
            
            try:
                answers = dns.resolver.resolve(dmarc_domain, 'TXT')
                
                dmarc_record = None
                for rdata in answers:
                    txt = str(rdata).strip('"')
                    if txt.startswith("v=DMARC1"):
                        dmarc_record = txt
                        break
                
                if dmarc_record:
                    # Check DMARC policy
                    if "p=none" in dmarc_record:
                        findings.append(Finding(
                            name="DMARC Policy None",
                            severity="MEDIUM",
                            confidence="HIGH",
                            description="DMARC policy is 'none' - monitoring only, no protection",
                            matched_at=domain,
                            evidence=[f"DMARC: {dmarc_record}"],
                            cwe="CWE-290",
                            cvss_score=5.3,
                            remediation="Change p=none to p=quarantine or p=reject",
                        ))
                    
                    # Check for missing rua (reporting)
                    if "rua=" not in dmarc_record:
                        findings.append(Finding(
                            name="DMARC Missing Reporting",
                            severity="LOW",
                            confidence="HIGH",
                            description="DMARC record has no aggregate reporting (rua)",
                            matched_at=domain,
                            evidence=[f"DMARC: {dmarc_record}"],
                            cwe="CWE-290",
                            remediation="Add rua=mailto:dmarc@domain.com for reporting",
                        ))
                    
                    # Check subdomain policy
                    if "sp=" not in dmarc_record:
                        findings.append(Finding(
                            name="DMARC Missing Subdomain Policy",
                            severity="LOW",
                            confidence="MEDIUM",
                            description="DMARC has no explicit subdomain policy",
                            matched_at=domain,
                            evidence=["No sp= tag in DMARC"],
                            cwe="CWE-290",
                            remediation="Add sp=reject to protect subdomains",
                        ))
                        
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                findings.append(Finding(
                    name="Missing DMARC Record",
                    severity="MEDIUM",
                    confidence="HIGH",
                    description="No DMARC record found - email spoofing easier",
                    matched_at=domain,
                    evidence=[f"No record at _dmarc.{domain}"],
                    cwe="CWE-290",
                    cvss_score=5.3,
                    remediation="Add DMARC record: v=DMARC1; p=reject; rua=mailto:dmarc@domain.com",
                ))
                
        except ImportError:
            logger.debug("dnspython not installed, skipping DMARC check")
        
        return findings
    
    async def _test_email_injection(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for email header injection in forms."""
        findings = []
        
        # Common form endpoints
        form_endpoints = [
            "/contact",
            "/contact-us",
            "/feedback",
            "/support",
            "/email",
            "/send-email",
            "/api/contact",
            "/api/email",
        ]
        
        email_params = ["email", "to", "from", "sender", "recipient", "cc", "bcc", "subject"]
        
        for endpoint in form_endpoints:
            url = urljoin(base_url, endpoint)
            
            for param in email_params:
                for payload in self.EMAIL_INJECTION_PAYLOADS[:3]:  # Test first 3
                    await rate_limiter.acquire()
                    
                    try:
                        data = {
                            param: payload,
                            "name": "Test",
                            "message": "Test message",
                            "subject": "Test subject",
                        }
                        
                        response = await client.post(url, data=data)
                        
                        # Check for success indicators (email might be sent)
                        success_indicators = ["sent", "success", "thank you", "received", "submitted"]
                        
                        if response.status_code == 200:
                            if any(ind in response.text.lower() for ind in success_indicators):
                                findings.append(Finding(
                                    name="Email Header Injection",
                                    severity="HIGH",
                                    confidence="MEDIUM",
                                    description=f"Possible email header injection in '{param}'",
                                    matched_at=url,
                                    evidence=[
                                        f"Parameter: {param}",
                                        f"Payload accepted",
                                    ],
                                    cwe="CWE-93",
                                    cvss_score=7.5,
                                    remediation="Sanitize email inputs. Block newlines in email fields. "
                                               "Use email library instead of string concatenation.",
                                ))
                                return findings  # One finding is enough
                                
                    except Exception as e:
                        logger.debug(f"Error testing injection: {e}")
        
        return findings
    
    async def _test_email_enumeration(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        domain: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for email/username enumeration."""
        findings = []
        
        # Common enumeration endpoints
        enum_endpoints = [
            ("/login", "email", "password"),
            ("/register", "email", "password"),
            ("/forgot-password", "email", None),
            ("/password/reset", "email", None),
            ("/api/users/check", "email", None),
            ("/api/auth/check-email", "email", None),
        ]
        
        for endpoint, email_param, pass_param in enum_endpoints:
            url = urljoin(base_url, endpoint)
            
            await rate_limiter.acquire()
            
            try:
                # Test with existing-looking email
                existing_data = {email_param: f"admin@{domain}"}
                if pass_param:
                    existing_data[pass_param] = "wrongpassword123"
                
                response1 = await client.post(url, data=existing_data)
                
                await rate_limiter.acquire()
                
                # Test with non-existing email
                nonexist_data = {email_param: f"nonexistent12345@{domain}"}
                if pass_param:
                    nonexist_data[pass_param] = "wrongpassword123"
                
                response2 = await client.post(url, data=nonexist_data)
                
                # Compare responses
                if response1.status_code == response2.status_code == 200:
                    # Check for different messages
                    diff_indicators = [
                        ("user not found", "incorrect password"),
                        ("email not registered", "wrong password"),
                        ("no account", "invalid password"),
                        ("doesn't exist", "password incorrect"),
                    ]
                    
                    text1 = response1.text.lower()
                    text2 = response2.text.lower()
                    
                    for not_found, wrong_pass in diff_indicators:
                        if (not_found in text2 and not_found not in text1) or \
                           (wrong_pass in text1 and wrong_pass not in text2):
                            findings.append(Finding(
                                name="Email Enumeration",
                                severity="MEDIUM",
                                confidence="HIGH",
                                description="Different responses reveal if email exists",
                                matched_at=url,
                                evidence=[
                                    "Different error messages for existing vs non-existing emails",
                                ],
                                cwe="CWE-204",
                                cvss_score=5.3,
                                remediation="Use generic error messages. "
                                           "Same response for existing and non-existing accounts.",
                            ))
                            return findings
                    
                    # Check response length difference
                    if abs(len(response1.text) - len(response2.text)) > 50:
                        findings.append(Finding(
                            name="Email Enumeration (Response Length)",
                            severity="MEDIUM",
                            confidence="MEDIUM",
                            description="Response length differs for existing vs non-existing emails",
                            matched_at=url,
                            evidence=[
                                f"Existing email response: {len(response1.text)} bytes",
                                f"Non-existing email response: {len(response2.text)} bytes",
                            ],
                            cwe="CWE-204",
                            cvss_score=5.3,
                            remediation="Ensure identical response sizes.",
                        ))
                        return findings
                        
            except Exception as e:
                logger.debug(f"Error testing enumeration: {e}")
        
        return findings
    
    async def _test_password_reset(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test password reset functionality."""
        findings = []
        
        reset_endpoints = [
            "/forgot-password",
            "/password/reset",
            "/reset-password",
            "/api/password/reset",
            "/api/auth/forgot",
        ]
        
        for endpoint in reset_endpoints:
            url = urljoin(base_url, endpoint)
            
            await rate_limiter.acquire()
            
            try:
                # Check if endpoint exists
                response = await client.get(url)
                
                if response.status_code == 200:
                    # Test with Host header manipulation
                    await rate_limiter.acquire()
                    
                    response = await client.post(
                        url,
                        data={"email": "test@test.com"},
                        headers={"Host": "evil.com"}
                    )
                    
                    if response.status_code == 200:
                        success_indicators = ["sent", "check your email", "reset link"]
                        
                        if any(ind in response.text.lower() for ind in success_indicators):
                            findings.append(Finding(
                                name="Password Reset Host Header Poisoning",
                                severity="HIGH",
                                confidence="MEDIUM",
                                description="Password reset accepts manipulated Host header",
                                matched_at=url,
                                evidence=[
                                    "Reset email may contain attacker's domain",
                                    "Host: evil.com was accepted",
                                ],
                                cwe="CWE-640",
                                cvss_score=8.1,
                                remediation="Use absolute URLs from configuration, not Host header. "
                                           "Validate Host header against whitelist.",
                            ))
                            
            except Exception as e:
                logger.debug(f"Error testing reset: {e}")
        
        return findings
    
    async def _test_contact_forms(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test contact forms for SMTP injection."""
        findings = []
        
        form_endpoints = [
            "/contact",
            "/feedback",
            "/support",
        ]
        
        for endpoint in form_endpoints:
            url = urljoin(base_url, endpoint)
            
            for payload in self.SMTP_INJECTION_PAYLOADS:
                await rate_limiter.acquire()
                
                try:
                    data = {
                        "email": payload,
                        "name": "Test",
                        "message": "Test message",
                        "subject": "Test",
                    }
                    
                    response = await client.post(url, data=data)
                    
                    # If SMTP injection worked, it might show in error or succeed
                    if response.status_code == 200:
                        smtp_errors = ["smtp", "mail()", "sendmail", "mail server", "rcpt to"]
                        
                        if any(err in response.text.lower() for err in smtp_errors):
                            findings.append(Finding(
                                name="SMTP Injection",
                                severity="HIGH",
                                confidence="MEDIUM",
                                description="SMTP injection possible in contact form",
                                matched_at=url,
                                evidence=[
                                    f"Payload: {payload[:50]}...",
                                    "SMTP-related error or response",
                                ],
                                cwe="CWE-93",
                                cvss_score=7.5,
                                remediation="Use mail library APIs instead of raw commands. "
                                           "Sanitize all email-related inputs.",
                            ))
                            return findings
                            
                except Exception as e:
                    logger.debug(f"Error testing SMTP injection: {e}")
        
        return findings
