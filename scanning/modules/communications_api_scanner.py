"""
Communications API Security Scanner - Twilio/SMS/Voice Focused

Specialized scanner for communications platforms (Twilio, SendGrid, Authy, etc.)
targeting high-value vulnerabilities specific to telecom/messaging APIs.

Research-Based Attack Vectors:
- Phone Number Enumeration (CVE-2024-39891 pattern)
- SMS Pumping / Toll Fraud (IRSF) Detection
- Authentication Bypass (CVE-2020-24655 null injection pattern)
- Twilio Credential Exposure (Account SID, Auth Token)
- SMS Verification Abuse Endpoints
- Premium Rate Number Injection
- Voice API Abuse Vectors

CWE Coverage:
- CWE-200: Information Exposure (phone enumeration)
- CWE-307: Improper Restriction of Excessive Authentication Attempts
- CWE-770: Allocation of Resources Without Limits (SMS pumping)
- CWE-287: Improper Authentication
- CWE-798: Use of Hard-coded Credentials
- CWE-639: Authorization Bypass Through User-Controlled Key

Author: PHANTOM AI
Version: 1.0.0
"""

from __future__ import annotations

import re
import json
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field

import httpx

from scanning.findings import Finding, Severity
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


# Twilio-specific patterns for credential detection
TWILIO_PATTERNS = {
    "account_sid": re.compile(r'AC[a-f0-9]{32}', re.IGNORECASE),
    "auth_token": re.compile(r'[a-f0-9]{32}', re.IGNORECASE),
    "api_key": re.compile(r'SK[a-f0-9]{32}', re.IGNORECASE),
    "api_secret": re.compile(r'[a-zA-Z0-9]{32}'),
    "phone_number": re.compile(r'\+?[1-9]\d{1,14}'),
}

# SendGrid patterns
SENDGRID_PATTERNS = {
    "api_key": re.compile(r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}'),
}

# Known vulnerable endpoint patterns (based on historical CVEs)
PHONE_ENUM_ENDPOINTS = [
    "/authy/users/new",
    "/protected/json/users/new",
    "/protected/json/users/{phone}/status",
    "/v1/users/registration/start",
    "/v1/users/registration/verify",
    "/verify/lookup",
    "/lookup/phone",
    "/api/phone/check",
    "/api/v1/phone/validate",
    "/api/verify/start",
    "/users/exists",
    "/account/phone/check",
]

# SMS/Voice endpoints that could be abused for toll fraud
SMS_ABUSE_ENDPOINTS = [
    "/Messages.json",
    "/Calls.json",
    "/2010-04-01/Accounts/{sid}/Messages.json",
    "/2010-04-01/Accounts/{sid}/Calls.json",
    "/api/sms/send",
    "/api/voice/call",
    "/v1/Messages",
    "/v1/Calls",
    "/verify/v1/Services/{service}/Verifications",
    "/v2/Services/{service}/Verifications",
]

# Premium rate number prefixes (IRSF targets)
PREMIUM_RATE_PREFIXES = [
    "+882",   # International Networks
    "+883",   # International Networks
    "+808",   # Shared Cost
    "+870",   # Inmarsat
    "+878",   # Universal Personal Telecommunications
    "+881",   # Global Mobile Satellite
    "+979",   # International Premium Rate
]


@dataclass
class CommunicationsEndpoint:
    """Discovered communications API endpoint."""
    url: str
    method: str
    endpoint_type: str  # sms, voice, verify, lookup, auth
    parameters: list[str] = field(default_factory=list)
    requires_auth: bool = True
    risk_level: str = "medium"


class CommunicationsAPIScanner(ScanModule):
    """
    Communications API Security Scanner.

    Targets high-value vulnerabilities in Twilio, SendGrid, Authy,
    and similar communications platforms.

    Focus areas (based on historical CVEs and bounty payouts):
    1. Phone Number Enumeration (CVE-2024-39891) - HIGH VALUE
    2. SMS Pumping / Toll Fraud - CRITICAL VALUE
    3. Credential Exposure - HIGH VALUE
    4. Authentication Bypass - CRITICAL VALUE
    5. Rate Limit Bypass on Verify - HIGH VALUE
    """

    name = "communications_api_scanner"

    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
        self.discovered_endpoints: list[CommunicationsEndpoint] = []

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Main scan entry point."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings: list[Finding] = []

        base_url = f"https://{host}" if not host.startswith("http") else host
        parsed = urlparse(base_url)

        # Check if this is a communications platform target
        is_twilio_target = self._is_communications_target(parsed.netloc)

        if not is_twilio_target:
            logger.debug(f"Skipping non-communications target: {host}")
            return findings

        logger.info(f"[COMMS] Scanning communications API: {base_url}")

        async with httpx.AsyncClient(
            verify=False,
            timeout=self.timeout,
            follow_redirects=True
        ) as client:

            # 1. Phone Number Enumeration (CVE-2024-39891 pattern)
            enum_findings = await self._test_phone_enumeration(
                client, base_url, rate_limiter
            )
            findings.extend(enum_findings)

            # 2. Credential Exposure in Responses
            cred_findings = await self._test_credential_exposure(
                client, base_url, rate_limiter
            )
            findings.extend(cred_findings)

            # 3. SMS/Voice Endpoint Abuse Detection
            abuse_findings = await self._test_sms_abuse_endpoints(
                client, base_url, rate_limiter
            )
            findings.extend(abuse_findings)

            # 4. Authentication Bypass (null injection pattern)
            auth_findings = await self._test_auth_bypass(
                client, base_url, rate_limiter
            )
            findings.extend(auth_findings)

            # 5. Verify Rate Limit Bypass
            verify_findings = await self._test_verify_rate_limit(
                client, base_url, rate_limiter
            )
            findings.extend(verify_findings)

            # 6. API Documentation Exposure
            docs_findings = await self._test_api_docs_exposure(
                client, base_url, rate_limiter
            )
            findings.extend(docs_findings)

        return findings

    def _is_communications_target(self, hostname: str) -> bool:
        """Check if target is a communications platform."""
        comm_domains = [
            "twilio.com",
            "sendgrid.com",
            "sendgrid.net",
            "authy.com",
            "segment.io",
            "segment.com",
        ]

        hostname_lower = hostname.lower()
        return any(domain in hostname_lower for domain in comm_domains)

    async def _test_phone_enumeration(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for phone number enumeration vulnerabilities.

        CVE-2024-39891 Pattern: API returns different responses for
        registered vs unregistered phone numbers, allowing enumeration
        without authentication.
        """
        findings = []

        # Test known vulnerable endpoint patterns
        for endpoint_template in PHONE_ENUM_ENDPOINTS:
            endpoint = endpoint_template.replace("{phone}", "+15551234567")
            url = urljoin(base_url, endpoint)

            await rate_limiter.acquire()

            try:
                # Test with two different phone numbers
                test_numbers = ["+15551234567", "+15559876543"]
                responses = []

                for phone in test_numbers:
                    test_url = url.replace("+15551234567", phone)

                    # Try GET first
                    response = await client.get(test_url)

                    if response.status_code == 404:
                        # Try POST with phone in body
                        response = await client.post(
                            url.split("{")[0] if "{" in url else url,
                            json={"phone": phone, "phone_number": phone}
                        )

                    responses.append({
                        "phone": phone,
                        "status": response.status_code,
                        "length": len(response.content),
                        "body": response.text[:500]
                    })

                    await rate_limiter.acquire()

                # Analyze response differences
                if len(responses) == 2:
                    r1, r2 = responses

                    # Check for enumeration indicators
                    enumeration_detected = False
                    evidence = []

                    # Different status codes
                    if r1["status"] != r2["status"]:
                        enumeration_detected = True
                        evidence.append(
                            f"Status codes differ: {r1['status']} vs {r2['status']}"
                        )

                    # Significant content length difference (>20%)
                    if r1["length"] > 0 and r2["length"] > 0:
                        diff_pct = abs(r1["length"] - r2["length"]) / max(r1["length"], r2["length"])
                        if diff_pct > 0.2:
                            enumeration_detected = True
                            evidence.append(
                                f"Response sizes differ: {r1['length']} vs {r2['length']} bytes"
                            )

                    # Check for enumeration keywords in responses
                    enum_keywords = [
                        "not found", "not registered", "invalid phone",
                        "user exists", "already registered", "phone taken"
                    ]

                    for keyword in enum_keywords:
                        if keyword in r1["body"].lower() and keyword not in r2["body"].lower():
                            enumeration_detected = True
                            evidence.append(f"Keyword '{keyword}' in one response only")
                            break

                    if enumeration_detected and r1["status"] not in [401, 403]:
                        findings.append(Finding(
                            name="Phone Number Enumeration",
                            severity=Severity.HIGH,
                            confidence_score=85.0,
                            description=(
                                "API endpoint reveals phone number registration status. "
                                "This is similar to CVE-2024-39891 which affected Twilio Authy "
                                "and led to enumeration of 33M phone numbers."
                            ),
                            endpoint=url,
                            evidence=evidence,
                            cwe_id="CWE-200",
                            cvss_score=7.5,
                            remediation=(
                                "Return identical responses regardless of phone status. "
                                "Use generic messages like 'If this number is registered, "
                                "a verification code will be sent.' Implement rate limiting."
                            ),
                        ))
                        break  # One finding is enough

            except httpx.HTTPError as e:
                logger.debug(f"Error testing phone enumeration at {url}: {e}")
            except Exception as e:
                logger.debug(f"Unexpected error in phone enumeration test: {e}")

        return findings

    async def _test_credential_exposure(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for Twilio/SendGrid credential exposure in responses.

        Look for Account SID, Auth Token, API Keys in:
        - Error messages
        - Debug responses
        - Configuration endpoints
        """
        findings = []

        exposure_endpoints = [
            "/",
            "/api",
            "/api/v1",
            "/debug",
            "/config",
            "/status",
            "/health",
            "/.env",
            "/config.json",
            "/settings",
            "/api/settings",
            "/account",
            "/api/account",
        ]

        for endpoint in exposure_endpoints:
            url = urljoin(base_url, endpoint)

            await rate_limiter.acquire()

            try:
                response = await client.get(url)
                content = response.text

                # Check for Twilio credentials
                for cred_type, pattern in TWILIO_PATTERNS.items():
                    matches = pattern.findall(content)

                    if matches and cred_type in ["account_sid", "api_key"]:
                        # Account SID starts with AC, API Key with SK
                        for match in matches:
                            if (cred_type == "account_sid" and match.startswith("AC")) or \
                               (cred_type == "api_key" and match.startswith("SK")):
                                findings.append(Finding(
                                    name=f"Twilio {cred_type.replace('_', ' ').title()} Exposure",
                                    severity=Severity.CRITICAL,
                                    confidence_score=85.0,
                                    description=(
                                        f"Twilio {cred_type} found in API response. "
                                        "This credential can be used to access the Twilio account, "
                                        "send SMS/calls, and potentially incur toll fraud charges."
                                    ),
                                    endpoint=url,
                                    evidence=[
                                        f"Found: {match[:8]}...{match[-4:]}",
                                        f"Endpoint: {endpoint}",
                                    ],
                                    cwe_id="CWE-798",
                                    cvss_score=9.8,
                                    remediation=(
                                        "Remove credentials from responses immediately. "
                                        "Rotate the exposed credentials. "
                                        "Review code for credential logging."
                                    ),
                                ))
                                return findings  # Critical finding, stop here

                # Check for SendGrid API Key
                for match in SENDGRID_PATTERNS["api_key"].findall(content):
                    findings.append(Finding(
                        name="SendGrid API Key Exposure",
                        severity=Severity.CRITICAL,
                        confidence_score=85.0,
                        description=(
                            "SendGrid API key found in response. "
                            "This can be used to send emails as the account owner."
                        ),
                        endpoint=url,
                        evidence=[
                            f"Found: SG.{match[3:10]}...{match[-4:]}",
                        ],
                        cwe_id="CWE-798",
                        cvss_score=9.1,
                        remediation="Rotate API key immediately. Remove from response.",
                    ))
                    return findings

            except Exception as e:
                logger.debug(f"Error testing credential exposure at {url}: {e}")

        return findings

    async def _test_sms_abuse_endpoints(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for unprotected SMS/Voice endpoints vulnerable to abuse.

        SMS Pumping / Toll Fraud (IRSF) is a major concern for Twilio.
        Check for endpoints that:
        - Accept SMS/call requests without proper authentication
        - Don't validate destination numbers against premium rates
        - Lack rate limiting
        """
        findings = []

        # Test SMS endpoint accessibility
        for endpoint_template in SMS_ABUSE_ENDPOINTS:
            # Replace placeholders with test values
            endpoint = endpoint_template.replace("{sid}", "AC_TEST").replace("{service}", "VA_TEST")
            url = urljoin(base_url, endpoint)

            await rate_limiter.acquire()

            try:
                # Test OPTIONS to see what's available
                options_response = await client.options(url)

                # Test GET
                get_response = await client.get(url)

                # Check if endpoint is accessible without auth
                if get_response.status_code in [200, 201, 400]:
                    # 400 might mean we need parameters but endpoint exists

                    # Check if it mentions authentication in error
                    content = get_response.text.lower()

                    if get_response.status_code == 200:
                        findings.append(Finding(
                            name="Unprotected SMS/Voice API Endpoint",
                            severity=Severity.HIGH,
                            confidence_score=85.0,
                            description=(
                                "SMS/Voice API endpoint accessible without authentication. "
                                "This could enable SMS pumping (IRSF) attacks causing "
                                "significant financial damage via premium rate fraud."
                            ),
                            endpoint=url,
                            evidence=[
                                f"Status: {get_response.status_code}",
                                f"Endpoint: {endpoint}",
                                "No authentication required",
                            ],
                            cwe_id="CWE-287",
                            cvss_score=8.6,
                            remediation=(
                                "Require authentication for all SMS/Voice endpoints. "
                                "Implement destination number validation. "
                                "Block premium rate number prefixes."
                            ),
                        ))

                    elif "unauthorized" not in content and "authentication" not in content:
                        if "to" in content or "from" in content or "body" in content:
                            # Endpoint returns parameter hints - exists but may need params
                            findings.append(Finding(
                                name="SMS/Voice Endpoint Parameter Exposure",
                                severity=Severity.MEDIUM,
                                confidence_score=65.0,
                                description=(
                                    "SMS/Voice endpoint reveals parameter information. "
                                    "This aids in understanding the API structure for abuse."
                                ),
                                endpoint=url,
                                evidence=[
                                    f"Status: {get_response.status_code}",
                                    "Parameter hints in response",
                                ],
                                cwe_id="CWE-200",
                                cvss_score=5.3,
                                remediation="Return generic error messages.",
                            ))

            except Exception as e:
                logger.debug(f"Error testing SMS endpoint at {url}: {e}")

        return findings

    async def _test_auth_bypass(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for authentication bypass vulnerabilities.

        CVE-2020-24655 Pattern: Authy Android app PIN bypass via @null injection.
        Test similar patterns across auth endpoints.
        """
        findings = []

        auth_endpoints = [
            "/login",
            "/auth",
            "/api/auth",
            "/api/login",
            "/verify/check",
            "/api/verify",
            "/protected/json/users/authenticate",
        ]

        # Bypass payloads (safe, non-destructive)
        bypass_payloads = [
            {"pin": "@null", "code": "@null"},
            {"pin": "null", "code": "null"},
            {"pin": "", "code": ""},
            {"pin": "0", "code": "0"},
            {"pin": "000000", "code": "000000"},
            {"token": "@null"},
            {"token": ""},
            {"otp": "@null"},
        ]

        for endpoint in auth_endpoints:
            url = urljoin(base_url, endpoint)

            await rate_limiter.acquire()

            try:
                # First check if endpoint exists
                check = await client.get(url)
                if check.status_code == 404:
                    continue

                # Test bypass payloads
                for payload in bypass_payloads:
                    await rate_limiter.acquire()

                    response = await client.post(url, json=payload)

                    # Check for successful bypass indicators
                    if response.status_code in [200, 201, 302]:
                        content = response.text.lower()

                        # Check for success indicators
                        success_indicators = [
                            "success", "authenticated", "token", "session",
                            "welcome", "dashboard", "access_token"
                        ]

                        for indicator in success_indicators:
                            if indicator in content:
                                findings.append(Finding(
                                    name="Authentication Bypass via Null Injection",
                                    severity=Severity.CRITICAL,
                                    confidence_score=85.0,
                                    description=(
                                        "Authentication bypassed using null/empty value injection. "
                                        "This is similar to CVE-2020-24655 which affected Authy."
                                    ),
                                    endpoint=url,
                                    evidence=[
                                        f"Payload: {json.dumps(payload)}",
                                        f"Status: {response.status_code}",
                                        f"Success indicator: '{indicator}'",
                                    ],
                                    cwe_id="CWE-287",
                                    cvss_score=9.8,
                                    remediation=(
                                        "Validate all authentication inputs. "
                                        "Reject null, empty, and special values. "
                                        "Implement proper type checking."
                                    ),
                                ))
                                return findings  # Critical, stop immediately

            except Exception as e:
                logger.debug(f"Error testing auth bypass at {url}: {e}")

        return findings

    async def _test_verify_rate_limit(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for rate limit bypass on verification endpoints.

        Weak rate limiting on verify endpoints enables:
        - OTP brute force
        - Account enumeration
        - SMS pumping attacks
        """
        findings = []

        verify_endpoints = [
            "/verify",
            "/api/verify",
            "/v1/verify",
            "/verify/start",
            "/api/verify/start",
            "/verification/start",
        ]

        for endpoint in verify_endpoints:
            url = urljoin(base_url, endpoint)

            await rate_limiter.acquire()

            try:
                # Check if endpoint exists
                check = await client.get(url)
                if check.status_code == 404:
                    continue

                # Send multiple verification requests
                success_count = 0
                rate_limited = False

                for i in range(10):
                    await rate_limiter.acquire()

                    response = await client.post(
                        url,
                        json={
                            "phone": f"+1555000{i:04d}",
                            "phone_number": f"+1555000{i:04d}",
                            "channel": "sms"
                        }
                    )

                    if response.status_code == 429:
                        rate_limited = True
                        break
                    elif response.status_code in [200, 201, 400]:
                        # 400 might mean invalid params but endpoint works
                        success_count += 1

                if not rate_limited and success_count >= 8:
                    findings.append(Finding(
                        name="Missing Rate Limit on Verification Endpoint",
                        severity=Severity.HIGH,
                        confidence_score=85.0,
                        description=(
                            "Verification endpoint lacks rate limiting, enabling "
                            "SMS pumping attacks and potential toll fraud. "
                            "Attackers can trigger mass SMS delivery to premium numbers."
                        ),
                        endpoint=url,
                        evidence=[
                            f"{success_count} requests without throttling",
                            "SMS pumping (IRSF) attack possible",
                            "Twilio Fraud Guard saved $62.7M from such attacks",
                        ],
                        cwe_id="CWE-770",
                        cvss_score=7.5,
                        remediation=(
                            "Implement strict rate limiting per IP and phone number. "
                            "Use Twilio Fraud Guard. "
                            "Block known premium rate number prefixes."
                        ),
                    ))
                    break

            except Exception as e:
                logger.debug(f"Error testing verify rate limit at {url}: {e}")

        return findings

    async def _test_api_docs_exposure(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for exposed API documentation that reveals internal endpoints.
        """
        findings = []

        doc_endpoints = [
            "/swagger.json",
            "/openapi.json",
            "/api-docs",
            "/swagger-ui.html",
            "/docs",
            "/redoc",
            "/api/docs",
            "/v1/docs",
            "/graphql",  # GraphQL introspection
        ]

        for endpoint in doc_endpoints:
            url = urljoin(base_url, endpoint)

            await rate_limiter.acquire()

            try:
                response = await client.get(url)

                if response.status_code == 200:
                    content = response.text

                    # Check for OpenAPI/Swagger indicators
                    if any(kw in content for kw in ["openapi", "swagger", "paths", "schemas"]):
                        # Count exposed endpoints
                        paths_match = re.findall(r'"(/[^"]+)":\s*\{', content)

                        findings.append(Finding(
                            name="API Documentation Exposure",
                            severity=Severity.MEDIUM,
                            confidence_score=85.0,
                            description=(
                                "API documentation publicly accessible, revealing "
                                "internal endpoint structure and parameters."
                            ),
                            endpoint=url,
                            evidence=[
                                f"Documentation type: {'OpenAPI' if 'openapi' in content else 'Swagger'}",
                                f"Endpoints exposed: {len(paths_match)}",
                            ],
                            cwe_id="CWE-200",
                            cvss_score=5.3,
                            remediation="Restrict API documentation to authenticated users.",
                        ))
                        break

                    # Check for GraphQL introspection
                    if endpoint == "/graphql":
                        introspection_query = {
                            "query": "{ __schema { types { name } } }"
                        }

                        await rate_limiter.acquire()

                        gql_response = await client.post(url, json=introspection_query)

                        if gql_response.status_code == 200 and "__schema" in gql_response.text:
                            findings.append(Finding(
                                name="GraphQL Introspection Enabled",
                                severity=Severity.MEDIUM,
                                confidence_score=85.0,
                                description=(
                                    "GraphQL introspection is enabled, allowing "
                                    "full schema discovery including hidden mutations."
                                ),
                                endpoint=url,
                                evidence=[
                                    "Introspection query successful",
                                    "Full schema exposed",
                                ],
                                cwe_id="CWE-200",
                                cvss_score=5.3,
                                remediation="Disable introspection in production.",
                            ))

            except Exception as e:
                logger.debug(f"Error testing API docs at {url}: {e}")

        return findings


# Export for module registration
__all__ = ["CommunicationsAPIScanner"]
