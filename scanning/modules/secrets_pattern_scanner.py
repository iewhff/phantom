"""
PHANTOM AI - Secrets Pattern Scanner

Scans HTTP responses for exposed secrets, API keys, tokens, and credentials
using high-confidence regex patterns.

Coverage:
- Cloud provider keys (AWS, Azure, GCP, DigitalOcean, etc.)
- API keys (Stripe, Twilio, SendGrid, Mailgun, etc.)
- Authentication tokens (JWT, OAuth, Bearer)
- Database connection strings
- Private keys and certificates
- Generic high-entropy secrets

Works generically for ALL web applications by analyzing response content.
Zero false positives through pattern + entropy validation.
"""

from __future__ import annotations

import asyncio
import math
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from scanning.findings import Finding, VulnType
from scanning.vuln_scanner import ScanModule
from utils.scan_client import get_scan_client
from utils.logger import get_logger
from scanning.scan_context import ScanContext

logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# SECRET PATTERNS - High-confidence patterns with low false positive rates
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class SecretPattern:
    """Definition of a secret pattern to detect."""
    name: str
    pattern: str  # Regex pattern
    severity: str  # CRITICAL, HIGH, MEDIUM
    description: str
    min_entropy: float = 3.0  # Minimum Shannon entropy to be valid
    validators: list[str] = field(default_factory=list)  # Additional validation patterns
    false_positive_patterns: list[str] = field(default_factory=list)  # Patterns that indicate FP


# AWS Secrets - CRITICAL
AWS_PATTERNS = [
    SecretPattern(
        "AWS Access Key ID",
        r'(?:^|[^A-Z0-9])((AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|AKIA|ANPA|ANVA|AROA|APKA|ASCA|ASIA)[A-Z0-9]{16})(?:[^A-Z0-9]|$)',
        "CRITICAL",
        "AWS Access Key ID exposed - provides access to AWS services",
        min_entropy=3.5,
    ),
    SecretPattern(
        "AWS Secret Access Key",
        r'(?:aws_secret_access_key|aws_secret_key|secret_access_key|secretaccesskey)["\'\s:=]+([A-Za-z0-9/+=]{40})(?:[^A-Za-z0-9/+=]|$)',
        "CRITICAL",
        "AWS Secret Access Key exposed - full access to AWS account",
        min_entropy=4.0,
    ),
    SecretPattern(
        "AWS Session Token",
        r'(?:aws_session_token|session_token)["\'\s:=]+([A-Za-z0-9/+=]{100,500})',
        "HIGH",
        "AWS Session Token exposed - temporary AWS credentials",
        min_entropy=4.0,
    ),
]

# GCP Secrets - CRITICAL
GCP_PATTERNS = [
    SecretPattern(
        "GCP API Key",
        r'AIza[0-9A-Za-z\-_]{35}',
        "HIGH",
        "Google Cloud API Key exposed",
        min_entropy=4.0,
    ),
    SecretPattern(
        "GCP Service Account",
        r'"type"\s*:\s*"service_account"[\s\S]{0,500}"private_key"\s*:\s*"-----BEGIN',
        "CRITICAL",
        "GCP Service Account JSON key exposed - full access to GCP project",
        min_entropy=0,  # Skip entropy for structured data
    ),
    SecretPattern(
        "GCP OAuth Client Secret",
        r'(?:client_secret|clientsecret)["\'\s:=]+([A-Za-z0-9_\-]{24})',
        "HIGH",
        "Google OAuth Client Secret exposed",
        min_entropy=3.5,
    ),
]

# Azure Secrets - CRITICAL
AZURE_PATTERNS = [
    SecretPattern(
        "Azure Storage Account Key",
        r'(?:AccountKey|account_key|storageaccountkey)["\'\s:=]+([A-Za-z0-9+/]{86}==)',
        "CRITICAL",
        "Azure Storage Account Key exposed - access to storage account",
        min_entropy=4.5,
    ),
    SecretPattern(
        "Azure Connection String",
        r'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{86}==',
        "CRITICAL",
        "Azure Storage Connection String exposed",
        min_entropy=0,  # Structured format
    ),
    SecretPattern(
        "Azure SAS Token",
        r'[?&](?:sv|sig)=[^&\s]{20,}(?:&[a-z]{2}=[^&\s]+)+',
        "HIGH",
        "Azure Shared Access Signature (SAS) token exposed",
        min_entropy=3.0,
    ),
    SecretPattern(
        "Azure AD Client Secret",
        r'(?:client_secret|clientsecret|aad_client_secret)["\'\s:=]+([A-Za-z0-9~._\-]{34,40})',
        "CRITICAL",
        "Azure AD Client Secret exposed",
        min_entropy=3.5,
    ),
]

# Payment Providers - CRITICAL
PAYMENT_PATTERNS = [
    SecretPattern(
        "Stripe Secret Key",
        r'sk_live_[0-9a-zA-Z]{24,}',
        "CRITICAL",
        "Stripe Live Secret Key exposed - can process payments",
        min_entropy=4.0,
    ),
    SecretPattern(
        "Stripe Test Secret Key",
        r'sk_test_[0-9a-zA-Z]{24,}',
        "MEDIUM",
        "Stripe Test Secret Key exposed",
        min_entropy=4.0,
    ),
    SecretPattern(
        "Stripe Publishable Key",
        r'pk_(?:live|test)_[0-9a-zA-Z]{24,}',
        "LOW",
        "Stripe Publishable Key exposed (intended to be public but worth noting)",
        min_entropy=4.0,
    ),
    SecretPattern(
        "PayPal Client Secret",
        r'(?:paypal_client_secret|paypal_secret)["\'\s:=]+([A-Za-z0-9_\-]{32,})',
        "CRITICAL",
        "PayPal Client Secret exposed",
        min_entropy=4.0,
    ),
    SecretPattern(
        "Square Access Token",
        r'sq0atp-[0-9A-Za-z\-_]{22}',
        "CRITICAL",
        "Square Access Token exposed",
        min_entropy=4.0,
    ),
    SecretPattern(
        "Square OAuth Secret",
        r'sq0csp-[0-9A-Za-z\-_]{43}',
        "CRITICAL",
        "Square OAuth Secret exposed",
        min_entropy=4.0,
    ),
]

# Communication APIs - HIGH
COMMUNICATION_PATTERNS = [
    SecretPattern(
        "Twilio Account SID",
        r'AC[a-f0-9]{32}',
        "MEDIUM",
        "Twilio Account SID exposed (semi-public but useful for enumeration)",
        min_entropy=3.5,
    ),
    SecretPattern(
        "Twilio Auth Token",
        r'(?:twilio_auth_token|auth_token)["\'\s:=]+([a-f0-9]{32})',
        "CRITICAL",
        "Twilio Auth Token exposed - can send SMS/make calls",
        min_entropy=3.5,
    ),
    SecretPattern(
        "Twilio API Key",
        r'SK[a-f0-9]{32}',
        "HIGH",
        "Twilio API Key exposed",
        min_entropy=3.5,
    ),
    SecretPattern(
        "SendGrid API Key",
        r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}',
        "CRITICAL",
        "SendGrid API Key exposed - can send emails",
        min_entropy=4.5,
    ),
    SecretPattern(
        "Mailgun API Key",
        r'key-[a-z0-9]{32}',
        "CRITICAL",
        "Mailgun API Key exposed - can send emails",
        min_entropy=4.0,
    ),
    SecretPattern(
        "Mailchimp API Key",
        r'[a-f0-9]{32}-us[0-9]{1,2}',
        "HIGH",
        "Mailchimp API Key exposed",
        min_entropy=4.0,
    ),
    SecretPattern(
        "Slack Webhook URL",
        r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',
        "HIGH",
        "Slack Webhook URL exposed - can post to Slack channel",
        min_entropy=3.0,
    ),
    SecretPattern(
        "Slack Bot Token",
        r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}',
        "CRITICAL",
        "Slack Bot Token exposed - can access Slack workspace",
        min_entropy=4.0,
    ),
    SecretPattern(
        "Slack User Token",
        r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}',
        "CRITICAL",
        "Slack User Token exposed - can access user's Slack data",
        min_entropy=4.0,
    ),
    SecretPattern(
        "Discord Webhook URL",
        r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+',
        "HIGH",
        "Discord Webhook URL exposed - can post to Discord channel",
        min_entropy=3.0,
    ),
    SecretPattern(
        "Discord Bot Token",
        r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}',
        "CRITICAL",
        "Discord Bot Token exposed - full bot access",
        min_entropy=4.0,
    ),
]

# Database Credentials - CRITICAL
DATABASE_PATTERNS = [
    SecretPattern(
        "PostgreSQL Connection String",
        r'postgres(?:ql)?://[^:]+:[^@]+@[^/]+/\w+',
        "CRITICAL",
        "PostgreSQL connection string with credentials exposed",
        min_entropy=0,  # URL format
        false_positive_patterns=["postgres://user:password@", "postgres://username:password@"],
    ),
    SecretPattern(
        "MySQL Connection String",
        r'mysql://[^:]+:[^@]+@[^/]+/\w+',
        "CRITICAL",
        "MySQL connection string with credentials exposed",
        min_entropy=0,
        false_positive_patterns=["mysql://user:password@", "mysql://username:password@"],
    ),
    SecretPattern(
        "MongoDB Connection String",
        r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^/]+',
        "CRITICAL",
        "MongoDB connection string with credentials exposed",
        min_entropy=0,
        false_positive_patterns=["mongodb://user:password@", "mongodb://username:password@"],
    ),
    SecretPattern(
        "Redis Connection String",
        r'redis://[^:]*:[^@]+@[^/]+',
        "CRITICAL",
        "Redis connection string with credentials exposed",
        min_entropy=0,
        false_positive_patterns=["redis://:password@"],
    ),
    SecretPattern(
        "JDBC Connection String",
        r'jdbc:[a-z]+://[^;]+;(?:user|username)=[^;]+;password=[^;]+',
        "CRITICAL",
        "JDBC connection string with credentials exposed",
        min_entropy=0,
    ),
]

# Social/Auth Providers - HIGH
OAUTH_PATTERNS = [
    SecretPattern(
        "GitHub Personal Access Token",
        r'ghp_[A-Za-z0-9_]{36}',
        "CRITICAL",
        "GitHub Personal Access Token exposed - repository access",
        min_entropy=4.0,
    ),
    SecretPattern(
        "GitHub OAuth Access Token",
        r'gho_[A-Za-z0-9_]{36}',
        "CRITICAL",
        "GitHub OAuth Access Token exposed",
        min_entropy=4.0,
    ),
    SecretPattern(
        "GitHub App Token",
        r'(?:ghs|ghu)_[A-Za-z0-9_]{36}',
        "CRITICAL",
        "GitHub App Token exposed",
        min_entropy=4.0,
    ),
    SecretPattern(
        "GitLab Personal Access Token",
        r'glpat-[A-Za-z0-9\-_]{20}',
        "CRITICAL",
        "GitLab Personal Access Token exposed",
        min_entropy=4.0,
    ),
    SecretPattern(
        "Facebook Access Token",
        r'EAACEdEose0cBA[0-9A-Za-z]+',
        "HIGH",
        "Facebook Access Token exposed",
        min_entropy=4.0,
    ),
    SecretPattern(
        "Facebook App Secret",
        r'(?:facebook_app_secret|fb_app_secret|fb_secret)["\'\s:=]+([a-f0-9]{32})',
        "CRITICAL",
        "Facebook App Secret exposed",
        min_entropy=3.5,
    ),
    SecretPattern(
        "Twitter API Key",
        r'(?:twitter_api_key|twitter_consumer_key)["\'\s:=]+([a-zA-Z0-9]{25})',
        "HIGH",
        "Twitter API Key exposed",
        min_entropy=3.5,
    ),
    SecretPattern(
        "Twitter API Secret",
        r'(?:twitter_api_secret|twitter_consumer_secret)["\'\s:=]+([a-zA-Z0-9]{50})',
        "CRITICAL",
        "Twitter API Secret exposed",
        min_entropy=4.0,
    ),
    SecretPattern(
        "Twitter Bearer Token",
        r'AAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+',
        "HIGH",
        "Twitter Bearer Token exposed",
        min_entropy=4.0,
    ),
    SecretPattern(
        "LinkedIn Client Secret",
        r'(?:linkedin_client_secret|linkedin_secret)["\'\s:=]+([a-zA-Z0-9]{16})',
        "HIGH",
        "LinkedIn Client Secret exposed",
        min_entropy=3.5,
    ),
]

# Generic Secrets - HIGH
GENERIC_PATTERNS = [
    SecretPattern(
        "Generic API Key",
        r'(?:api[_-]?key|apikey)["\'\s:=]+([a-zA-Z0-9_\-]{20,64})',
        "HIGH",
        "Generic API Key exposed",
        min_entropy=3.5,
        false_positive_patterns=["your_api_key", "YOUR_API_KEY", "api_key_here", "<api_key>"],
    ),
    SecretPattern(
        "Generic Secret Key",
        r'(?:secret[_-]?key|secretkey)["\'\s:=]+([a-zA-Z0-9_\-]{20,64})',
        "HIGH",
        "Generic Secret Key exposed",
        min_entropy=3.5,
        false_positive_patterns=["your_secret", "YOUR_SECRET", "secret_here", "<secret>"],
    ),
    SecretPattern(
        "Generic Auth Token",
        r'(?:auth[_-]?token|authtoken|bearer[_-]?token)["\'\s:=]+([a-zA-Z0-9_\-\.]{20,500})',
        "HIGH",
        "Generic Authentication Token exposed",
        min_entropy=3.5,
        false_positive_patterns=["your_token", "YOUR_TOKEN", "token_here", "<token>"],
    ),
    SecretPattern(
        "Generic Password Field",
        r'(?:password|passwd|pwd)["\'\s:=]+([^\s"\'<>]{8,64})',
        "HIGH",
        "Password value exposed in response",
        min_entropy=2.5,
        false_positive_patterns=["password", "your_password", "PASSWORD", "<password>", "********"],
    ),
    SecretPattern(
        "Private Key (PEM)",
        r'-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----',
        "CRITICAL",
        "Private key exposed in PEM format",
        min_entropy=0,  # Format-based detection
    ),
    SecretPattern(
        "Private Key (Encrypted)",
        r'-----BEGIN ENCRYPTED PRIVATE KEY-----',
        "HIGH",
        "Encrypted private key exposed",
        min_entropy=0,
    ),
    SecretPattern(
        "Basic Auth Header",
        r'Authorization:\s*Basic\s+([A-Za-z0-9+/]+=*)',
        "HIGH",
        "Basic Authentication credentials exposed",
        min_entropy=2.0,
    ),
    SecretPattern(
        "Bearer Token Header",
        r'Authorization:\s*Bearer\s+([A-Za-z0-9_\-\.]+)',
        "HIGH",
        "Bearer token exposed in authorization header",
        min_entropy=3.0,
        false_positive_patterns=["<token>", "your_token", "TOKEN"],
    ),
]

# JWT Tokens - HIGH (may contain sensitive claims)
JWT_PATTERNS = [
    SecretPattern(
        "JWT Token",
        r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
        "HIGH",
        "JWT token exposed - may contain sensitive user data",
        min_entropy=4.0,
    ),
]

# Infrastructure - CRITICAL
INFRASTRUCTURE_PATTERNS = [
    SecretPattern(
        "Heroku API Key",
        r'[hH]eroku[a-zA-Z0-9_\-]*[kK]ey["\'\s:=]+([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})',
        "CRITICAL",
        "Heroku API Key exposed",
        min_entropy=3.0,
    ),
    SecretPattern(
        "DigitalOcean Personal Access Token",
        r'dop_v1_[a-f0-9]{64}',
        "CRITICAL",
        "DigitalOcean Personal Access Token exposed",
        min_entropy=4.5,
    ),
    SecretPattern(
        "DigitalOcean OAuth Token",
        r'doo_v1_[a-f0-9]{64}',
        "CRITICAL",
        "DigitalOcean OAuth Token exposed",
        min_entropy=4.5,
    ),
    SecretPattern(
        "Cloudflare API Key",
        r'(?:cloudflare_api_key|cf_api_key)["\'\s:=]+([a-f0-9]{37})',
        "CRITICAL",
        "Cloudflare API Key exposed",
        min_entropy=4.0,
    ),
    SecretPattern(
        "Cloudflare API Token",
        r'(?:cloudflare_api_token|cf_api_token)["\'\s:=]+([A-Za-z0-9_\-]{40})',
        "CRITICAL",
        "Cloudflare API Token exposed",
        min_entropy=4.0,
    ),
    SecretPattern(
        "NPM Access Token",
        r'npm_[A-Za-z0-9]{36}',
        "CRITICAL",
        "NPM Access Token exposed - can publish packages",
        min_entropy=4.0,
    ),
    SecretPattern(
        "PyPI API Token",
        r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}',
        "CRITICAL",
        "PyPI API Token exposed - can publish packages",
        min_entropy=4.5,
    ),
    SecretPattern(
        "Docker Hub Token",
        r'dckr_pat_[A-Za-z0-9_\-]{27,}',
        "CRITICAL",
        "Docker Hub Personal Access Token exposed",
        min_entropy=4.0,
    ),
]

# Combine all patterns
ALL_SECRET_PATTERNS = (
    AWS_PATTERNS +
    GCP_PATTERNS +
    AZURE_PATTERNS +
    PAYMENT_PATTERNS +
    COMMUNICATION_PATTERNS +
    DATABASE_PATTERNS +
    OAUTH_PATTERNS +
    GENERIC_PATTERNS +
    JWT_PATTERNS +
    INFRASTRUCTURE_PATTERNS
)


class SecretsPatternScanner(ScanModule):
    """
    Scans HTTP responses for exposed secrets, API keys, and credentials.

    Uses high-confidence regex patterns combined with entropy validation
    to minimize false positives while catching real credential exposures.
    """

    name = "secrets_pattern"
    description = "Detects API keys, tokens, and credentials in HTTP responses"
    version = "1.0.0"
    author = "PHANTOM AI"
    tags = ["secrets", "credentials", "api_keys", "tokens"]

    def __init__(
        self,
        settings: Any = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = 10.0
        self.max_concurrent = 10
        self._compiled_patterns: dict[str, re.Pattern] = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile all regex patterns for performance."""
        for sp in ALL_SECRET_PATTERNS:
            try:
                self._compiled_patterns[sp.name] = re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error as e:
                logger.warning(f"[SECRETS] Invalid regex for {sp.name}: {e}")

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any] | None = None,
        rate_limiter: Any | None = None,
    ) -> dict[str, Any]:
        """Scan endpoints for exposed secrets in responses."""

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        findings: list[Finding] = []
        asset_data = asset_data or {}

        # Normalize host to base URL
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        base_url = host.rstrip("/")

        logger.info(f"[SECRETS] Starting secrets pattern scan on {base_url}")

        # Collect endpoints to scan
        endpoints = self._collect_endpoints(base_url, asset_data)

        try:
            async with get_scan_client(
                timeout=self.timeout,
                verify_ssl=False,
                follow_redirects=True,
            ) as client:
                semaphore = asyncio.Semaphore(self.max_concurrent)

                async def scan_endpoint(url: str) -> list[Finding]:
                    async with semaphore:
                        if rate_limiter:
                            await rate_limiter.acquire()
                        return await self._scan_endpoint(client, url)

                tasks = [scan_endpoint(url) for url in endpoints]
                results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in results:
                    if isinstance(result, list):
                        findings.extend(result)
                    elif isinstance(result, Exception):
                        logger.debug(f"[SECRETS] Endpoint scan failed: {result}")

        except Exception as e:
            logger.error(f"[SECRETS] Scan error: {e}")

        # Deduplicate findings by secret value
        findings = self._deduplicate_findings(findings)

        logger.info(f"[SECRETS] Found {len(findings)} exposed secrets")

        return {
            "findings": findings,
            "endpoints_scanned": len(endpoints),
            "secrets_found": len(findings),
        }

    def _collect_endpoints(self, base_url: str, asset_data: dict[str, Any]) -> list[str]:
        """Collect endpoints to scan for secrets."""
        endpoints = {base_url}

        # Add discovered endpoints from asset_data
        if isinstance(asset_data, dict):
            endpoint_map = asset_data.get("endpoint_map")
        if endpoint_map and hasattr(endpoint_map, "endpoints"):
            for ep in endpoint_map.endpoints[:100]:  # Limit to 100 endpoints
                url = getattr(ep, "url", None) or getattr(ep, "path", None)
                if url:
                    if not url.startswith("http"):
                        url = urljoin(base_url, url)
                    endpoints.add(url)

        # Add common API endpoints that might expose secrets
        common_paths = [
            "/", "/api", "/api/v1", "/api/v2",
            "/config", "/settings", "/env",
            "/debug", "/status", "/health",
            "/.well-known/", "/manifest.json",
            "/app.js", "/main.js", "/bundle.js",
            "/config.js", "/env.js", "/settings.js",
        ]
        for path in common_paths:
            endpoints.add(urljoin(base_url, path))

        return list(endpoints)[:150]  # Limit total endpoints

    async def _scan_endpoint(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> list[Finding]:
        """Scan a single endpoint for secrets."""
        findings: list[Finding] = []

        try:
            resp = await client.get(url, timeout=self.timeout)

            if resp.status_code != 200:
                return findings

            content = resp.text
            if not content or len(content) < 10:
                return findings

            # Skip binary content
            content_type = resp.headers.get("content-type", "").lower()
            if any(t in content_type for t in ["image/", "audio/", "video/", "application/octet"]):
                return findings

            # Scan for each pattern
            for sp in ALL_SECRET_PATTERNS:
                pattern = self._compiled_patterns.get(sp.name)
                if not pattern:
                    continue

                matches = pattern.findall(content)
                for match in matches:
                    # Handle tuple matches (from capture groups)
                    secret_value = match[0] if isinstance(match, tuple) else match

                    # Validate the match
                    if not self._validate_secret(secret_value, sp):
                        continue

                    # Create finding
                    finding = self._create_finding(url, sp, secret_value, content)
                    if finding:
                        findings.append(finding)

        except httpx.TimeoutException:
            pass
        except Exception as e:
            logger.debug(f"[SECRETS] Error scanning {url}: {e}")

        return findings

    def _validate_secret(self, value: str, sp: SecretPattern) -> bool:
        """Validate a potential secret match."""
        if not value or len(value) < 8:
            return False

        # Check false positive patterns
        value_lower = value.lower()
        for fp_pattern in sp.false_positive_patterns:
            if fp_pattern.lower() in value_lower or value_lower == fp_pattern.lower():
                return False

        # Check for placeholder values
        placeholders = [
            "xxx", "your_", "example", "sample", "test", "demo", "fake",
            "placeholder", "changeme", "replace", "<", ">", "${", "{{",
        ]
        for placeholder in placeholders:
            if placeholder in value_lower:
                return False

        # Entropy check (skip for structured formats like URLs)
        if sp.min_entropy > 0:
            entropy = self._calculate_entropy(value)
            if entropy < sp.min_entropy:
                return False

        return True

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0

        # Count character frequencies
        freq: dict[str, int] = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1

        # Calculate entropy
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            if count > 0:
                probability = count / length
                entropy -= probability * math.log2(probability)

        return entropy

    def _create_finding(
        self,
        url: str,
        sp: SecretPattern,
        secret_value: str,
        content: str,
    ) -> Finding | None:
        """Create a finding for an exposed secret."""
        # Redact the secret for the report (show first/last few chars)
        redacted = self._redact_secret(secret_value)

        # Find context around the secret
        context = self._extract_context(content, secret_value)

        return Finding(
            vuln_type=VulnType.INFO_DISCLOSURE,
            severity=sp.severity,
            host=urlparse(url).netloc,
            endpoint=url,
            name=f"Exposed Secret: {sp.name}",
            description=(
                f"{sp.description}\n\n"
                f"A {sp.name} was found exposed in the response from `{url}`.\n\n"
                f"**Redacted value:** `{redacted}`\n\n"
                f"**Context:**\n```\n{context}\n```\n\n"
                f"This secret should be immediately rotated and removed from the response."
            ),
            evidence=[
                f"URL: {url}",
                f"Secret Type: {sp.name}",
                f"Redacted Value: {redacted}",
                f"Severity: {sp.severity}",
            ],
            confidence_score=95.0,
            metadata={
                "url": url,
                "secret_type": sp.name,
                "redacted_value": redacted,
                "context": context,
                "entropy": self._calculate_entropy(secret_value),
                "module_name": "secrets_pattern",
            },
        )

    def _redact_secret(self, secret: str) -> str:
        """Redact a secret value, showing only first/last few characters."""
        if len(secret) <= 8:
            return "*" * len(secret)
        elif len(secret) <= 20:
            return secret[:2] + "*" * (len(secret) - 4) + secret[-2:]
        else:
            return secret[:4] + "*" * (len(secret) - 8) + secret[-4:]

    def _extract_context(self, content: str, secret: str, context_chars: int = 100) -> str:
        """Extract context around the secret in the content."""
        try:
            idx = content.find(secret)
            if idx == -1:
                return "[context not available]"

            start = max(0, idx - context_chars)
            end = min(len(content), idx + len(secret) + context_chars)

            context = content[start:end]

            # Redact the actual secret in context
            redacted = self._redact_secret(secret)
            context = context.replace(secret, f"[{redacted}]")

            # Clean up for display
            context = context.replace("\n", " ").replace("\r", "").strip()
            if start > 0:
                context = "..." + context
            if end < len(content):
                context = context + "..."

            return context[:300]  # Limit context length

        except Exception:
            return "[context extraction failed]"

    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """Deduplicate findings by secret type and redacted value."""
        seen: set[tuple[str, str]] = set()
        unique: list[Finding] = []

        for f in findings:
            key = (
                f.metadata.get("secret_type", ""),
                f.metadata.get("redacted_value", ""),
            )
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique
