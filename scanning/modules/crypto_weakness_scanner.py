"""
Cryptographic Weakness Scanner v1.0

Detects weak or insecure cryptographic implementations:
- Weak hashing algorithms (MD5, SHA1 for passwords)
- Insecure encryption (DES, 3DES, RC4, ECB mode)
- Weak JWT algorithms (none, HS256 with weak secret)
- Hardcoded keys/IVs/secrets
- Insecure random number generation
- Weak password hashing (unsalted, weak algorithms)
- Padding oracle vulnerabilities
- Certificate/TLS issues
- Key derivation weaknesses

MEDIUM Priority - 2-3 days effort

CWE Coverage:
- CWE-327: Use of Broken Crypto Algorithm
- CWE-328: Reversible One-Way Hash
- CWE-330: Use of Insufficiently Random Values
- CWE-331: Insufficient Entropy
- CWE-916: Use of Password Hash With Insufficient Computational Effort
- CWE-347: Improper Verification of Cryptographic Signature
- CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- CWE-757: Selection of Less-Secure Algorithm During Negotiation

Bug Bounty Value: $500 - $5,000 for critical crypto weaknesses
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin

import httpx

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.http_client import create_protected_client, get_configured_ssl_verify
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)

CRYPTO_SCANNER_VERSION = "1.0.0"


class CryptoVulnType(Enum):
    """Types of cryptographic vulnerabilities."""
    WEAK_HASH = auto()              # MD5, SHA1 for passwords
    WEAK_ENCRYPTION = auto()        # DES, 3DES, RC4, ECB
    WEAK_JWT = auto()               # alg:none, weak secret
    HARDCODED_SECRET = auto()       # Hardcoded keys/IVs
    WEAK_RANDOM = auto()            # Predictable random
    WEAK_PASSWORD_HASH = auto()     # Unsalted, weak algo
    PADDING_ORACLE = auto()         # CBC padding oracle
    WEAK_TLS = auto()               # Weak cipher suites
    KEY_DERIVATION = auto()         # Weak KDF
    INSECURE_COMPARISON = auto()    # Timing-safe comparison missing


@dataclass
class CryptoEndpoint:
    """Endpoint that uses cryptography."""
    url: str
    crypto_type: str  # "hash", "encrypt", "jwt", "password", "random"
    detected_algorithms: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)


@dataclass
class CryptoTestResult:
    """Result of a cryptographic security test."""
    vulnerable: bool
    vuln_type: CryptoVulnType
    confidence: int  # 0-100
    algorithm: str
    evidence: list[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    cwe: str = "CWE-327"
    payload: str = ""
    response_data: str = ""


# Common weak hash patterns
WEAK_HASH_PATTERNS = {
    "md5": [
        r"[a-f0-9]{32}",  # MD5 hex
        r"md5\s*\(",
        r"MD5\s*\(",
        r'"hash_type":\s*"md5"',
        r"algorithm[\"']?\s*[:=]\s*[\"']?md5",
    ],
    "sha1": [
        r"[a-f0-9]{40}",  # SHA1 hex
        r"sha1\s*\(",
        r"SHA1\s*\(",
        r'"hash_type":\s*"sha1"',
        r"algorithm[\"']?\s*[:=]\s*[\"']?sha1",
    ],
}

# Weak password hash patterns (should use bcrypt, scrypt, argon2)
WEAK_PASSWORD_HASH_PATTERNS = {
    "unsalted_md5": r"^[a-f0-9]{32}$",
    "unsalted_sha1": r"^[a-f0-9]{40}$",
    "unsalted_sha256": r"^[a-f0-9]{64}$",
    "mysql_old": r"^\*[A-F0-9]{40}$",  # MySQL old password
    "mysql_new": r"^\$mysql\$[A-Za-z0-9./=+]+$",
    "des_crypt": r"^[a-zA-Z0-9./]{13}$",  # DES crypt
    "plaintext_base64": r"^[A-Za-z0-9+/]{4,}={0,2}$",  # Might be base64 plaintext
}

# Strong password hash prefixes (for comparison)
STRONG_PASSWORD_HASH_PATTERNS = {
    "bcrypt": r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$",
    "scrypt": r"^\$scrypt\$",
    "argon2": r"^\$argon2(i|d|id)\$",
    "pbkdf2": r"^\$pbkdf2-sha(256|512)\$",
}

# Hardcoded secret patterns
HARDCODED_SECRET_PATTERNS = [
    # Keys
    r'["\']?(api[_-]?key|apikey)["\']?\s*[:=]\s*["\']?[A-Za-z0-9]{16,}["\']?',
    r'["\']?(secret[_-]?key|secretkey)["\']?\s*[:=]\s*["\']?[A-Za-z0-9]{16,}["\']?',
    r'["\']?(private[_-]?key)["\']?\s*[:=]\s*["\']?[A-Za-z0-9+/=]{20,}["\']?',
    r'["\']?(encryption[_-]?key)["\']?\s*[:=]\s*["\']?[A-Za-z0-9+/=]{16,}["\']?',

    # AWS
    r'AKIA[0-9A-Z]{16}',  # AWS Access Key
    r'["\']?aws_secret_access_key["\']?\s*[:=]\s*["\']?[A-Za-z0-9+/]{40}["\']?',

    # JWT secrets
    r'jwt[_-]?secret\s*[:=]\s*["\']?[A-Za-z0-9+/=]{16,}["\']?',

    # IVs (often hardcoded wrongly)
    r'["\']?(iv|initialization[_-]?vector)["\']?\s*[:=]\s*["\']?[A-Za-z0-9+/=]{16,}["\']?',

    # Database credentials
    r'["\']?(db_password|database_password|mysql_password|postgres_password)["\']?\s*[:=]\s*["\']?[^"\'\s]{8,}["\']?',

    # Generic secrets
    r'["\']?password["\']?\s*[:=]\s*["\']?(?!.*\*)[A-Za-z0-9!@#$%^&*]{8,}["\']?',
]

# JWT weak algorithm patterns
JWT_WEAK_ALGORITHMS = {
    "none": {
        "description": "No signature verification",
        "severity": "CRITICAL",
        "cwe": "CWE-347",
    },
    "HS256": {
        "description": "Symmetric algorithm - may have weak secret",
        "severity": "MEDIUM",
        "cwe": "CWE-327",
    },
    "RS256_with_HS256": {
        "description": "Algorithm confusion attack possible",
        "severity": "HIGH",
        "cwe": "CWE-347",
    },
}

# Common weak JWT secrets to test
WEAK_JWT_SECRETS = [
    "secret",
    "password",
    "123456",
    "jwt_secret",
    "jwt-secret",
    "your-secret-key",
    "your_secret_key",
    "supersecret",
    "changeme",
    "key",
    "private",
    "hmac_secret",
]


class CryptoWeaknessScanner(ScanModule):
    """
    Scanner for cryptographic weaknesses and misconfigurations.

    Focus areas:
    1. Weak hashing in password storage
    2. JWT algorithm vulnerabilities
    3. Hardcoded secrets in responses
    4. Weak encryption algorithms
    5. TLS/SSL weaknesses
    6. Padding oracle attacks
    """

    name = "crypto_weakness_scanner"
    version = CRYPTO_SCANNER_VERSION
    category = "crypto"

    def __init__(
        self,
        settings: Any = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.findings: list[dict[str, Any]] = []
        self.crypto_endpoints: list[CryptoEndpoint] = []
        self._ssl_verify = get_configured_ssl_verify()

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any] | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> dict[str, Any]:
        """Execute cryptographic weakness scan."""
        asset_data = asset_data or {}

        # SCAN CONTEXT
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        self.findings = []
        self.crypto_endpoints = []

        base_url = f"https://{host}" if not host.startswith("http") else host
        urls = asset_data.get("urls", [])
        cookies = asset_data.get("cookies", [])
        tokens = asset_data.get("tokens", {})

        logger.info(f"Crypto Weakness Scanner v{self.version} starting on {host}")

        client = create_protected_client(
            timeout=30.0,
            verify_ssl=self._ssl_verify,
            follow_redirects=True,
            custom_headers=self._auth_headers,
        )

        async with client:
            # Phase 1: Analyze existing tokens (JWTs, session tokens)
            await self._analyze_tokens(tokens, cookies, base_url)

            # Phase 2: Test JWT algorithm vulnerabilities
            await self._test_jwt_weaknesses(client, base_url, tokens, rate_limiter)

            # Phase 3: Scan for hardcoded secrets in responses
            await self._scan_hardcoded_secrets(client, base_url, urls, rate_limiter)

            # Phase 4: Detect weak password hashing
            await self._detect_weak_password_hash(client, base_url, rate_limiter)

            # Phase 5: Test for padding oracle
            await self._test_padding_oracle(client, base_url, cookies, rate_limiter)

            # Phase 6: Check TLS configuration
            await self._check_tls_config(host)

            # Phase 7: Test for weak random number generation
            await self._test_weak_random(client, base_url, rate_limiter)

        logger.info(f"Crypto scan complete. Found {len(self.findings)} vulnerabilities")

        return {
            "module": self.name,
            "version": self.version,
            "findings": self.findings,
            "crypto_endpoints": [
                {
                    "url": ep.url,
                    "crypto_type": ep.crypto_type,
                    "algorithms": ep.detected_algorithms,
                }
                for ep in self.crypto_endpoints
            ],
        }

    async def _analyze_tokens(
        self,
        tokens: dict[str, Any],
        cookies: list[dict[str, Any]],
        base_url: str,
    ) -> None:
        """Analyze existing tokens for cryptographic weaknesses."""
        logger.debug("Phase 1: Analyzing tokens for crypto weaknesses")

        # Check JWTs in tokens
        jwt_sources = []

        # From token dict
        for key, value in tokens.items():
            if isinstance(value, str) and self._is_jwt(value):
                jwt_sources.append(("token", key, value))

        # From cookies
        for cookie in cookies:
            if isinstance(cookie, dict):
                value = cookie.get("value", "")
                name = cookie.get("name", "")
            else:
                continue

            if self._is_jwt(value):
                jwt_sources.append(("cookie", name, value))

        # Analyze each JWT
        for source_type, name, jwt_value in jwt_sources:
            analysis = self._analyze_jwt(jwt_value)

            if analysis.get("weak_algorithm"):
                result = CryptoTestResult(
                    vulnerable=True,
                    vuln_type=CryptoVulnType.WEAK_JWT,
                    confidence_score=85,
                    algorithm=analysis.get("algorithm", "unknown"),
                    evidence=[
                        f"JWT found in {source_type}: {name}",
                        f"Algorithm: {analysis.get('algorithm')}",
                        f"Issue: {analysis.get('issue', 'Weak algorithm')}",
                    ],
                    severity=analysis.get("severity", "MEDIUM"),
                    cwe_id="CWE-347",
                )

                self._add_finding(
                    name=f"Weak JWT Algorithm ({analysis.get('algorithm')})",
                    description=(
                        f"JWT token uses weak algorithm '{analysis.get('algorithm')}'. "
                        f"Issue: {analysis.get('issue', 'Algorithm may be vulnerable')}"
                    ),
                    endpoint=base_url,
                    result=result,
                )

    def _is_jwt(self, value: str) -> bool:
        """Check if a value looks like a JWT."""
        if not value:
            return False

        parts = value.split(".")
        if len(parts) != 3:
            return False

        # Check if parts are base64-like
        for part in parts[:2]:  # Header and payload
            try:
                # JWT uses URL-safe base64
                padding = 4 - len(part) % 4
                if padding != 4:
                    part += "=" * padding
                base64.urlsafe_b64decode(part)
            except Exception:
                return False

        return True

    def _analyze_jwt(self, jwt_value: str) -> dict[str, Any]:
        """Analyze a JWT for weaknesses."""
        result = {
            "valid": False,
            "algorithm": None,
            "weak_algorithm": False,
            "issue": None,
            "severity": "INFO",
        }

        try:
            parts = jwt_value.split(".")
            if len(parts) != 3:
                return result

            # Decode header
            header_b64 = parts[0]
            padding = 4 - len(header_b64) % 4
            if padding != 4:
                header_b64 += "=" * padding

            header = json.loads(base64.urlsafe_b64decode(header_b64))
            result["valid"] = True

            alg = header.get("alg", "").upper()
            result["algorithm"] = alg

            # Check for weak algorithms
            if alg == "NONE" or alg == "":
                result["weak_algorithm"] = True
                result["issue"] = "No signature verification - anyone can forge tokens"
                result["severity"] = "CRITICAL"

            elif alg in ["HS256", "HS384", "HS512"]:
                result["weak_algorithm"] = True
                result["issue"] = "Symmetric algorithm - secret may be brute-forceable"
                result["severity"] = "MEDIUM"

            elif alg in ["RS256", "RS384", "RS512"]:
                # Check for algorithm confusion potential
                if "kid" not in header:
                    result["issue"] = "No key ID - may be vulnerable to algorithm confusion"
                    result["severity"] = "LOW"

            # Decode payload for additional checks
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding

            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # Check expiration
            exp = payload.get("exp")
            if exp:
                import time
                if exp < time.time():
                    result["issue"] = (result.get("issue", "") + "; Token is expired").strip("; ")
                elif exp > time.time() + 86400 * 365:  # > 1 year
                    result["issue"] = (result.get("issue", "") + "; Excessive expiration time").strip("; ")
                    result["weak_algorithm"] = True
                    result["severity"] = "LOW"

            return result

        except Exception as e:
            logger.debug(f"JWT analysis error: {e}")
            return result

    async def _test_jwt_weaknesses(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        tokens: dict[str, Any],
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Test for JWT algorithm vulnerabilities."""
        logger.debug("Phase 2: Testing JWT weaknesses")

        # Find endpoints that might accept JWTs
        jwt_endpoints = [
            "/api/auth/verify",
            "/api/token/verify",
            "/api/user",
            "/api/profile",
            "/api/me",
            "/api/account",
            "/graphql",
        ]

        # Get existing JWT from tokens
        existing_jwt = None
        for key, value in tokens.items():
            if isinstance(value, str) and self._is_jwt(value):
                existing_jwt = value
                break

        if not existing_jwt:
            return

        # Test 1: Algorithm None attack
        await self._test_jwt_alg_none(client, base_url, existing_jwt, jwt_endpoints, rate_limiter)

        # Test 2: Weak secret brute force
        await self._test_jwt_weak_secret(client, base_url, existing_jwt, jwt_endpoints, rate_limiter)

    async def _test_jwt_alg_none(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        original_jwt: str,
        endpoints: list[str],
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Test for JWT algorithm=none vulnerability."""
        try:
            parts = original_jwt.split(".")
            if len(parts) != 3:
                return

            # Decode original header and payload
            header_b64 = parts[0]
            payload_b64 = parts[1]

            padding = 4 - len(header_b64) % 4
            if padding != 4:
                header_b64 += "=" * padding

            header = json.loads(base64.urlsafe_b64decode(header_b64))
            original_alg = header.get("alg")

            # Create none algorithm token
            header["alg"] = "none"
            new_header = base64.urlsafe_b64encode(
                json.dumps(header).encode()
            ).decode().rstrip("=")

            # Token with no signature
            none_token = f"{new_header}.{payload_b64}."

            # Test on endpoints
            for endpoint in endpoints[:5]:
                if rate_limiter:
                    await rate_limiter.acquire()

                url = urljoin(base_url, endpoint)

                try:
                    # Test with none token
                    headers = {"Authorization": f"Bearer {none_token}"}
                    response = await client.get(url, headers=headers)

                    # Check if accepted (200 with user data)
                    if response.status_code == 200:
                        body = response.text.lower()
                        if any(x in body for x in ["user", "email", "profile", "account", "id"]):
                            result = CryptoTestResult(
                                vulnerable=True,
                                vuln_type=CryptoVulnType.WEAK_JWT,
                                confidence_score=95,
                                algorithm="none",
                                evidence=[
                                    f"Original algorithm: {original_alg}",
                                    "Server accepts alg=none tokens",
                                    f"Tested endpoint: {url}",
                                    "Any user can forge valid tokens",
                                ],
                                severity=Severity.CRITICAL,
                                cwe_id="CWE-347",
                                payload=none_token[:50] + "...",
                            )

                            self._add_finding(
                                name="JWT Algorithm None Accepted",
                                description=(
                                    "Server accepts JWT tokens with algorithm='none'. "
                                    "This allows any attacker to forge valid tokens without "
                                    "knowing the secret key."
                                ),
                                endpoint=url,
                                result=result,
                            )
                            return  # One finding is enough

                except Exception as e:
                    logger.debug(f"JWT none test error: {e}")

        except Exception as e:
            logger.debug(f"JWT none attack setup error: {e}")

    async def _test_jwt_weak_secret(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        original_jwt: str,
        endpoints: list[str],
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Test for weak JWT secrets using common passwords."""
        try:
            parts = original_jwt.split(".")
            if len(parts) != 3:
                return

            # Get algorithm
            header_b64 = parts[0]
            padding = 4 - len(header_b64) % 4
            if padding != 4:
                header_b64 += "=" * padding

            header = json.loads(base64.urlsafe_b64decode(header_b64))
            alg = header.get("alg", "").upper()

            if alg not in ["HS256", "HS384", "HS512"]:
                return  # Only test symmetric algorithms

            # Get payload
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding

            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # Test weak secrets
            import hmac

            hash_algs = {
                "HS256": hashlib.sha256,
                "HS384": hashlib.sha384,
                "HS512": hashlib.sha512,
            }

            hash_func = hash_algs.get(alg)
            if not hash_func:
                return

            signing_input = f"{parts[0]}.{parts[1]}"

            for weak_secret in WEAK_JWT_SECRETS:
                # Create signature with weak secret
                signature = hmac.new(
                    weak_secret.encode(),
                    signing_input.encode(),
                    hash_func
                ).digest()

                sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")
                test_token = f"{signing_input}.{sig_b64}"

                # Test on endpoint
                if endpoints:
                    if rate_limiter:
                        await rate_limiter.acquire()

                    url = urljoin(base_url, endpoints[0])

                    try:
                        headers = {"Authorization": f"Bearer {test_token}"}
                        response = await client.get(url, headers=headers)

                        if response.status_code == 200:
                            body = response.text.lower()
                            if any(x in body for x in ["user", "email", "profile"]):
                                result = CryptoTestResult(
                                    vulnerable=True,
                                    vuln_type=CryptoVulnType.WEAK_JWT,
                                    confidence_score=90,
                                    algorithm=alg,
                                    evidence=[
                                        f"Algorithm: {alg}",
                                        f"Weak secret found: '{weak_secret}'",
                                        "Attacker can forge valid tokens",
                                    ],
                                    severity=Severity.HIGH,
                                    cwe_id="CWE-327",
                                )

                                self._add_finding(
                                    name="JWT Weak Secret",
                                    description=(
                                        f"JWT uses weak secret '{weak_secret}'. "
                                        "Attackers can forge valid tokens using this secret."
                                    ),
                                    endpoint=base_url,
                                    result=result,
                                )
                                return

                    except Exception:
                        pass

        except Exception as e:
            logger.debug(f"JWT weak secret test error: {e}")

    async def _scan_hardcoded_secrets(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Scan responses for hardcoded secrets."""
        logger.debug("Phase 3: Scanning for hardcoded secrets")

        # Endpoints likely to leak secrets
        secret_endpoints = [
            "/config",
            "/settings",
            "/.env",
            "/env",
            "/debug",
            "/api/config",
            "/api/settings",
            "/js/config.js",
            "/js/app.js",
            "/static/js/main.js",
            "/build/static/js/main.*.js",
            "/__webpack_hmr",
            "/source-map",
        ]

        all_urls = list(set(secret_endpoints + urls[:20]))

        for url_path in all_urls:
            if rate_limiter:
                await rate_limiter.acquire()

            url = urljoin(base_url, url_path) if not url_path.startswith("http") else url_path

            try:
                response = await client.get(url)

                if response.status_code == 200:
                    body = response.text

                    # Check for hardcoded secrets
                    for pattern in HARDCODED_SECRET_PATTERNS:
                        matches = re.findall(pattern, body, re.IGNORECASE)

                        if matches:
                            # Filter out false positives
                            real_secrets = []
                            for match in matches[:5]:
                                if isinstance(match, tuple):
                                    match = match[0] if match else ""

                                # Skip common false positives
                                if match and len(match) > 8:
                                    if not any(fp in match.lower() for fp in [
                                        "example", "sample", "placeholder", "your_",
                                        "xxx", "changeme", "todo", "fixme"
                                    ]):
                                        real_secrets.append(match[:50])

                            if real_secrets:
                                result = CryptoTestResult(
                                    vulnerable=True,
                                    vuln_type=CryptoVulnType.HARDCODED_SECRET,
                                    confidence_score=75,
                                    algorithm="N/A",
                                    evidence=[
                                        f"Found potential secret in: {url}",
                                        f"Pattern: {pattern[:50]}...",
                                        f"Matches (partial): {real_secrets}",
                                    ],
                                    severity=Severity.HIGH,
                                    cwe_id="CWE-798",  # Hardcoded credentials
                                )

                                self._add_finding(
                                    name="Hardcoded Secret Detected",
                                    description=(
                                        "Response contains what appears to be hardcoded secrets. "
                                        "This may include API keys, encryption keys, or credentials."
                                    ),
                                    endpoint=url,
                                    result=result,
                                )
                                break  # One finding per URL

            except Exception as e:
                logger.debug(f"Secret scan error for {url}: {e}")

    async def _detect_weak_password_hash(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Detect weak password hashing in responses."""
        logger.debug("Phase 4: Detecting weak password hashing")

        # Endpoints that might leak password hashes
        hash_endpoints = [
            "/api/users",
            "/api/user",
            "/api/accounts",
            "/admin/users",
            "/debug/users",
            "/export/users",
            "/backup",
        ]

        for endpoint in hash_endpoints:
            if rate_limiter:
                await rate_limiter.acquire()

            url = urljoin(base_url, endpoint)

            try:
                response = await client.get(url)

                if response.status_code == 200:
                    body = response.text

                    # Look for hash patterns
                    for hash_name, pattern in WEAK_PASSWORD_HASH_PATTERNS.items():
                        matches = re.findall(pattern, body)

                        if matches:
                            # Verify it's not a strong hash
                            is_strong = False
                            for strong_pattern in STRONG_PASSWORD_HASH_PATTERNS.values():
                                if any(re.match(strong_pattern, m) for m in matches):
                                    is_strong = True
                                    break

                            if not is_strong:
                                result = CryptoTestResult(
                                    vulnerable=True,
                                    vuln_type=CryptoVulnType.WEAK_PASSWORD_HASH,
                                    confidence_score=70,
                                    algorithm=hash_name,
                                    evidence=[
                                        f"Weak password hash format detected: {hash_name}",
                                        f"Found in: {url}",
                                        f"Sample (partial): {matches[0][:20]}...",
                                        "Should use bcrypt, scrypt, or argon2",
                                    ],
                                    severity=Severity.HIGH,
                                    cwe_id="CWE-916",
                                )

                                self._add_finding(
                                    name=f"Weak Password Hash ({hash_name})",
                                    description=(
                                        f"Response contains password hashes using weak algorithm: {hash_name}. "
                                        "Modern applications should use bcrypt, scrypt, or argon2."
                                    ),
                                    endpoint=url,
                                    result=result,
                                )
                                break

            except Exception as e:
                logger.debug(f"Password hash detection error: {e}")

    async def _test_padding_oracle(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        cookies: list[dict[str, Any]],
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Test for padding oracle vulnerabilities."""
        logger.debug("Phase 5: Testing for padding oracle")

        # Find encrypted cookies/tokens
        encrypted_values = []

        for cookie in cookies:
            if isinstance(cookie, dict):
                name = cookie.get("name", "")
                value = cookie.get("value", "")

                # Check if value looks like encrypted data (base64 with specific length)
                if len(value) >= 32 and len(value) % 4 == 0:
                    try:
                        decoded = base64.b64decode(value)
                        # Likely CBC encrypted if length is multiple of 16
                        if len(decoded) >= 16 and len(decoded) % 16 == 0:
                            encrypted_values.append((name, value, "cookie"))
                    except Exception:
                        pass

        for name, value, source in encrypted_values[:3]:
            if rate_limiter:
                await rate_limiter.acquire()

            # Test padding oracle by modifying last block
            try:
                decoded = base64.b64decode(value)

                # Flip a bit in the last byte (padding byte)
                modified = bytearray(decoded)
                modified[-1] ^= 0x01
                modified_b64 = base64.b64encode(bytes(modified)).decode()

                # Send request with modified value
                cookies_dict = {name: modified_b64}

                response = await client.get(base_url, cookies=cookies_dict)

                # Check for padding error indicators
                padding_errors = [
                    "padding", "decrypt", "invalid", "corrupt",
                    "bad data", "pkcs", "block", "cipher"
                ]

                body_lower = response.text.lower()
                error_found = any(err in body_lower for err in padding_errors)

                # Different response for invalid padding is a sign
                if error_found or response.status_code == 500:
                    result = CryptoTestResult(
                        vulnerable=True,
                        vuln_type=CryptoVulnType.PADDING_ORACLE,
                        confidence_score=65,
                        algorithm="CBC (suspected)",
                        evidence=[
                            f"Encrypted {source}: {name}",
                            "Modified padding caused different response",
                            f"Status: {response.status_code}",
                            "May allow decryption via padding oracle attack",
                        ],
                        severity=Severity.HIGH,
                        cwe_id="CWE-649",  # Reliance on Obfuscation
                    )

                    self._add_finding(
                        name="Potential Padding Oracle",
                        description=(
                            f"Encrypted {source} '{name}' may be vulnerable to padding oracle attack. "
                            "Server returns different errors for invalid vs valid padding."
                        ),
                        endpoint=base_url,
                        result=result,
                    )

            except Exception as e:
                logger.debug(f"Padding oracle test error: {e}")

    async def _check_tls_config(self, host: str) -> None:
        """Check TLS configuration for weaknesses."""
        logger.debug("Phase 6: Checking TLS configuration")

        import ssl
        import socket

        # Parse host
        if host.startswith("http://"):
            logger.debug("HTTP target - skipping TLS check")
            return

        hostname = host.replace("https://", "").split("/")[0].split(":")[0]
        port = 443

        try:
            # Create SSL context
            context = ssl.create_default_context()

            # Test connection
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()

                    issues = []

                    # Check protocol version
                    if protocol in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.0"]:
                        issues.append(f"Outdated protocol: {protocol}")

                    elif protocol == "TLSv1.1":
                        issues.append(f"Deprecated protocol: {protocol}")

                    # Check cipher
                    if cipher:
                        cipher_name = cipher[0] if cipher else ""
                        weak_ciphers = [
                            "RC4", "DES", "3DES", "NULL", "EXPORT",
                            "MD5", "SHA1", "CBC"  # CBC is vulnerable to BEAST
                        ]

                        for weak in weak_ciphers:
                            if weak in cipher_name.upper():
                                issues.append(f"Weak cipher: {cipher_name}")
                                break

                    # Check certificate
                    if cert:
                        # Check key size (if available)
                        subject = dict(x[0] for x in cert.get('subject', ()))

                        # Check expiration
                        not_after = cert.get('notAfter', '')
                        if not_after:
                            from datetime import datetime
                            try:
                                exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                if exp_date < datetime.now():
                                    issues.append("Certificate expired")
                            except Exception:
                                pass

                    if issues:
                        result = CryptoTestResult(
                            vulnerable=True,
                            vuln_type=CryptoVulnType.WEAK_TLS,
                            confidence_score=80,
                            algorithm=protocol or "unknown",
                            evidence=[
                                f"Protocol: {protocol}",
                                f"Cipher: {cipher[0] if cipher else 'unknown'}",
                            ] + issues,
                            severity=Severity.MEDIUM if "Outdated" in str(issues) else "LOW",
                            cwe_id="CWE-326",  # Inadequate Encryption Strength
                        )

                        self._add_finding(
                            name="Weak TLS Configuration",
                            description=(
                                "TLS configuration has weaknesses. "
                                f"Issues: {', '.join(issues)}"
                            ),
                            endpoint=f"https://{hostname}",
                            result=result,
                        )

        except Exception as e:
            logger.debug(f"TLS check error: {e}")

    async def _test_weak_random(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter | None,
    ) -> None:
        """Test for weak random number generation."""
        logger.debug("Phase 7: Testing for weak random")

        # Endpoints that generate random values
        random_endpoints = [
            "/api/token",
            "/api/session",
            "/api/generate",
            "/api/code",
            "/api/otp",
            "/api/reset-password",
            "/api/invite",
        ]

        for endpoint in random_endpoints[:3]:
            if rate_limiter:
                await rate_limiter.acquire()

            url = urljoin(base_url, endpoint)
            tokens = []

            try:
                # Collect multiple tokens
                for _ in range(5):
                    response = await client.post(url)

                    if response.status_code == 200:
                        try:
                            data = response.json()
                            # Look for token-like fields
                            for key in ["token", "code", "otp", "session_id", "id"]:
                                if key in data:
                                    tokens.append(str(data[key]))
                                    break
                        except Exception:
                            # Check for token in text
                            text = response.text
                            # Look for hex or base64 patterns
                            hex_match = re.search(r'[a-f0-9]{16,}', text, re.IGNORECASE)
                            if hex_match:
                                tokens.append(hex_match.group())

                    await asyncio.sleep(0.1)

                # Analyze tokens for patterns
                if len(tokens) >= 3:
                    # Check for sequential patterns
                    sequential = self._check_sequential(tokens)
                    timestamp_based = self._check_timestamp_based(tokens)
                    low_entropy = self._check_low_entropy(tokens)

                    if sequential or timestamp_based or low_entropy:
                        issues = []
                        if sequential:
                            issues.append("Sequential/predictable pattern")
                        if timestamp_based:
                            issues.append("Timestamp-based generation")
                        if low_entropy:
                            issues.append("Low entropy")

                        result = CryptoTestResult(
                            vulnerable=True,
                            vuln_type=CryptoVulnType.WEAK_RANDOM,
                            confidence_score=60,
                            algorithm="PRNG (suspected weak)",
                            evidence=[
                                f"Endpoint: {url}",
                                f"Collected {len(tokens)} tokens",
                                f"Issues: {', '.join(issues)}",
                                f"Sample tokens: {tokens[:3]}",
                            ],
                            severity=Severity.MEDIUM,
                            cwe_id="CWE-330",
                        )

                        self._add_finding(
                            name="Weak Random Number Generation",
                            description=(
                                f"Tokens from {endpoint} show signs of weak randomness. "
                                f"Issues: {', '.join(issues)}. Tokens may be predictable."
                            ),
                            endpoint=url,
                            result=result,
                        )

            except Exception as e:
                logger.debug(f"Weak random test error: {e}")

    def _check_sequential(self, tokens: list[str]) -> bool:
        """Check if tokens are sequential."""
        try:
            # Try to parse as integers
            values = []
            for t in tokens:
                try:
                    values.append(int(t, 16))  # Try hex
                except ValueError:
                    try:
                        values.append(int(t))  # Try decimal
                    except ValueError:
                        return False

            if len(values) < 2:
                return False

            # Check if sequential
            diffs = [values[i+1] - values[i] for i in range(len(values)-1)]

            # If all differences are the same or very similar
            if len(set(diffs)) == 1:
                return True

            # Check if differences are small
            if all(abs(d) < 1000 for d in diffs):
                return True

            return False

        except Exception:
            return False

    def _check_timestamp_based(self, tokens: list[str]) -> bool:
        """Check if tokens are timestamp-based."""
        import time

        current_time = int(time.time())

        for token in tokens:
            try:
                # Check various timestamp formats
                value = int(token, 16) if len(token) >= 10 else int(token)

                # Unix timestamp range (1970-2100)
                if 0 < value < 4102444800:
                    # Close to current time (within a day)
                    if abs(value - current_time) < 86400:
                        return True

                # Millisecond timestamp
                if 1000000000000 < value < 5000000000000:
                    if abs(value - current_time * 1000) < 86400000:
                        return True

            except Exception:
                pass

        return False

    def _check_low_entropy(self, tokens: list[str]) -> bool:
        """Check if tokens have low entropy."""
        for token in tokens:
            if len(token) < 16:
                return True

            # Check character diversity
            unique_chars = len(set(token))
            if unique_chars < len(token) * 0.4:  # Less than 40% unique
                return True

            # Check for repeated patterns
            for pattern_len in range(2, min(8, len(token) // 3)):
                for i in range(len(token) - pattern_len * 2):
                    pattern = token[i:i + pattern_len]
                    if token.count(pattern) >= 3:
                        return True

        return False

    def _add_finding(
        self,
        name: str,
        description: str,
        endpoint: str,
        result: CryptoTestResult,
    ) -> None:
        """Add a finding to the results."""
        finding = Finding(
            vuln_type=VulnType.SSL_TLS_ISSUE,
            name=name,
            severity=result.severity,
            confidence_score=float(result.confidence),
            description=description,
            url=endpoint,
            endpoint=endpoint,
            evidence=result.evidence,
            metadata={
                "crypto_vuln_type": result.vuln_type.name,
                "algorithm": result.algorithm,
                "cwe": result.cwe,
                "payload": result.payload if result.payload else None,
            },
        )

        self.findings.append(finding.to_dict())

        logger.info(
            f"Crypto vulnerability [{result.severity}]: {name} "
            f"| Algorithm: {result.algorithm} | Confidence: {result.confidence}%"
        )


# Export
__all__ = [
    "CryptoWeaknessScanner",
    "CryptoVulnType",
    "CRYPTO_SCANNER_VERSION",
]
