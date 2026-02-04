"""
JWT Vulnerability Scanner

Enterprise-grade JWT security testing including:
- Algorithm 'none' bypass
- Algorithm confusion (RS256 -> HS256)
- Weak secret detection
- Claim tampering analysis
- Expiration bypass

CWE Coverage:
- CWE-327: Use of Broken Crypto Algorithm
- CWE-613: Insufficient Session Expiration
- CWE-798: Use of Hard-coded Credentials

Author: PetNTester AI Enterprise
Version: 2.0.0
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import TYPE_CHECKING, Any

import httpx

from scanning.vuln_scanner import Finding
from utils.exploitation_helper import ExploitationHelper
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter

from .auth_base import JWT_WEAK_SECRETS, is_jwt

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class JWTScanner:
    """
    JWT Vulnerability Scanner

    Tests for common JWT security issues including algorithm manipulation,
    weak secrets, and claim-based vulnerabilities.
    """

    def __init__(self, settings: Settings) -> None:
        self.timeout = settings.timeouts.request_timeout

    async def scan(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Comprehensive JWT vulnerability scan.

        Finds JWTs in cookies, response bodies, and Authorization headers,
        then tests each for various vulnerabilities.
        """
        findings = []

        await rate_limiter.acquire()

        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                response = await client.get(base_url)

                # Collect JWTs from various locations
                jwts_found = []

                # Check cookies
                for cookie in response.cookies.jar:
                    if is_jwt(cookie.value):
                        jwts_found.append((cookie.value, f"Cookie: {cookie.name}"))

                # Check response body
                jwt_pattern = r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'
                for jwt in re.findall(jwt_pattern, response.text)[:3]:
                    jwts_found.append((jwt, "Response body"))

                # Check endpoints for Authorization headers
                endpoints = asset_data.get("endpoints", [])
                for endpoint in endpoints[:3]:
                    await rate_limiter.acquire()
                    try:
                        resp = await client.get(endpoint)
                        auth_header = resp.headers.get("Authorization", "")
                        if auth_header.startswith("Bearer "):
                            token = auth_header[7:]
                            if is_jwt(token):
                                jwts_found.append((token, f"Auth header at {endpoint}"))
                    except (httpx.HTTPError, httpx.TimeoutException, OSError):
                        continue

                # Analyze each JWT
                for jwt, location in jwts_found:
                    # Basic analysis
                    basic_findings = self._analyze_jwt(jwt, base_url, location)
                    findings.extend(basic_findings)

                    # Algorithm confusion test
                    confusion_findings = self._test_algorithm_confusion(jwt, base_url, location)
                    findings.extend(confusion_findings)

                    # Weak secret test
                    weak_secret_findings = self._test_weak_secret(jwt, base_url, location)
                    findings.extend(weak_secret_findings)

                    # Claim analysis
                    claim_findings = self._analyze_claims(jwt, base_url, location)
                    findings.extend(claim_findings)

        except (httpx.HTTPError, httpx.TimeoutException, OSError) as e:
            logger.debug(f"JWT scan failed: {e}")

        return findings

    def _analyze_jwt(
        self,
        jwt: str,
        base_url: str,
        location: str,
    ) -> list[dict[str, Any]]:
        """Analyze JWT for basic vulnerabilities."""
        findings = []

        try:
            parts = jwt.split(".")
            if len(parts) != 3:
                return findings

            # Decode header
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            alg = header.get("alg", "").upper()

            # Check for 'none' algorithm
            if alg == "NONE" or alg == "":
                # Generate POC for none algorithm bypass
                poc = ExploitationHelper.generate_jwt_poc(
                    url=base_url,
                    original_token=jwt,
                    attack_type="none_algorithm",
                    forged_token=f"{parts[0]}.{parts[1]}.",  # Remove signature
                )
                findings.append(Finding(
                    type="authentication",
                    name="JWT with 'none' Algorithm",
                    severity="CRITICAL",
                    description="JWT uses 'none' algorithm, allowing signature bypass.",
                    host=base_url,
                    matched_at=base_url,
                    evidence=[f"Location: {location}", f"Algorithm: {alg}"],
                    cvss_score=9.8,
                    cwe="CWE-327",
                    remediation="Use strong algorithms (RS256, ES256). Never accept 'none' algorithm.",
                    metadata={"poc": poc.to_dict()},
                ).to_dict())

            # Check for weak algorithm
            if alg in ["HS256", "HS384", "HS512"]:
                findings.append(Finding(
                    type="authentication",
                    name="JWT with Symmetric Algorithm",
                    severity="LOW",
                    description=f"JWT uses symmetric algorithm ({alg}). If the secret is weak, "
                               f"it may be brute-forced.",
                    host=base_url,
                    matched_at=base_url,
                    evidence=[f"Location: {location}", f"Algorithm: {alg}"],
                    cvss_score=3.7,
                    cwe="CWE-327",
                    remediation="Consider using asymmetric algorithms (RS256, ES256) for better security.",
                ).to_dict())

            # Decode payload for sensitive data
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # Check for sensitive data in payload
            sensitive_keys = ["password", "secret", "key", "credit", "ssn", "token"]
            found_sensitive = [k for k in payload.keys() if any(s in k.lower() for s in sensitive_keys)]

            if found_sensitive:
                findings.append(Finding(
                    type="authentication",
                    name="Sensitive Data in JWT Payload",
                    severity="MEDIUM",
                    description="JWT payload contains potentially sensitive data.",
                    host=base_url,
                    matched_at=base_url,
                    evidence=[f"Sensitive keys found: {found_sensitive}"],
                    cvss_score=5.3,
                    cwe="CWE-200",
                    remediation="Do not store sensitive data in JWT payload. Use encrypted JWTs (JWE) if needed.",
                ).to_dict())

        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.debug(f"JWT analysis failed: {e}")

        return findings

    def _test_algorithm_confusion(
        self,
        jwt: str,
        base_url: str,
        location: str,
    ) -> list[dict[str, Any]]:
        """Test for JWT algorithm confusion vulnerability."""
        findings = []

        try:
            parts = jwt.split(".")
            if len(parts) != 3:
                return findings

            # Decode header
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            alg = header.get("alg", "").upper()

            # Check for RS256 which is vulnerable to HS256 confusion
            if alg in ["RS256", "RS384", "RS512"]:
                # Generate POC for algorithm confusion attack
                poc = ExploitationHelper.generate_jwt_poc(
                    url=base_url,
                    original_token=jwt,
                    attack_type="algorithm_confusion",
                    forged_token="[forge with HS256 using public key as secret]",
                )
                findings.append(Finding(
                    type="authentication",
                    name="JWT Algorithm Confusion Risk",
                    severity="HIGH",
                    description=f"JWT uses {alg} algorithm. If the server doesn't strictly "
                               f"validate the algorithm, an attacker could switch to HS256 "
                               f"and sign with the public key.",
                    host=base_url,
                    matched_at=base_url,
                    evidence=[
                        f"Location: {location}",
                        f"Algorithm: {alg}",
                        "Potential RS256->HS256 confusion attack",
                    ],
                    cvss_score=8.1,
                    cwe="CWE-327",
                    remediation="Explicitly verify the expected algorithm. "
                               "Never allow algorithm switching. "
                               "Use a JWT library that prevents algorithm confusion.",
                    metadata={"poc": poc.to_dict()},
                ).to_dict())

        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.debug(f"Algorithm confusion test failed: {e}")

        return findings

    def _test_weak_secret(
        self,
        jwt: str,
        base_url: str,
        location: str,
    ) -> list[dict[str, Any]]:
        """Test if JWT uses a weak secret (for HS* algorithms)."""
        findings = []

        try:
            parts = jwt.split(".")
            if len(parts) != 3:
                return findings

            # Decode header
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            alg = header.get("alg", "").upper()

            if alg not in ["HS256", "HS384", "HS512"]:
                return findings

            # Try weak secrets
            message = f"{parts[0]}.{parts[1]}".encode()
            original_sig = parts[2]

            hash_func = {
                "HS256": hashlib.sha256,
                "HS384": hashlib.sha384,
                "HS512": hashlib.sha512,
            }.get(alg, hashlib.sha256)

            for secret in JWT_WEAK_SECRETS:
                try:
                    sig = hmac.new(
                        secret.encode(),
                        message,
                        hash_func
                    ).digest()

                    # Base64url encode
                    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b'=').decode()

                    if sig_b64 == original_sig:
                        # Generate POC for weak secret exploitation
                        poc = ExploitationHelper.generate_jwt_poc(
                            url=base_url,
                            original_token=jwt,
                            attack_type="weak_secret",
                            forged_token="[forge admin token with discovered secret]",
                            secret=secret,
                        )
                        findings.append(Finding(
                            type="authentication",
                            name="JWT Weak Secret Detected",
                            severity="CRITICAL",
                            description="JWT is signed with a weak/common secret. "
                                       "Attackers can forge valid tokens.",
                            host=base_url,
                            matched_at=base_url,
                            evidence=[
                                f"Location: {location}",
                                f"Algorithm: {alg}",
                                f"Secret found: {secret}",
                            ],
                            cvss_score=9.8,
                            cwe="CWE-798",
                            remediation="Use a strong, randomly generated secret (256+ bits). "
                                       "Consider using asymmetric algorithms (RS256, ES256).",
                            metadata={"poc": poc.to_dict()},
                        ).to_dict())
                        break

                except (ValueError, UnicodeDecodeError):
                    continue

        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.debug(f"Weak secret test failed: {e}")

        return findings

    def _analyze_claims(
        self,
        jwt: str,
        base_url: str,
        location: str,
    ) -> list[dict[str, Any]]:
        """Analyze JWT claims for security issues."""
        findings = []

        try:
            parts = jwt.split(".")
            if len(parts) != 3:
                return findings

            # Decode payload
            payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))

            # Check expiration
            exp = payload.get("exp")
            if exp:
                if exp < time.time():
                    findings.append(Finding(
                        type="authentication",
                        name="Expired JWT Still Valid",
                        severity="HIGH",
                        description="An expired JWT was found in the response. "
                                   "The server may not be validating expiration.",
                        host=base_url,
                        matched_at=base_url,
                        evidence=[
                            f"Location: {location}",
                            f"Expiration: {exp} ({time.ctime(exp)})",
                            f"Current time: {int(time.time())}",
                        ],
                        cvss_score=7.5,
                        cwe="CWE-613",
                        remediation="Validate JWT expiration on every request. "
                                   "Implement token refresh mechanism.",
                    ).to_dict())
            else:
                findings.append(Finding(
                    type="authentication",
                    name="JWT Missing Expiration",
                    severity="MEDIUM",
                    description="JWT does not contain an expiration claim (exp). "
                               "Tokens may be valid indefinitely.",
                    host=base_url,
                    matched_at=base_url,
                    evidence=[f"Location: {location}", "No 'exp' claim found"],
                    cvss_score=5.3,
                    cwe="CWE-613",
                    remediation="Always include 'exp' claim with reasonable expiration time.",
                ).to_dict())

            # Check for privilege-related claims
            priv_claims = ["role", "admin", "is_admin", "privilege", "permissions", "scope"]
            for claim in priv_claims:
                if claim in payload:
                    findings.append(Finding(
                        type="authentication",
                        name="JWT Contains Privilege Claims",
                        severity="INFO",
                        description=f"JWT contains privilege-related claim '{claim}'. "
                                   f"Ensure this cannot be tampered with.",
                        host=base_url,
                        matched_at=base_url,
                        evidence=[
                            f"Location: {location}",
                            f"Claim: {claim}={payload[claim]}",
                        ],
                        cvss_score=0.0,
                        cwe="CWE-269",
                        remediation="Verify privilege claims against server-side records. "
                                   "Never trust client-provided role information.",
                    ).to_dict())
                    break

        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.debug(f"JWT claims analysis failed: {e}")

        return findings
