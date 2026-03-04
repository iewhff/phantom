"""
Tests for scanning/modules/jwt_scanner.py

Covers:
- JWTAttackType enum (17 types)
- JWTAlgorithm enum (13 algorithms)
- WEAK_SECRETS list
- JWTToken dataclass (parse, get_algorithm, is_expired, has_claim)
- JWTVulnerability dataclass
- JWTManipulator class (b64url, create_token, none_algorithm, kid injection, etc.)
- JWTScanner class attributes
"""

import pytest
import json
import base64
import time
import hmac
import hashlib
from scanning.modules.jwt_scanner import (
    JWTAttackType,
    JWTAlgorithm,
    WEAK_SECRETS,
    JWTToken,
    JWTVulnerability,
    JWTManipulator,
    JWTScanner,
)


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestJWTAttackType:
    """Test JWTAttackType enum."""

    def test_count(self):
        assert len(JWTAttackType) == 17

    def test_algorithm_none(self):
        assert JWTAttackType.ALGORITHM_NONE.value == "algorithm_none"

    def test_algorithm_confusion(self):
        assert JWTAttackType.ALGORITHM_CONFUSION.value == "algorithm_confusion"

    def test_weak_secret(self):
        assert JWTAttackType.WEAK_SECRET.value == "weak_secret"

    def test_key_injection(self):
        assert JWTAttackType.KEY_INJECTION.value == "key_injection"

    def test_jku_injection(self):
        assert JWTAttackType.JKU_INJECTION.value == "jku_injection"

    def test_x5u_injection(self):
        assert JWTAttackType.X5U_INJECTION.value == "x5u_injection"

    def test_kid_injection(self):
        assert JWTAttackType.KID_INJECTION.value == "kid_injection"

    def test_expiration_bypass(self):
        assert JWTAttackType.EXPIRATION_BYPASS.value == "expiration_bypass"

    def test_claim_tampering(self):
        assert JWTAttackType.CLAIM_TAMPERING.value == "claim_tampering"

    def test_signature_bypass(self):
        assert JWTAttackType.SIGNATURE_BYPASS.value == "signature_bypass"

    def test_token_replay(self):
        assert JWTAttackType.TOKEN_REPLAY.value == "token_replay"

    def test_embedded_jwk(self):
        assert JWTAttackType.EMBEDDED_JWK.value == "embedded_jwk"

    def test_nbf_bypass(self):
        assert JWTAttackType.NBF_BYPASS.value == "nbf_bypass"

    def test_audience_confusion(self):
        assert JWTAttackType.AUDIENCE_CONFUSION.value == "audience_confusion"

    def test_issuer_spoofing(self):
        assert JWTAttackType.ISSUER_SPOOFING.value == "issuer_spoofing"

    def test_long_lived_token(self):
        assert JWTAttackType.LONG_LIVED_TOKEN.value == "long_lived_token"

    def test_signature_stripping(self):
        assert JWTAttackType.SIGNATURE_STRIPPING.value == "signature_stripping"


class TestJWTAlgorithm:
    """Test JWTAlgorithm enum."""

    def test_count(self):
        assert len(JWTAlgorithm) == 13

    def test_none(self):
        assert JWTAlgorithm.NONE.value == "none"

    def test_hs256(self):
        assert JWTAlgorithm.HS256.value == "HS256"

    def test_hs384(self):
        assert JWTAlgorithm.HS384.value == "HS384"

    def test_hs512(self):
        assert JWTAlgorithm.HS512.value == "HS512"

    def test_rs256(self):
        assert JWTAlgorithm.RS256.value == "RS256"

    def test_rs384(self):
        assert JWTAlgorithm.RS384.value == "RS384"

    def test_rs512(self):
        assert JWTAlgorithm.RS512.value == "RS512"

    def test_es256(self):
        assert JWTAlgorithm.ES256.value == "ES256"

    def test_es384(self):
        assert JWTAlgorithm.ES384.value == "ES384"

    def test_es512(self):
        assert JWTAlgorithm.ES512.value == "ES512"

    def test_ps256(self):
        assert JWTAlgorithm.PS256.value == "PS256"

    def test_ps384(self):
        assert JWTAlgorithm.PS384.value == "PS384"

    def test_ps512(self):
        assert JWTAlgorithm.PS512.value == "PS512"

    def test_has_hmac_algorithms(self):
        hmac_algs = [a for a in JWTAlgorithm if a.value.startswith("HS")]
        assert len(hmac_algs) == 3

    def test_has_rsa_algorithms(self):
        rsa_algs = [a for a in JWTAlgorithm if a.value.startswith("RS")]
        assert len(rsa_algs) == 3

    def test_has_ecdsa_algorithms(self):
        ec_algs = [a for a in JWTAlgorithm if a.value.startswith("ES")]
        assert len(ec_algs) == 3


# =============================================================================
# WEAK SECRETS
# =============================================================================

class TestWeakSecrets:
    """Test WEAK_SECRETS list."""

    def test_not_empty(self):
        assert len(WEAK_SECRETS) > 0

    def test_has_secret(self):
        assert "secret" in WEAK_SECRETS

    def test_has_password(self):
        assert "password" in WEAK_SECRETS

    def test_has_empty(self):
        assert "" in WEAK_SECRETS

    def test_has_changeme(self):
        assert "changeme" in WEAK_SECRETS

    def test_has_admin(self):
        assert "admin" in WEAK_SECRETS

    def test_has_jwt_specific(self):
        assert "jwt_secret" in WEAK_SECRETS
        assert "jwt-secret" in WEAK_SECRETS

    def test_has_api_specific(self):
        assert "api_secret" in WEAK_SECRETS

    def test_has_environment_names(self):
        assert "development" in WEAK_SECRETS
        assert "production" in WEAK_SECRETS
        assert "staging" in WEAK_SECRETS

    def test_has_common_examples(self):
        assert "your-256-bit-secret" in WEAK_SECRETS

    def test_has_case_variants(self):
        """Should have multiple case variants for common words."""
        assert "secret" in WEAK_SECRETS
        assert "Secret" in WEAK_SECRETS
        assert "SECRET" in WEAK_SECRETS

    def test_all_are_strings(self):
        for s in WEAK_SECRETS:
            assert isinstance(s, str)


# =============================================================================
# JWT TOKEN
# =============================================================================

class TestJWTToken:
    """Test JWTToken dataclass and methods."""

    def _make_token(self, header=None, payload=None, secret="secret"):
        """Helper to create a test JWT token string."""
        if header is None:
            header = {"alg": "HS256", "typ": "JWT"}
        if payload is None:
            payload = {"sub": "1234567890", "name": "Test User", "iat": 1516239022}
        return JWTManipulator.create_token(header, payload, secret=secret, algorithm=header.get("alg", "HS256"))

    def test_parse_valid_token(self):
        token_str = self._make_token()
        token = JWTToken.parse(token_str)
        assert token is not None
        assert token.header["alg"] == "HS256"
        assert token.payload["sub"] == "1234567890"
        assert token.is_valid is True

    def test_parse_invalid_token(self):
        token = JWTToken.parse("not.a.valid.jwt")
        assert token is None

    def test_parse_too_few_parts(self):
        token = JWTToken.parse("only.two")
        assert token is None

    def test_parse_garbage(self):
        token = JWTToken.parse("completely-invalid-string")
        assert token is None

    def test_parse_with_location(self):
        token_str = self._make_token()
        token = JWTToken.parse(token_str, location="Authorization header")
        assert token is not None
        assert token.location == "Authorization header"

    def test_get_algorithm(self):
        token_str = self._make_token(header={"alg": "RS256", "typ": "JWT"})
        # RS256 won't have valid signature but we can still parse
        token = JWTToken.parse(token_str)
        assert token is not None
        assert token.get_algorithm() == "RS256"

    def test_get_claims(self):
        payload = {"sub": "user123", "role": "admin", "iat": 1234567890}
        token_str = self._make_token(payload=payload)
        token = JWTToken.parse(token_str)
        claims = token.get_claims()
        assert claims["sub"] == "user123"
        assert claims["role"] == "admin"

    def test_is_expired_true(self):
        payload = {"sub": "user", "exp": int(time.time()) - 3600}  # 1 hour ago
        token_str = self._make_token(payload=payload)
        token = JWTToken.parse(token_str)
        assert token.is_expired() is True

    def test_is_expired_false(self):
        payload = {"sub": "user", "exp": int(time.time()) + 3600}  # 1 hour from now
        token_str = self._make_token(payload=payload)
        token = JWTToken.parse(token_str)
        assert token.is_expired() is False

    def test_is_expired_no_exp(self):
        payload = {"sub": "user"}  # No exp claim
        token_str = self._make_token(payload=payload)
        token = JWTToken.parse(token_str)
        assert token.is_expired() is False

    def test_has_claim_true(self):
        payload = {"sub": "user", "role": "admin"}
        token_str = self._make_token(payload=payload)
        token = JWTToken.parse(token_str)
        assert token.has_claim("role") is True

    def test_has_claim_false(self):
        payload = {"sub": "user"}
        token_str = self._make_token(payload=payload)
        token = JWTToken.parse(token_str)
        assert token.has_claim("role") is False

    def test_raw_preserved(self):
        token_str = self._make_token()
        token = JWTToken.parse(token_str)
        assert token.raw == token_str


# =============================================================================
# JWT VULNERABILITY
# =============================================================================

class TestJWTVulnerability:
    """Test JWTVulnerability dataclass."""

    def test_basic_creation(self):
        vuln = JWTVulnerability(
            attack_type=JWTAttackType.ALGORITHM_NONE,
            severity="CRITICAL",
            description="Server accepts tokens with 'none' algorithm",
            token_location="Authorization header",
            original_token="eyJ...",
        )
        assert vuln.attack_type == JWTAttackType.ALGORITHM_NONE
        assert vuln.severity == "CRITICAL"
        assert vuln.manipulated_token is None  # default
        assert vuln.evidence == ""  # default

    def test_with_all_fields(self):
        vuln = JWTVulnerability(
            attack_type=JWTAttackType.WEAK_SECRET,
            severity="HIGH",
            description="JWT signed with weak secret 'password'",
            token_location="cookie:jwt",
            original_token="eyJ...",
            manipulated_token="eyJ...modified",
            evidence="Forged token accepted with 200 OK",
            remediation="Use a strong, random secret (>256 bits)",
            cwe="CWE-798",
            cvss_score=8.1,
        )
        assert vuln.manipulated_token == "eyJ...modified"
        assert vuln.cwe == "CWE-798"
        assert vuln.cvss_score == 8.1


# =============================================================================
# JWT MANIPULATOR
# =============================================================================

class TestJWTManipulator:
    """Test JWTManipulator class."""

    def _make_token_obj(self, header=None, payload=None):
        """Create a JWTToken object for testing."""
        if header is None:
            header = {"alg": "HS256", "typ": "JWT"}
        if payload is None:
            payload = {"sub": "user123", "role": "user", "iat": 1234567890}
        token_str = JWTManipulator.create_token(header, payload, secret="secret", algorithm="HS256")
        return JWTToken.parse(token_str)

    # b64url encode/decode
    def test_b64url_encode(self):
        result = JWTManipulator.b64url_encode(b"hello")
        assert isinstance(result, str)
        assert "=" not in result  # No padding

    def test_b64url_decode(self):
        encoded = JWTManipulator.b64url_encode(b"hello world")
        decoded = JWTManipulator.b64url_decode(encoded)
        assert decoded == b"hello world"

    def test_b64url_roundtrip(self):
        data = b"test data with special chars: +/="
        encoded = JWTManipulator.b64url_encode(data)
        decoded = JWTManipulator.b64url_decode(encoded)
        assert decoded == data

    # create_token
    def test_create_token_none_algorithm(self):
        header = {"alg": "none", "typ": "JWT"}
        payload = {"sub": "admin"}
        token = JWTManipulator.create_token(header, payload, algorithm="none")
        parts = token.split(".")
        assert len(parts) == 3
        assert parts[2] == ""  # Empty signature

    def test_create_token_hs256(self):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "user"}
        token = JWTManipulator.create_token(header, payload, secret="mysecret", algorithm="HS256")
        parts = token.split(".")
        assert len(parts) == 3
        assert parts[2] != ""  # Has signature

    def test_create_token_hs384(self):
        header = {"alg": "HS384", "typ": "JWT"}
        payload = {"sub": "user"}
        token = JWTManipulator.create_token(header, payload, secret="mysecret", algorithm="HS384")
        parts = token.split(".")
        assert len(parts) == 3
        assert parts[2] != ""

    def test_create_token_hs512(self):
        header = {"alg": "HS512", "typ": "JWT"}
        payload = {"sub": "user"}
        token = JWTManipulator.create_token(header, payload, secret="mysecret", algorithm="HS512")
        parts = token.split(".")
        assert len(parts) == 3
        assert parts[2] != ""

    def test_create_token_payload_preserved(self):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "user", "role": "admin", "exp": 9999999999}
        token_str = JWTManipulator.create_token(header, payload, secret="s", algorithm="HS256")
        parsed = JWTToken.parse(token_str)
        assert parsed.payload["sub"] == "user"
        assert parsed.payload["role"] == "admin"

    # create_none_algorithm_token
    def test_create_none_algorithm_token(self):
        original = self._make_token_obj()
        none_token = JWTManipulator.create_none_algorithm_token(original)
        parsed = JWTToken.parse(none_token)
        assert parsed is not None
        assert parsed.header["alg"] == "none"
        assert parsed.payload["sub"] == original.payload["sub"]

    # create_algorithm_confusion_token
    def test_create_algorithm_confusion_token(self):
        original = self._make_token_obj(header={"alg": "RS256", "typ": "JWT"})
        confused = JWTManipulator.create_algorithm_confusion_token(original, "fake-public-key")
        parsed = JWTToken.parse(confused)
        assert parsed is not None
        assert parsed.header["alg"] == "HS256"  # Switched from RS256

    # create_expired_bypass_token
    def test_create_expired_bypass_token(self):
        original = self._make_token_obj(payload={"sub": "user", "exp": 1000000})
        bypass = JWTManipulator.create_expired_bypass_token(original)
        parsed = JWTToken.parse(bypass)
        assert parsed is not None
        assert parsed.payload["exp"] > time.time()  # Far future

    # create_kid_injection_tokens
    def test_create_kid_injection_tokens(self):
        original = self._make_token_obj()
        tokens = JWTManipulator.create_kid_injection_tokens(original)
        assert len(tokens) > 0

    def test_kid_injection_has_sqli(self):
        original = self._make_token_obj()
        tokens = JWTManipulator.create_kid_injection_tokens(original)
        # Parse and check kid values
        all_kids = []
        for t in tokens:
            parsed = JWTToken.parse(t)
            if parsed and "kid" in parsed.header:
                all_kids.append(parsed.header["kid"])
        assert any("OR" in k for k in all_kids)

    def test_kid_injection_has_path_traversal(self):
        original = self._make_token_obj()
        tokens = JWTManipulator.create_kid_injection_tokens(original)
        all_kids = []
        for t in tokens:
            parsed = JWTToken.parse(t)
            if parsed and "kid" in parsed.header:
                all_kids.append(parsed.header["kid"])
        assert any("../" in k or "/etc/passwd" in k for k in all_kids)

    def test_kid_injection_has_cmdi(self):
        original = self._make_token_obj()
        tokens = JWTManipulator.create_kid_injection_tokens(original)
        all_kids = []
        for t in tokens:
            parsed = JWTToken.parse(t)
            if parsed and "kid" in parsed.header:
                all_kids.append(parsed.header["kid"])
        assert any("`" in k or "$(" in k for k in all_kids)

    # create_jku_injection_token
    def test_create_jku_injection_token(self):
        original = self._make_token_obj()
        jku_token = JWTManipulator.create_jku_injection_token(original, "https://evil.com/.well-known/jwks.json")
        parsed = JWTToken.parse(jku_token)
        assert parsed is not None
        assert parsed.header["jku"] == "https://evil.com/.well-known/jwks.json"

    # create_claim_tampered_token
    def test_create_claim_tampered_token(self):
        original = self._make_token_obj(payload={"sub": "user", "role": "user"})
        tampered = JWTManipulator.create_claim_tampered_token(original, "role", "admin")
        parsed = JWTToken.parse(tampered)
        assert parsed.payload["role"] == "admin"

    def test_create_claim_add_new_claim(self):
        original = self._make_token_obj(payload={"sub": "user"})
        tampered = JWTManipulator.create_claim_tampered_token(original, "isAdmin", True)
        parsed = JWTToken.parse(tampered)
        assert parsed.payload["isAdmin"] is True

    # forge_with_secret
    def test_forge_with_secret(self):
        original = self._make_token_obj()
        forged = JWTManipulator.forge_with_secret(original, "newsecret", "HS256")
        assert forged != ""
        parsed = JWTToken.parse(forged)
        assert parsed is not None
        assert parsed.header["alg"] == "HS256"

    def test_forge_with_secret_hs384(self):
        original = self._make_token_obj()
        forged = JWTManipulator.forge_with_secret(original, "secret", "HS384")
        parsed = JWTToken.parse(forged)
        assert parsed.header["alg"] == "HS384"

    # verify_hmac_signature
    def test_verify_hmac_correct_secret(self):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "user"}
        token_str = JWTManipulator.create_token(header, payload, secret="correct", algorithm="HS256")
        token = JWTToken.parse(token_str)
        assert JWTManipulator.verify_hmac_signature(token, "correct") is True

    def test_verify_hmac_wrong_secret(self):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "user"}
        token_str = JWTManipulator.create_token(header, payload, secret="correct", algorithm="HS256")
        token = JWTToken.parse(token_str)
        assert JWTManipulator.verify_hmac_signature(token, "wrong") is False

    def test_verify_hmac_hs384(self):
        header = {"alg": "HS384", "typ": "JWT"}
        payload = {"sub": "user"}
        token_str = JWTManipulator.create_token(header, payload, secret="mysecret", algorithm="HS384")
        token = JWTToken.parse(token_str)
        assert JWTManipulator.verify_hmac_signature(token, "mysecret") is True

    def test_verify_hmac_hs512(self):
        header = {"alg": "HS512", "typ": "JWT"}
        payload = {"sub": "user"}
        token_str = JWTManipulator.create_token(header, payload, secret="mysecret", algorithm="HS512")
        token = JWTToken.parse(token_str)
        assert JWTManipulator.verify_hmac_signature(token, "mysecret") is True


# =============================================================================
# JWT SCANNER CLASS
# =============================================================================

class TestJWTScannerClass:
    """Test JWTScanner class attributes."""

    def test_module_name(self):
        assert JWTScanner.MODULE_NAME == "jwt"

    def test_module_version(self):
        assert JWTScanner.MODULE_VERSION == "3.0.0"

    def test_is_scan_module(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(JWTScanner, ScanModule)


# =============================================================================
# ATTACK SCENARIOS
# =============================================================================

class TestAttackScenarios:
    """Test realistic JWT attack scenarios."""

    def test_none_algorithm_attack(self):
        """alg:none allows forging tokens without a secret."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "user", "role": "user"}
        original_str = JWTManipulator.create_token(header, payload, secret="secret", algorithm="HS256")
        original = JWTToken.parse(original_str)

        # Attacker creates none-algorithm token
        forged = JWTManipulator.create_none_algorithm_token(original)
        parsed = JWTToken.parse(forged)

        assert parsed.header["alg"] == "none"
        assert parsed.payload["sub"] == "user"
        assert parsed.payload["role"] == "user"

    def test_weak_secret_brute_force(self):
        """Brute-force weak JWT secrets."""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "admin", "role": "admin"}
        token_str = JWTManipulator.create_token(header, payload, secret="secret", algorithm="HS256")
        token = JWTToken.parse(token_str)

        # Attacker tries common secrets
        found_secret = None
        for secret in WEAK_SECRETS[:10]:
            if JWTManipulator.verify_hmac_signature(token, secret):
                found_secret = secret
                break

        assert found_secret == "secret"

    def test_algorithm_confusion_rs256_to_hs256(self):
        """RS256→HS256 confusion: use public key as HMAC secret."""
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"sub": "admin", "role": "admin"}
        original_str = JWTManipulator.create_token(header, payload, algorithm="RS256")
        original = JWTToken.parse(original_str)

        confused = JWTManipulator.create_algorithm_confusion_token(original, "public-key-content")
        parsed = JWTToken.parse(confused)

        assert parsed.header["alg"] == "HS256"
        assert parsed.payload["role"] == "admin"

    def test_kid_sql_injection(self):
        """SQL injection via kid parameter."""
        original = JWTToken.parse(
            JWTManipulator.create_token({"alg": "HS256", "typ": "JWT"}, {"sub": "user"}, secret="s", algorithm="HS256")
        )
        tokens = JWTManipulator.create_kid_injection_tokens(original)
        assert len(tokens) >= 5  # Multiple injection payloads

    def test_claim_escalation(self):
        """Privilege escalation by tampering role claim."""
        original = JWTToken.parse(
            JWTManipulator.create_token(
                {"alg": "HS256", "typ": "JWT"},
                {"sub": "user", "role": "user"},
                secret="s",
                algorithm="HS256",
            )
        )
        escalated = JWTManipulator.create_claim_tampered_token(original, "role", "admin")
        parsed = JWTToken.parse(escalated)
        assert parsed.payload["role"] == "admin"

    def test_expiration_bypass(self):
        """Bypass token expiration."""
        expired_payload = {"sub": "user", "exp": int(time.time()) - 86400}
        original = JWTToken.parse(
            JWTManipulator.create_token(
                {"alg": "HS256", "typ": "JWT"},
                expired_payload,
                secret="s",
                algorithm="HS256",
            )
        )
        assert original.is_expired() is True

        bypass = JWTManipulator.create_expired_bypass_token(original)
        parsed = JWTToken.parse(bypass)
        assert parsed.is_expired() is False  # No longer expired


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Test edge cases."""

    def test_all_attack_types_unique(self):
        values = [t.value for t in JWTAttackType]
        assert len(values) == len(set(values))

    def test_all_algorithms_unique(self):
        values = [a.value for a in JWTAlgorithm]
        assert len(values) == len(set(values))

    def test_parse_empty_payload(self):
        header = {"alg": "none"}
        payload = {}
        token_str = JWTManipulator.create_token(header, payload, algorithm="none")
        token = JWTToken.parse(token_str)
        assert token is not None
        assert token.payload == {}

    def test_parse_complex_payload(self):
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "user",
            "roles": ["admin", "user"],
            "metadata": {"department": "engineering"},
            "iat": 1234567890,
            "exp": 9999999999,
        }
        token_str = JWTManipulator.create_token(header, payload, secret="s", algorithm="HS256")
        token = JWTToken.parse(token_str)
        assert token.payload["roles"] == ["admin", "user"]
        assert token.payload["metadata"]["department"] == "engineering"

    def test_vulnerability_defaults(self):
        vuln = JWTVulnerability(
            attack_type=JWTAttackType.WEAK_SECRET,
            severity="HIGH",
            description="test",
            token_location="header",
            original_token="eyJ...",
        )
        assert vuln.manipulated_token is None
        assert vuln.evidence == ""
        assert vuln.remediation == ""
        assert vuln.cwe == ""
        assert vuln.cvss_score == 0.0
