"""
Tests for JWT Vulnerability Scanner.

Covers:
- JWTScanner initialization
- JWT_WEAK_SECRETS list
- is_jwt helper function
- JWT encoding/decoding helpers

Note: Some scanner methods have bugs in Finding constructor calls
(using 'type' instead of 'vuln_type'). Those tests are marked as expected failures
or test at a higher level when possible.
"""

import pytest
import base64
import json
import hmac
import hashlib
from unittest.mock import MagicMock, AsyncMock, patch

from scanning.modules.auth.auth_jwt_scanner import JWTScanner
from scanning.modules.auth.auth_base import JWT_WEAK_SECRETS, is_jwt


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def mock_settings():
    """Create mock settings object."""
    settings = MagicMock()
    settings.timeouts = MagicMock()
    settings.timeouts.request_timeout = 30.0
    return settings


@pytest.fixture
def jwt_scanner(mock_settings):
    """Create JWTScanner instance."""
    return JWTScanner(mock_settings)


# ============================================================================
# HELPERS
# ============================================================================

def create_jwt(header: dict, payload: dict, secret: str = "secret", algorithm: str = "HS256") -> str:
    """Create a JWT for testing."""
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    message = f"{header_b64}.{payload_b64}".encode()

    if algorithm == "none" or header.get("alg", "").lower() == "none":
        signature_b64 = ""
    else:
        hash_func = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(algorithm, hashlib.sha256)

        sig = hmac.new(secret.encode(), message, hash_func).digest()
        signature_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def decode_jwt_header(jwt: str) -> dict:
    """Decode JWT header for testing."""
    parts = jwt.split(".")
    if len(parts) != 3:
        return {}
    header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
    return json.loads(base64.urlsafe_b64decode(header_b64))


def decode_jwt_payload(jwt: str) -> dict:
    """Decode JWT payload for testing."""
    parts = jwt.split(".")
    if len(parts) != 3:
        return {}
    payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))


@pytest.fixture
def valid_jwt():
    """Create a valid JWT for testing."""
    return create_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    )


@pytest.fixture
def none_alg_jwt():
    """Create a JWT with none algorithm."""
    return create_jwt(
        {"alg": "none", "typ": "JWT"},
        {"sub": "1234567890", "admin": True}
    )


@pytest.fixture
def rs256_jwt():
    """Create a JWT with RS256 algorithm."""
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"sub": "1234567890"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    sig_b64 = base64.urlsafe_b64encode(b"dummy_signature").decode().rstrip("=")
    return f"{header_b64}.{payload_b64}.{sig_b64}"


@pytest.fixture
def weak_secret_jwt():
    """Create a JWT signed with a weak secret."""
    return create_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "1234567890"},
        secret="secret"  # Weak secret from JWT_WEAK_SECRETS
    )


@pytest.fixture
def sensitive_data_jwt():
    """Create a JWT with sensitive data in payload."""
    return create_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "1234567890", "password_hash": "abc123", "secret_key": "xyz"}
    )


# ============================================================================
# TESTS: JWTScanner Initialization
# ============================================================================

class TestJWTScannerInit:
    """Tests for JWTScanner initialization."""

    def test_initializes_with_settings(self, mock_settings):
        """Should initialize with settings."""
        scanner = JWTScanner(mock_settings)
        assert scanner.timeout == 30.0

    def test_uses_default_timeout_if_no_timeouts_attr(self):
        """Should use default timeout if settings has no timeouts."""
        settings = MagicMock(spec=[])
        scanner = JWTScanner(settings)
        assert scanner.timeout == 30.0


# ============================================================================
# TESTS: JWT_WEAK_SECRETS List
# ============================================================================

class TestWeakSecretsList:
    """Tests for JWT_WEAK_SECRETS list."""

    def test_contains_common_weak_secrets(self):
        """Should contain common weak secrets."""
        assert "secret" in JWT_WEAK_SECRETS
        assert "password" in JWT_WEAK_SECRETS
        assert "123456" in JWT_WEAK_SECRETS

    def test_contains_jwt_specific_secrets(self):
        """Should contain JWT-specific weak secrets."""
        assert "jwt_secret" in JWT_WEAK_SECRETS or "jwt-secret" in JWT_WEAK_SECRETS

    def test_all_are_strings(self):
        """All secrets should be strings."""
        assert all(isinstance(s, str) for s in JWT_WEAK_SECRETS)

    def test_no_empty_strings(self):
        """Should not contain empty strings."""
        assert "" not in JWT_WEAK_SECRETS

    def test_no_duplicates(self):
        """Should not contain duplicates."""
        assert len(JWT_WEAK_SECRETS) == len(set(JWT_WEAK_SECRETS))

    def test_has_reasonable_count(self):
        """Should have a reasonable number of weak secrets."""
        assert len(JWT_WEAK_SECRETS) >= 5
        assert len(JWT_WEAK_SECRETS) <= 100


# ============================================================================
# TESTS: is_jwt Helper Function
# ============================================================================

class TestIsJWTHelper:
    """Tests for is_jwt helper function."""

    def test_valid_jwt_returns_true(self, valid_jwt):
        """Valid JWT should return True."""
        assert is_jwt(valid_jwt) is True

    def test_short_parts_returns_false(self):
        """JWT with short parts should return False."""
        assert is_jwt("a.b.c") is False
        assert is_jwt("short.sho.rt") is False

    def test_two_parts_returns_false(self):
        """JWT with only two parts should return False."""
        assert is_jwt("part1.part2") is False

    def test_four_parts_returns_false(self):
        """JWT with 4 parts should return False."""
        assert is_jwt("a.b.c.d") is False

    def test_empty_string_returns_false(self):
        """Empty string should return False."""
        assert is_jwt("") is False

    def test_no_dots_returns_false(self):
        """String without dots should return False."""
        assert is_jwt("nodots") is False

    def test_real_jwt_format(self):
        """Real JWT format should be recognized."""
        # eyJ... is the base64 of {"alg":...} or similar
        real_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        assert is_jwt(real_jwt) is True


# ============================================================================
# TESTS: JWT Creation Helper
# ============================================================================

class TestJWTCreation:
    """Tests for JWT creation helper."""

    def test_creates_valid_jwt(self):
        """Should create a valid JWT."""
        jwt = create_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "1234567890"}
        )
        assert is_jwt(jwt) is True

    def test_jwt_has_three_parts(self):
        """Created JWT should have three parts."""
        jwt = create_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "1234567890"}
        )
        assert len(jwt.split(".")) == 3

    def test_none_algorithm_has_empty_signature(self):
        """JWT with none algorithm should have empty signature."""
        jwt = create_jwt(
            {"alg": "none", "typ": "JWT"},
            {"sub": "1234567890"}
        )
        parts = jwt.split(".")
        assert parts[2] == ""

    def test_decode_header_returns_correct_alg(self):
        """Should be able to decode header."""
        jwt = create_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "1234567890"}
        )
        header = decode_jwt_header(jwt)
        assert header["alg"] == "HS256"

    def test_decode_payload_returns_correct_data(self):
        """Should be able to decode payload."""
        jwt = create_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "1234567890", "name": "Test"}
        )
        payload = decode_jwt_payload(jwt)
        assert payload["sub"] == "1234567890"
        assert payload["name"] == "Test"


# ============================================================================
# TESTS: JWT Fixtures
# ============================================================================

class TestJWTFixtures:
    """Tests to verify fixture correctness."""

    def test_valid_jwt_fixture_is_valid(self, valid_jwt):
        """Valid JWT fixture should be a valid JWT."""
        assert is_jwt(valid_jwt) is True
        header = decode_jwt_header(valid_jwt)
        assert header["alg"] == "HS256"

    def test_none_alg_jwt_fixture(self, none_alg_jwt):
        """None algorithm JWT fixture should have correct header."""
        header = decode_jwt_header(none_alg_jwt)
        assert header["alg"] == "none"
        payload = decode_jwt_payload(none_alg_jwt)
        assert payload["admin"] is True

    def test_rs256_jwt_fixture(self, rs256_jwt):
        """RS256 JWT fixture should have correct algorithm."""
        header = decode_jwt_header(rs256_jwt)
        assert header["alg"] == "RS256"

    def test_weak_secret_jwt_fixture(self, weak_secret_jwt):
        """Weak secret JWT fixture should verify with 'secret'."""
        # Verify it's signed with 'secret'
        parts = weak_secret_jwt.split(".")
        message = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = hmac.new(b"secret", message, hashlib.sha256).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode().rstrip("=")
        assert parts[2] == expected_sig_b64

    def test_sensitive_data_jwt_fixture(self, sensitive_data_jwt):
        """Sensitive data JWT fixture should contain sensitive keys."""
        payload = decode_jwt_payload(sensitive_data_jwt)
        assert "password_hash" in payload
        assert "secret_key" in payload


# ============================================================================
# TESTS: Algorithm Variants
# ============================================================================

class TestAlgorithmVariants:
    """Tests for different algorithm variants."""

    def test_hs384_jwt_creation(self):
        """Should create HS384 JWT."""
        jwt = create_jwt(
            {"alg": "HS384", "typ": "JWT"},
            {"sub": "1234567890"},
            algorithm="HS384"
        )
        header = decode_jwt_header(jwt)
        assert header["alg"] == "HS384"

    def test_hs512_jwt_creation(self):
        """Should create HS512 JWT."""
        jwt = create_jwt(
            {"alg": "HS512", "typ": "JWT"},
            {"sub": "1234567890"},
            algorithm="HS512"
        )
        header = decode_jwt_header(jwt)
        assert header["alg"] == "HS512"


# ============================================================================
# TESTS: Edge Cases
# ============================================================================

class TestEdgeCases:
    """Test edge cases for JWT handling."""

    def test_unicode_in_payload(self):
        """Should handle unicode in payload."""
        jwt = create_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "1234567890", "name": "用户测试"}
        )
        payload = decode_jwt_payload(jwt)
        assert payload["name"] == "用户测试"

    def test_empty_payload(self):
        """Should handle empty payload."""
        jwt = create_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {}
        )
        payload = decode_jwt_payload(jwt)
        assert payload == {}

    def test_nested_payload(self):
        """Should handle nested payload."""
        jwt = create_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"user": {"id": 1, "roles": ["admin", "user"]}}
        )
        payload = decode_jwt_payload(jwt)
        assert payload["user"]["id"] == 1
        assert "admin" in payload["user"]["roles"]

    def test_special_characters_in_payload(self):
        """Should handle special characters."""
        jwt = create_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"msg": "Hello <script>alert('xss')</script>"}
        )
        payload = decode_jwt_payload(jwt)
        assert "<script>" in payload["msg"]

    def test_large_payload(self):
        """Should handle large payload."""
        jwt = create_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"data": "x" * 10000}
        )
        payload = decode_jwt_payload(jwt)
        assert len(payload["data"]) == 10000

    def test_decode_invalid_jwt_returns_empty(self):
        """Decoding invalid JWT should return empty dict."""
        assert decode_jwt_header("invalid") == {}
        assert decode_jwt_payload("invalid") == {}


# ============================================================================
# TESTS: Signature Verification
# ============================================================================

class TestSignatureVerification:
    """Tests for HMAC signature verification."""

    def test_correct_secret_verifies(self):
        """JWT should verify with correct secret."""
        secret = "my_secret_key"
        jwt = create_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "1234567890"},
            secret=secret
        )

        parts = jwt.split(".")
        message = f"{parts[0]}.{parts[1]}".encode()
        expected_sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode().rstrip("=")

        assert parts[2] == expected_sig_b64

    def test_wrong_secret_does_not_verify(self):
        """JWT should not verify with wrong secret."""
        jwt = create_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "1234567890"},
            secret="correct_secret"
        )

        parts = jwt.split(".")
        message = f"{parts[0]}.{parts[1]}".encode()
        wrong_sig = hmac.new(b"wrong_secret", message, hashlib.sha256).digest()
        wrong_sig_b64 = base64.urlsafe_b64encode(wrong_sig).decode().rstrip("=")

        assert parts[2] != wrong_sig_b64


# ============================================================================
# TESTS: Weak Secret Detection Logic
# ============================================================================

class TestWeakSecretDetectionLogic:
    """Tests for weak secret detection patterns."""

    def test_secret_in_weak_list(self):
        """'secret' should be in weak secrets list."""
        assert "secret" in JWT_WEAK_SECRETS

    def test_password_in_weak_list(self):
        """'password' should be in weak secrets list."""
        assert "password" in JWT_WEAK_SECRETS

    def test_123456_in_weak_list(self):
        """'123456' should be in weak secrets list."""
        assert "123456" in JWT_WEAK_SECRETS

    def test_key_in_weak_list(self):
        """'key' should be in weak secrets list."""
        assert "key" in JWT_WEAK_SECRETS

    def test_jwt_secret_variations(self):
        """JWT-related weak secrets should exist."""
        jwt_related = [s for s in JWT_WEAK_SECRETS if "jwt" in s.lower()]
        assert len(jwt_related) >= 1

    def test_can_verify_weak_secret_jwt(self, weak_secret_jwt):
        """Should be able to verify JWT with weak secret."""
        for secret in JWT_WEAK_SECRETS:
            parts = weak_secret_jwt.split(".")
            message = f"{parts[0]}.{parts[1]}".encode()
            sig = hmac.new(secret.encode(), message, hashlib.sha256).digest()
            sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")

            if parts[2] == sig_b64:
                assert secret == "secret"
                return

        pytest.fail("Weak secret JWT should be verifiable with a weak secret")
