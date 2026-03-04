"""
Tests for scanning/modules/crypto_weakness_scanner.py

Covers:
- CRYPTO_SCANNER_VERSION constant
- CryptoVulnType enum (10 members)
- CryptoEndpoint dataclass
- CryptoTestResult dataclass
- WEAK_HASH_PATTERNS dict (md5, sha1 regex lists)
- WEAK_PASSWORD_HASH_PATTERNS dict (7 items)
- STRONG_PASSWORD_HASH_PATTERNS dict (4 items: bcrypt, scrypt, argon2, pbkdf2)
- HARDCODED_SECRET_PATTERNS list (10 items)
- Regex pattern compilation and matching
"""

import re

import pytest
from scanning.modules.crypto_weakness_scanner import (
    CRYPTO_SCANNER_VERSION,
    CryptoVulnType,
    CryptoEndpoint,
    CryptoTestResult,
    WEAK_HASH_PATTERNS,
    WEAK_PASSWORD_HASH_PATTERNS,
    STRONG_PASSWORD_HASH_PATTERNS,
    HARDCODED_SECRET_PATTERNS,
)


# =============================================================================
# VERSION CONSTANT
# =============================================================================

class TestCryptoScannerVersion:
    """Test CRYPTO_SCANNER_VERSION constant."""

    def test_version_value(self):
        assert CRYPTO_SCANNER_VERSION == "1.0.0"

    def test_version_is_string(self):
        assert isinstance(CRYPTO_SCANNER_VERSION, str)

    def test_version_semver_format(self):
        parts = CRYPTO_SCANNER_VERSION.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()


# =============================================================================
# ENUM TESTS
# =============================================================================

class TestCryptoVulnType:
    """Test CryptoVulnType enum."""

    def test_count(self):
        assert len(CryptoVulnType) == 10

    def test_weak_hash(self):
        assert CryptoVulnType.WEAK_HASH is not None

    def test_weak_encryption(self):
        assert CryptoVulnType.WEAK_ENCRYPTION is not None

    def test_weak_jwt(self):
        assert CryptoVulnType.WEAK_JWT is not None

    def test_hardcoded_secret(self):
        assert CryptoVulnType.HARDCODED_SECRET is not None

    def test_weak_random(self):
        assert CryptoVulnType.WEAK_RANDOM is not None

    def test_weak_password_hash(self):
        assert CryptoVulnType.WEAK_PASSWORD_HASH is not None

    def test_padding_oracle(self):
        assert CryptoVulnType.PADDING_ORACLE is not None

    def test_weak_tls(self):
        assert CryptoVulnType.WEAK_TLS is not None

    def test_key_derivation(self):
        assert CryptoVulnType.KEY_DERIVATION is not None

    def test_insecure_comparison(self):
        assert CryptoVulnType.INSECURE_COMPARISON is not None

    def test_all_members_are_unique(self):
        values = [member.value for member in CryptoVulnType]
        assert len(values) == len(set(values))

    def test_members_list(self):
        expected = {
            "WEAK_HASH",
            "WEAK_ENCRYPTION",
            "WEAK_JWT",
            "HARDCODED_SECRET",
            "WEAK_RANDOM",
            "WEAK_PASSWORD_HASH",
            "PADDING_ORACLE",
            "WEAK_TLS",
            "KEY_DERIVATION",
            "INSECURE_COMPARISON",
        }
        actual = {member.name for member in CryptoVulnType}
        assert actual == expected


# =============================================================================
# DATACLASS TESTS
# =============================================================================

class TestCryptoEndpoint:
    """Test CryptoEndpoint dataclass."""

    def test_basic_creation(self):
        ep = CryptoEndpoint(url="https://example.com/api", crypto_type="hash")
        assert ep.url == "https://example.com/api"
        assert ep.crypto_type == "hash"

    def test_default_detected_algorithms(self):
        ep = CryptoEndpoint(url="https://example.com", crypto_type="encrypt")
        assert ep.detected_algorithms == []

    def test_default_evidence(self):
        ep = CryptoEndpoint(url="https://example.com", crypto_type="jwt")
        assert ep.evidence == []

    def test_custom_detected_algorithms(self):
        ep = CryptoEndpoint(
            url="https://example.com",
            crypto_type="hash",
            detected_algorithms=["md5", "sha1"],
        )
        assert ep.detected_algorithms == ["md5", "sha1"]

    def test_custom_evidence(self):
        ep = CryptoEndpoint(
            url="https://example.com",
            crypto_type="password",
            evidence=["Found MD5 hash in response body"],
        )
        assert ep.evidence == ["Found MD5 hash in response body"]

    def test_all_crypto_types(self):
        """Verify dataclass accepts all expected crypto_type values."""
        for ctype in ["hash", "encrypt", "jwt", "password", "random"]:
            ep = CryptoEndpoint(url="https://example.com", crypto_type=ctype)
            assert ep.crypto_type == ctype

    def test_default_lists_are_independent(self):
        """Verify default mutable lists are not shared between instances."""
        ep1 = CryptoEndpoint(url="https://a.com", crypto_type="hash")
        ep2 = CryptoEndpoint(url="https://b.com", crypto_type="hash")
        ep1.detected_algorithms.append("md5")
        assert ep2.detected_algorithms == []


class TestCryptoTestResult:
    """Test CryptoTestResult dataclass."""

    def test_basic_creation(self):
        result = CryptoTestResult(
            vulnerable=True,
            vuln_type=CryptoVulnType.WEAK_HASH,
            confidence=85,
            algorithm="md5",
        )
        assert result.vulnerable is True
        assert result.vuln_type == CryptoVulnType.WEAK_HASH
        assert result.confidence == 85
        assert result.algorithm == "md5"

    def test_default_evidence(self):
        result = CryptoTestResult(
            vulnerable=False,
            vuln_type=CryptoVulnType.WEAK_ENCRYPTION,
            confidence=0,
            algorithm="aes-256-gcm",
        )
        assert result.evidence == []

    def test_default_severity(self):
        result = CryptoTestResult(
            vulnerable=True,
            vuln_type=CryptoVulnType.WEAK_JWT,
            confidence=90,
            algorithm="none",
        )
        assert result.severity == "MEDIUM"

    def test_default_cwe(self):
        result = CryptoTestResult(
            vulnerable=True,
            vuln_type=CryptoVulnType.WEAK_HASH,
            confidence=80,
            algorithm="sha1",
        )
        assert result.cwe == "CWE-327"

    def test_default_payload(self):
        result = CryptoTestResult(
            vulnerable=True,
            vuln_type=CryptoVulnType.PADDING_ORACLE,
            confidence=70,
            algorithm="aes-cbc",
        )
        assert result.payload == ""

    def test_default_response_data(self):
        result = CryptoTestResult(
            vulnerable=True,
            vuln_type=CryptoVulnType.HARDCODED_SECRET,
            confidence=95,
            algorithm="n/a",
        )
        assert result.response_data == ""

    def test_custom_severity(self):
        result = CryptoTestResult(
            vulnerable=True,
            vuln_type=CryptoVulnType.WEAK_JWT,
            confidence=95,
            algorithm="none",
            severity="CRITICAL",
        )
        assert result.severity == "CRITICAL"

    def test_custom_cwe(self):
        result = CryptoTestResult(
            vulnerable=True,
            vuln_type=CryptoVulnType.WEAK_JWT,
            confidence=90,
            algorithm="none",
            cwe="CWE-347",
        )
        assert result.cwe == "CWE-347"

    def test_full_construction(self):
        result = CryptoTestResult(
            vulnerable=True,
            vuln_type=CryptoVulnType.HARDCODED_SECRET,
            confidence=100,
            algorithm="plaintext",
            evidence=["Found api_key=ABCDEF1234567890 in response"],
            severity="HIGH",
            cwe="CWE-798",
            payload="GET /config HTTP/1.1",
            response_data='{"api_key": "ABCDEF1234567890"}',
        )
        assert result.vulnerable is True
        assert result.vuln_type == CryptoVulnType.HARDCODED_SECRET
        assert result.confidence == 100
        assert result.algorithm == "plaintext"
        assert len(result.evidence) == 1
        assert result.severity == "HIGH"
        assert result.cwe == "CWE-798"
        assert result.payload == "GET /config HTTP/1.1"
        assert "api_key" in result.response_data

    def test_not_vulnerable_result(self):
        result = CryptoTestResult(
            vulnerable=False,
            vuln_type=CryptoVulnType.WEAK_HASH,
            confidence=0,
            algorithm="sha256",
        )
        assert result.vulnerable is False
        assert result.confidence == 0

    def test_default_lists_are_independent(self):
        """Verify default mutable lists are not shared between instances."""
        r1 = CryptoTestResult(
            vulnerable=True,
            vuln_type=CryptoVulnType.WEAK_HASH,
            confidence=80,
            algorithm="md5",
        )
        r2 = CryptoTestResult(
            vulnerable=True,
            vuln_type=CryptoVulnType.WEAK_HASH,
            confidence=80,
            algorithm="md5",
        )
        r1.evidence.append("test")
        assert r2.evidence == []


# =============================================================================
# WEAK_HASH_PATTERNS TESTS
# =============================================================================

class TestWeakHashPatterns:
    """Test WEAK_HASH_PATTERNS dict."""

    def test_has_md5_key(self):
        assert "md5" in WEAK_HASH_PATTERNS

    def test_has_sha1_key(self):
        assert "sha1" in WEAK_HASH_PATTERNS

    def test_md5_patterns_is_list(self):
        assert isinstance(WEAK_HASH_PATTERNS["md5"], list)

    def test_sha1_patterns_is_list(self):
        assert isinstance(WEAK_HASH_PATTERNS["sha1"], list)

    def test_md5_patterns_not_empty(self):
        assert len(WEAK_HASH_PATTERNS["md5"]) > 0

    def test_sha1_patterns_not_empty(self):
        assert len(WEAK_HASH_PATTERNS["sha1"]) > 0

    def test_all_md5_patterns_compile(self):
        for pattern in WEAK_HASH_PATTERNS["md5"]:
            compiled = re.compile(pattern)
            assert compiled is not None

    def test_all_sha1_patterns_compile(self):
        for pattern in WEAK_HASH_PATTERNS["sha1"]:
            compiled = re.compile(pattern)
            assert compiled is not None

    # -- MD5 pattern matching --

    def test_md5_hex_match(self):
        """MD5 hex pattern matches a 32-char hex string."""
        pattern = re.compile(WEAK_HASH_PATTERNS["md5"][0])
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        assert pattern.search(md5_hash)

    def test_md5_function_call_lowercase(self):
        """MD5 function pattern matches md5( call."""
        pattern = re.compile(WEAK_HASH_PATTERNS["md5"][1])
        assert pattern.search("var hash = md5(input)")

    def test_md5_function_call_uppercase(self):
        """MD5 function pattern matches MD5( call."""
        pattern = re.compile(WEAK_HASH_PATTERNS["md5"][2])
        assert pattern.search('result = MD5("password")')

    def test_md5_hash_type_json(self):
        """MD5 hash_type pattern matches JSON response."""
        pattern = re.compile(WEAK_HASH_PATTERNS["md5"][3])
        assert pattern.search('{"hash_type": "md5", "value": "abc"}')

    def test_md5_algorithm_assignment(self):
        """MD5 algorithm assignment pattern matches config."""
        pattern = re.compile(WEAK_HASH_PATTERNS["md5"][4])
        assert pattern.search('algorithm = md5')
        assert pattern.search("algorithm: md5")
        assert pattern.search('algorithm"  :  "md5')

    # -- SHA1 pattern matching --

    def test_sha1_hex_match(self):
        """SHA1 hex pattern matches a 40-char hex string."""
        pattern = re.compile(WEAK_HASH_PATTERNS["sha1"][0])
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        assert pattern.search(sha1_hash)

    def test_sha1_function_call_lowercase(self):
        """SHA1 function pattern matches sha1( call."""
        pattern = re.compile(WEAK_HASH_PATTERNS["sha1"][1])
        assert pattern.search("sha1(data)")

    def test_sha1_function_call_uppercase(self):
        """SHA1 function pattern matches SHA1( call."""
        pattern = re.compile(WEAK_HASH_PATTERNS["sha1"][2])
        assert pattern.search("SHA1(message)")

    def test_sha1_hash_type_json(self):
        """SHA1 hash_type pattern matches JSON response."""
        pattern = re.compile(WEAK_HASH_PATTERNS["sha1"][3])
        assert pattern.search('{"hash_type": "sha1"}')

    def test_sha1_algorithm_assignment(self):
        """SHA1 algorithm assignment pattern matches config."""
        pattern = re.compile(WEAK_HASH_PATTERNS["sha1"][4])
        assert pattern.search("algorithm = sha1")
        assert pattern.search("algorithm: sha1")


# =============================================================================
# WEAK_PASSWORD_HASH_PATTERNS TESTS
# =============================================================================

class TestWeakPasswordHashPatterns:
    """Test WEAK_PASSWORD_HASH_PATTERNS dict."""

    def test_count(self):
        assert len(WEAK_PASSWORD_HASH_PATTERNS) == 7

    def test_has_unsalted_md5(self):
        assert "unsalted_md5" in WEAK_PASSWORD_HASH_PATTERNS

    def test_has_unsalted_sha1(self):
        assert "unsalted_sha1" in WEAK_PASSWORD_HASH_PATTERNS

    def test_has_unsalted_sha256(self):
        assert "unsalted_sha256" in WEAK_PASSWORD_HASH_PATTERNS

    def test_has_mysql_old(self):
        assert "mysql_old" in WEAK_PASSWORD_HASH_PATTERNS

    def test_has_mysql_new(self):
        assert "mysql_new" in WEAK_PASSWORD_HASH_PATTERNS

    def test_has_des_crypt(self):
        assert "des_crypt" in WEAK_PASSWORD_HASH_PATTERNS

    def test_has_plaintext_base64(self):
        assert "plaintext_base64" in WEAK_PASSWORD_HASH_PATTERNS

    def test_all_patterns_compile(self):
        for name, pattern in WEAK_PASSWORD_HASH_PATTERNS.items():
            compiled = re.compile(pattern)
            assert compiled is not None, f"Pattern '{name}' failed to compile"

    def test_unsalted_md5_matches(self):
        """Matches a 32-char hex string (MD5)."""
        pattern = re.compile(WEAK_PASSWORD_HASH_PATTERNS["unsalted_md5"])
        assert pattern.match("d41d8cd98f00b204e9800998ecf8427e")

    def test_unsalted_md5_rejects_sha1(self):
        """Rejects a 40-char hex string (too long for MD5)."""
        pattern = re.compile(WEAK_PASSWORD_HASH_PATTERNS["unsalted_md5"])
        assert not pattern.match("da39a3ee5e6b4b0d3255bfef95601890afd80709")

    def test_unsalted_sha1_matches(self):
        """Matches a 40-char hex string (SHA1)."""
        pattern = re.compile(WEAK_PASSWORD_HASH_PATTERNS["unsalted_sha1"])
        assert pattern.match("da39a3ee5e6b4b0d3255bfef95601890afd80709")

    def test_unsalted_sha256_matches(self):
        """Matches a 64-char hex string (SHA256)."""
        pattern = re.compile(WEAK_PASSWORD_HASH_PATTERNS["unsalted_sha256"])
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert pattern.match(sha256_hash)

    def test_mysql_old_matches(self):
        """Matches MySQL old password format: *<40 hex chars>."""
        pattern = re.compile(WEAK_PASSWORD_HASH_PATTERNS["mysql_old"])
        assert pattern.match("*6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9")

    def test_mysql_old_rejects_no_star(self):
        """Rejects MySQL old without leading asterisk."""
        pattern = re.compile(WEAK_PASSWORD_HASH_PATTERNS["mysql_old"])
        assert not pattern.match("6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9")

    def test_des_crypt_matches(self):
        """Matches 13-char DES crypt string."""
        pattern = re.compile(WEAK_PASSWORD_HASH_PATTERNS["des_crypt"])
        assert pattern.match("abJnggxhB/yWI")

    def test_plaintext_base64_matches(self):
        """Matches base64-encoded plaintext."""
        pattern = re.compile(WEAK_PASSWORD_HASH_PATTERNS["plaintext_base64"])
        assert pattern.match("cGFzc3dvcmQ=")  # base64 of "password"


# =============================================================================
# STRONG_PASSWORD_HASH_PATTERNS TESTS
# =============================================================================

class TestStrongPasswordHashPatterns:
    """Test STRONG_PASSWORD_HASH_PATTERNS dict."""

    def test_count(self):
        assert len(STRONG_PASSWORD_HASH_PATTERNS) == 4

    def test_has_bcrypt(self):
        assert "bcrypt" in STRONG_PASSWORD_HASH_PATTERNS

    def test_has_scrypt(self):
        assert "scrypt" in STRONG_PASSWORD_HASH_PATTERNS

    def test_has_argon2(self):
        assert "argon2" in STRONG_PASSWORD_HASH_PATTERNS

    def test_has_pbkdf2(self):
        assert "pbkdf2" in STRONG_PASSWORD_HASH_PATTERNS

    def test_all_patterns_compile(self):
        for name, pattern in STRONG_PASSWORD_HASH_PATTERNS.items():
            compiled = re.compile(pattern)
            assert compiled is not None, f"Pattern '{name}' failed to compile"

    def test_bcrypt_matches(self):
        """Matches a bcrypt hash ($2b variant, 53-char body)."""
        pattern = re.compile(STRONG_PASSWORD_HASH_PATTERNS["bcrypt"])
        # 53 chars after $2b$12$: 22 salt + 31 hash
        bcrypt_hash = "$2b$12$WApznUPhDubN0oeveSXHp.eRfx4gSEOzMMwPnPOSGaIXkBmSAGNCe"
        assert pattern.match(bcrypt_hash)

    def test_bcrypt_matches_variant_a(self):
        """Matches bcrypt $2a$ variant."""
        pattern = re.compile(STRONG_PASSWORD_HASH_PATTERNS["bcrypt"])
        bcrypt_hash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
        assert pattern.match(bcrypt_hash)

    def test_scrypt_matches(self):
        """Matches a scrypt hash prefix."""
        pattern = re.compile(STRONG_PASSWORD_HASH_PATTERNS["scrypt"])
        assert pattern.match("$scrypt$n=16384,r=8,p=1$salt$hash")

    def test_argon2_matches_argon2id(self):
        """Matches argon2id variant."""
        pattern = re.compile(STRONG_PASSWORD_HASH_PATTERNS["argon2"])
        assert pattern.match("$argon2id$v=19$m=65536,t=3,p=4$salt$hash")

    def test_argon2_matches_argon2i(self):
        """Matches argon2i variant."""
        pattern = re.compile(STRONG_PASSWORD_HASH_PATTERNS["argon2"])
        assert pattern.match("$argon2i$v=19$m=65536,t=3,p=4$salt$hash")

    def test_argon2_matches_argon2d(self):
        """Matches argon2d variant."""
        pattern = re.compile(STRONG_PASSWORD_HASH_PATTERNS["argon2"])
        assert pattern.match("$argon2d$v=19$m=65536,t=3,p=4$salt$hash")

    def test_pbkdf2_sha256_matches(self):
        """Matches PBKDF2-SHA256."""
        pattern = re.compile(STRONG_PASSWORD_HASH_PATTERNS["pbkdf2"])
        assert pattern.match("$pbkdf2-sha256$29000$salt$hash")

    def test_pbkdf2_sha512_matches(self):
        """Matches PBKDF2-SHA512."""
        pattern = re.compile(STRONG_PASSWORD_HASH_PATTERNS["pbkdf2"])
        assert pattern.match("$pbkdf2-sha512$29000$salt$hash")

    def test_strong_patterns_reject_weak_hashes(self):
        """Strong patterns should NOT match plain MD5/SHA1 hashes."""
        weak_md5 = "d41d8cd98f00b204e9800998ecf8427e"
        weak_sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        for name, pattern in STRONG_PASSWORD_HASH_PATTERNS.items():
            compiled = re.compile(pattern)
            assert not compiled.match(weak_md5), f"{name} matched MD5"
            assert not compiled.match(weak_sha1), f"{name} matched SHA1"


# =============================================================================
# HARDCODED_SECRET_PATTERNS TESTS
# =============================================================================

class TestHardcodedSecretPatterns:
    """Test HARDCODED_SECRET_PATTERNS list."""

    def test_minimum_count(self):
        assert len(HARDCODED_SECRET_PATTERNS) >= 8

    def test_is_list(self):
        assert isinstance(HARDCODED_SECRET_PATTERNS, list)

    def test_all_patterns_compile(self):
        for i, pattern in enumerate(HARDCODED_SECRET_PATTERNS):
            compiled = re.compile(pattern)
            assert compiled is not None, f"Pattern at index {i} failed to compile"

    def test_api_key_match(self):
        """Detects api_key in assignment."""
        matched = False
        text = 'api_key = "ABCDEF1234567890ABCDEF"'
        for pattern in HARDCODED_SECRET_PATTERNS:
            if re.search(pattern, text):
                matched = True
                break
        assert matched, f"No pattern matched api_key assignment: {text}"

    def test_secret_key_match(self):
        """Detects secret_key in assignment."""
        matched = False
        text = 'secret_key: "SuperSecretKey12345678"'
        for pattern in HARDCODED_SECRET_PATTERNS:
            if re.search(pattern, text):
                matched = True
                break
        assert matched, f"No pattern matched secret_key assignment: {text}"

    def test_aws_access_key_match(self):
        """Detects AWS access key (AKIA...)."""
        matched = False
        text = "aws_key = AKIAIOSFODNN7EXAMPLE"
        for pattern in HARDCODED_SECRET_PATTERNS:
            if re.search(pattern, text):
                matched = True
                break
        assert matched, f"No pattern matched AWS key: {text}"

    def test_jwt_secret_match(self):
        """Detects jwt_secret assignment."""
        matched = False
        text = 'jwt_secret = "MyJwtSecretKey12345678"'
        for pattern in HARDCODED_SECRET_PATTERNS:
            if re.search(pattern, text):
                matched = True
                break
        assert matched, f"No pattern matched jwt_secret: {text}"

    def test_private_key_match(self):
        """Detects private_key assignment."""
        matched = False
        text = 'private_key = "MIIEvQIBADANBgkqhkiG"'
        for pattern in HARDCODED_SECRET_PATTERNS:
            if re.search(pattern, text):
                matched = True
                break
        assert matched, f"No pattern matched private_key: {text}"

    def test_encryption_key_match(self):
        """Detects encryption_key assignment."""
        matched = False
        text = '"encryption_key": "aGVsbG93b3JsZDEyMzQ1"'
        for pattern in HARDCODED_SECRET_PATTERNS:
            if re.search(pattern, text):
                matched = True
                break
        assert matched, f"No pattern matched encryption_key: {text}"

    def test_db_password_match(self):
        """Detects database password in config."""
        matched = False
        text = 'db_password = "MyDbPassword123"'
        for pattern in HARDCODED_SECRET_PATTERNS:
            if re.search(pattern, text):
                matched = True
                break
        assert matched, f"No pattern matched db_password: {text}"

    def test_iv_match(self):
        """Detects hardcoded initialization vector."""
        matched = False
        text = '"iv": "0123456789abcdef0123"'
        for pattern in HARDCODED_SECRET_PATTERNS:
            if re.search(pattern, text):
                matched = True
                break
        assert matched, f"No pattern matched IV: {text}"

    def test_generic_password_match(self):
        """Detects generic password assignment."""
        matched = False
        text = 'password = "MyP@ssw0rd123"'
        for pattern in HARDCODED_SECRET_PATTERNS:
            if re.search(pattern, text):
                matched = True
                break
        assert matched, f"No pattern matched password: {text}"

    def test_aws_secret_access_key_match(self):
        """Detects AWS secret access key."""
        matched = False
        text = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        for pattern in HARDCODED_SECRET_PATTERNS:
            if re.search(pattern, text):
                matched = True
                break
        assert matched, f"No pattern matched aws_secret_access_key: {text}"


# =============================================================================
# CROSS-PATTERN DIFFERENTIATION TESTS
# =============================================================================

class TestPatternDifferentiation:
    """Test that weak vs. strong pattern sets are correctly separated."""

    def test_bcrypt_not_matched_by_weak_patterns(self):
        """Bcrypt hash should not match weak password hash patterns."""
        bcrypt_hash = "$2b$12$WApznUPhDubN0oeveSXHp.Rfx4gSEOzMMwPnPOSGaIXkBmSAGNCe"
        for name, pattern in WEAK_PASSWORD_HASH_PATTERNS.items():
            assert not re.match(pattern, bcrypt_hash), (
                f"Weak pattern '{name}' incorrectly matched bcrypt hash"
            )

    def test_argon2_not_matched_by_weak_patterns(self):
        """Argon2 hash should not match weak password hash patterns."""
        argon2_hash = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$hash"
        for name, pattern in WEAK_PASSWORD_HASH_PATTERNS.items():
            assert not re.match(pattern, argon2_hash), (
                f"Weak pattern '{name}' incorrectly matched argon2 hash"
            )

    def test_plain_md5_not_matched_by_strong_patterns(self):
        """Plain MD5 should not match strong password hash patterns."""
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        for name, pattern in STRONG_PASSWORD_HASH_PATTERNS.items():
            assert not re.match(pattern, md5_hash), (
                f"Strong pattern '{name}' incorrectly matched plain MD5"
            )

    def test_plain_md5_matched_by_weak_patterns(self):
        """Plain MD5 should match the unsalted_md5 weak pattern."""
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        pattern = re.compile(WEAK_PASSWORD_HASH_PATTERNS["unsalted_md5"])
        assert pattern.match(md5_hash)

    def test_plain_sha1_matched_by_weak_patterns(self):
        """Plain SHA1 should match the unsalted_sha1 weak pattern."""
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        pattern = re.compile(WEAK_PASSWORD_HASH_PATTERNS["unsalted_sha1"])
        assert pattern.match(sha1_hash)
