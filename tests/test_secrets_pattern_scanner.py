"""
Tests for scanning/modules/secrets_pattern_scanner.py

Covers:
- SecretPattern dataclass (defaults, full creation, fields)
- Pattern list constants (AWS, GCP, Azure, Payment, Communication,
  Database, OAuth, Generic, JWT, Infrastructure)
- ALL_SECRET_PATTERNS aggregate list
- SecretsPatternScanner class identity and attributes
- ScanModule subclass verification
- Regex compilation and positive/negative matching
- Entropy calculation (_calculate_entropy)
- Secret redaction (_redact_secret)
- Secret validation (_validate_secret)
- Context extraction (_extract_context)

Run with: pytest tests/test_secrets_pattern_scanner.py -v
"""

import math
import re

import pytest

from scanning.modules.secrets_pattern_scanner import (
    ALL_SECRET_PATTERNS,
    AWS_PATTERNS,
    AZURE_PATTERNS,
    COMMUNICATION_PATTERNS,
    DATABASE_PATTERNS,
    GCP_PATTERNS,
    GENERIC_PATTERNS,
    INFRASTRUCTURE_PATTERNS,
    JWT_PATTERNS,
    OAUTH_PATTERNS,
    PAYMENT_PATTERNS,
    SecretPattern,
    SecretsPatternScanner,
)


MOCK_SETTINGS = {"target_url": "http://test.local", "safety_level": "safe"}


# =============================================================================
# SECRETPATTERN DATACLASS
# =============================================================================

class TestSecretPatternDataclass:
    """Test SecretPattern dataclass creation and defaults."""

    def test_minimal_creation(self):
        sp = SecretPattern(
            name="test",
            pattern=r"test_\d+",
            severity="HIGH",
            description="A test pattern",
        )
        assert sp.name == "test"
        assert sp.pattern == r"test_\d+"
        assert sp.severity == "HIGH"
        assert sp.description == "A test pattern"

    def test_default_min_entropy(self):
        sp = SecretPattern(name="x", pattern="x", severity="LOW", description="x")
        assert sp.min_entropy == 3.0

    def test_default_validators(self):
        sp = SecretPattern(name="x", pattern="x", severity="LOW", description="x")
        assert sp.validators == []
        assert isinstance(sp.validators, list)

    def test_default_false_positive_patterns(self):
        sp = SecretPattern(name="x", pattern="x", severity="LOW", description="x")
        assert sp.false_positive_patterns == []
        assert isinstance(sp.false_positive_patterns, list)

    def test_custom_min_entropy(self):
        sp = SecretPattern(
            name="x", pattern="x", severity="LOW", description="x",
            min_entropy=4.5,
        )
        assert sp.min_entropy == 4.5

    def test_custom_validators(self):
        sp = SecretPattern(
            name="x", pattern="x", severity="LOW", description="x",
            validators=["v1", "v2"],
        )
        assert sp.validators == ["v1", "v2"]

    def test_custom_false_positive_patterns(self):
        sp = SecretPattern(
            name="x", pattern="x", severity="LOW", description="x",
            false_positive_patterns=["fp1"],
        )
        assert sp.false_positive_patterns == ["fp1"]

    def test_field_types(self):
        sp = SecretPattern(name="n", pattern="p", severity="s", description="d")
        assert isinstance(sp.name, str)
        assert isinstance(sp.pattern, str)
        assert isinstance(sp.severity, str)
        assert isinstance(sp.description, str)
        assert isinstance(sp.min_entropy, float)
        assert isinstance(sp.validators, list)
        assert isinstance(sp.false_positive_patterns, list)

    def test_independent_defaults(self):
        """Default mutable fields should be independent across instances."""
        sp1 = SecretPattern(name="a", pattern="a", severity="a", description="a")
        sp2 = SecretPattern(name="b", pattern="b", severity="b", description="b")
        sp1.validators.append("added")
        assert sp2.validators == []
        sp1.false_positive_patterns.append("added")
        assert sp2.false_positive_patterns == []


# =============================================================================
# PATTERN LIST CONSTANTS — COUNTS AND KEY ENTRIES
# =============================================================================

class TestAWSPatterns:
    """Test AWS_PATTERNS list."""

    def test_count(self):
        assert len(AWS_PATTERNS) == 3

    def test_all_are_secret_pattern(self):
        for sp in AWS_PATTERNS:
            assert isinstance(sp, SecretPattern)

    def test_names(self):
        names = {sp.name for sp in AWS_PATTERNS}
        assert "AWS Access Key ID" in names
        assert "AWS Secret Access Key" in names
        assert "AWS Session Token" in names

    def test_severities(self):
        sev = {sp.name: sp.severity for sp in AWS_PATTERNS}
        assert sev["AWS Access Key ID"] == "CRITICAL"
        assert sev["AWS Secret Access Key"] == "CRITICAL"
        assert sev["AWS Session Token"] == "HIGH"


class TestGCPPatterns:
    """Test GCP_PATTERNS list."""

    def test_count(self):
        assert len(GCP_PATTERNS) == 3

    def test_all_are_secret_pattern(self):
        for sp in GCP_PATTERNS:
            assert isinstance(sp, SecretPattern)

    def test_names(self):
        names = {sp.name for sp in GCP_PATTERNS}
        assert "GCP API Key" in names
        assert "GCP Service Account" in names
        assert "GCP OAuth Client Secret" in names

    def test_gcp_service_account_zero_entropy(self):
        sa = [sp for sp in GCP_PATTERNS if sp.name == "GCP Service Account"][0]
        assert sa.min_entropy == 0


class TestAzurePatterns:
    """Test AZURE_PATTERNS list."""

    def test_count(self):
        assert len(AZURE_PATTERNS) == 4

    def test_all_are_secret_pattern(self):
        for sp in AZURE_PATTERNS:
            assert isinstance(sp, SecretPattern)

    def test_names(self):
        names = {sp.name for sp in AZURE_PATTERNS}
        assert "Azure Storage Account Key" in names
        assert "Azure Connection String" in names
        assert "Azure SAS Token" in names
        assert "Azure AD Client Secret" in names

    def test_connection_string_zero_entropy(self):
        cs = [sp for sp in AZURE_PATTERNS if sp.name == "Azure Connection String"][0]
        assert cs.min_entropy == 0


class TestPaymentPatterns:
    """Test PAYMENT_PATTERNS list."""

    def test_count(self):
        assert len(PAYMENT_PATTERNS) == 6

    def test_all_are_secret_pattern(self):
        for sp in PAYMENT_PATTERNS:
            assert isinstance(sp, SecretPattern)

    def test_key_names(self):
        names = {sp.name for sp in PAYMENT_PATTERNS}
        assert "Stripe Secret Key" in names
        assert "Stripe Test Secret Key" in names
        assert "Stripe Publishable Key" in names
        assert "PayPal Client Secret" in names
        assert "Square Access Token" in names
        assert "Square OAuth Secret" in names

    def test_stripe_live_is_critical(self):
        sk = [sp for sp in PAYMENT_PATTERNS if sp.name == "Stripe Secret Key"][0]
        assert sk.severity == "CRITICAL"

    def test_stripe_test_is_medium(self):
        sk = [sp for sp in PAYMENT_PATTERNS if sp.name == "Stripe Test Secret Key"][0]
        assert sk.severity == "MEDIUM"


class TestCommunicationPatterns:
    """Test COMMUNICATION_PATTERNS list."""

    def test_count(self):
        assert len(COMMUNICATION_PATTERNS) == 11

    def test_all_are_secret_pattern(self):
        for sp in COMMUNICATION_PATTERNS:
            assert isinstance(sp, SecretPattern)

    def test_key_names(self):
        names = {sp.name for sp in COMMUNICATION_PATTERNS}
        assert "Twilio Account SID" in names
        assert "Twilio Auth Token" in names
        assert "SendGrid API Key" in names
        assert "Mailgun API Key" in names
        assert "Slack Bot Token" in names
        assert "Slack Webhook URL" in names
        assert "Discord Bot Token" in names
        assert "Discord Webhook URL" in names

    def test_twilio_sid_severity(self):
        sid = [sp for sp in COMMUNICATION_PATTERNS if sp.name == "Twilio Account SID"][0]
        assert sid.severity == "MEDIUM"


class TestDatabasePatterns:
    """Test DATABASE_PATTERNS list."""

    def test_count(self):
        assert len(DATABASE_PATTERNS) == 5

    def test_all_are_secret_pattern(self):
        for sp in DATABASE_PATTERNS:
            assert isinstance(sp, SecretPattern)

    def test_names(self):
        names = {sp.name for sp in DATABASE_PATTERNS}
        assert "PostgreSQL Connection String" in names
        assert "MySQL Connection String" in names
        assert "MongoDB Connection String" in names
        assert "Redis Connection String" in names
        assert "JDBC Connection String" in names

    def test_all_critical(self):
        for sp in DATABASE_PATTERNS:
            assert sp.severity == "CRITICAL", f"{sp.name} should be CRITICAL"

    def test_all_zero_entropy(self):
        for sp in DATABASE_PATTERNS:
            assert sp.min_entropy == 0, f"{sp.name} should have min_entropy=0"

    def test_postgres_false_positives(self):
        pg = [sp for sp in DATABASE_PATTERNS if sp.name == "PostgreSQL Connection String"][0]
        assert len(pg.false_positive_patterns) > 0
        assert "postgres://user:password@" in pg.false_positive_patterns


class TestOAuthPatterns:
    """Test OAUTH_PATTERNS list."""

    def test_count(self):
        assert len(OAUTH_PATTERNS) == 10

    def test_all_are_secret_pattern(self):
        for sp in OAUTH_PATTERNS:
            assert isinstance(sp, SecretPattern)

    def test_key_names(self):
        names = {sp.name for sp in OAUTH_PATTERNS}
        assert "GitHub Personal Access Token" in names
        assert "GitHub OAuth Access Token" in names
        assert "GitHub App Token" in names
        assert "GitLab Personal Access Token" in names
        assert "Facebook Access Token" in names
        assert "Facebook App Secret" in names
        assert "Twitter API Key" in names
        assert "Twitter API Secret" in names
        assert "Twitter Bearer Token" in names
        assert "LinkedIn Client Secret" in names


class TestGenericPatterns:
    """Test GENERIC_PATTERNS list."""

    def test_count(self):
        assert len(GENERIC_PATTERNS) == 8

    def test_all_are_secret_pattern(self):
        for sp in GENERIC_PATTERNS:
            assert isinstance(sp, SecretPattern)

    def test_key_names(self):
        names = {sp.name for sp in GENERIC_PATTERNS}
        assert "Generic API Key" in names
        assert "Generic Secret Key" in names
        assert "Generic Auth Token" in names
        assert "Generic Password Field" in names
        assert "Private Key (PEM)" in names
        assert "Private Key (Encrypted)" in names
        assert "Basic Auth Header" in names
        assert "Bearer Token Header" in names

    def test_private_key_pem_zero_entropy(self):
        pk = [sp for sp in GENERIC_PATTERNS if sp.name == "Private Key (PEM)"][0]
        assert pk.min_entropy == 0
        assert pk.severity == "CRITICAL"

    def test_generic_api_key_false_positives(self):
        gak = [sp for sp in GENERIC_PATTERNS if sp.name == "Generic API Key"][0]
        assert "your_api_key" in gak.false_positive_patterns
        assert "YOUR_API_KEY" in gak.false_positive_patterns
        assert "<api_key>" in gak.false_positive_patterns


class TestJWTPatterns:
    """Test JWT_PATTERNS list."""

    def test_count(self):
        assert len(JWT_PATTERNS) == 1

    def test_name(self):
        assert JWT_PATTERNS[0].name == "JWT Token"

    def test_severity(self):
        assert JWT_PATTERNS[0].severity == "HIGH"


class TestInfrastructurePatterns:
    """Test INFRASTRUCTURE_PATTERNS list."""

    def test_count(self):
        assert len(INFRASTRUCTURE_PATTERNS) == 8

    def test_all_are_secret_pattern(self):
        for sp in INFRASTRUCTURE_PATTERNS:
            assert isinstance(sp, SecretPattern)

    def test_key_names(self):
        names = {sp.name for sp in INFRASTRUCTURE_PATTERNS}
        assert "Heroku API Key" in names
        assert "DigitalOcean Personal Access Token" in names
        assert "DigitalOcean OAuth Token" in names
        assert "Cloudflare API Key" in names
        assert "Cloudflare API Token" in names
        assert "NPM Access Token" in names
        assert "PyPI API Token" in names
        assert "Docker Hub Token" in names


# =============================================================================
# ALL_SECRET_PATTERNS AGGREGATE
# =============================================================================

class TestAllSecretPatterns:
    """Test the aggregate ALL_SECRET_PATTERNS list."""

    def test_total_count(self):
        expected = (
            len(AWS_PATTERNS)
            + len(GCP_PATTERNS)
            + len(AZURE_PATTERNS)
            + len(PAYMENT_PATTERNS)
            + len(COMMUNICATION_PATTERNS)
            + len(DATABASE_PATTERNS)
            + len(OAUTH_PATTERNS)
            + len(GENERIC_PATTERNS)
            + len(JWT_PATTERNS)
            + len(INFRASTRUCTURE_PATTERNS)
        )
        assert len(ALL_SECRET_PATTERNS) == expected

    def test_total_count_numeric(self):
        # 3+3+4+6+11+5+10+8+1+8 = 59
        assert len(ALL_SECRET_PATTERNS) == 59

    def test_all_are_secret_pattern(self):
        for sp in ALL_SECRET_PATTERNS:
            assert isinstance(sp, SecretPattern)

    def test_unique_names(self):
        names = [sp.name for sp in ALL_SECRET_PATTERNS]
        assert len(names) == len(set(names)), "Pattern names must be unique"

    def test_severities_are_valid(self):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for sp in ALL_SECRET_PATTERNS:
            assert sp.severity in valid, f"{sp.name} has invalid severity '{sp.severity}'"

    def test_all_have_descriptions(self):
        for sp in ALL_SECRET_PATTERNS:
            assert sp.description, f"{sp.name} has empty description"

    def test_all_have_patterns(self):
        for sp in ALL_SECRET_PATTERNS:
            assert sp.pattern, f"{sp.name} has empty pattern"


# =============================================================================
# SCANNER CLASS IDENTITY
# =============================================================================

class TestSecretsPatternScannerClass:
    """Test SecretsPatternScanner class identity and attributes."""

    def test_is_scan_module_subclass(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(SecretsPatternScanner, ScanModule)

    def test_name_attribute(self):
        assert SecretsPatternScanner.name == "secrets_pattern"

    def test_description_attribute(self):
        assert SecretsPatternScanner.description
        assert isinstance(SecretsPatternScanner.description, str)

    def test_version_attribute(self):
        assert SecretsPatternScanner.version == "1.0.0"

    def test_author_attribute(self):
        assert SecretsPatternScanner.author == "PHANTOM AI"

    def test_tags_attribute(self):
        tags = SecretsPatternScanner.tags
        assert isinstance(tags, list)
        assert "secrets" in tags
        assert "credentials" in tags
        assert "api_keys" in tags
        assert "tokens" in tags


class TestSecretsPatternScannerInstance:
    """Test SecretsPatternScanner instance attributes."""

    def test_instantiation(self):
        scanner = SecretsPatternScanner(MOCK_SETTINGS)
        assert scanner is not None

    def test_timeout_default(self):
        scanner = SecretsPatternScanner(MOCK_SETTINGS)
        assert scanner.timeout == 10.0

    def test_max_concurrent_default(self):
        scanner = SecretsPatternScanner(MOCK_SETTINGS)
        assert scanner.max_concurrent == 10

    def test_compiled_patterns_populated(self):
        scanner = SecretsPatternScanner(MOCK_SETTINGS)
        assert len(scanner._compiled_patterns) > 0

    def test_all_patterns_compiled(self):
        scanner = SecretsPatternScanner(MOCK_SETTINGS)
        for sp in ALL_SECRET_PATTERNS:
            assert sp.name in scanner._compiled_patterns, (
                f"Pattern '{sp.name}' was not compiled"
            )

    def test_compiled_patterns_are_regex(self):
        scanner = SecretsPatternScanner(MOCK_SETTINGS)
        for name, compiled in scanner._compiled_patterns.items():
            assert isinstance(compiled, re.Pattern), (
                f"'{name}' is not a compiled regex"
            )


# =============================================================================
# REGEX PATTERNS — POSITIVE AND NEGATIVE MATCHES
# =============================================================================

class TestRegexAWSAccessKeyID:
    """Test AWS Access Key ID regex pattern."""

    def _pattern(self):
        sp = [p for p in AWS_PATTERNS if p.name == "AWS Access Key ID"][0]
        return re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)

    def test_matches_akia_prefix(self):
        p = self._pattern()
        assert p.search(" AKIAIOSFODNN7EXAMPLE ")

    def test_matches_asia_prefix(self):
        p = self._pattern()
        assert p.search(" ASIAJEXAMPLEEXAM1234 ")

    def test_no_match_short_key(self):
        p = self._pattern()
        assert not p.search(" AKIA12345 ")

    def test_no_match_random_string(self):
        p = self._pattern()
        assert not p.search("just_some_random_text")


class TestRegexStripeSecretKey:
    """Test Stripe Secret Key regex pattern."""

    def _pattern(self):
        sp = [p for p in PAYMENT_PATTERNS if p.name == "Stripe Secret Key"][0]
        return re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)

    def test_matches_live_key(self):
        p = self._pattern()
        assert p.search("sk_live_4eC39HqLyjWDarjtT1zdp7dc")

    def test_no_match_test_key(self):
        p = self._pattern()
        assert not p.search("sk_test_4eC39HqLyjWDarjtT1zdp7dc")

    def test_no_match_short(self):
        p = self._pattern()
        assert not p.search("sk_live_short")


class TestRegexStripeTestKey:
    """Test Stripe Test Secret Key regex pattern."""

    def _pattern(self):
        sp = [p for p in PAYMENT_PATTERNS if p.name == "Stripe Test Secret Key"][0]
        return re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)

    def test_matches_test_key(self):
        p = self._pattern()
        assert p.search("sk_test_4eC39HqLyjWDarjtT1zdp7dc")

    def test_no_match_live_key(self):
        p = self._pattern()
        assert not p.search("sk_live_4eC39HqLyjWDarjtT1zdp7dc")


class TestRegexGCPAPIKey:
    """Test GCP API Key regex pattern."""

    def _pattern(self):
        sp = [p for p in GCP_PATTERNS if p.name == "GCP API Key"][0]
        return re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)

    def test_matches_valid_key(self):
        p = self._pattern()
        assert p.search("AIzaSyA1234567890abcdefghijklmnopqrstuv")

    def test_no_match_wrong_prefix(self):
        p = self._pattern()
        assert not p.search("BIzaSyA1234567890abcdefghijklmnopqrstuv")


class TestRegexSendGridKey:
    """Test SendGrid API Key regex pattern."""

    def _pattern(self):
        sp = [p for p in COMMUNICATION_PATTERNS if p.name == "SendGrid API Key"][0]
        return re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)

    def test_matches_valid_key(self):
        p = self._pattern()
        assert p.search("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")

    def test_no_match_missing_dot(self):
        p = self._pattern()
        assert not p.search("SGngeVfQFYQlKU0ufo8x5d1ATwL2iGABf9")


class TestRegexGitHubPAT:
    """Test GitHub Personal Access Token regex pattern."""

    def _pattern(self):
        sp = [p for p in OAUTH_PATTERNS if p.name == "GitHub Personal Access Token"][0]
        return re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)

    def test_matches_valid_token(self):
        p = self._pattern()
        assert p.search("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")

    def test_no_match_wrong_prefix(self):
        p = self._pattern()
        assert not p.search("gxx_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij")


class TestRegexGitLabPAT:
    """Test GitLab Personal Access Token regex pattern."""

    def _pattern(self):
        sp = [p for p in OAUTH_PATTERNS if sp.name == "GitLab Personal Access Token" for sp in OAUTH_PATTERNS][0]
        return re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)

    def test_matches_valid(self):
        sp = [p for p in OAUTH_PATTERNS if p.name == "GitLab Personal Access Token"][0]
        p = re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)
        assert p.search("glpat-abcdefghij1234567890")

    def test_no_match_wrong_prefix(self):
        sp = [p for p in OAUTH_PATTERNS if p.name == "GitLab Personal Access Token"][0]
        p = re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)
        assert not p.search("glxxx-abcdefghij1234567890")


class TestRegexJWT:
    """Test JWT Token regex pattern."""

    def _pattern(self):
        sp = JWT_PATTERNS[0]
        return re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)

    def test_matches_valid_jwt(self):
        p = self._pattern()
        # Standard JWT structure: header.payload.signature
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.abc123def456"
        assert p.search(jwt)

    def test_no_match_missing_parts(self):
        p = self._pattern()
        assert not p.search("eyJhbGciOiJIUzI1NiJ9.notavalidjwt")

    def test_no_match_random(self):
        p = self._pattern()
        assert not p.search("this is not a jwt token at all")


class TestRegexPrivateKeyPEM:
    """Test Private Key PEM regex pattern."""

    def _pattern(self):
        sp = [p for p in GENERIC_PATTERNS if p.name == "Private Key (PEM)"][0]
        return re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)

    def test_matches_rsa_private_key(self):
        p = self._pattern()
        assert p.search("-----BEGIN RSA PRIVATE KEY-----")

    def test_matches_ec_private_key(self):
        p = self._pattern()
        assert p.search("-----BEGIN EC PRIVATE KEY-----")

    def test_matches_generic_private_key(self):
        p = self._pattern()
        assert p.search("-----BEGIN PRIVATE KEY-----")

    def test_no_match_public_key(self):
        p = self._pattern()
        assert not p.search("-----BEGIN PUBLIC KEY-----")


class TestRegexPostgresConnectionString:
    """Test PostgreSQL Connection String regex pattern."""

    def _pattern(self):
        sp = [p for p in DATABASE_PATTERNS if p.name == "PostgreSQL Connection String"][0]
        return re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)

    def test_matches_postgresql_uri(self):
        p = self._pattern()
        assert p.search("postgresql://admin:s3cret@db.example.com/mydb")

    def test_matches_postgres_uri(self):
        p = self._pattern()
        assert p.search("postgres://admin:s3cret@localhost/mydb")

    def test_no_match_without_credentials(self):
        p = self._pattern()
        assert not p.search("postgres://localhost/mydb")


class TestRegexMongoDBConnectionString:
    """Test MongoDB Connection String regex pattern."""

    def _pattern(self):
        sp = [p for p in DATABASE_PATTERNS if p.name == "MongoDB Connection String"][0]
        return re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)

    def test_matches_mongodb_uri(self):
        p = self._pattern()
        assert p.search("mongodb://admin:pass123@mongo.example.com")

    def test_matches_srv_uri(self):
        p = self._pattern()
        assert p.search("mongodb+srv://user:pass@cluster0.abc.mongodb.net")

    def test_no_match_without_credentials(self):
        p = self._pattern()
        assert not p.search("mongodb://localhost")


class TestRegexSlackBotToken:
    """Test Slack Bot Token regex pattern."""

    def _pattern(self):
        sp = [p for p in COMMUNICATION_PATTERNS if p.name == "Slack Bot Token"][0]
        return re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)

    def test_matches_valid_token(self):
        p = self._pattern()
        assert p.search("xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx")

    def test_no_match_wrong_prefix(self):
        p = self._pattern()
        assert not p.search("xoxa-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx")


class TestRegexNPMToken:
    """Test NPM Access Token regex pattern."""

    def _pattern(self):
        sp = [p for p in INFRASTRUCTURE_PATTERNS if p.name == "NPM Access Token"][0]
        return re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)

    def test_matches_valid_token(self):
        p = self._pattern()
        assert p.search("npm_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")

    def test_no_match_wrong_prefix(self):
        p = self._pattern()
        assert not p.search("npx_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")


class TestRegexBasicAuthHeader:
    """Test Basic Auth Header regex pattern."""

    def _pattern(self):
        sp = [p for p in GENERIC_PATTERNS if p.name == "Basic Auth Header"][0]
        return re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)

    def test_matches_valid_header(self):
        p = self._pattern()
        assert p.search("Authorization: Basic dXNlcjpwYXNz")

    def test_no_match_bearer(self):
        p = self._pattern()
        # Should not match the "Basic" part for a Bearer header
        m = p.search("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9")
        assert not m


class TestRegexDockerHubToken:
    """Test Docker Hub Token regex pattern."""

    def _pattern(self):
        sp = [p for p in INFRASTRUCTURE_PATTERNS if sp.name == "Docker Hub Token" for sp in INFRASTRUCTURE_PATTERNS][0]
        return re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)

    def test_matches_valid(self):
        sp = [p for p in INFRASTRUCTURE_PATTERNS if p.name == "Docker Hub Token"][0]
        p = re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)
        assert p.search("dckr_pat_ABCDEFghijklmnop1234567890a")

    def test_no_match_wrong_prefix(self):
        sp = [p for p in INFRASTRUCTURE_PATTERNS if p.name == "Docker Hub Token"][0]
        p = re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)
        assert not p.search("dock_pat_ABCDEFghijklmnop1234567890a")


class TestRegexMailgunKey:
    """Test Mailgun API Key regex pattern."""

    def _pattern(self):
        sp = [p for p in COMMUNICATION_PATTERNS if p.name == "Mailgun API Key"][0]
        return re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)

    def test_matches_valid(self):
        p = self._pattern()
        assert p.search("key-abcdef1234567890abcdef1234567890")

    def test_no_match_short(self):
        p = self._pattern()
        assert not p.search("key-abc123")


class TestRegexDigitalOceanPAT:
    """Test DigitalOcean Personal Access Token regex pattern."""

    def _pattern(self):
        sp = [p for p in INFRASTRUCTURE_PATTERNS if p.name == "DigitalOcean Personal Access Token"][0]
        return re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)

    def test_matches_valid(self):
        p = self._pattern()
        token = "dop_v1_" + "a" * 64
        assert p.search(token)

    def test_no_match_short(self):
        p = self._pattern()
        assert not p.search("dop_v1_abc123")


# =============================================================================
# ALL PATTERNS COMPILE
# =============================================================================

class TestAllPatternsCompile:
    """Verify every pattern in ALL_SECRET_PATTERNS compiles without error."""

    def test_all_compile(self):
        for sp in ALL_SECRET_PATTERNS:
            compiled = re.compile(sp.pattern, re.IGNORECASE | re.MULTILINE)
            assert compiled is not None, f"Failed to compile pattern for {sp.name}"

    def test_compiled_count_matches(self):
        scanner = SecretsPatternScanner(MOCK_SETTINGS)
        assert len(scanner._compiled_patterns) == len(ALL_SECRET_PATTERNS)


# =============================================================================
# ENTROPY CALCULATION
# =============================================================================

class TestEntropyCalculation:
    """Test _calculate_entropy method."""

    def _scanner(self):
        return SecretsPatternScanner(MOCK_SETTINGS)

    def test_empty_string(self):
        s = self._scanner()
        assert s._calculate_entropy("") == 0.0

    def test_single_char_repeated(self):
        s = self._scanner()
        assert s._calculate_entropy("aaaaaaa") == 0.0

    def test_two_distinct_chars_equal(self):
        s = self._scanner()
        # "ab" has entropy = 1.0
        assert abs(s._calculate_entropy("ab") - 1.0) < 0.01

    def test_high_entropy_random_string(self):
        s = self._scanner()
        # High-entropy string with many distinct characters
        val = "aB3$fG7!kL9@mN1#pQ5"
        ent = s._calculate_entropy(val)
        assert ent > 3.5

    def test_low_entropy_repeated(self):
        s = self._scanner()
        # "aaaaabbbbb" has low entropy
        ent = s._calculate_entropy("aaaaabbbbb")
        assert ent <= 1.1

    def test_entropy_non_negative(self):
        s = self._scanner()
        for text in ["test", "a", "abc123", ""]:
            assert s._calculate_entropy(text) >= 0.0


# =============================================================================
# SECRET REDACTION
# =============================================================================

class TestSecretRedaction:
    """Test _redact_secret method."""

    def _scanner(self):
        return SecretsPatternScanner(MOCK_SETTINGS)

    def test_short_secret_fully_redacted(self):
        s = self._scanner()
        result = s._redact_secret("abc")
        assert result == "***"

    def test_eight_char_fully_redacted(self):
        s = self._scanner()
        result = s._redact_secret("12345678")
        assert result == "********"

    def test_medium_secret_partial_redact(self):
        s = self._scanner()
        # 12 chars: first 2 + 8 stars + last 2
        result = s._redact_secret("abcdefghijkl")
        assert result.startswith("ab")
        assert result.endswith("kl")
        assert "*" in result

    def test_long_secret_partial_redact(self):
        s = self._scanner()
        # 30 chars: first 4 + 22 stars + last 4
        secret = "A" * 4 + "B" * 22 + "C" * 4
        result = s._redact_secret(secret)
        assert result.startswith("AAAA")  # first 4 of the original 30-char string
        assert result.endswith("CCCC")  # last 4 of the original 30-char string
        assert "****" in result

    def test_redacted_same_length_short(self):
        s = self._scanner()
        secret = "short"
        result = s._redact_secret(secret)
        assert len(result) == len(secret)

    def test_redacted_same_length_medium(self):
        s = self._scanner()
        secret = "medium_secret_"  # 14 chars
        result = s._redact_secret(secret)
        assert len(result) == len(secret)

    def test_redacted_same_length_long(self):
        s = self._scanner()
        secret = "a_very_long_secret_value_12345"  # 29 chars
        result = s._redact_secret(secret)
        assert len(result) == len(secret)


# =============================================================================
# SECRET VALIDATION
# =============================================================================

class TestSecretValidation:
    """Test _validate_secret method."""

    def _scanner(self):
        return SecretsPatternScanner(MOCK_SETTINGS)

    def _pattern_with_entropy(self, min_entropy=3.0, fp_patterns=None):
        return SecretPattern(
            name="test",
            pattern="x",
            severity="HIGH",
            description="test",
            min_entropy=min_entropy,
            false_positive_patterns=fp_patterns or [],
        )

    def test_rejects_empty(self):
        s = self._scanner()
        sp = self._pattern_with_entropy()
        assert not s._validate_secret("", sp)

    def test_rejects_too_short(self):
        s = self._scanner()
        sp = self._pattern_with_entropy()
        assert not s._validate_secret("abc", sp)

    def test_rejects_false_positive_pattern(self):
        s = self._scanner()
        sp = self._pattern_with_entropy(fp_patterns=["your_api_key"])
        assert not s._validate_secret("your_api_key_value", sp)

    def test_rejects_placeholder_xxx(self):
        s = self._scanner()
        sp = self._pattern_with_entropy(min_entropy=0)
        assert not s._validate_secret("xxx_placeholder_key", sp)

    def test_rejects_placeholder_example(self):
        s = self._scanner()
        sp = self._pattern_with_entropy(min_entropy=0)
        assert not s._validate_secret("example_api_key_12345678", sp)

    def test_rejects_placeholder_changeme(self):
        s = self._scanner()
        sp = self._pattern_with_entropy(min_entropy=0)
        assert not s._validate_secret("changeme_this_secret", sp)

    def test_rejects_placeholder_angle_brackets(self):
        s = self._scanner()
        sp = self._pattern_with_entropy(min_entropy=0)
        assert not s._validate_secret("<your_secret_key_here>", sp)

    def test_rejects_placeholder_template_vars(self):
        s = self._scanner()
        sp = self._pattern_with_entropy(min_entropy=0)
        assert not s._validate_secret("${SECRET_KEY_VALUE_HERE}", sp)

    def test_rejects_low_entropy(self):
        s = self._scanner()
        sp = self._pattern_with_entropy(min_entropy=4.0)
        # "aaaaaaaaaa" has 0 entropy
        assert not s._validate_secret("aaaaaaaaaa", sp)

    def test_accepts_high_entropy_value(self):
        s = self._scanner()
        sp = self._pattern_with_entropy(min_entropy=3.0)
        # High entropy random-looking string
        assert s._validate_secret("xK9m2PvL5nQ8wR3jF7hY", sp)

    def test_accepts_zero_entropy_threshold(self):
        s = self._scanner()
        sp = self._pattern_with_entropy(min_entropy=0)
        # Even low entropy should pass when threshold is 0
        assert s._validate_secret("aabbccddee", sp)


# =============================================================================
# CONTEXT EXTRACTION
# =============================================================================

class TestContextExtraction:
    """Test _extract_context method."""

    def _scanner(self):
        return SecretsPatternScanner(MOCK_SETTINGS)

    def test_extracts_around_secret(self):
        s = self._scanner()
        content = "prefix_text SECRET_VALUE_HERE suffix_text"
        ctx = s._extract_context(content, "SECRET_VALUE_HERE", context_chars=20)
        assert "prefix_text" in ctx or "suffix_text" in ctx

    def test_secret_not_found(self):
        s = self._scanner()
        ctx = s._extract_context("some content", "nonexistent", context_chars=20)
        assert ctx == "[context not available]"

    def test_redacts_secret_in_context(self):
        s = self._scanner()
        content = "key=MYSUPERSECRETVALUE123 next"
        ctx = s._extract_context(content, "MYSUPERSECRETVALUE123", context_chars=50)
        # The actual secret should not appear in the context
        assert "MYSUPERSECRETVALUE123" not in ctx

    def test_context_has_ellipsis_prefix(self):
        s = self._scanner()
        content = "A" * 200 + "SECRET12345678" + "B" * 200
        ctx = s._extract_context(content, "SECRET12345678", context_chars=50)
        assert ctx.startswith("...")

    def test_context_has_ellipsis_suffix(self):
        s = self._scanner()
        content = "A" * 200 + "SECRET12345678" + "B" * 200
        ctx = s._extract_context(content, "SECRET12345678", context_chars=50)
        assert ctx.endswith("...")

    def test_context_length_limited(self):
        s = self._scanner()
        content = "X" * 1000 + "THE_SECRET_1234" + "Y" * 1000
        ctx = s._extract_context(content, "THE_SECRET_1234", context_chars=200)
        assert len(ctx) <= 300


# =============================================================================
# PLACEHOLDER CONSTANTS
# =============================================================================

class TestPlaceholderConstants:
    """Test the placeholder detection list in _validate_secret."""

    def test_all_placeholders_detected(self):
        """Ensure all known placeholders are rejected."""
        s = SecretsPatternScanner(MOCK_SETTINGS)
        sp = SecretPattern(
            name="test", pattern="x", severity="HIGH", description="test",
            min_entropy=0,
        )
        placeholders_that_should_reject = [
            "xxx_long_enough_pad",
            "your_secret_value_here",
            "example_key_1234567890",
            "sample_token_abcdefgh",
            "test_value_placeholder",
            "demo_api_key_12345678",
            "fake_secret_key_value",
            "placeholder_value_pad",
            "changeme_secret_value",
            "replace_this_key_here",
            "<some_api_key_here__>",
            "${SOME_VARIABLE_NAME}",
            "{{template_variable}}",
        ]
        for val in placeholders_that_should_reject:
            assert not s._validate_secret(val, sp), (
                f"Should reject placeholder: {val}"
            )
