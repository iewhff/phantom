"""
Tests for scanning/modules/third_party_scanner.py

Covers:
- KeySeverity enum (5 members, values, uniqueness)
- DiscoveredKey dataclass (defaults, full creation, to_dict method)
- ThirdPartyScanResult dataclass (defaults, properties: critical_count, has_secret_exposure)
- ThirdPartyScanner class-level KEY_PATTERNS dict (count, key entries, structure)
- Scanner identity (class attributes, init defaults)
- Regex patterns (compilation, positive/negative matching for all key types)
- No async/HTTP tests -- static data and structure only

Run with: pytest tests/test_third_party_scanner.py -v
"""

import re
from dataclasses import fields

import pytest

from scanning.modules.third_party_scanner import (
    DiscoveredKey,
    KeySeverity,
    ThirdPartyScanner,
    ThirdPartyScanResult,
)


MOCK_SETTINGS = {"target_url": "http://test.local", "safety_level": "safe"}


# =============================================================================
# KeySeverity ENUM
# =============================================================================

class TestKeySeverityEnum:
    """Test KeySeverity enum members and values."""

    def test_member_count(self):
        assert len(KeySeverity) == 5

    def test_critical_exists(self):
        assert KeySeverity.CRITICAL is not None

    def test_high_exists(self):
        assert KeySeverity.HIGH is not None

    def test_medium_exists(self):
        assert KeySeverity.MEDIUM is not None

    def test_low_exists(self):
        assert KeySeverity.LOW is not None

    def test_info_exists(self):
        assert KeySeverity.INFO is not None

    def test_values_are_unique(self):
        values = [m.value for m in KeySeverity]
        assert len(values) == len(set(values))

    def test_names_are_unique(self):
        names = [m.name for m in KeySeverity]
        assert len(names) == len(set(names))

    def test_names_list(self):
        names = {m.name for m in KeySeverity}
        assert names == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def test_critical_name(self):
        assert KeySeverity.CRITICAL.name == "CRITICAL"

    def test_info_name(self):
        assert KeySeverity.INFO.name == "INFO"


# =============================================================================
# DiscoveredKey DATACLASS
# =============================================================================

class TestDiscoveredKeyDataclass:
    """Test DiscoveredKey dataclass creation and defaults."""

    def test_minimal_creation(self):
        dk = DiscoveredKey(
            service="Stripe",
            key_type="stripe_secret",
            key_value="sk_live_abcdef1234567890abcdef12",
            severity=KeySeverity.CRITICAL,
        )
        assert dk.service == "Stripe"
        assert dk.key_type == "stripe_secret"
        assert dk.key_value == "sk_live_abcdef1234567890abcdef12"
        assert dk.severity == KeySeverity.CRITICAL

    def test_default_is_valid(self):
        dk = DiscoveredKey(
            service="X", key_type="x", key_value="x", severity=KeySeverity.LOW,
        )
        assert dk.is_valid is None

    def test_default_description(self):
        dk = DiscoveredKey(
            service="X", key_type="x", key_value="x", severity=KeySeverity.LOW,
        )
        assert dk.description == ""

    def test_default_remediation(self):
        dk = DiscoveredKey(
            service="X", key_type="x", key_value="x", severity=KeySeverity.LOW,
        )
        assert dk.remediation == ""

    def test_full_creation(self):
        dk = DiscoveredKey(
            service="AWS",
            key_type="aws_access_key",
            key_value="AKIAIOSFODNN7EXAMPLE",
            severity=KeySeverity.CRITICAL,
            is_valid=True,
            description="AWS Access Key ID",
            remediation="Rotate in AWS IAM immediately",
        )
        assert dk.service == "AWS"
        assert dk.is_valid is True
        assert dk.description == "AWS Access Key ID"
        assert dk.remediation == "Rotate in AWS IAM immediately"

    def test_is_valid_false(self):
        dk = DiscoveredKey(
            service="X", key_type="x", key_value="x",
            severity=KeySeverity.LOW, is_valid=False,
        )
        assert dk.is_valid is False

    def test_field_count(self):
        assert len(fields(DiscoveredKey)) == 7

    def test_field_names(self):
        names = {f.name for f in fields(DiscoveredKey)}
        assert names == {
            "service", "key_type", "key_value", "severity",
            "is_valid", "description", "remediation",
        }


# =============================================================================
# DiscoveredKey.to_dict METHOD
# =============================================================================

class TestDiscoveredKeyToDict:
    """Test DiscoveredKey.to_dict serialization."""

    def test_short_key_is_redacted(self):
        dk = DiscoveredKey(
            service="Test", key_type="test_key",
            key_value="shortkey",  # len <= 30
            severity=KeySeverity.LOW,
        )
        d = dk.to_dict()
        assert d["key_value"] == "REDACTED"

    def test_long_key_is_partially_shown(self):
        long_key = "sk_live_" + "A" * 40  # len > 30
        dk = DiscoveredKey(
            service="Stripe", key_type="stripe_secret",
            key_value=long_key,
            severity=KeySeverity.CRITICAL,
        )
        d = dk.to_dict()
        assert d["key_value"].startswith(long_key[:20])
        assert d["key_value"].endswith(long_key[-4:])
        assert "..." in d["key_value"]

    def test_dict_keys(self):
        dk = DiscoveredKey(
            service="X", key_type="x", key_value="x",
            severity=KeySeverity.LOW,
        )
        d = dk.to_dict()
        assert set(d.keys()) == {
            "service", "key_type", "key_value", "severity",
            "is_valid", "description", "remediation",
        }

    def test_severity_is_string_name(self):
        dk = DiscoveredKey(
            service="X", key_type="x", key_value="x",
            severity=KeySeverity.HIGH,
        )
        d = dk.to_dict()
        assert d["severity"] == "HIGH"

    def test_is_valid_none_in_dict(self):
        dk = DiscoveredKey(
            service="X", key_type="x", key_value="x",
            severity=KeySeverity.LOW,
        )
        d = dk.to_dict()
        assert d["is_valid"] is None

    def test_is_valid_true_in_dict(self):
        dk = DiscoveredKey(
            service="X", key_type="x", key_value="x",
            severity=KeySeverity.LOW, is_valid=True,
        )
        d = dk.to_dict()
        assert d["is_valid"] is True

    def test_boundary_key_30_chars_redacted(self):
        """A key of exactly 30 chars should be REDACTED (not > 30)."""
        dk = DiscoveredKey(
            service="X", key_type="x",
            key_value="A" * 30,
            severity=KeySeverity.LOW,
        )
        d = dk.to_dict()
        assert d["key_value"] == "REDACTED"

    def test_boundary_key_31_chars_partial(self):
        """A key of 31 chars should be partially shown (> 30)."""
        key = "A" * 31
        dk = DiscoveredKey(
            service="X", key_type="x",
            key_value=key,
            severity=KeySeverity.LOW,
        )
        d = dk.to_dict()
        assert d["key_value"] != "REDACTED"
        assert "..." in d["key_value"]


# =============================================================================
# ThirdPartyScanResult DATACLASS
# =============================================================================

class TestThirdPartyScanResultDataclass:
    """Test ThirdPartyScanResult dataclass creation and properties."""

    def test_default_creation(self):
        result = ThirdPartyScanResult()
        assert result.keys_discovered == []
        assert result.validated_keys == []

    def test_independent_defaults(self):
        r1 = ThirdPartyScanResult()
        r2 = ThirdPartyScanResult()
        r1.keys_discovered.append(
            DiscoveredKey(
                service="X", key_type="x", key_value="x",
                severity=KeySeverity.LOW,
            )
        )
        assert r2.keys_discovered == []

    def test_field_count(self):
        assert len(fields(ThirdPartyScanResult)) == 2

    def test_field_names(self):
        names = {f.name for f in fields(ThirdPartyScanResult)}
        assert names == {"keys_discovered", "validated_keys"}


class TestThirdPartyScanResultCriticalCount:
    """Test ThirdPartyScanResult.critical_count property."""

    def test_empty_result(self):
        result = ThirdPartyScanResult()
        assert result.critical_count == 0

    def test_no_critical_keys(self):
        result = ThirdPartyScanResult()
        result.keys_discovered.append(
            DiscoveredKey(
                service="GA", key_type="google_analytics",
                key_value="UA-12345-1", severity=KeySeverity.LOW,
            )
        )
        assert result.critical_count == 0

    def test_one_critical_key(self):
        result = ThirdPartyScanResult()
        result.keys_discovered.append(
            DiscoveredKey(
                service="Stripe", key_type="stripe_secret",
                key_value="sk_live_abc", severity=KeySeverity.CRITICAL,
            )
        )
        assert result.critical_count == 1

    def test_mixed_severities(self):
        result = ThirdPartyScanResult()
        result.keys_discovered.append(
            DiscoveredKey(
                service="Stripe", key_type="stripe_secret",
                key_value="sk_live_abc", severity=KeySeverity.CRITICAL,
            )
        )
        result.keys_discovered.append(
            DiscoveredKey(
                service="GA", key_type="google_analytics",
                key_value="UA-12345-1", severity=KeySeverity.LOW,
            )
        )
        result.keys_discovered.append(
            DiscoveredKey(
                service="AWS", key_type="aws_access_key",
                key_value="AKIA1234", severity=KeySeverity.CRITICAL,
            )
        )
        assert result.critical_count == 2


class TestThirdPartyScanResultHasSecretExposure:
    """Test ThirdPartyScanResult.has_secret_exposure property."""

    def test_empty_result(self):
        result = ThirdPartyScanResult()
        assert result.has_secret_exposure is False

    def test_no_validated_keys(self):
        result = ThirdPartyScanResult()
        result.keys_discovered.append(
            DiscoveredKey(
                service="Stripe", key_type="stripe_secret",
                key_value="sk_live_abc", severity=KeySeverity.CRITICAL,
            )
        )
        assert result.has_secret_exposure is False

    def test_validated_but_not_critical(self):
        result = ThirdPartyScanResult()
        key = DiscoveredKey(
            service="GA", key_type="google_analytics",
            key_value="UA-12345-1", severity=KeySeverity.LOW, is_valid=True,
        )
        result.validated_keys.append(key)
        assert result.has_secret_exposure is False

    def test_critical_but_not_valid(self):
        result = ThirdPartyScanResult()
        key = DiscoveredKey(
            service="Stripe", key_type="stripe_secret",
            key_value="sk_live_abc", severity=KeySeverity.CRITICAL, is_valid=False,
        )
        result.validated_keys.append(key)
        assert result.has_secret_exposure is False

    def test_critical_valid_none(self):
        result = ThirdPartyScanResult()
        key = DiscoveredKey(
            service="Stripe", key_type="stripe_secret",
            key_value="sk_live_abc", severity=KeySeverity.CRITICAL, is_valid=None,
        )
        result.validated_keys.append(key)
        assert result.has_secret_exposure is False

    def test_critical_and_valid(self):
        result = ThirdPartyScanResult()
        key = DiscoveredKey(
            service="Stripe", key_type="stripe_secret",
            key_value="sk_live_abc", severity=KeySeverity.CRITICAL, is_valid=True,
        )
        result.validated_keys.append(key)
        assert result.has_secret_exposure is True


# =============================================================================
# ThirdPartyScanner CLASS IDENTITY
# =============================================================================

class TestThirdPartyScannerClass:
    """Test ThirdPartyScanner class identity and init defaults."""

    def test_not_scan_module_subclass(self):
        """ThirdPartyScanner is a standalone class, not a ScanModule subclass."""
        from scanning.vuln_scanner import ScanModule
        assert not issubclass(ThirdPartyScanner, ScanModule)

    def test_instantiation_no_settings(self):
        scanner = ThirdPartyScanner()
        assert scanner.settings is None

    def test_instantiation_with_settings(self):
        scanner = ThirdPartyScanner(settings=MOCK_SETTINGS)
        assert scanner.settings == MOCK_SETTINGS

    def test_timeout_default(self):
        scanner = ThirdPartyScanner()
        # httpx.Timeout(10.0) -- connect/read/write/pool all 10.0
        assert scanner.timeout.connect == 10.0
        assert scanner.timeout.read == 10.0

    def test_result_initialized(self):
        scanner = ThirdPartyScanner()
        assert isinstance(scanner.result, ThirdPartyScanResult)
        assert scanner.result.keys_discovered == []
        assert scanner.result.validated_keys == []

    def test_has_key_patterns_class_attribute(self):
        assert hasattr(ThirdPartyScanner, "KEY_PATTERNS")
        assert isinstance(ThirdPartyScanner.KEY_PATTERNS, dict)


# =============================================================================
# KEY_PATTERNS DICT -- COUNTS AND STRUCTURE
# =============================================================================

class TestKeyPatternsCount:
    """Test KEY_PATTERNS dictionary size and key entries."""

    def test_total_pattern_count(self):
        assert len(ThirdPartyScanner.KEY_PATTERNS) == 36

    def test_all_keys_are_strings(self):
        for key in ThirdPartyScanner.KEY_PATTERNS:
            assert isinstance(key, str)

    def test_all_values_are_dicts(self):
        for key, val in ThirdPartyScanner.KEY_PATTERNS.items():
            assert isinstance(val, dict), f"{key} value is not a dict"

    def test_all_have_pattern_key(self):
        for key, val in ThirdPartyScanner.KEY_PATTERNS.items():
            assert "pattern" in val, f"{key} missing 'pattern'"

    def test_all_have_severity_key(self):
        for key, val in ThirdPartyScanner.KEY_PATTERNS.items():
            assert "severity" in val, f"{key} missing 'severity'"

    def test_all_have_description_key(self):
        for key, val in ThirdPartyScanner.KEY_PATTERNS.items():
            assert "description" in val, f"{key} missing 'description'"

    def test_all_patterns_are_compiled_regex(self):
        for key, val in ThirdPartyScanner.KEY_PATTERNS.items():
            assert isinstance(val["pattern"], re.Pattern), (
                f"{key} pattern is not a compiled regex"
            )

    def test_all_severities_are_key_severity(self):
        for key, val in ThirdPartyScanner.KEY_PATTERNS.items():
            assert isinstance(val["severity"], KeySeverity), (
                f"{key} severity is not KeySeverity"
            )

    def test_descriptions_are_nonempty_strings(self):
        for key, val in ThirdPartyScanner.KEY_PATTERNS.items():
            desc = val["description"]
            assert isinstance(desc, str) and len(desc) > 0, (
                f"{key} has empty description"
            )


class TestKeyPatternsCategories:
    """Test that all expected key pattern names exist."""

    def test_payment_patterns_present(self):
        patterns = ThirdPartyScanner.KEY_PATTERNS
        assert "stripe_publishable" in patterns
        assert "stripe_secret" in patterns
        assert "stripe_restricted" in patterns
        assert "paypal_client" in patterns
        assert "paypal_secret" in patterns
        assert "square_access" in patterns

    def test_error_tracking_patterns_present(self):
        patterns = ThirdPartyScanner.KEY_PATTERNS
        assert "sentry_dsn" in patterns
        assert "sentry_auth" in patterns
        assert "bugsnag_key" in patterns

    def test_analytics_patterns_present(self):
        patterns = ThirdPartyScanner.KEY_PATTERNS
        assert "google_analytics" in patterns
        assert "google_analytics_4" in patterns
        assert "posthog_key" in patterns
        assert "mixpanel_token" in patterns
        assert "amplitude_key" in patterns

    def test_cloud_patterns_present(self):
        patterns = ThirdPartyScanner.KEY_PATTERNS
        assert "aws_access_key" in patterns
        assert "aws_secret_key" in patterns
        assert "gcp_api_key" in patterns
        assert "azure_connection" in patterns
        assert "digitalocean_token" in patterns

    def test_communication_patterns_present(self):
        patterns = ThirdPartyScanner.KEY_PATTERNS
        assert "twilio_sid" in patterns
        assert "twilio_auth" in patterns
        assert "sendgrid_key" in patterns
        assert "mailgun_key" in patterns

    def test_oauth_social_patterns_present(self):
        patterns = ThirdPartyScanner.KEY_PATTERNS
        assert "facebook_app_secret" in patterns
        assert "github_token" in patterns
        assert "github_oauth_secret" in patterns
        assert "slack_webhook" in patterns
        assert "slack_token" in patterns
        assert "discord_webhook" in patterns
        assert "discord_bot_token" in patterns

    def test_database_patterns_present(self):
        patterns = ThirdPartyScanner.KEY_PATTERNS
        assert "mongodb_uri" in patterns
        assert "postgres_uri" in patterns
        assert "redis_url" in patterns

    def test_cdn_patterns_present(self):
        patterns = ThirdPartyScanner.KEY_PATTERNS
        assert "cloudflare_api" in patterns

    def test_jwt_generic_patterns_present(self):
        patterns = ThirdPartyScanner.KEY_PATTERNS
        assert "jwt_secret" in patterns
        assert "private_key" in patterns


class TestKeyPatternsSeverities:
    """Test severity assignments for key patterns."""

    def test_stripe_publishable_medium(self):
        assert ThirdPartyScanner.KEY_PATTERNS["stripe_publishable"]["severity"] == KeySeverity.MEDIUM

    def test_stripe_secret_critical(self):
        assert ThirdPartyScanner.KEY_PATTERNS["stripe_secret"]["severity"] == KeySeverity.CRITICAL

    def test_stripe_restricted_high(self):
        assert ThirdPartyScanner.KEY_PATTERNS["stripe_restricted"]["severity"] == KeySeverity.HIGH

    def test_paypal_secret_critical(self):
        assert ThirdPartyScanner.KEY_PATTERNS["paypal_secret"]["severity"] == KeySeverity.CRITICAL

    def test_aws_access_key_critical(self):
        assert ThirdPartyScanner.KEY_PATTERNS["aws_access_key"]["severity"] == KeySeverity.CRITICAL

    def test_gcp_api_key_high(self):
        assert ThirdPartyScanner.KEY_PATTERNS["gcp_api_key"]["severity"] == KeySeverity.HIGH

    def test_azure_connection_critical(self):
        assert ThirdPartyScanner.KEY_PATTERNS["azure_connection"]["severity"] == KeySeverity.CRITICAL

    def test_google_analytics_low(self):
        assert ThirdPartyScanner.KEY_PATTERNS["google_analytics"]["severity"] == KeySeverity.LOW

    def test_google_analytics_4_low(self):
        assert ThirdPartyScanner.KEY_PATTERNS["google_analytics_4"]["severity"] == KeySeverity.LOW

    def test_sentry_dsn_medium(self):
        assert ThirdPartyScanner.KEY_PATTERNS["sentry_dsn"]["severity"] == KeySeverity.MEDIUM

    def test_sendgrid_key_critical(self):
        assert ThirdPartyScanner.KEY_PATTERNS["sendgrid_key"]["severity"] == KeySeverity.CRITICAL

    def test_mailgun_key_critical(self):
        assert ThirdPartyScanner.KEY_PATTERNS["mailgun_key"]["severity"] == KeySeverity.CRITICAL

    def test_github_token_critical(self):
        assert ThirdPartyScanner.KEY_PATTERNS["github_token"]["severity"] == KeySeverity.CRITICAL

    def test_slack_token_critical(self):
        assert ThirdPartyScanner.KEY_PATTERNS["slack_token"]["severity"] == KeySeverity.CRITICAL

    def test_slack_webhook_medium(self):
        assert ThirdPartyScanner.KEY_PATTERNS["slack_webhook"]["severity"] == KeySeverity.MEDIUM

    def test_discord_webhook_medium(self):
        assert ThirdPartyScanner.KEY_PATTERNS["discord_webhook"]["severity"] == KeySeverity.MEDIUM

    def test_discord_bot_token_critical(self):
        assert ThirdPartyScanner.KEY_PATTERNS["discord_bot_token"]["severity"] == KeySeverity.CRITICAL

    def test_mongodb_uri_critical(self):
        assert ThirdPartyScanner.KEY_PATTERNS["mongodb_uri"]["severity"] == KeySeverity.CRITICAL

    def test_postgres_uri_critical(self):
        assert ThirdPartyScanner.KEY_PATTERNS["postgres_uri"]["severity"] == KeySeverity.CRITICAL

    def test_redis_url_critical(self):
        assert ThirdPartyScanner.KEY_PATTERNS["redis_url"]["severity"] == KeySeverity.CRITICAL

    def test_private_key_critical(self):
        assert ThirdPartyScanner.KEY_PATTERNS["private_key"]["severity"] == KeySeverity.CRITICAL

    def test_jwt_secret_critical(self):
        assert ThirdPartyScanner.KEY_PATTERNS["jwt_secret"]["severity"] == KeySeverity.CRITICAL

    def test_digitalocean_token_critical(self):
        assert ThirdPartyScanner.KEY_PATTERNS["digitalocean_token"]["severity"] == KeySeverity.CRITICAL

    def test_cloudflare_api_high(self):
        assert ThirdPartyScanner.KEY_PATTERNS["cloudflare_api"]["severity"] == KeySeverity.HIGH


class TestKeyPatternsContextField:
    """Test which patterns have the optional 'context' field."""

    def test_sentry_auth_has_context(self):
        assert ThirdPartyScanner.KEY_PATTERNS["sentry_auth"].get("context") == "sentry"

    def test_bugsnag_key_has_context(self):
        assert ThirdPartyScanner.KEY_PATTERNS["bugsnag_key"].get("context") == "bugsnag"

    def test_mixpanel_token_has_context(self):
        assert ThirdPartyScanner.KEY_PATTERNS["mixpanel_token"].get("context") == "mixpanel"

    def test_amplitude_key_has_context(self):
        assert ThirdPartyScanner.KEY_PATTERNS["amplitude_key"].get("context") == "amplitude"

    def test_aws_secret_key_has_context(self):
        assert ThirdPartyScanner.KEY_PATTERNS["aws_secret_key"].get("context") == "aws"

    def test_twilio_auth_has_context(self):
        assert ThirdPartyScanner.KEY_PATTERNS["twilio_auth"].get("context") == "twilio"

    def test_facebook_app_secret_has_context(self):
        assert ThirdPartyScanner.KEY_PATTERNS["facebook_app_secret"].get("context") == "facebook"

    def test_github_oauth_secret_has_context(self):
        assert ThirdPartyScanner.KEY_PATTERNS["github_oauth_secret"].get("context") == "github"

    def test_cloudflare_api_has_context(self):
        assert ThirdPartyScanner.KEY_PATTERNS["cloudflare_api"].get("context") == "cloudflare"

    def test_stripe_secret_no_context(self):
        assert "context" not in ThirdPartyScanner.KEY_PATTERNS["stripe_secret"]

    def test_aws_access_key_no_context(self):
        assert "context" not in ThirdPartyScanner.KEY_PATTERNS["aws_access_key"]

    def test_sendgrid_key_no_context(self):
        assert "context" not in ThirdPartyScanner.KEY_PATTERNS["sendgrid_key"]


class TestKeyPatternsRemediationField:
    """Test which patterns have the optional 'remediation' field."""

    def test_stripe_secret_has_remediation(self):
        r = ThirdPartyScanner.KEY_PATTERNS["stripe_secret"].get("remediation")
        assert r is not None and "Stripe" in r

    def test_aws_access_key_has_remediation(self):
        r = ThirdPartyScanner.KEY_PATTERNS["aws_access_key"].get("remediation")
        assert r is not None and "AWS" in r

    def test_google_analytics_no_remediation(self):
        assert "remediation" not in ThirdPartyScanner.KEY_PATTERNS["google_analytics"]


# =============================================================================
# REGEX PATTERNS -- POSITIVE AND NEGATIVE MATCHES
# =============================================================================

class TestRegexStripePublishable:
    """Test stripe_publishable pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["stripe_publishable"]["pattern"]

    def test_matches_live_key(self):
        assert self._pattern().search("pk_live_abcdefghijklmnopqrstuvwx")

    def test_matches_test_key(self):
        assert self._pattern().search("pk_test_abcdefghijklmnopqrstuvwx")

    def test_no_match_secret_key(self):
        assert not self._pattern().search("sk_live_abcdefghijklmnopqrstuvwx")

    def test_no_match_short(self):
        assert not self._pattern().search("pk_live_abc")


class TestRegexStripeSecret:
    """Test stripe_secret pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["stripe_secret"]["pattern"]

    def test_matches_live_key(self):
        assert self._pattern().search("sk_live_abcdefghijklmnopqrstuvwx")

    def test_matches_test_key(self):
        assert self._pattern().search("sk_test_abcdefghijklmnopqrstuvwx")

    def test_no_match_publishable_key(self):
        assert not self._pattern().search("pk_live_abcdefghijklmnopqrstuvwx")

    def test_no_match_short(self):
        assert not self._pattern().search("sk_live_abc")


class TestRegexStripeRestricted:
    """Test stripe_restricted pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["stripe_restricted"]["pattern"]

    def test_matches_live_key(self):
        assert self._pattern().search("rk_live_abcdefghijklmnopqrstuvwx")

    def test_matches_test_key(self):
        assert self._pattern().search("rk_test_abcdefghijklmnopqrstuvwx")

    def test_no_match_secret_key(self):
        assert not self._pattern().search("sk_live_abcdefghijklmnopqrstuvwx")


class TestRegexPaypalClient:
    """Test paypal_client pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["paypal_client"]["pattern"]

    def test_matches_valid(self):
        # AY prefix + 60 alphanumeric chars
        assert self._pattern().search("AY" + "a" * 60)

    def test_no_match_wrong_prefix(self):
        assert not self._pattern().search("BZ" + "a" * 60)

    def test_no_match_short(self):
        assert not self._pattern().search("AY" + "a" * 10)


class TestRegexPaypalSecret:
    """Test paypal_secret pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["paypal_secret"]["pattern"]

    def test_matches_valid(self):
        assert self._pattern().search("EL" + "a" * 60)

    def test_no_match_wrong_prefix(self):
        assert not self._pattern().search("AY" + "a" * 60)


class TestRegexSquareAccess:
    """Test square_access pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["square_access"]["pattern"]

    def test_matches_valid(self):
        assert self._pattern().search("sq0atp-abcdefghijklmnopqrstuv")

    def test_no_match_wrong_prefix(self):
        assert not self._pattern().search("sq1atp-abcdefghijklmnopqrstuv")


class TestRegexSentryDsn:
    """Test sentry_dsn pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["sentry_dsn"]["pattern"]

    def test_matches_valid_dsn(self):
        assert self._pattern().search(
            "https://abcdef1234567890@o123456.ingest.sentry.io/5678901"
        )

    def test_no_match_wrong_domain(self):
        assert not self._pattern().search(
            "https://abcdef1234567890@evil.sentry.io/5678901"
        )


class TestRegexGoogleAnalytics:
    """Test google_analytics pattern (UA)."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["google_analytics"]["pattern"]

    def test_matches_valid_ua(self):
        assert self._pattern().search("UA-123456-1")

    def test_matches_larger_numbers(self):
        assert self._pattern().search("UA-123456789-12")

    def test_no_match_ga4(self):
        assert not self._pattern().search("G-ABC1234567")


class TestRegexGoogleAnalytics4:
    """Test google_analytics_4 pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["google_analytics_4"]["pattern"]

    def test_matches_valid_ga4(self):
        assert self._pattern().search("G-ABC1234567")

    def test_no_match_ua(self):
        assert not self._pattern().search("UA-123456-1")

    def test_no_match_short(self):
        assert not self._pattern().search("G-ABC")


class TestRegexPosthogKey:
    """Test posthog_key pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["posthog_key"]["pattern"]

    def test_matches_valid(self):
        assert self._pattern().search("phc_" + "a" * 32)

    def test_no_match_wrong_prefix(self):
        assert not self._pattern().search("phx_" + "a" * 32)

    def test_no_match_short(self):
        assert not self._pattern().search("phc_abc")


class TestRegexAwsAccessKey:
    """Test aws_access_key pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["aws_access_key"]["pattern"]

    def test_matches_valid_key(self):
        assert self._pattern().search("AKIAIOSFODNN7EXAMPLE")

    def test_no_match_wrong_prefix(self):
        assert not self._pattern().search("BKIAIOSFODNN7EXAMPLE")

    def test_no_match_short(self):
        assert not self._pattern().search("AKIA12345")


class TestRegexGcpApiKey:
    """Test gcp_api_key pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["gcp_api_key"]["pattern"]

    def test_matches_valid(self):
        assert self._pattern().search("AIzaSyA" + "a" * 32)

    def test_no_match_wrong_prefix(self):
        assert not self._pattern().search("BIzaSyA" + "a" * 32)


class TestRegexAzureConnection:
    """Test azure_connection pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["azure_connection"]["pattern"]

    def test_matches_valid(self):
        assert self._pattern().search(
            "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123def456"
        )

    def test_no_match_http_protocol(self):
        assert not self._pattern().search(
            "DefaultEndpointsProtocol=http;AccountName=myaccount;AccountKey=abc123def456"
        )


class TestRegexDigitaloceanToken:
    """Test digitalocean_token pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["digitalocean_token"]["pattern"]

    def test_matches_valid(self):
        assert self._pattern().search("dop_v1_" + "a" * 64)

    def test_no_match_short(self):
        assert not self._pattern().search("dop_v1_abc")

    def test_no_match_wrong_prefix(self):
        assert not self._pattern().search("dox_v1_" + "a" * 64)


class TestRegexTwilioSid:
    """Test twilio_sid pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["twilio_sid"]["pattern"]

    def test_matches_valid(self):
        assert self._pattern().search("AC" + "a" * 32)

    def test_no_match_wrong_prefix(self):
        assert not self._pattern().search("BC" + "a" * 32)


class TestRegexSendgridKey:
    """Test sendgrid_key pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["sendgrid_key"]["pattern"]

    def test_matches_valid(self):
        assert self._pattern().search(
            "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"
        )

    def test_no_match_missing_prefix(self):
        assert not self._pattern().search(
            "XX.ngeVfQFYQlKU0ufo8x5d1A.TwL2iGABf9DHoTf-09kqeF8tAmbihYzrnopKc-1s5cr"
        )


class TestRegexMailgunKey:
    """Test mailgun_key pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["mailgun_key"]["pattern"]

    def test_matches_valid(self):
        assert self._pattern().search("key-" + "a" * 32)

    def test_no_match_wrong_prefix(self):
        assert not self._pattern().search("kex-" + "a" * 32)

    def test_no_match_short(self):
        assert not self._pattern().search("key-abc")


class TestRegexGithubToken:
    """Test github_token pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["github_token"]["pattern"]

    def test_matches_ghp(self):
        assert self._pattern().search("ghp_" + "A" * 36)

    def test_matches_gho(self):
        assert self._pattern().search("gho_" + "A" * 36)

    def test_matches_ghu(self):
        assert self._pattern().search("ghu_" + "A" * 36)

    def test_matches_ghs(self):
        assert self._pattern().search("ghs_" + "A" * 36)

    def test_matches_ghr(self):
        assert self._pattern().search("ghr_" + "A" * 36)

    def test_no_match_wrong_prefix(self):
        assert not self._pattern().search("ghx_" + "A" * 36)

    def test_no_match_short(self):
        assert not self._pattern().search("ghp_ABC")


class TestRegexSlackWebhook:
    """Test slack_webhook pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["slack_webhook"]["pattern"]

    def test_matches_valid(self):
        assert self._pattern().search(
            "https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnop"
        )

    def test_no_match_wrong_domain(self):
        assert not self._pattern().search(
            "https://hooks.evil.com/services/T12345678/B12345678/abcdefghijklmnop"
        )


class TestRegexSlackToken:
    """Test slack_token pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["slack_token"]["pattern"]

    def test_matches_xoxb(self):
        assert self._pattern().search("xoxb-123456789012-abcdefghijklmnop")

    def test_matches_xoxp(self):
        assert self._pattern().search("xoxp-123456789012-abcdefghijklmnop")

    def test_matches_xoxa(self):
        assert self._pattern().search("xoxa-123456789012-abcdefghijklmnop")

    def test_matches_xoxr(self):
        assert self._pattern().search("xoxr-123456789012-abcdefghijklmnop")

    def test_matches_xoxs(self):
        assert self._pattern().search("xoxs-123456789012-abcdefghijklmnop")

    def test_no_match_wrong_prefix(self):
        assert not self._pattern().search("xoxx-123456789012-abcdefghijklmnop")


class TestRegexDiscordWebhook:
    """Test discord_webhook pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["discord_webhook"]["pattern"]

    def test_matches_valid(self):
        assert self._pattern().search(
            "https://discord.com/api/webhooks/1234567890/abcDEF_ghi-JKL"
        )

    def test_no_match_wrong_domain(self):
        assert not self._pattern().search(
            "https://evil.com/api/webhooks/1234567890/abcDEF_ghi-JKL"
        )


class TestRegexDiscordBotToken:
    """Test discord_bot_token pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["discord_bot_token"]["pattern"]

    def test_matches_m_prefix(self):
        # M + 23 alphanum, dot, 6 word-chars, dot, 27 word-chars
        token = "M" + "a" * 23 + "." + "b" * 6 + "." + "c" * 27
        assert self._pattern().search(token)

    def test_matches_n_prefix(self):
        token = "N" + "a" * 23 + "." + "b" * 6 + "." + "c" * 27
        assert self._pattern().search(token)

    def test_no_match_wrong_prefix(self):
        token = "A" + "a" * 23 + "." + "b" * 6 + "." + "c" * 27
        assert not self._pattern().search(token)


class TestRegexMongodbUri:
    """Test mongodb_uri pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["mongodb_uri"]["pattern"]

    def test_matches_srv(self):
        assert self._pattern().search(
            "mongodb+srv://admin:password@cluster0.abc.mongodb.net"
        )

    def test_no_match_without_creds(self):
        assert not self._pattern().search("mongodb+srv://cluster0.abc.mongodb.net")


class TestRegexPostgresUri:
    """Test postgres_uri pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["postgres_uri"]["pattern"]

    def test_matches_postgresql(self):
        assert self._pattern().search("postgresql://admin:secret@db.example.com/mydb")

    def test_matches_postgres(self):
        assert self._pattern().search("postgres://admin:secret@localhost/mydb")

    def test_no_match_without_creds(self):
        assert not self._pattern().search("postgres://localhost/mydb")


class TestRegexRedisUrl:
    """Test redis_url pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["redis_url"]["pattern"]

    def test_matches_valid(self):
        assert self._pattern().search("redis://user:password@redis.example.com/0")

    def test_no_match_without_creds(self):
        assert not self._pattern().search("redis://redis.example.com/0")


class TestRegexJwtSecret:
    """Test jwt_secret pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["jwt_secret"]["pattern"]

    def test_matches_jwt_secret_assignment(self):
        assert self._pattern().search('jwt_secret = "mysuperlongsecretkeythatismorethan20chars"')

    def test_matches_secret_key_colon(self):
        assert self._pattern().search('"secret_key": "another_very_long_secret_here_123"')

    def test_matches_token_secret(self):
        assert self._pattern().search("token_secret='averyverylongsecretvalue123456'")

    def test_no_match_short_value(self):
        assert not self._pattern().search('jwt_secret = "short"')


class TestRegexPrivateKey:
    """Test private_key pattern."""

    def _pattern(self):
        return ThirdPartyScanner.KEY_PATTERNS["private_key"]["pattern"]

    def test_matches_rsa(self):
        assert self._pattern().search("-----BEGIN RSA PRIVATE KEY-----")

    def test_matches_ec(self):
        assert self._pattern().search("-----BEGIN EC PRIVATE KEY-----")

    def test_matches_generic(self):
        assert self._pattern().search("-----BEGIN PRIVATE KEY-----")

    def test_no_match_public_key(self):
        assert not self._pattern().search("-----BEGIN PUBLIC KEY-----")

    def test_no_match_certificate(self):
        assert not self._pattern().search("-----BEGIN CERTIFICATE-----")


# =============================================================================
# ALL PATTERNS COMPILE
# =============================================================================

class TestAllPatternsCompile:
    """Verify every pattern in KEY_PATTERNS compiles without error."""

    def test_all_compile(self):
        for key, config in ThirdPartyScanner.KEY_PATTERNS.items():
            p = config["pattern"]
            assert isinstance(p, re.Pattern), f"{key} pattern failed to compile"

    def test_compiled_count_matches(self):
        assert len(ThirdPartyScanner.KEY_PATTERNS) == 36


# =============================================================================
# CRITICAL PATTERN COUNT
# =============================================================================

class TestCriticalPatternCounts:
    """Verify severity distribution across KEY_PATTERNS."""

    def test_critical_count(self):
        count = sum(
            1 for c in ThirdPartyScanner.KEY_PATTERNS.values()
            if c["severity"] == KeySeverity.CRITICAL
        )
        assert count == 19

    def test_high_count(self):
        count = sum(
            1 for c in ThirdPartyScanner.KEY_PATTERNS.values()
            if c["severity"] == KeySeverity.HIGH
        )
        assert count == 6

    def test_medium_count(self):
        count = sum(
            1 for c in ThirdPartyScanner.KEY_PATTERNS.values()
            if c["severity"] == KeySeverity.MEDIUM
        )
        assert count == 9

    def test_low_count(self):
        count = sum(
            1 for c in ThirdPartyScanner.KEY_PATTERNS.values()
            if c["severity"] == KeySeverity.LOW
        )
        assert count == 2

    def test_info_count(self):
        count = sum(
            1 for c in ThirdPartyScanner.KEY_PATTERNS.values()
            if c["severity"] == KeySeverity.INFO
        )
        assert count == 0

    def test_severity_totals(self):
        """All severity counts should sum to total patterns."""
        total = 0
        for sev in KeySeverity:
            total += sum(
                1 for c in ThirdPartyScanner.KEY_PATTERNS.values()
                if c["severity"] == sev
            )
        assert total == len(ThirdPartyScanner.KEY_PATTERNS)
