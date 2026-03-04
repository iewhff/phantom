"""
Tests for scanning/modules/webhook_security_scanner.py

Covers:
- WebhookEndpoint dataclass defaults and field values
- WEBHOOK_URL_PARAMS constant (21 items, key param names)
- WEBHOOK_PATH_PATTERNS constant (9 regex patterns, compilation)
- WEBHOOK_EVENT_TYPES constant (18+ items, event names, injection attempts)
- SSRF_TEST_DOMAINS constant (2 items)
- WebhookSecurityScanner class attributes (name, description, version, author, tags, min_safety_level, ScanModule subclass)
"""

import re

import pytest

from scanning.modules.webhook_security_scanner import (
    WebhookEndpoint,
    WEBHOOK_URL_PARAMS,
    WEBHOOK_PATH_PATTERNS,
    WEBHOOK_EVENT_TYPES,
    SSRF_TEST_DOMAINS,
    WebhookSecurityScanner,
)


# =============================================================================
# DATACLASS TESTS: WebhookEndpoint
# =============================================================================

class TestWebhookEndpointDefaults:
    """Test WebhookEndpoint dataclass default values."""

    def test_url_required(self):
        """url is a required field with no default."""
        with pytest.raises(TypeError):
            WebhookEndpoint()  # type: ignore[call-arg]

    def test_url_stored(self):
        ep = WebhookEndpoint(url="https://example.com/webhook")
        assert ep.url == "https://example.com/webhook"

    def test_method_default(self):
        ep = WebhookEndpoint(url="https://example.com")
        assert ep.method == "POST"

    def test_method_custom(self):
        ep = WebhookEndpoint(url="https://example.com", method="PUT")
        assert ep.method == "PUT"

    def test_param_name_default(self):
        ep = WebhookEndpoint(url="https://example.com")
        assert ep.param_name == ""

    def test_param_name_custom(self):
        ep = WebhookEndpoint(url="https://example.com", param_name="callback_url")
        assert ep.param_name == "callback_url"

    def test_endpoint_type_default(self):
        ep = WebhookEndpoint(url="https://example.com")
        assert ep.endpoint_type == "unknown"

    def test_endpoint_type_custom(self):
        ep = WebhookEndpoint(url="https://example.com", endpoint_type="subscription")
        assert ep.endpoint_type == "subscription"

    def test_all_fields_set(self):
        ep = WebhookEndpoint(
            url="https://api.example.com/hooks",
            method="PATCH",
            param_name="notify_url",
            endpoint_type="notification",
        )
        assert ep.url == "https://api.example.com/hooks"
        assert ep.method == "PATCH"
        assert ep.param_name == "notify_url"
        assert ep.endpoint_type == "notification"


# =============================================================================
# CONSTANTS TESTS: WEBHOOK_URL_PARAMS
# =============================================================================

class TestWebhookUrlParams:
    """Test WEBHOOK_URL_PARAMS constant."""

    def test_is_list(self):
        assert isinstance(WEBHOOK_URL_PARAMS, list)

    def test_count(self):
        assert len(WEBHOOK_URL_PARAMS) == 24

    def test_all_strings(self):
        for param in WEBHOOK_URL_PARAMS:
            assert isinstance(param, str), f"Not a string: {param!r}"

    def test_all_non_empty(self):
        for param in WEBHOOK_URL_PARAMS:
            assert len(param) > 0, "Found empty string in WEBHOOK_URL_PARAMS"

    def test_contains_webhook_url(self):
        assert "webhook_url" in WEBHOOK_URL_PARAMS

    def test_contains_callback_url(self):
        assert "callback_url" in WEBHOOK_URL_PARAMS

    def test_contains_notify_url(self):
        assert "notify_url" in WEBHOOK_URL_PARAMS

    def test_contains_endpoint(self):
        assert "endpoint" in WEBHOOK_URL_PARAMS

    def test_contains_target_url(self):
        assert "target_url" in WEBHOOK_URL_PARAMS

    def test_contains_ipn_url(self):
        assert "ipn_url" in WEBHOOK_URL_PARAMS

    def test_contains_postback_url(self):
        assert "postback_url" in WEBHOOK_URL_PARAMS

    def test_contains_ping_url(self):
        assert "ping_url" in WEBHOOK_URL_PARAMS

    def test_contains_webhook(self):
        assert "webhook" in WEBHOOK_URL_PARAMS

    def test_contains_callback(self):
        assert "callback" in WEBHOOK_URL_PARAMS

    def test_contains_url(self):
        assert "url" in WEBHOOK_URL_PARAMS

    def test_contains_destination(self):
        assert "destination" in WEBHOOK_URL_PARAMS

    def test_no_duplicates(self):
        assert len(WEBHOOK_URL_PARAMS) == len(set(WEBHOOK_URL_PARAMS))


# =============================================================================
# CONSTANTS TESTS: WEBHOOK_PATH_PATTERNS
# =============================================================================

class TestWebhookPathPatterns:
    """Test WEBHOOK_PATH_PATTERNS constant."""

    def test_is_list(self):
        assert isinstance(WEBHOOK_PATH_PATTERNS, list)

    def test_count(self):
        assert len(WEBHOOK_PATH_PATTERNS) == 9

    def test_all_strings(self):
        for pattern in WEBHOOK_PATH_PATTERNS:
            assert isinstance(pattern, str), f"Not a string: {pattern!r}"

    def test_all_compile_as_regex(self):
        """Every pattern must be a valid regular expression."""
        for pattern in WEBHOOK_PATH_PATTERNS:
            compiled = re.compile(pattern, re.IGNORECASE)
            assert compiled is not None, f"Failed to compile: {pattern!r}"

    def test_webhooks_pattern_matches(self):
        """The webhooks? pattern should match /webhook and /webhooks."""
        pattern = WEBHOOK_PATH_PATTERNS[0]
        assert re.search(pattern, "/webhook", re.IGNORECASE)
        assert re.search(pattern, "/webhooks", re.IGNORECASE)
        assert re.search(pattern, "/webhooks/", re.IGNORECASE)

    def test_callbacks_pattern_matches(self):
        pattern = WEBHOOK_PATH_PATTERNS[1]
        assert re.search(pattern, "/callback", re.IGNORECASE)
        assert re.search(pattern, "/callbacks", re.IGNORECASE)

    def test_hooks_pattern_matches(self):
        pattern = WEBHOOK_PATH_PATTERNS[2]
        assert re.search(pattern, "/hook", re.IGNORECASE)
        assert re.search(pattern, "/hooks", re.IGNORECASE)

    def test_notify_pattern_matches(self):
        pattern = WEBHOOK_PATH_PATTERNS[3]
        assert re.search(pattern, "/notify", re.IGNORECASE)
        assert re.search(pattern, "/notify/", re.IGNORECASE)

    def test_notifications_pattern_matches(self):
        pattern = WEBHOOK_PATH_PATTERNS[4]
        assert re.search(pattern, "/notification", re.IGNORECASE)
        assert re.search(pattern, "/notifications", re.IGNORECASE)

    def test_events_pattern_matches(self):
        pattern = WEBHOOK_PATH_PATTERNS[5]
        assert re.search(pattern, "/event", re.IGNORECASE)
        assert re.search(pattern, "/events", re.IGNORECASE)

    def test_subscriptions_pattern_matches(self):
        pattern = WEBHOOK_PATH_PATTERNS[6]
        assert re.search(pattern, "/subscription", re.IGNORECASE)
        assert re.search(pattern, "/subscriptions", re.IGNORECASE)

    def test_ipn_pattern_matches(self):
        pattern = WEBHOOK_PATH_PATTERNS[7]
        assert re.search(pattern, "/ipn", re.IGNORECASE)
        assert re.search(pattern, "/ipn/", re.IGNORECASE)

    def test_postback_pattern_matches(self):
        pattern = WEBHOOK_PATH_PATTERNS[8]
        assert re.search(pattern, "/postback", re.IGNORECASE)
        assert re.search(pattern, "/postback/", re.IGNORECASE)

    def test_no_duplicates(self):
        assert len(WEBHOOK_PATH_PATTERNS) == len(set(WEBHOOK_PATH_PATTERNS))


# =============================================================================
# CONSTANTS TESTS: WEBHOOK_EVENT_TYPES
# =============================================================================

class TestWebhookEventTypes:
    """Test WEBHOOK_EVENT_TYPES constant."""

    def test_is_list(self):
        assert isinstance(WEBHOOK_EVENT_TYPES, list)

    def test_count_at_least_18(self):
        assert len(WEBHOOK_EVENT_TYPES) >= 18

    def test_all_strings(self):
        for event in WEBHOOK_EVENT_TYPES:
            assert isinstance(event, str), f"Not a string: {event!r}"

    def test_all_non_empty(self):
        for event in WEBHOOK_EVENT_TYPES:
            assert len(event) > 0, "Found empty string in WEBHOOK_EVENT_TYPES"

    # Payment events
    def test_contains_payment_completed(self):
        assert "payment.completed" in WEBHOOK_EVENT_TYPES

    def test_contains_payment_failed(self):
        assert "payment.failed" in WEBHOOK_EVENT_TYPES

    # Order events
    def test_contains_order_created(self):
        assert "order.created" in WEBHOOK_EVENT_TYPES

    def test_contains_order_updated(self):
        assert "order.updated" in WEBHOOK_EVENT_TYPES

    def test_contains_order_cancelled(self):
        assert "order.cancelled" in WEBHOOK_EVENT_TYPES

    # User events
    def test_contains_user_created(self):
        assert "user.created" in WEBHOOK_EVENT_TYPES

    def test_contains_user_deleted(self):
        assert "user.deleted" in WEBHOOK_EVENT_TYPES

    def test_contains_user_updated(self):
        assert "user.updated" in WEBHOOK_EVENT_TYPES

    # Subscription events
    def test_contains_subscription_created(self):
        assert "subscription.created" in WEBHOOK_EVENT_TYPES

    def test_contains_subscription_cancelled(self):
        assert "subscription.cancelled" in WEBHOOK_EVENT_TYPES

    # Invoice events
    def test_contains_invoice_paid(self):
        assert "invoice.paid" in WEBHOOK_EVENT_TYPES

    def test_contains_invoice_failed(self):
        assert "invoice.failed" in WEBHOOK_EVENT_TYPES

    # Charge events
    def test_contains_charge_succeeded(self):
        assert "charge.succeeded" in WEBHOOK_EVENT_TYPES

    def test_contains_charge_failed(self):
        assert "charge.failed" in WEBHOOK_EVENT_TYPES

    # Customer events
    def test_contains_customer_created(self):
        assert "customer.created" in WEBHOOK_EVENT_TYPES

    def test_contains_customer_deleted(self):
        assert "customer.deleted" in WEBHOOK_EVENT_TYPES

    # Injection attempts
    def test_contains_admin_debug_injection(self):
        assert "__admin.debug" in WEBHOOK_EVENT_TYPES

    def test_contains_internal_test_injection(self):
        assert "__internal.test" in WEBHOOK_EVENT_TYPES

    def test_contains_path_traversal_injection(self):
        assert "../../../etc/passwd" in WEBHOOK_EVENT_TYPES

    def test_no_duplicates(self):
        assert len(WEBHOOK_EVENT_TYPES) == len(set(WEBHOOK_EVENT_TYPES))


# =============================================================================
# CONSTANTS TESTS: SSRF_TEST_DOMAINS
# =============================================================================

class TestSSRFTestDomains:
    """Test SSRF_TEST_DOMAINS constant."""

    def test_is_list(self):
        assert isinstance(SSRF_TEST_DOMAINS, list)

    def test_count(self):
        assert len(SSRF_TEST_DOMAINS) == 2

    def test_all_strings(self):
        for domain in SSRF_TEST_DOMAINS:
            assert isinstance(domain, str), f"Not a string: {domain!r}"

    def test_all_non_empty(self):
        for domain in SSRF_TEST_DOMAINS:
            assert len(domain) > 0

    def test_domains_contain_example(self):
        """SSRF test domains should use safe example.com subdomains."""
        for domain in SSRF_TEST_DOMAINS:
            assert "example.com" in domain, (
                f"SSRF test domain should use example.com: {domain!r}"
            )

    def test_no_duplicates(self):
        assert len(SSRF_TEST_DOMAINS) == len(set(SSRF_TEST_DOMAINS))


# =============================================================================
# CLASS ATTRIBUTE TESTS: WebhookSecurityScanner
# =============================================================================

class TestWebhookSecurityScannerAttributes:
    """Test WebhookSecurityScanner class-level attributes."""

    def test_name(self):
        assert WebhookSecurityScanner.name == "webhook_security"

    def test_is_scan_module_subclass(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(WebhookSecurityScanner, ScanModule)

    def test_description_is_string(self):
        assert isinstance(WebhookSecurityScanner.description, str)

    def test_description_non_empty(self):
        assert len(WebhookSecurityScanner.description) > 0

    def test_description_mentions_webhook(self):
        assert "webhook" in WebhookSecurityScanner.description.lower()

    def test_version(self):
        assert WebhookSecurityScanner.version == "1.0.0"

    def test_author_is_string(self):
        assert isinstance(WebhookSecurityScanner.author, str)

    def test_author_non_empty(self):
        assert len(WebhookSecurityScanner.author) > 0

    def test_tags_is_list(self):
        assert isinstance(WebhookSecurityScanner.tags, list)

    def test_tags_non_empty(self):
        assert len(WebhookSecurityScanner.tags) > 0

    def test_tags_all_strings(self):
        for tag in WebhookSecurityScanner.tags:
            assert isinstance(tag, str), f"Tag is not a string: {tag!r}"

    def test_tags_contains_webhook(self):
        assert "webhook" in WebhookSecurityScanner.tags

    def test_tags_contains_callback(self):
        assert "callback" in WebhookSecurityScanner.tags

    def test_tags_contains_ssrf(self):
        assert "ssrf" in WebhookSecurityScanner.tags

    def test_tags_contains_integration(self):
        assert "integration" in WebhookSecurityScanner.tags

    def test_min_safety_level(self):
        assert WebhookSecurityScanner.min_safety_level == "standard"
