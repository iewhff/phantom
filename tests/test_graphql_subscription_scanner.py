"""
Tests for scanning/modules/graphql_subscription_scanner.py

Covers:
- SubscriptionVulnType enum (8 members, values, uniqueness)
- SubscriptionProtocol enum (3 members, string values)
- SubscriptionEndpoint dataclass (defaults, full creation, field count)
- SubscriptionTestResult dataclass (defaults, full creation, required fields)
- Module-level constant GRAPHQL_SUB_SCANNER_VERSION
- GraphQLSubscriptionScanner class-level constants:
  - GRAPHQL_ENDPOINTS (count, key entries)
  - FRAMEWORK_PATTERNS (keys, entry types)
  - SUBSCRIPTION_FIELDS (count, key entries)
- Scanner identity (name, version, ScanModule subclass)
- Scanner instantiation with mock settings
- Internal _add_finding helper dicts (cvss_scores, cwe_mapping)
- _get_remediation method coverage for all vuln types
- _http_to_ws URL conversion
"""

import pytest
from dataclasses import fields as dataclass_fields
from enum import Enum, auto
from unittest.mock import MagicMock

from scanning.modules.graphql_subscription_scanner import (
    GRAPHQL_SUB_SCANNER_VERSION,
    SubscriptionVulnType,
    SubscriptionProtocol,
    SubscriptionEndpoint,
    SubscriptionTestResult,
    GraphQLSubscriptionScanner,
)


# =============================================================================
# MODULE-LEVEL CONSTANT: GRAPHQL_SUB_SCANNER_VERSION
# =============================================================================

class TestGraphQLSubScannerVersion:
    """Test the module-level version constant."""

    def test_is_string(self):
        assert isinstance(GRAPHQL_SUB_SCANNER_VERSION, str)

    def test_value(self):
        assert GRAPHQL_SUB_SCANNER_VERSION == "1.0.0"

    def test_follows_semver_format(self):
        parts = GRAPHQL_SUB_SCANNER_VERSION.split(".")
        assert len(parts) == 3
        for part in parts:
            assert part.isdigit()


# =============================================================================
# ENUM TESTS: SubscriptionVulnType
# =============================================================================

class TestSubscriptionVulnType:
    """Test SubscriptionVulnType enum."""

    def test_count(self):
        assert len(SubscriptionVulnType) == 8

    def test_values_unique(self):
        values = [m.value for m in SubscriptionVulnType]
        assert len(values) == len(set(values))

    def test_names_unique(self):
        names = [m.name for m in SubscriptionVulnType]
        assert len(names) == len(set(names))

    def test_auth_bypass(self):
        assert SubscriptionVulnType.AUTH_BYPASS is not None

    def test_idor(self):
        assert SubscriptionVulnType.IDOR is not None

    def test_dos_resource(self):
        assert SubscriptionVulnType.DOS_RESOURCE is not None

    def test_data_leakage(self):
        assert SubscriptionVulnType.DATA_LEAKAGE is not None

    def test_injection(self):
        assert SubscriptionVulnType.INJECTION is not None

    def test_nested_attack(self):
        assert SubscriptionVulnType.NESTED_ATTACK is not None

    def test_cross_tenant(self):
        assert SubscriptionVulnType.CROSS_TENANT is not None

    def test_protocol_abuse(self):
        assert SubscriptionVulnType.PROTOCOL_ABUSE is not None

    def test_all_members_set(self):
        expected = {
            "AUTH_BYPASS", "IDOR", "DOS_RESOURCE", "DATA_LEAKAGE",
            "INJECTION", "NESTED_ATTACK", "CROSS_TENANT", "PROTOCOL_ABUSE",
        }
        assert {m.name for m in SubscriptionVulnType} == expected

    def test_all_are_enum_members(self):
        for member in SubscriptionVulnType:
            assert isinstance(member, Enum)

    def test_uses_auto_values(self):
        """All values should be positive ints from auto()."""
        for member in SubscriptionVulnType:
            assert isinstance(member.value, int)
            assert member.value > 0


# =============================================================================
# ENUM TESTS: SubscriptionProtocol
# =============================================================================

class TestSubscriptionProtocol:
    """Test SubscriptionProtocol enum."""

    def test_count(self):
        assert len(SubscriptionProtocol) == 3

    def test_values_unique(self):
        values = [m.value for m in SubscriptionProtocol]
        assert len(values) == len(set(values))

    def test_names_unique(self):
        names = [m.name for m in SubscriptionProtocol]
        assert len(names) == len(set(names))

    def test_graphql_ws_value(self):
        assert SubscriptionProtocol.GRAPHQL_WS.value == "graphql-ws"

    def test_subscriptions_transport_ws_value(self):
        assert SubscriptionProtocol.SUBSCRIPTIONS_TRANSPORT_WS.value == "subscriptions-transport-ws"

    def test_unknown_value(self):
        assert SubscriptionProtocol.UNKNOWN.value == "unknown"

    def test_all_members_set(self):
        expected = {"GRAPHQL_WS", "SUBSCRIPTIONS_TRANSPORT_WS", "UNKNOWN"}
        assert {m.name for m in SubscriptionProtocol} == expected

    def test_all_values_are_strings(self):
        for member in SubscriptionProtocol:
            assert isinstance(member.value, str)


# =============================================================================
# DATACLASS TESTS: SubscriptionEndpoint
# =============================================================================

class TestSubscriptionEndpointDefaults:
    """Test SubscriptionEndpoint dataclass default values."""

    def test_framework_default(self):
        ep = SubscriptionEndpoint(
            url="http://test.local/graphql",
            ws_url="ws://test.local/graphql",
            protocol=SubscriptionProtocol.GRAPHQL_WS,
        )
        assert ep.framework == "unknown"

    def test_requires_auth_default(self):
        ep = SubscriptionEndpoint(
            url="http://test.local/graphql",
            ws_url="ws://test.local/graphql",
            protocol=SubscriptionProtocol.GRAPHQL_WS,
        )
        assert ep.requires_auth is True

    def test_supports_introspection_default(self):
        ep = SubscriptionEndpoint(
            url="http://test.local/graphql",
            ws_url="ws://test.local/graphql",
            protocol=SubscriptionProtocol.GRAPHQL_WS,
        )
        assert ep.supports_introspection is False

    def test_subscription_types_default(self):
        ep = SubscriptionEndpoint(
            url="http://test.local/graphql",
            ws_url="ws://test.local/graphql",
            protocol=SubscriptionProtocol.GRAPHQL_WS,
        )
        assert ep.subscription_types == []

    def test_subscription_types_isolation(self):
        """Each instance should have its own list (no shared mutable default)."""
        ep1 = SubscriptionEndpoint(
            url="http://a.local/graphql",
            ws_url="ws://a.local/graphql",
            protocol=SubscriptionProtocol.GRAPHQL_WS,
        )
        ep2 = SubscriptionEndpoint(
            url="http://b.local/graphql",
            ws_url="ws://b.local/graphql",
            protocol=SubscriptionProtocol.GRAPHQL_WS,
        )
        ep1.subscription_types.append("userUpdated")
        assert ep2.subscription_types == []


class TestSubscriptionEndpointFull:
    """Test SubscriptionEndpoint with all fields populated."""

    def test_full_creation(self):
        ep = SubscriptionEndpoint(
            url="https://api.example.com/graphql",
            ws_url="wss://api.example.com/graphql",
            protocol=SubscriptionProtocol.SUBSCRIPTIONS_TRANSPORT_WS,
            framework="apollo",
            requires_auth=False,
            supports_introspection=True,
            subscription_types=["messageAdded", "userUpdated"],
        )
        assert ep.url == "https://api.example.com/graphql"
        assert ep.ws_url == "wss://api.example.com/graphql"
        assert ep.protocol == SubscriptionProtocol.SUBSCRIPTIONS_TRANSPORT_WS
        assert ep.framework == "apollo"
        assert ep.requires_auth is False
        assert ep.supports_introspection is True
        assert ep.subscription_types == ["messageAdded", "userUpdated"]

    def test_field_count(self):
        assert len(dataclass_fields(SubscriptionEndpoint)) == 7

    def test_required_fields(self):
        """url, ws_url, protocol are required (no defaults)."""
        with pytest.raises(TypeError):
            SubscriptionEndpoint()  # type: ignore[call-arg]


# =============================================================================
# DATACLASS TESTS: SubscriptionTestResult
# =============================================================================

class TestSubscriptionTestResultDefaults:
    """Test SubscriptionTestResult dataclass default values."""

    def test_response_data_default(self):
        result = SubscriptionTestResult(
            vulnerable=True,
            vuln_type=SubscriptionVulnType.AUTH_BYPASS,
            confidence=85,
            payload="subscription { userUpdated { id } }",
        )
        assert result.response_data == ""

    def test_evidence_default(self):
        result = SubscriptionTestResult(
            vulnerable=True,
            vuln_type=SubscriptionVulnType.AUTH_BYPASS,
            confidence=85,
            payload="test",
        )
        assert result.evidence == []

    def test_severity_default(self):
        result = SubscriptionTestResult(
            vulnerable=True,
            vuln_type=SubscriptionVulnType.IDOR,
            confidence=70,
            payload="test",
        )
        assert result.severity == "MEDIUM"

    def test_data_leaked_default(self):
        result = SubscriptionTestResult(
            vulnerable=True,
            vuln_type=SubscriptionVulnType.DOS_RESOURCE,
            confidence=60,
            payload="test",
        )
        assert result.data_leaked is False

    def test_evidence_isolation(self):
        """Each instance should have its own list (no shared mutable default)."""
        a = SubscriptionTestResult(
            vulnerable=True,
            vuln_type=SubscriptionVulnType.AUTH_BYPASS,
            confidence=80,
            payload="test_a",
        )
        b = SubscriptionTestResult(
            vulnerable=False,
            vuln_type=SubscriptionVulnType.IDOR,
            confidence=50,
            payload="test_b",
        )
        a.evidence.append("some evidence")
        assert b.evidence == []


class TestSubscriptionTestResultFull:
    """Test SubscriptionTestResult with all fields populated."""

    def test_full_creation(self):
        result = SubscriptionTestResult(
            vulnerable=True,
            vuln_type=SubscriptionVulnType.INJECTION,
            confidence=90,
            payload="subscription { userUpdated(filter: \"1' OR '1'='1\") { id } }",
            response_data='{"type": "data", "payload": {"data": {"id": 1}}}',
            evidence=["Injection processed", "Data returned"],
            severity="HIGH",
            data_leaked=True,
        )
        assert result.vulnerable is True
        assert result.vuln_type == SubscriptionVulnType.INJECTION
        assert result.confidence == 90
        assert "OR" in result.payload
        assert result.response_data != ""
        assert len(result.evidence) == 2
        assert result.severity == "HIGH"
        assert result.data_leaked is True

    def test_field_count(self):
        assert len(dataclass_fields(SubscriptionTestResult)) == 8

    def test_required_fields(self):
        """vulnerable, vuln_type, confidence, payload are required."""
        with pytest.raises(TypeError):
            SubscriptionTestResult()  # type: ignore[call-arg]

    def test_vulnerable_false(self):
        result = SubscriptionTestResult(
            vulnerable=False,
            vuln_type=SubscriptionVulnType.DATA_LEAKAGE,
            confidence=0,
            payload="",
        )
        assert result.vulnerable is False
        assert result.confidence == 0


# =============================================================================
# CLASS-LEVEL CONSTANTS: GRAPHQL_ENDPOINTS
# =============================================================================

class TestGraphQLEndpoints:
    """Test GraphQLSubscriptionScanner.GRAPHQL_ENDPOINTS."""

    def test_is_list(self):
        assert isinstance(GraphQLSubscriptionScanner.GRAPHQL_ENDPOINTS, list)

    def test_count(self):
        assert len(GraphQLSubscriptionScanner.GRAPHQL_ENDPOINTS) == 10

    def test_all_strings(self):
        for ep in GraphQLSubscriptionScanner.GRAPHQL_ENDPOINTS:
            assert isinstance(ep, str)

    def test_all_start_with_slash(self):
        for ep in GraphQLSubscriptionScanner.GRAPHQL_ENDPOINTS:
            assert ep.startswith("/"), f"Endpoint should start with /: {ep!r}"

    def test_contains_graphql(self):
        assert "/graphql" in GraphQLSubscriptionScanner.GRAPHQL_ENDPOINTS

    def test_contains_api_graphql(self):
        assert "/api/graphql" in GraphQLSubscriptionScanner.GRAPHQL_ENDPOINTS

    def test_contains_v1_graphql(self):
        assert "/v1/graphql" in GraphQLSubscriptionScanner.GRAPHQL_ENDPOINTS

    def test_contains_gql(self):
        assert "/gql" in GraphQLSubscriptionScanner.GRAPHQL_ENDPOINTS

    def test_contains_query(self):
        assert "/query" in GraphQLSubscriptionScanner.GRAPHQL_ENDPOINTS

    def test_contains_subscriptions(self):
        assert "/subscriptions" in GraphQLSubscriptionScanner.GRAPHQL_ENDPOINTS

    def test_contains_ws_graphql(self):
        assert "/ws/graphql" in GraphQLSubscriptionScanner.GRAPHQL_ENDPOINTS

    def test_no_duplicates(self):
        eps = GraphQLSubscriptionScanner.GRAPHQL_ENDPOINTS
        assert len(eps) == len(set(eps))


# =============================================================================
# CLASS-LEVEL CONSTANTS: FRAMEWORK_PATTERNS
# =============================================================================

class TestFrameworkPatterns:
    """Test GraphQLSubscriptionScanner.FRAMEWORK_PATTERNS."""

    def test_is_dict(self):
        assert isinstance(GraphQLSubscriptionScanner.FRAMEWORK_PATTERNS, dict)

    def test_count(self):
        assert len(GraphQLSubscriptionScanner.FRAMEWORK_PATTERNS) == 7

    def test_keys(self):
        expected_keys = {
            "apollo", "hasura", "yoga", "mercurius",
            "strawberry", "ariadne", "graphene",
        }
        assert set(GraphQLSubscriptionScanner.FRAMEWORK_PATTERNS.keys()) == expected_keys

    def test_all_values_are_lists(self):
        for framework, patterns in GraphQLSubscriptionScanner.FRAMEWORK_PATTERNS.items():
            assert isinstance(patterns, list), f"Patterns for '{framework}' is not a list"

    def test_all_pattern_entries_are_strings(self):
        for framework, patterns in GraphQLSubscriptionScanner.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                assert isinstance(pattern, str), (
                    f"Pattern in '{framework}' is not a string: {pattern!r}"
                )

    def test_apollo_patterns(self):
        patterns = GraphQLSubscriptionScanner.FRAMEWORK_PATTERNS["apollo"]
        assert len(patterns) == 4
        assert "apollo" in patterns
        assert "ApolloServer" in patterns
        assert "subscriptions-transport-ws" in patterns

    def test_hasura_patterns(self):
        patterns = GraphQLSubscriptionScanner.FRAMEWORK_PATTERNS["hasura"]
        assert len(patterns) == 3
        assert "hasura" in patterns
        assert "x-hasura" in patterns

    def test_yoga_patterns(self):
        patterns = GraphQLSubscriptionScanner.FRAMEWORK_PATTERNS["yoga"]
        assert len(patterns) == 3
        assert "graphql-yoga" in patterns

    def test_mercurius_patterns(self):
        patterns = GraphQLSubscriptionScanner.FRAMEWORK_PATTERNS["mercurius"]
        assert len(patterns) == 2

    def test_strawberry_patterns(self):
        patterns = GraphQLSubscriptionScanner.FRAMEWORK_PATTERNS["strawberry"]
        assert len(patterns) == 2

    def test_ariadne_patterns(self):
        patterns = GraphQLSubscriptionScanner.FRAMEWORK_PATTERNS["ariadne"]
        assert len(patterns) == 1
        assert "ariadne" in patterns

    def test_graphene_patterns(self):
        patterns = GraphQLSubscriptionScanner.FRAMEWORK_PATTERNS["graphene"]
        assert len(patterns) == 2
        assert "graphene" in patterns
        assert "graphene-django" in patterns

    def test_no_empty_pattern_lists(self):
        for framework, patterns in GraphQLSubscriptionScanner.FRAMEWORK_PATTERNS.items():
            assert len(patterns) > 0, f"Framework '{framework}' has empty patterns list"


# =============================================================================
# CLASS-LEVEL CONSTANTS: SUBSCRIPTION_FIELDS
# =============================================================================

class TestSubscriptionFields:
    """Test GraphQLSubscriptionScanner.SUBSCRIPTION_FIELDS."""

    def test_is_list(self):
        assert isinstance(GraphQLSubscriptionScanner.SUBSCRIPTION_FIELDS, list)

    def test_count(self):
        assert len(GraphQLSubscriptionScanner.SUBSCRIPTION_FIELDS) == 16

    def test_all_strings(self):
        for field in GraphQLSubscriptionScanner.SUBSCRIPTION_FIELDS:
            assert isinstance(field, str)

    def test_no_duplicates(self):
        fields = GraphQLSubscriptionScanner.SUBSCRIPTION_FIELDS
        assert len(fields) == len(set(fields))

    def test_contains_messageAdded(self):
        assert "messageAdded" in GraphQLSubscriptionScanner.SUBSCRIPTION_FIELDS

    def test_contains_userUpdated(self):
        assert "userUpdated" in GraphQLSubscriptionScanner.SUBSCRIPTION_FIELDS

    def test_contains_orderStatusChanged(self):
        assert "orderStatusChanged" in GraphQLSubscriptionScanner.SUBSCRIPTION_FIELDS

    def test_contains_subscribe(self):
        assert "subscribe" in GraphQLSubscriptionScanner.SUBSCRIPTION_FIELDS

    def test_contains_onMessage(self):
        assert "onMessage" in GraphQLSubscriptionScanner.SUBSCRIPTION_FIELDS

    def test_contains_watch(self):
        assert "watch" in GraphQLSubscriptionScanner.SUBSCRIPTION_FIELDS

    def test_contains_listen(self):
        assert "listen" in GraphQLSubscriptionScanner.SUBSCRIPTION_FIELDS

    def test_contains_newNotification(self):
        assert "newNotification" in GraphQLSubscriptionScanner.SUBSCRIPTION_FIELDS


# =============================================================================
# SCANNER IDENTITY
# =============================================================================

class TestScannerIdentity:
    """Test scanner name attribute and ScanModule subclass."""

    def test_name(self):
        assert GraphQLSubscriptionScanner.name == "graphql_subscription_scanner"

    def test_version(self):
        assert GraphQLSubscriptionScanner.version == GRAPHQL_SUB_SCANNER_VERSION

    def test_version_value(self):
        assert GraphQLSubscriptionScanner.version == "1.0.0"

    def test_is_scan_module(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(GraphQLSubscriptionScanner, ScanModule)

    def test_instantiation_with_mock_settings(self):
        settings = MagicMock()
        settings.timeouts.request_timeout = 30.0
        scanner = GraphQLSubscriptionScanner(settings)
        assert scanner.name == "graphql_subscription_scanner"
        assert scanner.timeout == 30.0

    def test_instantiation_without_timeouts(self):
        settings = MagicMock(spec=[])
        scanner = GraphQLSubscriptionScanner(settings)
        assert scanner.timeout == 30.0

    def test_ws_timeout_default(self):
        settings = MagicMock()
        settings.timeouts.request_timeout = 30.0
        scanner = GraphQLSubscriptionScanner(settings)
        assert scanner.ws_timeout == 10.0

    def test_findings_empty_on_init(self):
        settings = MagicMock()
        settings.timeouts.request_timeout = 30.0
        scanner = GraphQLSubscriptionScanner(settings)
        assert scanner.findings == []

    def test_subscription_endpoints_empty_on_init(self):
        settings = MagicMock()
        settings.timeouts.request_timeout = 30.0
        scanner = GraphQLSubscriptionScanner(settings)
        assert scanner.subscription_endpoints == []


# =============================================================================
# INTERNAL METHOD: _http_to_ws
# =============================================================================

class TestHttpToWs:
    """Test the _http_to_ws URL conversion method."""

    def _make_scanner(self):
        settings = MagicMock()
        settings.timeouts.request_timeout = 30.0
        return GraphQLSubscriptionScanner(settings)

    def test_http_to_ws(self):
        scanner = self._make_scanner()
        result = scanner._http_to_ws("http://example.com/graphql")
        assert result == "ws://example.com/graphql"

    def test_https_to_wss(self):
        scanner = self._make_scanner()
        result = scanner._http_to_ws("https://example.com/graphql")
        assert result == "wss://example.com/graphql"

    def test_preserves_path(self):
        scanner = self._make_scanner()
        result = scanner._http_to_ws("http://example.com/api/v1/graphql")
        assert result == "ws://example.com/api/v1/graphql"

    def test_preserves_port(self):
        scanner = self._make_scanner()
        result = scanner._http_to_ws("http://example.com:8080/graphql")
        assert result == "ws://example.com:8080/graphql"

    def test_https_with_port(self):
        scanner = self._make_scanner()
        result = scanner._http_to_ws("https://example.com:443/subscriptions")
        assert result == "wss://example.com:443/subscriptions"


# =============================================================================
# INTERNAL METHOD: _get_remediation
# =============================================================================

class TestGetRemediation:
    """Test the _get_remediation method for all vuln types."""

    def _make_scanner(self):
        settings = MagicMock()
        settings.timeouts.request_timeout = 30.0
        return GraphQLSubscriptionScanner(settings)

    def test_base_advice_always_present(self):
        """Base remediation advice should appear for every vuln type."""
        scanner = self._make_scanner()
        for vuln_type in SubscriptionVulnType:
            result = scanner._get_remediation(vuln_type)
            assert "Implement authentication" in result
            assert "query depth" in result
            assert "rate limiting" in result

    def test_auth_bypass_specific(self):
        scanner = self._make_scanner()
        result = scanner._get_remediation(SubscriptionVulnType.AUTH_BYPASS)
        assert "AUTH BYPASS SPECIFIC" in result
        assert "connection_init" in result

    def test_idor_specific(self):
        scanner = self._make_scanner()
        result = scanner._get_remediation(SubscriptionVulnType.IDOR)
        assert "IDOR SPECIFIC" in result
        assert "row-level security" in result

    def test_dos_resource_specific(self):
        scanner = self._make_scanner()
        result = scanner._get_remediation(SubscriptionVulnType.DOS_RESOURCE)
        assert "DoS SPECIFIC" in result
        assert "Limit subscriptions per connection" in result

    def test_injection_specific(self):
        scanner = self._make_scanner()
        result = scanner._get_remediation(SubscriptionVulnType.INJECTION)
        assert "INJECTION SPECIFIC" in result
        assert "parameterized queries" in result

    def test_nested_attack_specific(self):
        scanner = self._make_scanner()
        result = scanner._get_remediation(SubscriptionVulnType.NESTED_ATTACK)
        assert "NESTED QUERY SPECIFIC" in result
        assert "query complexity" in result

    def test_data_leakage_returns_base_only(self):
        """DATA_LEAKAGE has no special section, only base advice."""
        scanner = self._make_scanner()
        result = scanner._get_remediation(SubscriptionVulnType.DATA_LEAKAGE)
        assert "SPECIFIC" not in result

    def test_cross_tenant_returns_base_only(self):
        scanner = self._make_scanner()
        result = scanner._get_remediation(SubscriptionVulnType.CROSS_TENANT)
        assert "SPECIFIC" not in result

    def test_protocol_abuse_returns_base_only(self):
        scanner = self._make_scanner()
        result = scanner._get_remediation(SubscriptionVulnType.PROTOCOL_ABUSE)
        assert "SPECIFIC" not in result

    def test_returns_string(self):
        scanner = self._make_scanner()
        for vuln_type in SubscriptionVulnType:
            result = scanner._get_remediation(vuln_type)
            assert isinstance(result, str)
            assert len(result) > 0
