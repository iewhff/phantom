"""
Tests for scanning/modules/graphql_advanced_scanner.py

Covers:
- GraphQLVulnType enum (27 members, values, uniqueness)
- SchemaInfo dataclass (defaults, full creation, properties)
- Module-level payload lists (counts, key entries, types)
- Class-level constants (GRAPHQL_ENDPOINTS, SENSITIVE_FIELDS, MAX_SCAN_DURATION)
- Scanner identity (name attribute, ScanModule subclass)
- Scanner instantiation with mock settings
"""

import pytest
from unittest.mock import MagicMock

from scanning.modules.graphql_advanced_scanner import (
    GraphQLVulnType,
    SchemaInfo,
    RLS_FILTER_BYPASS_PAYLOADS,
    AGGREGATE_PAYLOADS,
    RELATIONSHIP_TRAVERSAL_PAYLOADS,
    SUPABASE_RLS_PAYLOADS,
    HASURA_PAYLOADS,
    MUTATION_BYPASS_PAYLOADS,
    GraphQLAdvancedScanner,
)


# =============================================================================
# GraphQLVulnType ENUM
# =============================================================================

class TestGraphQLVulnType:
    """Test GraphQLVulnType enum."""

    def test_count(self):
        assert len(GraphQLVulnType) == 27

    def test_values_unique(self):
        values = [m.value for m in GraphQLVulnType]
        assert len(values) == len(set(values))

    def test_names_unique(self):
        names = [m.name for m in GraphQLVulnType]
        assert len(names) == len(set(names))

    # --- Core GraphQL attacks ---

    def test_introspection_enabled(self):
        assert GraphQLVulnType.INTROSPECTION_ENABLED is not None

    def test_batching_attack(self):
        assert GraphQLVulnType.BATCHING_ATTACK is not None

    def test_alias_dos(self):
        assert GraphQLVulnType.ALIAS_DOS is not None

    def test_depth_attack(self):
        assert GraphQLVulnType.DEPTH_ATTACK is not None

    def test_field_suggestion(self):
        assert GraphQLVulnType.FIELD_SUGGESTION is not None

    def test_directive_abuse(self):
        assert GraphQLVulnType.DIRECTIVE_ABUSE is not None

    def test_circular_fragment(self):
        assert GraphQLVulnType.CIRCULAR_FRAGMENT is not None

    def test_idor(self):
        assert GraphQLVulnType.IDOR is not None

    def test_injection(self):
        assert GraphQLVulnType.INJECTION is not None

    # --- RLS/Access control bypass ---

    def test_rls_bypass(self):
        assert GraphQLVulnType.RLS_BYPASS is not None

    def test_filter_manipulation(self):
        assert GraphQLVulnType.FILTER_MANIPULATION is not None

    def test_column_access(self):
        assert GraphQLVulnType.COLUMN_ACCESS is not None

    def test_aggregate_abuse(self):
        assert GraphQLVulnType.AGGREGATE_ABUSE is not None

    def test_relationship_traversal(self):
        assert GraphQLVulnType.RELATIONSHIP_TRAVERSAL is not None

    def test_mutation_bypass(self):
        assert GraphQLVulnType.MUTATION_BYPASS is not None

    def test_subscription_leak(self):
        assert GraphQLVulnType.SUBSCRIPTION_LEAK is not None

    def test_admin_secret_found(self):
        assert GraphQLVulnType.ADMIN_SECRET_FOUND is not None

    def test_service_role_key(self):
        assert GraphQLVulnType.SERVICE_ROLE_KEY is not None

    # --- Modern GraphQL attacks ---

    def test_persisted_query_abuse(self):
        assert GraphQLVulnType.PERSISTED_QUERY_ABUSE is not None

    def test_complexity_bypass(self):
        assert GraphQLVulnType.COMPLEXITY_BYPASS is not None

    def test_field_duplication_dos(self):
        assert GraphQLVulnType.FIELD_DUPLICATION_DOS is not None

    def test_extension_exposure(self):
        assert GraphQLVulnType.EXTENSION_EXPOSURE is not None

    def test_federation_sdl_leak(self):
        assert GraphQLVulnType.FEDERATION_SDL_LEAK is not None

    def test_federation_entity_access(self):
        assert GraphQLVulnType.FEDERATION_ENTITY_ACCESS is not None

    def test_websocket_subscription(self):
        assert GraphQLVulnType.WEBSOCKET_SUBSCRIPTION is not None

    def test_type_confusion(self):
        assert GraphQLVulnType.TYPE_CONFUSION is not None

    def test_defer_abuse(self):
        assert GraphQLVulnType.DEFER_ABUSE is not None

    def test_all_are_enum_members(self):
        from enum import Enum
        for member in GraphQLVulnType:
            assert isinstance(member, Enum)


# =============================================================================
# SchemaInfo DATACLASS
# =============================================================================

class TestSchemaInfo:
    """Test SchemaInfo dataclass."""

    def test_defaults(self):
        info = SchemaInfo()
        assert info.types == []
        assert info.queries == []
        assert info.mutations == []
        assert info.subscriptions == []
        assert info.sensitive_fields == []
        assert info.filter_args == []
        assert info.backend_type is None

    def test_full_creation(self):
        info = SchemaInfo(
            types=["User", "Post"],
            queries=["getUser", "listPosts"],
            mutations=["createUser"],
            subscriptions=["onMessage"],
            sensitive_fields=["password", "token"],
            filter_args=["where", "order_by"],
            backend_type="hasura",
        )
        assert info.types == ["User", "Post"]
        assert info.queries == ["getUser", "listPosts"]
        assert info.mutations == ["createUser"]
        assert info.subscriptions == ["onMessage"]
        assert info.sensitive_fields == ["password", "token"]
        assert info.filter_args == ["where", "order_by"]
        assert info.backend_type == "hasura"

    def test_backend_type_nullable(self):
        info = SchemaInfo(backend_type=None)
        assert info.backend_type is None

    def test_backend_type_supabase(self):
        info = SchemaInfo(backend_type="supabase")
        assert info.backend_type == "supabase"

    def test_backend_type_postgraphile(self):
        info = SchemaInfo(backend_type="postgraphile")
        assert info.backend_type == "postgraphile"

    def test_lists_are_independent(self):
        """Each instance should have independent lists (no shared default)."""
        info1 = SchemaInfo()
        info2 = SchemaInfo()
        info1.types.append("User")
        assert info2.types == []

    def test_has_seven_fields(self):
        from dataclasses import fields
        assert len(fields(SchemaInfo)) == 7


# =============================================================================
# RLS_FILTER_BYPASS_PAYLOADS
# =============================================================================

class TestRLSFilterBypassPayloads:
    """Test RLS_FILTER_BYPASS_PAYLOADS list."""

    def test_count(self):
        assert len(RLS_FILTER_BYPASS_PAYLOADS) == 12

    def test_all_are_dicts(self):
        for payload in RLS_FILTER_BYPASS_PAYLOADS:
            assert isinstance(payload, dict)

    def test_has_or_condition(self):
        has_or = any("_or" in p for p in RLS_FILTER_BYPASS_PAYLOADS)
        assert has_or

    def test_has_and_condition(self):
        has_and = any("_and" in p for p in RLS_FILTER_BYPASS_PAYLOADS)
        assert has_and

    def test_has_gte_condition(self):
        has_gte = any(
            isinstance(v, dict) and "_gte" in v
            for p in RLS_FILTER_BYPASS_PAYLOADS
            for v in p.values()
            if isinstance(v, dict)
        )
        assert has_gte

    def test_has_like_wildcard(self):
        has_like = any(
            isinstance(v, dict) and "_like" in v
            for p in RLS_FILTER_BYPASS_PAYLOADS
            for v in p.values()
            if isinstance(v, dict)
        )
        assert has_like

    def test_has_regex_bypass(self):
        has_regex = any(
            isinstance(v, dict) and "_regex" in v
            for p in RLS_FILTER_BYPASS_PAYLOADS
            for v in p.values()
            if isinstance(v, dict)
        )
        assert has_regex

    def test_first_is_boolean_condition_bypass(self):
        assert "_or" in RLS_FILTER_BYPASS_PAYLOADS[0]


# =============================================================================
# AGGREGATE_PAYLOADS
# =============================================================================

class TestAggregatePayloads:
    """Test AGGREGATE_PAYLOADS list."""

    def test_count(self):
        assert len(AGGREGATE_PAYLOADS) == 6

    def test_all_are_strings(self):
        for payload in AGGREGATE_PAYLOADS:
            assert isinstance(payload, str)

    def test_all_start_with_aggregate(self):
        for payload in AGGREGATE_PAYLOADS:
            assert payload.startswith("aggregate {")

    def test_has_count(self):
        assert any("count" in p for p in AGGREGATE_PAYLOADS)

    def test_has_sum(self):
        assert any("sum" in p for p in AGGREGATE_PAYLOADS)

    def test_has_avg(self):
        assert any("avg" in p for p in AGGREGATE_PAYLOADS)

    def test_has_max(self):
        assert any("max" in p for p in AGGREGATE_PAYLOADS)

    def test_has_min(self):
        assert any("min" in p for p in AGGREGATE_PAYLOADS)


# =============================================================================
# RELATIONSHIP_TRAVERSAL_PAYLOADS
# =============================================================================

class TestRelationshipTraversalPayloads:
    """Test RELATIONSHIP_TRAVERSAL_PAYLOADS list."""

    def test_count(self):
        assert len(RELATIONSHIP_TRAVERSAL_PAYLOADS) == 4

    def test_all_are_strings(self):
        for payload in RELATIONSHIP_TRAVERSAL_PAYLOADS:
            assert isinstance(payload, str)

    def test_has_parent_child_traversal(self):
        assert any("parent" in p and "children" in p for p in RELATIONSHIP_TRAVERSAL_PAYLOADS)

    def test_has_circular_reference(self):
        assert any("author" in p and "posts" in p for p in RELATIONSHIP_TRAVERSAL_PAYLOADS)

    def test_has_many_to_many_bypass(self):
        assert any("users_roles" in p for p in RELATIONSHIP_TRAVERSAL_PAYLOADS)

    def test_has_password_access(self):
        assert any("password" in p for p in RELATIONSHIP_TRAVERSAL_PAYLOADS)


# =============================================================================
# SUPABASE_RLS_PAYLOADS
# =============================================================================

class TestSupabaseRLSPayloads:
    """Test SUPABASE_RLS_PAYLOADS list."""

    def test_count(self):
        assert len(SUPABASE_RLS_PAYLOADS) == 3

    def test_all_are_dicts(self):
        for payload in SUPABASE_RLS_PAYLOADS:
            assert isinstance(payload, dict)

    def test_has_service_role_header(self):
        has_service_role = any(
            "headers" in p and "apikey" in p.get("headers", {})
            for p in SUPABASE_RLS_PAYLOADS
        )
        assert has_service_role

    def test_has_query_payload(self):
        has_query = any("query" in p for p in SUPABASE_RLS_PAYLOADS)
        assert has_query

    def test_has_postgrest_filter(self):
        has_select = any("select" in p for p in SUPABASE_RLS_PAYLOADS)
        assert has_select


# =============================================================================
# HASURA_PAYLOADS
# =============================================================================

class TestHasuraPayloads:
    """Test HASURA_PAYLOADS list."""

    def test_count(self):
        assert len(HASURA_PAYLOADS) == 7

    def test_all_are_dicts(self):
        for payload in HASURA_PAYLOADS:
            assert isinstance(payload, dict)

    def test_has_admin_secret_probes(self):
        admin_probes = [
            p for p in HASURA_PAYLOADS
            if "x-hasura-admin-secret" in p
        ]
        assert len(admin_probes) >= 4

    def test_has_role_escalation(self):
        role_probes = [
            p for p in HASURA_PAYLOADS
            if "x-hasura-role" in p and "x-hasura-admin-secret" not in p
        ]
        assert len(role_probes) >= 1

    def test_has_allow_list_bypass(self):
        has_allowed_roles = any("x-hasura-allowed-roles" in p for p in HASURA_PAYLOADS)
        assert has_allowed_roles

    def test_admin_secret_values(self):
        """Admin secret payloads should contain common weak secrets."""
        secrets = [
            p["x-hasura-admin-secret"]
            for p in HASURA_PAYLOADS
            if "x-hasura-admin-secret" in p
        ]
        assert "admin" in secrets
        assert "secret" in secrets
        assert "hasura" in secrets
        assert "password" in secrets


# =============================================================================
# MUTATION_BYPASS_PAYLOADS
# =============================================================================

class TestMutationBypassPayloads:
    """Test MUTATION_BYPASS_PAYLOADS list."""

    def test_count(self):
        assert len(MUTATION_BYPASS_PAYLOADS) == 4

    def test_all_are_strings(self):
        for payload in MUTATION_BYPASS_PAYLOADS:
            assert isinstance(payload, str)

    def test_has_insert(self):
        assert any("insert_users" in p for p in MUTATION_BYPASS_PAYLOADS)

    def test_has_update(self):
        assert any("update_users" in p for p in MUTATION_BYPASS_PAYLOADS)

    def test_has_delete(self):
        assert any("delete_users" in p for p in MUTATION_BYPASS_PAYLOADS)

    def test_has_upsert(self):
        assert any("on_conflict" in p for p in MUTATION_BYPASS_PAYLOADS)

    def test_insert_attempts_admin_role(self):
        insert_payloads = [p for p in MUTATION_BYPASS_PAYLOADS if "insert_users" in p]
        assert any("admin" in p for p in insert_payloads)


# =============================================================================
# GraphQLAdvancedScanner CLASS-LEVEL CONSTANTS
# =============================================================================

class TestGraphQLAdvancedScannerConstants:
    """Test class-level constants on GraphQLAdvancedScanner."""

    def test_max_scan_duration(self):
        assert GraphQLAdvancedScanner.MAX_SCAN_DURATION == 180.0

    def test_max_scan_duration_is_float(self):
        assert isinstance(GraphQLAdvancedScanner.MAX_SCAN_DURATION, float)

    # --- GRAPHQL_ENDPOINTS ---

    def test_graphql_endpoints_count(self):
        assert len(GraphQLAdvancedScanner.GRAPHQL_ENDPOINTS) == 31

    def test_graphql_endpoints_all_strings(self):
        for ep in GraphQLAdvancedScanner.GRAPHQL_ENDPOINTS:
            assert isinstance(ep, str)

    def test_graphql_endpoints_all_start_with_slash(self):
        for ep in GraphQLAdvancedScanner.GRAPHQL_ENDPOINTS:
            assert ep.startswith("/"), f"Endpoint should start with /: {ep}"

    def test_has_standard_graphql(self):
        assert "/graphql" in GraphQLAdvancedScanner.GRAPHQL_ENDPOINTS

    def test_has_api_graphql(self):
        assert "/api/graphql" in GraphQLAdvancedScanner.GRAPHQL_ENDPOINTS

    def test_has_hasura_v1(self):
        assert "/v1/graphql" in GraphQLAdvancedScanner.GRAPHQL_ENDPOINTS

    def test_has_supabase_rest(self):
        assert "/rest/v1/" in GraphQLAdvancedScanner.GRAPHQL_ENDPOINTS

    def test_has_postgraphile(self):
        assert "/postgraphile" in GraphQLAdvancedScanner.GRAPHQL_ENDPOINTS

    def test_has_graphiql(self):
        assert "/graphiql" in GraphQLAdvancedScanner.GRAPHQL_ENDPOINTS

    def test_has_playground(self):
        assert "/playground" in GraphQLAdvancedScanner.GRAPHQL_ENDPOINTS

    def test_has_apollo(self):
        assert "/apollo" in GraphQLAdvancedScanner.GRAPHQL_ENDPOINTS

    def test_has_appsync(self):
        assert "/appsync" in GraphQLAdvancedScanner.GRAPHQL_ENDPOINTS

    # --- SENSITIVE_FIELDS ---

    def test_sensitive_fields_count(self):
        assert len(GraphQLAdvancedScanner.SENSITIVE_FIELDS) == 15

    def test_sensitive_fields_all_strings(self):
        for f in GraphQLAdvancedScanner.SENSITIVE_FIELDS:
            assert isinstance(f, str)

    def test_sensitive_fields_has_password(self):
        assert "password" in GraphQLAdvancedScanner.SENSITIVE_FIELDS

    def test_sensitive_fields_has_secret(self):
        assert "secret" in GraphQLAdvancedScanner.SENSITIVE_FIELDS

    def test_sensitive_fields_has_token(self):
        assert "token" in GraphQLAdvancedScanner.SENSITIVE_FIELDS

    def test_sensitive_fields_has_api_key(self):
        assert "api_key" in GraphQLAdvancedScanner.SENSITIVE_FIELDS

    def test_sensitive_fields_has_admin(self):
        assert "admin" in GraphQLAdvancedScanner.SENSITIVE_FIELDS

    def test_sensitive_fields_has_credit_card(self):
        assert "credit_card" in GraphQLAdvancedScanner.SENSITIVE_FIELDS

    def test_sensitive_fields_has_ssn(self):
        assert "ssn" in GraphQLAdvancedScanner.SENSITIVE_FIELDS

    def test_sensitive_fields_has_access_token(self):
        assert "access_token" in GraphQLAdvancedScanner.SENSITIVE_FIELDS

    def test_sensitive_fields_has_refresh_token(self):
        assert "refresh_token" in GraphQLAdvancedScanner.SENSITIVE_FIELDS


# =============================================================================
# SCANNER IDENTITY
# =============================================================================

class TestScannerIdentity:
    """Test scanner name attribute and ScanModule subclass."""

    def test_name(self):
        assert GraphQLAdvancedScanner.name == "graphql_advanced_scanner"

    def test_is_scan_module(self):
        from scanning.vuln_scanner import ScanModule
        assert issubclass(GraphQLAdvancedScanner, ScanModule)

    def test_instantiation_with_mock_settings(self):
        settings = MagicMock()
        settings.timeouts.request_timeout = 30.0
        scanner = GraphQLAdvancedScanner(settings)
        assert scanner.name == "graphql_advanced_scanner"
        assert scanner.timeout == 30.0

    def test_instantiation_without_timeouts(self):
        settings = MagicMock(spec=[])
        scanner = GraphQLAdvancedScanner(settings)
        assert scanner.timeout == 30.0

    def test_schema_info_none_on_init(self):
        settings = MagicMock()
        settings.timeouts.request_timeout = 30.0
        scanner = GraphQLAdvancedScanner(settings)
        assert scanner.schema_info is None

    def test_discovered_tables_empty_on_init(self):
        settings = MagicMock()
        settings.timeouts.request_timeout = 30.0
        scanner = GraphQLAdvancedScanner(settings)
        assert scanner._discovered_tables == []
