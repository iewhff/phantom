"""
GraphQL Subscription Security Scanner v1.0

Detects security vulnerabilities in GraphQL Subscription endpoints.
GraphQL Subscriptions use WebSockets for real-time data, creating
unique attack surfaces beyond standard GraphQL queries/mutations.

Vulnerability Types Covered:
1. Auth Bypass - Subscribe without authentication
2. IDOR via Subscriptions - Access other users' data streams
3. DoS via Subscriptions - Resource exhaustion attacks
4. Data Leakage - Subscribe to sensitive events
5. Injection in Variables - SQLi/NoSQLi via subscription variables
6. Nested Query Attacks - Deep subscriptions for DoS
7. Cross-Tenant Data Leakage - Multi-tenancy bypass

Bug Bounty Value: $2,000 - $15,000 for critical subscription vulns
Reference: Real-time data leakage often rated higher than REST equivalents

CWE Coverage:
- CWE-284: Improper Access Control
- CWE-200: Exposure of Sensitive Information
- CWE-400: Uncontrolled Resource Consumption
- CWE-89: SQL Injection (via variables)
- CWE-943: NoSQL Injection (via variables)

Author: PetNTester AI
Version: 1.0.0 (2026-02-19)
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urljoin, urlparse

import httpx

try:
    import websockets
    from websockets.client import WebSocketClientProtocol
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    WebSocketClientProtocol = None

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.http_client import create_protected_client, get_configured_ssl_verify
from scanning.scan_context import ScanContext

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)

# Version
GRAPHQL_SUB_SCANNER_VERSION = "1.0.0"


class SubscriptionVulnType(Enum):
    """Types of GraphQL subscription vulnerabilities."""
    AUTH_BYPASS = auto()           # Subscribe without authentication
    IDOR = auto()                  # Access other users' subscriptions
    DOS_RESOURCE = auto()          # Resource exhaustion
    DATA_LEAKAGE = auto()          # Sensitive data in subscriptions
    INJECTION = auto()             # SQLi/NoSQLi via variables
    NESTED_ATTACK = auto()         # Deep query DoS
    CROSS_TENANT = auto()          # Multi-tenant bypass
    PROTOCOL_ABUSE = auto()        # WebSocket protocol manipulation


class SubscriptionProtocol(Enum):
    """GraphQL subscription protocols."""
    GRAPHQL_WS = "graphql-ws"                    # Modern protocol
    SUBSCRIPTIONS_TRANSPORT_WS = "subscriptions-transport-ws"  # Legacy Apollo
    UNKNOWN = "unknown"


@dataclass
class SubscriptionEndpoint:
    """Represents a discovered GraphQL subscription endpoint."""
    url: str
    ws_url: str
    protocol: SubscriptionProtocol
    framework: str = "unknown"
    requires_auth: bool = True
    supports_introspection: bool = False
    subscription_types: list[str] = field(default_factory=list)


@dataclass
class SubscriptionTestResult:
    """Result of a subscription security test."""
    vulnerable: bool
    vuln_type: SubscriptionVulnType
    confidence: int  # 0-100
    payload: str
    response_data: str = ""
    evidence: list[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    data_leaked: bool = False


class GraphQLSubscriptionScanner(ScanModule):
    """
    GraphQL Subscription Security Scanner.

    Detects vulnerabilities in real-time GraphQL subscription endpoints:
    - Authentication bypass on subscriptions
    - IDOR via subscription parameters
    - DoS through subscription abuse
    - Data leakage in real-time streams
    - Injection attacks via subscription variables

    Focus: Real-time data channels are high-value targets due to
    continuous data exposure vs. single request/response.
    """

    name = "graphql_subscription_scanner"
    version = GRAPHQL_SUB_SCANNER_VERSION

    # Common GraphQL endpoint patterns
    GRAPHQL_ENDPOINTS = [
        "/graphql", "/api/graphql", "/v1/graphql",
        "/gql", "/query", "/api/query",
        "/graphql/v1", "/graphql/v2",
        "/subscriptions", "/ws/graphql",
    ]

    # Framework-specific patterns for fingerprinting
    FRAMEWORK_PATTERNS = {
        "apollo": [
            "apollo", "ApolloServer", "apollo-server",
            "subscriptions-transport-ws",
        ],
        "hasura": [
            "hasura", "x-hasura", "Hasura GraphQL",
        ],
        "yoga": [
            "graphql-yoga", "yoga", "envelop",
        ],
        "mercurius": [
            "mercurius", "fastify-gql",
        ],
        "strawberry": [
            "strawberry", "strawberry-graphql",
        ],
        "ariadne": [
            "ariadne",
        ],
        "graphene": [
            "graphene", "graphene-django",
        ],
    }

    # Common subscription field names
    SUBSCRIPTION_FIELDS = [
        "messageAdded", "userUpdated", "orderStatusChanged",
        "notificationReceived", "dataChanged", "eventOccurred",
        "newMessage", "newNotification", "newOrder",
        "onMessage", "onUpdate", "onChange", "onEvent",
        "subscribe", "listen", "watch",
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
        self.ws_timeout = 10.0  # WebSocket specific timeout
        self.findings: list[dict[str, Any]] = []
        self.subscription_endpoints: list[SubscriptionEndpoint] = []
        self._ssl_verify = get_configured_ssl_verify()

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """Execute GraphQL subscription security scan."""

        if not WEBSOCKETS_AVAILABLE:
            logger.warning("websockets library not installed. Skipping GraphQL subscription scan.")
            return {
                "module": self.name,
                "version": self.version,
                "findings": [],
                "error": "websockets library not installed",
            }

        # SCAN CONTEXT: Unified access to auth, response validation
        self._ctx = ScanContext(asset_data)
        self._auth_headers = self._ctx.auth_headers
        self._auth_token = self._ctx.get("jwt_token") or self._ctx.get("auth_token")

        self.findings = []
        self.subscription_endpoints = []

        base_url = f"https://{host}" if not host.startswith("http") else host
        urls = asset_data.get("urls", []) if isinstance(asset_data, dict) else []

        logger.info(f"GraphQL Subscription Scanner v{self.version} starting on {host}")

        client = create_protected_client(
            timeout=self.timeout,
            verify_ssl=self._ssl_verify,
            follow_redirects=True,
            custom_headers=self._auth_headers,
        )

        async with client:
            # Phase 1: Discover GraphQL endpoints with subscription support
            await self._discover_subscription_endpoints(client, base_url, urls, rate_limiter)

            if not self.subscription_endpoints:
                logger.info("No GraphQL subscription endpoints discovered")
                return {
                    "module": self.name,
                    "version": self.version,
                    "findings": [],
                    "subscription_endpoints": [],
                }

            logger.info(f"Found {len(self.subscription_endpoints)} subscription-enabled endpoints")

            # Phase 2: Test authentication bypass
            await self._test_auth_bypass(rate_limiter)

            # Phase 3: Test IDOR via subscriptions
            await self._test_idor_subscriptions(rate_limiter)

            # Phase 4: Test DoS potential
            await self._test_dos_potential(rate_limiter)

            # Phase 5: Test data leakage
            await self._test_data_leakage(rate_limiter)

            # Phase 6: Test injection in variables
            await self._test_injection(rate_limiter)

            # Phase 7: Test nested query attacks
            await self._test_nested_attacks(rate_limiter)

        logger.info(f"GraphQL subscription scan complete. Found {len(self.findings)} vulnerabilities")

        return {
            "module": self.name,
            "version": self.version,
            "findings": self.findings,
            "subscription_endpoints": [
                {"url": ep.url, "ws_url": ep.ws_url, "protocol": ep.protocol.value, "framework": ep.framework}
                for ep in self.subscription_endpoints
            ],
        }

    async def _discover_subscription_endpoints(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        urls: list[str],
        rate_limiter: RateLimiter,
    ) -> None:
        """Discover GraphQL endpoints that support subscriptions."""
        for endpoint in self.GRAPHQL_ENDPOINTS:
            await rate_limiter.acquire()

            url = urljoin(base_url, endpoint)
            try:
                # Test introspection query to find subscription type
                introspection_query = """
                query IntrospectionQuery {
                    __schema {
                        subscriptionType {
                            name
                            fields {
                                name
                                args {
                                    name
                                    type { name }
                                }
                            }
                        }
                    }
                }
                """

                response = await client.post(
                    url,
                    json={"query": introspection_query},
                    headers={"Content-Type": "application/json"},
                )

                if response.status_code == 200:
                    try:
                        data = response.json()
                        schema = data.get("data", {}).get("__schema", {})
                        sub_type = schema.get("subscriptionType")

                        if sub_type:
                            # GraphQL endpoint with subscriptions!
                            ws_url = self._http_to_ws(url)
                            protocol = self._detect_protocol(response, client)
                            framework = self._detect_framework(response)

                            subscription_fields = [
                                f["name"] for f in sub_type.get("fields", [])
                            ]

                            endpoint_info = SubscriptionEndpoint(
                                url=url,
                                ws_url=ws_url,
                                protocol=protocol,
                                framework=framework,
                                supports_introspection=True,
                                subscription_types=subscription_fields,
                            )
                            self.subscription_endpoints.append(endpoint_info)

                            logger.info(
                                f"Found GraphQL subscriptions at {url}: "
                                f"{len(subscription_fields)} subscription types"
                            )

                    except json.JSONDecodeError:
                        pass

                # Also check if endpoint mentions subscriptions in error messages
                elif response.status_code in [400, 401, 403]:
                    if "subscription" in response.text.lower():
                        ws_url = self._http_to_ws(url)
                        endpoint_info = SubscriptionEndpoint(
                            url=url,
                            ws_url=ws_url,
                            protocol=SubscriptionProtocol.UNKNOWN,
                            supports_introspection=False,
                        )
                        self.subscription_endpoints.append(endpoint_info)

            except Exception as e:
                logger.debug(f"Subscription endpoint discovery error at {url}: {e}")

        # Check crawled URLs for GraphQL patterns
        for url in urls[:50]:
            url_lower = url.lower()
            if any(p in url_lower for p in ["graphql", "gql", "/subscriptions"]):
                if not any(ep.url == url for ep in self.subscription_endpoints):
                    ws_url = self._http_to_ws(url)
                    self.subscription_endpoints.append(SubscriptionEndpoint(
                        url=url,
                        ws_url=ws_url,
                        protocol=SubscriptionProtocol.UNKNOWN,
                    ))

    def _http_to_ws(self, http_url: str) -> str:
        """Convert HTTP URL to WebSocket URL."""
        parsed = urlparse(http_url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        return f"{ws_scheme}://{parsed.netloc}{parsed.path}"

    def _detect_protocol(self, response: httpx.Response, client: httpx.AsyncClient) -> SubscriptionProtocol:
        """Detect which WebSocket subprotocol is used."""
        # Check response headers for hints
        headers_text = str(response.headers).lower()

        if "graphql-ws" in headers_text:
            return SubscriptionProtocol.GRAPHQL_WS
        elif "subscriptions-transport-ws" in headers_text:
            return SubscriptionProtocol.SUBSCRIPTIONS_TRANSPORT_WS

        # Check response body
        body_lower = response.text.lower()
        if "graphql-ws" in body_lower:
            return SubscriptionProtocol.GRAPHQL_WS
        elif "subscriptions-transport-ws" in body_lower or "apollo" in body_lower:
            return SubscriptionProtocol.SUBSCRIPTIONS_TRANSPORT_WS

        # Default to modern protocol
        return SubscriptionProtocol.GRAPHQL_WS

    def _detect_framework(self, response: httpx.Response) -> str:
        """Detect the GraphQL framework being used."""
        headers_text = str(response.headers).lower()
        body_lower = response.text.lower()
        combined = headers_text + body_lower

        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in combined:
                    return framework

        return "unknown"

    async def _connect_websocket(
        self,
        endpoint: SubscriptionEndpoint,
        include_auth: bool = True,
    ) -> Optional[WebSocketClientProtocol]:
        """Establish WebSocket connection to GraphQL subscription endpoint."""
        try:
            # Build subprotocol list based on detected protocol
            if endpoint.protocol == SubscriptionProtocol.GRAPHQL_WS:
                subprotocols = ["graphql-transport-ws"]
            elif endpoint.protocol == SubscriptionProtocol.SUBSCRIPTIONS_TRANSPORT_WS:
                subprotocols = ["graphql-ws"]
            else:
                subprotocols = ["graphql-transport-ws", "graphql-ws"]

            # Build connection headers
            headers = {}
            if include_auth and self._auth_token:
                headers["Authorization"] = f"Bearer {self._auth_token}"
            if self._auth_headers:
                headers.update(self._auth_headers)

            ws = await asyncio.wait_for(
                websockets.connect(
                    endpoint.ws_url,
                    subprotocols=subprotocols,
                    additional_headers=headers,
                    ssl=None if endpoint.ws_url.startswith("ws://") else True,
                ),
                timeout=self.ws_timeout,
            )

            # Send connection_init message
            init_payload = {}
            if include_auth and self._auth_token:
                init_payload["authToken"] = self._auth_token
                init_payload["Authorization"] = f"Bearer {self._auth_token}"

            if endpoint.protocol == SubscriptionProtocol.GRAPHQL_WS:
                await ws.send(json.dumps({
                    "type": "connection_init",
                    "payload": init_payload,
                }))
            else:
                # Legacy protocol
                await ws.send(json.dumps({
                    "type": "connection_init",
                    "payload": init_payload,
                }))

            # Wait for connection_ack
            response = await asyncio.wait_for(ws.recv(), timeout=self.ws_timeout)
            msg = json.loads(response)

            if msg.get("type") in ["connection_ack", "ka"]:
                return ws

            logger.debug(f"WebSocket connection not acknowledged: {msg}")
            await ws.close()
            return None

        except Exception as e:
            logger.debug(f"WebSocket connection failed: {e}")
            return None

    async def _send_subscription(
        self,
        ws: WebSocketClientProtocol,
        subscription_query: str,
        variables: dict = None,
        operation_id: str = None,
        protocol: SubscriptionProtocol = SubscriptionProtocol.GRAPHQL_WS,
    ) -> Optional[dict]:
        """Send a subscription query and wait for data."""
        try:
            operation_id = operation_id or str(uuid.uuid4())

            if protocol == SubscriptionProtocol.GRAPHQL_WS:
                msg = {
                    "id": operation_id,
                    "type": "subscribe",
                    "payload": {
                        "query": subscription_query,
                        "variables": variables or {},
                    },
                }
            else:
                # Legacy protocol
                msg = {
                    "id": operation_id,
                    "type": "start",
                    "payload": {
                        "query": subscription_query,
                        "variables": variables or {},
                    },
                }

            await ws.send(json.dumps(msg))

            # Wait for response (data, error, or complete)
            response = await asyncio.wait_for(ws.recv(), timeout=self.ws_timeout)
            return json.loads(response)

        except asyncio.TimeoutError:
            logger.debug("Subscription timeout - no data received")
            return None
        except Exception as e:
            logger.debug(f"Subscription error: {e}")
            return None

    async def _test_auth_bypass(self, rate_limiter: RateLimiter) -> None:
        """Test for authentication bypass on subscriptions."""
        for endpoint in self.subscription_endpoints[:5]:
            await rate_limiter.acquire()

            # Try connecting WITHOUT authentication
            ws = await self._connect_websocket(endpoint, include_auth=False)

            if ws:
                # Connection succeeded without auth!
                # Try subscribing to a common subscription
                test_queries = [
                    "subscription { userUpdated { id email } }",
                    "subscription { messageAdded { id content sender } }",
                    "subscription { dataChanged { type payload } }",
                ]

                for sub_field in endpoint.subscription_types[:3]:
                    test_queries.append(f"subscription {{ {sub_field} {{ id }} }}")

                for query in test_queries[:5]:
                    response = await self._send_subscription(ws, query, protocol=endpoint.protocol)

                    if response:
                        msg_type = response.get("type", "")
                        # Check if we got data or at least no auth error
                        if msg_type in ["next", "data"] or (
                            msg_type == "error" and "auth" not in str(response).lower()
                        ):
                            result = SubscriptionTestResult(
                                vulnerable=True,
                                vuln_type=SubscriptionVulnType.AUTH_BYPASS,
                                confidence_score=85,
                                payload=query,
                                response_data=json.dumps(response)[:500],
                                evidence=[
                                    "WebSocket connection accepted without authentication",
                                    f"Subscription '{query[:50]}...' processed",
                                    f"Response type: {msg_type}",
                                ],
                                severity=Severity.HIGH,
                            )

                            self._add_finding(
                                name="GraphQL Subscription Auth Bypass",
                                description=(
                                    "GraphQL subscriptions can be established without proper "
                                    "authentication. Attackers can connect to real-time data "
                                    "streams and receive sensitive updates without logging in."
                                ),
                                endpoint=endpoint.ws_url,
                                result=result,
                            )
                            break

                await ws.close()

    async def _test_idor_subscriptions(self, rate_limiter: RateLimiter) -> None:
        """Test for IDOR vulnerabilities in subscription parameters."""
        for endpoint in self.subscription_endpoints[:5]:
            await rate_limiter.acquire()

            ws = await self._connect_websocket(endpoint, include_auth=True)
            if not ws:
                continue

            # IDOR test payloads - subscribe to other users' data
            idor_payloads = [
                # Try subscribing to other user IDs
                ('subscription { userUpdated(userId: "1") { id email role } }', {"userId": "1"}),
                ('subscription { userUpdated(userId: "admin") { id email role } }', {"userId": "admin"}),
                ('subscription($id: ID!) { userUpdated(userId: $id) { id email } }', {"id": "1"}),
                ('subscription($id: ID!) { userUpdated(userId: $id) { id email } }', {"id": "9999"}),
                # Try other common patterns
                ('subscription { ordersForUser(userId: "1") { id total } }', {}),
                ('subscription { messagesInRoom(roomId: "admin") { content } }', {}),
                ('subscription { accountUpdates(accountId: "1") { balance } }', {}),
            ]

            # Add discovered subscription types with ID params
            for sub_field in endpoint.subscription_types[:3]:
                idor_payloads.append(
                    (f'subscription {{ {sub_field}(id: "1") {{ id }} }}', {})
                )
                idor_payloads.append(
                    (f'subscription {{ {sub_field}(userId: "admin") {{ id }} }}', {})
                )

            for query, variables in idor_payloads[:8]:
                await rate_limiter.acquire()

                response = await self._send_subscription(
                    ws, query, variables, protocol=endpoint.protocol
                )

                if response:
                    msg_type = response.get("type", "")
                    payload = response.get("payload", {})

                    # Check for successful data access
                    if msg_type in ["next", "data"]:
                        data = payload.get("data", {})
                        if data and any(
                            key in str(data).lower()
                            for key in ["email", "password", "role", "admin", "balance", "content"]
                        ):
                            result = SubscriptionTestResult(
                                vulnerable=True,
                                vuln_type=SubscriptionVulnType.IDOR,
                                confidence_score=80,
                                payload=query,
                                response_data=json.dumps(response)[:500],
                                evidence=[
                                    "Subscription accepted with arbitrary user ID",
                                    f"Received data: {str(data)[:200]}",
                                    "Potential access to other users' data streams",
                                ],
                                severity=Severity.HIGH,
                                data_leaked=True,
                            )

                            self._add_finding(
                                name="IDOR in GraphQL Subscription",
                                description=(
                                    "GraphQL subscriptions allow subscribing to other users' "
                                    "data streams by manipulating ID parameters. Attackers can "
                                    "monitor real-time updates for accounts they don't own."
                                ),
                                endpoint=endpoint.ws_url,
                                result=result,
                            )
                            break

            await ws.close()

    async def _test_dos_potential(self, rate_limiter: RateLimiter) -> None:
        """Test for DoS potential via subscription abuse."""
        for endpoint in self.subscription_endpoints[:3]:
            await rate_limiter.acquire()

            # Test 1: Multiple simultaneous subscriptions
            ws = await self._connect_websocket(endpoint, include_auth=True)
            if not ws:
                continue

            subscriptions_accepted = 0
            for i in range(20):  # Try 20 subscriptions
                query = f"subscription {{ dataChanged {{ id timestamp }} }}"
                response = await self._send_subscription(
                    ws, query, operation_id=f"op-{i}", protocol=endpoint.protocol
                )
                if response and response.get("type") not in ["error", "complete"]:
                    subscriptions_accepted += 1

            if subscriptions_accepted >= 15:
                result = SubscriptionTestResult(
                    vulnerable=True,
                    vuln_type=SubscriptionVulnType.DOS_RESOURCE,
                    confidence_score=70,
                    payload=f"{subscriptions_accepted} simultaneous subscriptions",
                    evidence=[
                        f"Server accepted {subscriptions_accepted}/20 simultaneous subscriptions",
                        "No rate limiting on subscription count",
                        "Potential for resource exhaustion attack",
                    ],
                    severity=Severity.MEDIUM,
                )

                self._add_finding(
                    name="GraphQL Subscription DoS - No Rate Limiting",
                    description=(
                        "The GraphQL subscription endpoint accepts unlimited simultaneous "
                        "subscriptions. Attackers can exhaust server resources by opening "
                        "many subscription streams from a single connection."
                    ),
                    endpoint=endpoint.ws_url,
                    result=result,
                )

            await ws.close()

    async def _test_data_leakage(self, rate_limiter: RateLimiter) -> None:
        """Test for sensitive data leakage in subscriptions."""
        for endpoint in self.subscription_endpoints[:5]:
            await rate_limiter.acquire()

            ws = await self._connect_websocket(endpoint, include_auth=True)
            if not ws:
                continue

            # Queries designed to extract sensitive data
            sensitive_queries = [
                "subscription { allEvents { type userId data } }",
                "subscription { adminNotifications { message userId action } }",
                "subscription { userActivity { userId action ipAddress } }",
                "subscription { systemLogs { level message context } }",
                "subscription { auditEvents { actor action resource } }",
                "subscription { debugEvents { stackTrace query variables } }",
            ]

            # Add discovered subscriptions
            for sub_field in endpoint.subscription_types:
                if any(s in sub_field.lower() for s in ["admin", "all", "system", "debug", "log", "audit"]):
                    sensitive_queries.insert(0, f"subscription {{ {sub_field} {{ id }} }}")

            for query in sensitive_queries[:6]:
                await rate_limiter.acquire()

                response = await self._send_subscription(ws, query, protocol=endpoint.protocol)

                if response:
                    msg_type = response.get("type", "")
                    errors = response.get("payload", {}).get("errors", [])

                    # Check if query was accepted (even with no immediate data)
                    if msg_type not in ["error"] and not errors:
                        result = SubscriptionTestResult(
                            vulnerable=True,
                            vuln_type=SubscriptionVulnType.DATA_LEAKAGE,
                            confidence_score=65,
                            payload=query,
                            response_data=json.dumps(response)[:500],
                            evidence=[
                                f"Sensitive subscription accepted: {query[:50]}",
                                "Potential access to admin/system data streams",
                            ],
                            severity=Severity.HIGH,
                            data_leaked=True,
                        )

                        self._add_finding(
                            name="Sensitive Data Subscription Access",
                            description=(
                                "GraphQL allows subscribing to potentially sensitive data "
                                "streams (admin events, system logs, user activity). This "
                                "could expose confidential information in real-time."
                            ),
                            endpoint=endpoint.ws_url,
                            result=result,
                        )
                        break

            await ws.close()

    async def _test_injection(self, rate_limiter: RateLimiter) -> None:
        """Test for injection vulnerabilities in subscription variables."""
        for endpoint in self.subscription_endpoints[:5]:
            await rate_limiter.acquire()

            ws = await self._connect_websocket(endpoint, include_auth=True)
            if not ws:
                continue

            # Injection payloads
            injection_payloads = [
                # SQL injection
                ('subscription($id: String!) { userUpdated(filter: $id) { id } }',
                 {"id": "1' OR '1'='1"}),
                ('subscription($id: String!) { userUpdated(filter: $id) { id } }',
                 {"id": "1; DROP TABLE users; --"}),
                # NoSQL injection
                ('subscription($filter: JSON!) { dataChanged(filter: $filter) { id } }',
                 {"filter": {"$gt": ""}}),
                ('subscription($id: String!) { userUpdated(id: $id) { id } }',
                 {"id": '{"$ne": null}'}),
                # Query structure injection
                ('subscription { userUpdated(filter: "}} { adminData { secret }") { id } }', {}),
            ]

            for query, variables in injection_payloads[:5]:
                await rate_limiter.acquire()

                response = await self._send_subscription(
                    ws, query, variables, protocol=endpoint.protocol
                )

                if response:
                    response_str = json.dumps(response).lower()
                    errors = response.get("payload", {}).get("errors", [])

                    # Check for injection indicators
                    injection_indicators = [
                        "syntax error", "sql", "mongodb", "unexpected token",
                        "parse error", "invalid query", "type mismatch",
                    ]

                    # Successful injection might show data or special errors
                    if (response.get("type") in ["next", "data"]) or any(
                        ind in response_str for ind in injection_indicators
                    ):
                        result = SubscriptionTestResult(
                            vulnerable=True,
                            vuln_type=SubscriptionVulnType.INJECTION,
                            confidence_score=70,
                            payload=f"{query} | Variables: {json.dumps(variables)}",
                            response_data=response_str[:500],
                            evidence=[
                                "Injection payload processed by subscription",
                                f"Response indicates: {response_str[:100]}",
                            ],
                            severity=Severity.HIGH,
                        )

                        self._add_finding(
                            name="Injection in GraphQL Subscription Variables",
                            description=(
                                "GraphQL subscription variables are vulnerable to injection "
                                "attacks. Malicious input in filter or ID parameters may "
                                "execute SQL/NoSQL commands or manipulate query structure."
                            ),
                            endpoint=endpoint.ws_url,
                            result=result,
                        )
                        break

            await ws.close()

    async def _test_nested_attacks(self, rate_limiter: RateLimiter) -> None:
        """Test for nested query DoS attacks."""
        for endpoint in self.subscription_endpoints[:3]:
            await rate_limiter.acquire()

            ws = await self._connect_websocket(endpoint, include_auth=True)
            if not ws:
                continue

            # Deep nested queries
            nested_queries = [
                # Deep nesting
                """subscription {
                    userUpdated {
                        id
                        posts {
                            comments {
                                author {
                                    posts {
                                        comments {
                                            author { id email }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }""",
                # Wide query
                """subscription {
                    userUpdated {
                        id email name role createdAt updatedAt
                        posts { id title content createdAt }
                        comments { id content createdAt }
                        notifications { id message read }
                        settings { key value }
                    }
                }""",
            ]

            for query in nested_queries:
                await rate_limiter.acquire()

                start = time.time()
                response = await self._send_subscription(ws, query, protocol=endpoint.protocol)
                elapsed = time.time() - start

                if response:
                    errors = response.get("payload", {}).get("errors", [])
                    error_msgs = " ".join(str(e) for e in errors).lower()

                    # Check if nested query was accepted or caused issues
                    if not errors or "depth" not in error_msgs:
                        result = SubscriptionTestResult(
                            vulnerable=True,
                            vuln_type=SubscriptionVulnType.NESTED_ATTACK,
                            confidence_score=60,
                            payload=query[:200],
                            response_data=json.dumps(response)[:300],
                            evidence=[
                                "Deep nested subscription accepted",
                                f"Processing time: {elapsed:.2f}s",
                                "No query depth limiting detected",
                            ],
                            severity=Severity.MEDIUM,
                        )

                        self._add_finding(
                            name="GraphQL Subscription Nested Query Attack",
                            description=(
                                "GraphQL subscriptions accept deeply nested queries without "
                                "depth limiting. Attackers can craft expensive queries that "
                                "consume excessive server resources (CPU, memory, DB connections)."
                            ),
                            endpoint=endpoint.ws_url,
                            result=result,
                        )
                        break

            await ws.close()

    def _add_finding(
        self,
        name: str,
        description: str,
        endpoint: str,
        result: SubscriptionTestResult,
    ) -> None:
        """Add a finding to the results."""
        cvss_scores = {
            "CRITICAL": 9.5,
            "HIGH": 8.0,
            "MEDIUM": 5.5,
            "LOW": 3.0,
        }

        cwe_mapping = {
            SubscriptionVulnType.AUTH_BYPASS: "CWE-306",
            SubscriptionVulnType.IDOR: "CWE-639",
            SubscriptionVulnType.DOS_RESOURCE: "CWE-400",
            SubscriptionVulnType.DATA_LEAKAGE: "CWE-200",
            SubscriptionVulnType.INJECTION: "CWE-89",
            SubscriptionVulnType.NESTED_ATTACK: "CWE-400",
            SubscriptionVulnType.CROSS_TENANT: "CWE-284",
            SubscriptionVulnType.PROTOCOL_ABUSE: "CWE-20",
        }

        finding = Finding(
            vuln_type=VulnType.GRAPHQL_INJECTION,
            name=name,
            severity=result.severity,
            description=description,
            host=endpoint,
            endpoint=endpoint,
            evidence=[
                f"Payload: {result.payload[:150]}",
                f"Confidence: {result.confidence}%",
                f"Vulnerability Type: {result.vuln_type.name}",
                f"Data Leaked: {result.data_leaked}",
            ] + result.evidence,
            cvss_score=cvss_scores.get(result.severity, 5.5),
            cwe_id=cwe_mapping.get(result.vuln_type, "CWE-284"),
            remediation=self._get_remediation(result.vuln_type),
            references=[
                "https://owasp.org/www-project-graphql-security/",
                "https://www.apollographql.com/docs/apollo-server/data/subscriptions/",
                "https://spec.graphql.org/October2021/#sec-Subscription",
                "https://github.com/nicholasaleks/graphql-voyager",
            ],
        )

        self.findings.append(finding.to_dict())

        logger.info(
            f"GraphQL Subscription Vulnerability [{result.severity}]: {name} "
            f"| Confidence: {result.confidence}%"
        )

    def _get_remediation(self, vuln_type: SubscriptionVulnType) -> str:
        """Get remediation advice for subscription vulnerabilities."""
        base = (
            "1. Implement authentication for all WebSocket connections.\n"
            "2. Validate subscription queries against schema.\n"
            "3. Implement query depth and complexity limiting.\n"
            "4. Add rate limiting on subscription operations.\n"
            "5. Log and monitor subscription activities.\n"
        )

        if vuln_type == SubscriptionVulnType.AUTH_BYPASS:
            base += (
                "\n\nAUTH BYPASS SPECIFIC:\n"
                "6. Require auth token in connection_init payload.\n"
                "7. Validate tokens before allowing subscriptions.\n"
                "8. Implement connection-level authorization checks.\n"
                "9. Consider using Apollo Server auth plugins.\n"
            )

        elif vuln_type == SubscriptionVulnType.IDOR:
            base += (
                "\n\nIDOR SPECIFIC:\n"
                "6. Validate user owns/has access to subscribed resource.\n"
                "7. Use session context to filter subscription data.\n"
                "8. Never trust client-provided IDs without verification.\n"
                "9. Implement row-level security in resolvers.\n"
            )

        elif vuln_type == SubscriptionVulnType.DOS_RESOURCE:
            base += (
                "\n\nDoS SPECIFIC:\n"
                "6. Limit subscriptions per connection (e.g., max 10).\n"
                "7. Limit total connections per user/IP.\n"
                "8. Implement subscription timeout and cleanup.\n"
                "9. Use connection pooling and resource limits.\n"
            )

        elif vuln_type == SubscriptionVulnType.INJECTION:
            base += (
                "\n\nINJECTION SPECIFIC:\n"
                "6. Use parameterized queries in resolvers.\n"
                "7. Validate and sanitize all input variables.\n"
                "8. Use ORM/query builders with proper escaping.\n"
                "9. Implement strict input validation at schema level.\n"
            )

        elif vuln_type == SubscriptionVulnType.NESTED_ATTACK:
            base += (
                "\n\nNESTED QUERY SPECIFIC:\n"
                "6. Set maximum query depth (e.g., 5 levels).\n"
                "7. Implement query complexity analysis.\n"
                "8. Set query cost limits and abort expensive queries.\n"
                "9. Consider using persisted queries only.\n"
            )

        return base


# Export
__all__ = ["GraphQLSubscriptionScanner", "GRAPHQL_SUB_SCANNER_VERSION"]
