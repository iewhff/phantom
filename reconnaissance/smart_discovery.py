"""
Smart Endpoint Discovery - PHANTOM AI Enterprise Edition

Intelligent endpoint discovery orchestrator that replaces hardcoded patterns
with dynamically discovered endpoints from multiple sources.

Phases:
1. Passive Discovery - Parse existing resources (minimal requests)
2. Active Discovery - Technology-based smart probing
2.5 Tool Discovery - ffuf/gobuster rapid discovery (if needed)
3. Categorization - Semantic classification
4. Verification - Confirm existence via HEAD requests
5. Deep Analysis - Technology fingerprinting & parameter analysis (PHANTOM AI)

Philosophy: "Map first, test later" - White-hat enterprise-level

Usage:
    from reconnaissance.smart_discovery import SmartEndpointDiscovery

    discovery = SmartEndpointDiscovery(settings)
    endpoint_map = await discovery.discover(target_url, rate_limiter, technologies)

    # Scanners then use the map
    api_endpoints = endpoint_map.get_for_scanner("api_scanner")

    # PHANTOM AI enhancements
    attack_surface = endpoint_map.get_attack_surface_score()
    priority_endpoints = endpoint_map.get_priority_endpoints(limit=50)
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import httpx

from utils.endpoint_map import (
    EndpointMap,
    DiscoveredEndpoint,
    DiscoveredParameter,
    EndpointSource,
    EndpointCategory,
    HTTPMethod,
    categorize_path,
    infer_methods_from_path,
)
from utils.logger import get_logger

# PHANTOM AI imports (lazy loading for performance)
try:
    from phantom.tech_fingerprinter import TechFingerprinter, FingerprintResult
    from phantom.parameter_analyzer import ParameterAnalyzer, AnalysisResult
    PHANTOM_AVAILABLE = True
except ImportError:
    PHANTOM_AVAILABLE = False
    TechFingerprinter = None
    FingerprintResult = None
    ParameterAnalyzer = None
    AnalysisResult = None

if TYPE_CHECKING:
    from core.config_manager import Settings
    from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


@dataclass
class DiscoveryConfig:
    """Configuration for smart discovery."""
    # Passive discovery options
    parse_sitemap: bool = True
    parse_robots: bool = True
    parse_openapi: bool = True
    parse_graphql: bool = True
    parse_javascript: bool = True
    use_wayback: bool = True
    wayback_limit: int = 500

    # Active discovery options
    probe_common_paths: bool = True
    tech_based_inference: bool = True
    response_inference: bool = True

    # Tool-based discovery (NEW - Fast endpoint discovery)
    use_linux_tools: bool = True
    min_endpoints_before_tools: int = 10  # Use tools if <10 endpoints found
    ffuf_wordlist: str = "/usr/share/dirb/wordlists/common.txt"
    tool_timeout: int = 120  # Max seconds for tool execution

    # Limits
    max_endpoints: int = 5000
    max_js_files: int = 50
    max_concurrent: int = 10
    timeout: float = 10.0

    # Verification
    verify_endpoints: bool = True
    verify_limit: int = 500
    min_confidence_to_verify: float = 0.6

    # PHANTOM AI Deep Analysis (Phase 5)
    deep_analysis: bool = True  # Enable PHANTOM AI deep analysis
    fingerprint_target: bool = True  # Run technology fingerprinting
    analyze_parameters: bool = True  # Run parameter analysis
    deep_analysis_limit: int = 100  # Max endpoints for deep analysis
    reflection_testing: bool = True  # Test for parameter reflection


class SmartEndpointDiscovery:
    """
    Intelligent Endpoint Discovery Engine.

    Implements 4 phases:
    1. Passive Discovery - Parse existing resources
    2. Active Discovery - Tech-based smart probing
    3. Endpoint Map Generation - Unified registry
    4. Verification - Confirm endpoints exist

    This replaces hardcoded endpoint patterns across all scanners with
    dynamically discovered endpoints, reducing 404 requests by ~90%.
    """

    VERSION = "1.0.0-ENTERPRISE"

    # OpenAPI/Swagger spec paths to check
    OPENAPI_PATHS = [
        "/openapi.json", "/openapi.yaml", "/openapi.yml",
        "/swagger.json", "/swagger.yaml", "/swagger.yml",
        "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
        "/api-docs", "/api-docs.json", "/api-docs.yaml",
        "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/docs/swagger.json", "/docs/openapi.json",
        "/.well-known/openapi.json",
        "/api/swagger.json", "/api/openapi.json",
        "/spec.json", "/api.json",
    ]

    # GraphQL endpoints to check
    GRAPHQL_PATHS = [
        "/graphql", "/graphql/", "/api/graphql",
        "/v1/graphql", "/query", "/gql",
        "/graphql/v1", "/api/v1/graphql",
    ]

    # Sitemap locations
    SITEMAP_PATHS = [
        "/sitemap.xml",
        "/sitemap_index.xml",
        "/sitemaps/sitemap.xml",
        "/sitemap/sitemap.xml",
        "/wp-sitemap.xml",  # WordPress
    ]

    # Technology-specific endpoint patterns
    TECH_ENDPOINTS: Dict[str, List[str]] = {
        "wordpress": [
            "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts", "/wp-json/wp/v2/pages",
            "/wp-json/wp/v2/categories", "/wp-json/wp/v2/tags", "/wp-json/wp/v2/comments",
            "/wp-admin/admin-ajax.php", "/xmlrpc.php", "/wp-login.php",
            "/wp-json/", "/wp-content/", "/wp-includes/",
        ],
        "drupal": [
            "/jsonapi", "/jsonapi/node/article", "/user/login", "/admin",
            "/node/add", "/admin/content", "/admin/structure",
        ],
        "laravel": [
            "/api/user", "/api/login", "/api/register", "/api/logout",
            "/sanctum/csrf-cookie", "/api/password/email", "/api/password/reset",
            "/api/email/verify", "/api/email/resend", "/horizon", "/telescope",
        ],
        "django": [
            "/api/", "/admin/", "/api-auth/", "/rest-auth/",
            "/api/v1/", "/accounts/login/", "/accounts/logout/",
            "/__debug__/", "/api-token-auth/",
        ],
        "express": [
            "/api/v1/", "/api/users", "/api/auth", "/api/login",
            "/api/register", "/api/logout", "/health", "/status",
            # Juice Shop / common REST patterns
            "/rest/user/login", "/rest/user/register", "/rest/user/reset-password",
            "/rest/user/whoami", "/rest/user/change-password",
            "/rest/products/search", "/rest/products/reviews",
            "/rest/basket", "/rest/order", "/rest/track-order",
            "/rest/admin/application-configuration",
            "/api/Users", "/api/Products", "/api/BasketItems",
            "/api/Feedbacks", "/api/Complaints", "/api/Recycles",
            "/api/SecurityQuestions", "/api/Challenges",
        ],
        "spring": [
            "/actuator", "/actuator/health", "/actuator/info", "/actuator/env",
            "/actuator/metrics", "/actuator/beans", "/actuator/configprops",
            "/api/v1/", "/swagger-ui.html", "/v2/api-docs", "/v3/api-docs",
        ],
        "rails": [
            "/api/v1/", "/users.json", "/sessions", "/rails/info/routes",
            "/rails/mailers", "/sidekiq", "/admin",
        ],
        "nextjs": [
            "/api/", "/_next/data/", "/api/auth/", "/api/auth/session",
            "/api/auth/signin", "/api/auth/signout", "/api/auth/callback",
        ],
        "nuxtjs": [
            "/api/", "/_nuxt/", "/api/auth/", "/__nuxt_error",
        ],
        "fastapi": [
            "/docs", "/redoc", "/openapi.json", "/api/v1/",
            "/api/users/", "/api/items/", "/health", "/ping",
        ],
        "flask": [
            "/api/", "/api/v1/", "/login", "/logout", "/register",
            "/static/", "/admin/",
        ],
        "supabase": [
            "/rest/v1/", "/auth/v1/", "/storage/v1/", "/realtime/v1/",
            "/auth/v1/token", "/auth/v1/user", "/auth/v1/signup",
            "/auth/v1/recover", "/auth/v1/logout",
        ],
        "firebase": [
            "/__/firebase/", "/__/auth/", "/.json",
            "/.well-known/assetlinks.json",
        ],
        "strapi": [
            "/admin", "/api/", "/api/users", "/api/auth/local",
            "/api/auth/local/register", "/upload", "/graphql",
        ],
        "nestjs": [
            "/api/", "/api/v1/", "/auth/login", "/auth/register",
            "/users", "/health", "/graphql",
        ],
    }

    def __init__(
        self,
        settings: Optional[Settings] = None,
        config: Optional[DiscoveryConfig] = None,
    ) -> None:
        self.settings = settings
        self.config = config or DiscoveryConfig()
        self.endpoint_map = EndpointMap.get_instance()
        self._client: Optional[httpx.AsyncClient] = None

    async def discover(
        self,
        target: str,
        rate_limiter: Optional[RateLimiter] = None,
        detected_technologies: Optional[List[str]] = None,
    ) -> EndpointMap:
        """
        Main discovery method - runs all phases.

        Args:
            target: Target URL
            rate_limiter: Optional rate limiter
            detected_technologies: Pre-detected technologies from TechIntelligence

        Returns:
            Populated EndpointMap
        """
        base_url = target if target.startswith(("http://", "https://")) else f"https://{target}"
        parsed = urlparse(base_url)
        self.endpoint_map.set_host(parsed.netloc)

        logger.info(f"[SmartDiscovery] Starting discovery for {base_url}")

        async with httpx.AsyncClient(
            timeout=self.config.timeout,
            verify=False,
            follow_redirects=True,
        ) as client:
            self._client = client

            # Phase 1: Passive Discovery
            await self._phase1_passive_discovery(base_url, rate_limiter)

            # Phase 2: Active Discovery (tech-based)
            await self._phase2_active_discovery(base_url, rate_limiter, detected_technologies)

            # Phase 2.5: Tool-based Rapid Discovery (if not enough endpoints found)
            current_count = len(self.endpoint_map.get_all())
            if self.config.use_linux_tools and current_count < self.config.min_endpoints_before_tools:
                logger.info(f"[SmartDiscovery] Only {current_count} endpoints found, using Linux tools...")
                await self._phase2b_tools_discovery(base_url, rate_limiter)

            # Phase 3: Categorization
            self._phase3_categorize_endpoints()

            # Phase 4: Verification
            if self.config.verify_endpoints:
                await self._phase4_verify_endpoints(base_url, rate_limiter)

            # Phase 5: PHANTOM AI Deep Analysis
            if self.config.deep_analysis and PHANTOM_AVAILABLE:
                await self._phase5_deep_analysis(base_url, rate_limiter)

        stats = self.endpoint_map.get_statistics()
        logger.info(f"[SmartDiscovery] Discovery complete: {stats['total_endpoints']} endpoints")
        logger.info(f"[SmartDiscovery] By source: {stats['by_source']}")

        return self.endpoint_map

    # ========================================================================
    # PHASE 1: PASSIVE DISCOVERY
    # ========================================================================

    async def _phase1_passive_discovery(
        self,
        base_url: str,
        rate_limiter: Optional[RateLimiter],
    ) -> None:
        """Phase 1: Parse existing resources without excessive probing."""
        logger.info("[SmartDiscovery] Phase 1: Passive Discovery")

        tasks = []

        if self.config.parse_sitemap:
            tasks.append(self._parse_sitemap(base_url, rate_limiter))

        if self.config.parse_robots:
            tasks.append(self._parse_robots(base_url, rate_limiter))

        if self.config.parse_openapi:
            tasks.append(self._discover_and_parse_openapi(base_url, rate_limiter))

        if self.config.parse_graphql:
            tasks.append(self._discover_and_parse_graphql(base_url, rate_limiter))

        if self.config.use_wayback:
            tasks.append(self._query_wayback_machine(base_url))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.debug(f"[SmartDiscovery] Passive discovery error: {result}")

    async def _parse_sitemap(
        self,
        base_url: str,
        rate_limiter: Optional[RateLimiter],
    ) -> None:
        """Parse sitemap.xml for endpoints."""
        for sitemap_path in self.SITEMAP_PATHS:
            if rate_limiter:
                await rate_limiter.acquire()

            sitemap_url = urljoin(base_url, sitemap_path)
            try:
                response = await self._client.get(sitemap_url)
                if response.status_code == 200 and "xml" in response.headers.get("Content-Type", "").lower():
                    urls = self._extract_urls_from_sitemap(response.text, base_url)
                    for url in urls[:self.config.max_endpoints]:
                        path = urlparse(url).path
                        if path:
                            self.endpoint_map.add_endpoint(DiscoveredEndpoint(
                                path=path,
                                methods={HTTPMethod.GET},
                                source=EndpointSource.SITEMAP_XML,
                                confidence=0.9,
                                category=categorize_path(path),
                            ))
                    logger.info(f"[SmartDiscovery] Sitemap {sitemap_path}: {len(urls)} URLs")
                    break  # Found sitemap, stop looking
            except Exception as e:
                logger.debug(f"[SmartDiscovery] Sitemap error {sitemap_url}: {e}")

    def _extract_urls_from_sitemap(self, xml_content: str, base_url: str) -> List[str]:
        """Extract URLs from sitemap XML."""
        urls = []
        parsed_base = urlparse(base_url)

        # Simple regex extraction (works for most sitemaps)
        loc_pattern = re.compile(r'<loc>([^<]+)</loc>', re.IGNORECASE)
        for match in loc_pattern.finditer(xml_content):
            url = match.group(1).strip()
            # Filter to same domain
            parsed_url = urlparse(url)
            if parsed_url.netloc == parsed_base.netloc or not parsed_url.netloc:
                urls.append(url)

        return urls[:self.config.max_endpoints]

    async def _parse_robots(
        self,
        base_url: str,
        rate_limiter: Optional[RateLimiter],
    ) -> None:
        """Parse robots.txt for endpoint hints."""
        if rate_limiter:
            await rate_limiter.acquire()

        robots_url = urljoin(base_url, "/robots.txt")
        try:
            response = await self._client.get(robots_url)
            if response.status_code == 200:
                paths = self._extract_paths_from_robots(response.text)
                for path in paths:
                    self.endpoint_map.add_endpoint(DiscoveredEndpoint(
                        path=path,
                        methods={HTTPMethod.GET},
                        source=EndpointSource.ROBOTS_TXT,
                        confidence=0.7,
                        category=categorize_path(path),
                    ))
                logger.info(f"[SmartDiscovery] robots.txt: {len(paths)} paths")
        except Exception as e:
            logger.debug(f"[SmartDiscovery] robots.txt error: {e}")

    def _extract_paths_from_robots(self, content: str) -> List[str]:
        """Extract paths from robots.txt."""
        paths = set()
        for line in content.split('\n'):
            line = line.strip()
            if line.lower().startswith(('disallow:', 'allow:', 'sitemap:')):
                parts = line.split(':', 1)
                if len(parts) > 1:
                    path = parts[1].strip()
                    if path and path != '/' and path.startswith('/'):
                        # Clean wildcards
                        path = path.replace('*', '').replace('$', '')
                        if path and path != '/':
                            paths.add(path)
        return list(paths)

    async def _discover_and_parse_openapi(
        self,
        base_url: str,
        rate_limiter: Optional[RateLimiter],
    ) -> None:
        """Discover and parse OpenAPI/Swagger specifications."""
        for spec_path in self.OPENAPI_PATHS:
            if rate_limiter:
                await rate_limiter.acquire()

            spec_url = urljoin(base_url, spec_path)
            try:
                response = await self._client.get(spec_url)
                if response.status_code == 200:
                    content_type = response.headers.get("Content-Type", "")

                    # Try to parse as JSON or YAML
                    spec = None
                    try:
                        if "json" in content_type or spec_path.endswith(".json"):
                            spec = json.loads(response.text)
                        elif "yaml" in content_type or spec_path.endswith((".yaml", ".yml")):
                            try:
                                import yaml
                                spec = yaml.safe_load(response.text)
                            except ImportError:
                                pass
                        else:
                            # Try JSON first
                            try:
                                spec = json.loads(response.text)
                            except json.JSONDecodeError:
                                pass
                    except Exception:
                        pass

                    if spec and isinstance(spec, dict):
                        # Validate it's an OpenAPI spec
                        if "openapi" in spec or "swagger" in spec or "paths" in spec:
                            endpoints = self._parse_openapi_spec(spec)
                            for ep in endpoints:
                                self.endpoint_map.add_endpoint(ep)
                            logger.info(f"[SmartDiscovery] OpenAPI {spec_path}: {len(endpoints)} endpoints")
                            return  # Found and parsed, stop looking

            except Exception as e:
                logger.debug(f"[SmartDiscovery] OpenAPI error {spec_url}: {e}")

    def _parse_openapi_spec(self, spec: Dict[str, Any]) -> List[DiscoveredEndpoint]:
        """Parse OpenAPI spec into DiscoveredEndpoints."""
        endpoints = []

        # Get base path if specified
        base_path = ""
        if "basePath" in spec:  # Swagger 2.0
            base_path = spec["basePath"].rstrip("/")
        elif "servers" in spec:  # OpenAPI 3.0
            for server in spec.get("servers", []):
                url = server.get("url", "")
                if url.startswith("/"):
                    base_path = url.rstrip("/")
                    break

        # Get paths
        paths = spec.get("paths", {})

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue

            full_path = base_path + path if not path.startswith(base_path) else path

            for method_str, operation in methods.items():
                method_upper = method_str.upper()
                if method_upper not in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]:
                    continue

                if not isinstance(operation, dict):
                    continue

                # Parse parameters
                parameters = []
                for param in operation.get("parameters", []):
                    if isinstance(param, dict):
                        parameters.append(DiscoveredParameter(
                            name=param.get("name", ""),
                            location=param.get("in", "query"),
                            param_type=param.get("schema", {}).get("type", "string") if isinstance(param.get("schema"), dict) else "string",
                            required=param.get("required", False),
                        ))

                # Parse request body (OpenAPI 3.0)
                request_body = operation.get("requestBody", {})
                content_types = list(request_body.get("content", {}).keys()) if isinstance(request_body, dict) else []

                # Determine auth requirement
                security = operation.get("security", spec.get("security", []))
                requires_auth = bool(security)

                # Get operation metadata
                operation_id = operation.get("operationId", "")
                description = operation.get("summary", operation.get("description", ""))

                # Determine category
                tags = operation.get("tags", [])
                category = self._categorize_from_tags(tags, full_path)

                try:
                    http_method = HTTPMethod(method_upper)
                    endpoints.append(DiscoveredEndpoint(
                        path=full_path,
                        methods={http_method},
                        source=EndpointSource.OPENAPI_SPEC,
                        confidence=0.95,
                        category=category,
                        parameters=parameters,
                        requires_auth=requires_auth,
                        content_types=content_types,
                        operation_id=operation_id,
                        description=description,
                    ))
                except ValueError:
                    pass

        return endpoints

    def _categorize_from_tags(self, tags: List[str], path: str) -> EndpointCategory:
        """Categorize endpoint from OpenAPI tags."""
        if not tags:
            return categorize_path(path)

        tags_lower = [t.lower() for t in tags if isinstance(t, str)]

        if any(t in tags_lower for t in ["auth", "authentication", "login", "user"]):
            return EndpointCategory.AUTH
        if any(t in tags_lower for t in ["admin", "administration", "management"]):
            return EndpointCategory.ADMIN
        if any(t in tags_lower for t in ["upload", "file", "media", "storage"]):
            return EndpointCategory.FILE_UPLOAD
        if any(t in tags_lower for t in ["payment", "checkout", "order", "cart"]):
            return EndpointCategory.PAYMENT
        if any(t in tags_lower for t in ["search", "query"]):
            return EndpointCategory.SEARCH

        return categorize_path(path)

    async def _discover_and_parse_graphql(
        self,
        base_url: str,
        rate_limiter: Optional[RateLimiter],
    ) -> None:
        """Discover and parse GraphQL schema via introspection."""
        introspection_query = '''
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
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
            }
        }
        '''

        for gql_path in self.GRAPHQL_PATHS:
            if rate_limiter:
                await rate_limiter.acquire()

            gql_url = urljoin(base_url, gql_path)
            try:
                response = await self._client.post(
                    gql_url,
                    json={"query": introspection_query},
                    headers={"Content-Type": "application/json"},
                )

                if response.status_code == 200:
                    try:
                        data = response.json()
                        if "data" in data and "__schema" in data.get("data", {}):
                            endpoints = self._parse_graphql_schema(gql_path, data["data"]["__schema"])
                            for ep in endpoints:
                                self.endpoint_map.add_endpoint(ep)
                            logger.info(f"[SmartDiscovery] GraphQL {gql_path}: {len(endpoints)} operations")
                            return
                    except json.JSONDecodeError:
                        pass

            except Exception as e:
                logger.debug(f"[SmartDiscovery] GraphQL error {gql_url}: {e}")

    def _parse_graphql_schema(self, base_path: str, schema: Dict[str, Any]) -> List[DiscoveredEndpoint]:
        """Parse GraphQL schema into DiscoveredEndpoints."""
        endpoints = []

        # First add the base GraphQL endpoint
        endpoints.append(DiscoveredEndpoint(
            path=base_path,
            methods={HTTPMethod.POST},
            source=EndpointSource.GRAPHQL_INTROSPECTION,
            confidence=0.95,
            category=EndpointCategory.API_GRAPHQL,
        ))

        # Get type names
        query_type_name = schema.get("queryType", {}).get("name", "Query")
        mutation_type_name = schema.get("mutationType", {}).get("name", "Mutation")
        subscription_type_name = schema.get("subscriptionType", {}).get("name", "Subscription")

        for type_def in schema.get("types", []):
            if not isinstance(type_def, dict):
                continue

            type_name = type_def.get("name", "")
            fields = type_def.get("fields", [])

            if not fields or not isinstance(fields, list):
                continue

            # Determine operation type
            if type_name == query_type_name:
                op_type = "query"
            elif type_name == mutation_type_name:
                op_type = "mutation"
            elif type_name == subscription_type_name:
                op_type = "subscription"
            else:
                continue

            for field in fields:
                if not isinstance(field, dict):
                    continue

                field_name = field.get("name", "")
                if not field_name or field_name.startswith("_"):
                    continue

                # Extract arguments as parameters
                params = []
                for arg in field.get("args", []):
                    if isinstance(arg, dict):
                        arg_type = arg.get("type", {})
                        type_name_str = arg_type.get("name", "String") if isinstance(arg_type, dict) else "String"
                        params.append(DiscoveredParameter(
                            name=arg.get("name", ""),
                            location="body",
                            param_type=type_name_str.lower() if type_name_str else "string",
                        ))

                # Create virtual endpoint for this operation
                endpoints.append(DiscoveredEndpoint(
                    path=f"{base_path}#{op_type}:{field_name}",
                    methods={HTTPMethod.POST},
                    source=EndpointSource.GRAPHQL_INTROSPECTION,
                    confidence=0.95,
                    category=EndpointCategory.API_GRAPHQL,
                    parameters=params,
                    operation_id=f"graphql_{op_type}_{field_name}",
                ))

        return endpoints

    async def _query_wayback_machine(self, base_url: str) -> None:
        """Query Wayback Machine for historical endpoints."""
        parsed = urlparse(base_url)
        domain = parsed.netloc

        wayback_url = (
            f"http://web.archive.org/cdx/search/cdx"
            f"?url={domain}/*&output=json&fl=original&collapse=urlkey"
            f"&limit={self.config.wayback_limit}"
        )

        try:
            async with httpx.AsyncClient(timeout=30, verify=False) as client:
                response = await client.get(wayback_url)
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if not data or len(data) < 2:
                            return

                        # Skip header row
                        seen_paths = set()
                        for row in data[1:]:
                            if row and len(row) > 0:
                                try:
                                    url = row[0]
                                    path = urlparse(url).path
                                    if path and path not in seen_paths:
                                        seen_paths.add(path)
                                        self.endpoint_map.add_endpoint(DiscoveredEndpoint(
                                            path=path,
                                            methods={HTTPMethod.GET},
                                            source=EndpointSource.WAYBACK_MACHINE,
                                            confidence=0.5,
                                            category=categorize_path(path),
                                        ))
                                except Exception:
                                    pass

                        logger.info(f"[SmartDiscovery] Wayback: {len(seen_paths)} historical paths")
                    except json.JSONDecodeError:
                        pass

        except Exception as e:
            logger.debug(f"[SmartDiscovery] Wayback error: {e}")

    # ========================================================================
    # PHASE 2: ACTIVE DISCOVERY
    # ========================================================================

    async def _phase2_active_discovery(
        self,
        base_url: str,
        rate_limiter: Optional[RateLimiter],
        detected_technologies: Optional[List[str]],
    ) -> None:
        """Phase 2: Technology-based smart probing."""
        logger.info("[SmartDiscovery] Phase 2: Active Discovery")

        if self.config.tech_based_inference and detected_technologies:
            await self._probe_tech_specific_endpoints(base_url, rate_limiter, detected_technologies)

        if self.config.response_inference:
            await self._infer_from_existing_endpoints(base_url, rate_limiter)

    async def _probe_tech_specific_endpoints(
        self,
        base_url: str,
        rate_limiter: Optional[RateLimiter],
        technologies: List[str],
    ) -> None:
        """Probe endpoints based on detected technologies."""
        paths_to_check = set()

        for tech in technologies:
            tech_lower = tech.lower()
            for tech_key, tech_paths in self.TECH_ENDPOINTS.items():
                if tech_key in tech_lower or tech_lower in tech_key:
                    paths_to_check.update(tech_paths)

        if not paths_to_check:
            return

        logger.info(f"[SmartDiscovery] Probing {len(paths_to_check)} tech-specific paths")

        # Batch probe with concurrency limit
        semaphore = asyncio.Semaphore(self.config.max_concurrent)

        async def probe_path(path: str) -> Optional[DiscoveredEndpoint]:
            async with semaphore:
                if rate_limiter:
                    await rate_limiter.acquire()

                url = urljoin(base_url, path)
                try:
                    response = await self._client.get(url)

                    # Valid endpoint if not 404
                    if response.status_code not in (404, 502, 503, 504):
                        return DiscoveredEndpoint(
                            path=path,
                            methods=infer_methods_from_path(path),
                            source=EndpointSource.TECH_INFERENCE,
                            confidence=0.8,
                            verified=True,
                            last_status_code=response.status_code,
                            requires_auth=(response.status_code in (401, 403)),
                            category=categorize_path(path),
                        )
                except Exception:
                    pass
                return None

        tasks = [probe_path(path) for path in paths_to_check]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        found_count = 0
        for result in results:
            if isinstance(result, DiscoveredEndpoint):
                self.endpoint_map.add_endpoint(result)
                found_count += 1

        logger.info(f"[SmartDiscovery] Tech probing found {found_count} endpoints")

    async def _infer_from_existing_endpoints(
        self,
        base_url: str,
        rate_limiter: Optional[RateLimiter],
    ) -> None:
        """Infer related endpoints from discovered ones."""
        existing_endpoints = self.endpoint_map.get_all()
        if not existing_endpoints:
            return

        # Find API patterns and infer related endpoints
        inferred_paths = set()

        for endpoint in existing_endpoints:
            path = endpoint.path

            # If path ends with collection, try /{id} variants
            if path.endswith(("s", "es", "ies")) and not path.endswith(("ss", "ess")):
                # /api/users → /api/users/{id}, /api/users/me
                inferred_paths.add(f"{path}/1")
                inferred_paths.add(f"{path}/me")

            # If path has /v1/, try /v2/, /v3/
            if "/v1/" in path:
                inferred_paths.add(path.replace("/v1/", "/v2/"))
                inferred_paths.add(path.replace("/v1/", "/v3/"))

            # If path is /api/resource, try /api/resource/{id}
            if "/api/" in path and "{" not in path and not path.endswith(("1", "2", "me")):
                parts = path.rstrip("/").split("/")
                if len(parts) >= 2:
                    inferred_paths.add(f"{path.rstrip('/')}/1")

        # Filter out already known paths
        new_paths = inferred_paths - set(self.endpoint_map.get_paths())

        if not new_paths:
            return

        logger.info(f"[SmartDiscovery] Inferring {len(new_paths)} related endpoints")

        # Probe inferred paths (limit to avoid too many requests)
        for path in list(new_paths)[:50]:
            if rate_limiter:
                await rate_limiter.acquire()

            url = urljoin(base_url, path)
            try:
                response = await self._client.get(url)
                if response.status_code not in (404, 502, 503, 504):
                    self.endpoint_map.add_endpoint(DiscoveredEndpoint(
                        path=path,
                        methods=infer_methods_from_path(path),
                        source=EndpointSource.RESPONSE_INFERENCE,
                        confidence=0.6,
                        verified=True,
                        last_status_code=response.status_code,
                        requires_auth=(response.status_code in (401, 403)),
                        category=categorize_path(path),
                    ))
            except Exception:
                pass

    # ========================================================================
    # PHASE 2.5: TOOL-BASED RAPID DISCOVERY
    # ========================================================================

    async def _phase2b_tools_discovery(
        self,
        base_url: str,
        rate_limiter: Optional[RateLimiter],
    ) -> None:
        """Phase 2.5: Use Linux tools (ffuf/gobuster) for rapid endpoint discovery."""
        logger.info("[SmartDiscovery] Phase 2.5: Tool-based Rapid Discovery")

        # Check ~/.local/bin for user-installed tools
        local_bin = Path.home() / ".local" / "bin"
        if local_bin.exists():
            os.environ["PATH"] = f"{local_bin}:{os.environ.get('PATH', '')}"

        # Try ffuf first (fastest), then gobuster as fallback
        if shutil.which("ffuf"):
            await self._run_ffuf_discovery(base_url)
        elif shutil.which("gobuster"):
            await self._run_gobuster_discovery(base_url)
        else:
            logger.warning("[SmartDiscovery] No fuzzing tools available (ffuf/gobuster)")

    async def _run_ffuf_discovery(self, base_url: str) -> None:
        """Run ffuf for rapid endpoint discovery."""
        wordlist = self.config.ffuf_wordlist

        # Check if wordlist exists
        if not Path(wordlist).exists():
            # Try alternative paths
            alternatives = [
                "/usr/share/dirb/wordlists/common.txt",
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            ]
            wordlist = next((w for w in alternatives if Path(w).exists()), None)

            if not wordlist:
                logger.warning("[SmartDiscovery] No wordlist found for ffuf")
                return

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name

        try:
            # Run ffuf with JSON output
            cmd = [
                "ffuf",
                "-u", f"{base_url.rstrip('/')}/FUZZ",
                "-w", wordlist,
                "-o", output_file,
                "-of", "json",
                "-mc", "200,201,204,301,302,307,401,403,405",  # Match these status codes
                "-s",  # Silent mode
                "-t", "50",  # 50 threads
                "-timeout", "5",  # 5 second timeout per request
            ]

            logger.info(f"[SmartDiscovery] Running ffuf with {wordlist}")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                _, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.config.tool_timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                logger.warning("[SmartDiscovery] ffuf timed out")
                return

            # Parse results
            if Path(output_file).exists():
                endpoints_found = self._parse_ffuf_output(output_file)
                logger.info(f"[SmartDiscovery] ffuf found {endpoints_found} endpoints")

        except Exception as e:
            logger.warning(f"[SmartDiscovery] ffuf error: {e}")
        finally:
            # Cleanup
            try:
                Path(output_file).unlink(missing_ok=True)
            except Exception:
                pass

    def _parse_ffuf_output(self, output_file: str) -> int:
        """Parse ffuf JSON output and add to endpoint map."""
        count = 0
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)

            for result in data.get("results", []):
                input_val = result.get("input", {}).get("FUZZ", "")
                status = result.get("status", 0)
                url = result.get("url", "")

                if input_val and status in (200, 201, 204, 301, 302, 307, 401, 403, 405):
                    path = f"/{input_val}"

                    self.endpoint_map.add_endpoint(DiscoveredEndpoint(
                        path=path,
                        methods=infer_methods_from_path(path),
                        source=EndpointSource.CRAWL_HTML,  # Use CRAWL as closest match
                        confidence=0.9,  # High confidence - actually exists
                        verified=True,
                        last_status_code=status,
                        requires_auth=(status in (401, 403)),
                        category=categorize_path(path),
                    ))
                    count += 1

        except Exception as e:
            logger.debug(f"[SmartDiscovery] Error parsing ffuf output: {e}")

        return count

    async def _run_gobuster_discovery(self, base_url: str) -> None:
        """Run gobuster for endpoint discovery (fallback to ffuf)."""
        wordlist = self.config.ffuf_wordlist

        if not Path(wordlist).exists():
            alternatives = [
                "/usr/share/dirb/wordlists/common.txt",
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
            ]
            wordlist = next((w for w in alternatives if Path(w).exists()), None)
            if not wordlist:
                logger.warning("[SmartDiscovery] No wordlist found for gobuster")
                return

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            output_file = f.name

        try:
            cmd = [
                "gobuster", "dir",
                "-u", base_url.rstrip('/'),
                "-w", wordlist,
                "-o", output_file,
                "-q",  # Quiet mode
                "--no-error",  # Don't show errors
                "-t", "50",  # 50 threads
            ]

            logger.info(f"[SmartDiscovery] Running gobuster with {wordlist}")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                await asyncio.wait_for(proc.communicate(), timeout=self.config.tool_timeout)
            except asyncio.TimeoutError:
                proc.kill()
                logger.warning("[SmartDiscovery] gobuster timed out")
                return

            # Parse results
            if Path(output_file).exists():
                endpoints_found = self._parse_gobuster_output(output_file)
                logger.info(f"[SmartDiscovery] gobuster found {endpoints_found} endpoints")

        except Exception as e:
            logger.warning(f"[SmartDiscovery] gobuster error: {e}")
        finally:
            try:
                Path(output_file).unlink(missing_ok=True)
            except Exception:
                pass

    def _parse_gobuster_output(self, output_file: str) -> int:
        """Parse gobuster text output and add to endpoint map."""
        count = 0
        try:
            with open(output_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    # gobuster format: /path (Status: 200)
                    match = re.match(r'^(/\S+)\s+\(Status:\s*(\d+)\)', line)
                    if match:
                        path = match.group(1)
                        status = int(match.group(2))

                        self.endpoint_map.add_endpoint(DiscoveredEndpoint(
                            path=path,
                            methods=infer_methods_from_path(path),
                            source=EndpointSource.CRAWL_HTML,
                            confidence=0.9,
                            verified=True,
                            last_status_code=status,
                            requires_auth=(status in (401, 403)),
                            category=categorize_path(path),
                        ))
                        count += 1

        except Exception as e:
            logger.debug(f"[SmartDiscovery] Error parsing gobuster output: {e}")

        return count

    # ========================================================================
    # PHASE 3: CATEGORIZATION
    # ========================================================================

    def _phase3_categorize_endpoints(self) -> None:
        """Phase 3: Categorize all endpoints semantically."""
        logger.info("[SmartDiscovery] Phase 3: Categorization")

        for endpoint in self.endpoint_map.get_all():
            if endpoint.category == EndpointCategory.UNKNOWN:
                endpoint.category = categorize_path(endpoint.path)

    # ========================================================================
    # PHASE 4: VERIFICATION
    # ========================================================================

    async def _phase4_verify_endpoints(
        self,
        base_url: str,
        rate_limiter: Optional[RateLimiter],
    ) -> None:
        """Phase 4: Verify endpoints exist using HEAD requests."""
        logger.info("[SmartDiscovery] Phase 4: Verification")

        # Only verify unverified endpoints with sufficient confidence
        to_verify = [
            ep for ep in self.endpoint_map.get_all()
            if not ep.verified and ep.confidence >= self.config.min_confidence_to_verify
        ]

        # Limit verification
        to_verify = to_verify[:self.config.verify_limit]

        if not to_verify:
            logger.info("[SmartDiscovery] No endpoints to verify")
            return

        logger.info(f"[SmartDiscovery] Verifying {len(to_verify)} endpoints")

        semaphore = asyncio.Semaphore(self.config.max_concurrent)

        async def verify_endpoint(endpoint: DiscoveredEndpoint) -> None:
            async with semaphore:
                if rate_limiter:
                    await rate_limiter.acquire()

                # Skip GraphQL operations (they're virtual)
                if "#" in endpoint.path:
                    endpoint.verified = True
                    return

                url = urljoin(base_url, endpoint.path)
                try:
                    response = await self._client.head(url)
                    if response.status_code not in (404, 502, 503, 504):
                        endpoint.verified = True
                        endpoint.last_status_code = response.status_code
                        if response.status_code in (401, 403):
                            endpoint.requires_auth = True
                    else:
                        # Mark as non-existent (low confidence sources)
                        if endpoint.confidence < 0.7:
                            self.endpoint_map.mark_nonexistent(endpoint.path)
                except Exception:
                    pass

        tasks = [verify_endpoint(ep) for ep in to_verify]
        await asyncio.gather(*tasks, return_exceptions=True)

        verified_count = len([ep for ep in to_verify if ep.verified])
        logger.info(f"[SmartDiscovery] Verified {verified_count}/{len(to_verify)} endpoints")

    # ========================================================================
    # PHASE 5: PHANTOM AI DEEP ANALYSIS
    # ========================================================================

    async def _phase5_deep_analysis(
        self,
        base_url: str,
        rate_limiter: Optional[RateLimiter],
    ) -> None:
        """
        Phase 5: PHANTOM AI Deep Analysis.

        This phase performs advanced analysis using PHANTOM AI modules:
        1. Technology Fingerprinting - Detect frameworks, libraries, and versions
        2. Parameter Analysis - Analyze parameters for injection potential
        3. Attack Surface Calculation - Score endpoints by risk

        Requires PHANTOM AI modules to be available.
        """
        if not PHANTOM_AVAILABLE:
            logger.warning("[SmartDiscovery] PHANTOM AI modules not available, skipping Phase 5")
            return

        logger.info("[SmartDiscovery] Phase 5: PHANTOM AI Deep Analysis")

        # Store analysis results
        self._fingerprint_result: Optional[FingerprintResult] = None
        self._parameter_analysis: Dict[str, AnalysisResult] = {}

        # 5.1: Technology Fingerprinting
        if self.config.fingerprint_target:
            await self._fingerprint_target(base_url)

        # 5.2: Parameter Analysis for priority endpoints
        if self.config.analyze_parameters:
            await self._analyze_endpoint_parameters(base_url, rate_limiter)

        # 5.3: Calculate and log attack surface
        self._calculate_attack_surface()

        logger.info("[SmartDiscovery] Phase 5 complete")

    async def _fingerprint_target(self, base_url: str) -> None:
        """Run technology fingerprinting on the target."""
        try:
            fingerprinter = TechFingerprinter()
            self._fingerprint_result = await fingerprinter.fingerprint(base_url)

            tech_count = len(self._fingerprint_result.technologies)
            logger.info(f"[SmartDiscovery] Fingerprinted {tech_count} technologies")

            # Log notable detections
            if self._fingerprint_result.waf_detected:
                logger.info(f"[SmartDiscovery] WAF detected: {self._fingerprint_result.waf_detected}")

            if self._fingerprint_result.cdn_detected:
                logger.info(f"[SmartDiscovery] CDN detected: {self._fingerprint_result.cdn_detected}")

            # Log high-confidence technologies
            for tech in self._fingerprint_result.technologies[:5]:  # Top 5
                if tech.confidence >= 0.7:
                    version_info = f" v{tech.version}" if tech.version else ""
                    cve_info = f" ({len(tech.cves)} CVEs)" if tech.cves else ""
                    logger.info(f"[SmartDiscovery] Detected: {tech.name}{version_info}{cve_info}")

            # Update endpoints with technology hints
            self._enrich_endpoints_with_tech()

        except Exception as e:
            logger.warning(f"[SmartDiscovery] Fingerprinting failed: {e}")

    def _enrich_endpoints_with_tech(self) -> None:
        """Enrich endpoints with detected technology information."""
        if not self._fingerprint_result:
            return

        # Get primary technology names
        primary_techs = [
            tech.name for tech in self._fingerprint_result.technologies
            if tech.confidence >= 0.7
        ][:3]

        tech_hint = ", ".join(primary_techs) if primary_techs else None

        # Update endpoints that don't have a technology hint
        for endpoint in self.endpoint_map.get_all():
            if not endpoint.technology_hint and tech_hint:
                endpoint.technology_hint = tech_hint

    async def _analyze_endpoint_parameters(
        self,
        base_url: str,
        rate_limiter: Optional[RateLimiter],
    ) -> None:
        """Analyze parameters for priority endpoints."""
        try:
            # Get priority endpoints for analysis
            priority_endpoints = self.endpoint_map.get_priority_endpoints(
                limit=self.config.deep_analysis_limit
            )

            if not priority_endpoints:
                logger.info("[SmartDiscovery] No priority endpoints for parameter analysis")
                return

            logger.info(f"[SmartDiscovery] Analyzing parameters for {len(priority_endpoints)} endpoints")

            analyzer = ParameterAnalyzer()

            for endpoint in priority_endpoints:
                # Skip static resources
                if endpoint.category == EndpointCategory.STATIC:
                    continue

                try:
                    # Prepare sample parameters from endpoint
                    sample_params = {
                        p.name: p.example_value or ""
                        for p in endpoint.parameters
                    }

                    # Analyze the endpoint
                    result = await analyzer.analyze(
                        base_url=base_url,
                        endpoint=endpoint.path,
                        method=list(endpoint.methods)[0].value if endpoint.methods else "GET",
                        sample_params=sample_params if sample_params else None,
                        test_reflection=self.config.reflection_testing,
                        test_behavior=False,  # Skip behavior testing for speed
                    )

                    # Store result
                    self._parameter_analysis[endpoint.path] = result

                    # Update endpoint parameters with analysis
                    self._update_endpoint_with_analysis(endpoint, result)

                    # Respect rate limiting
                    if rate_limiter:
                        await rate_limiter.acquire()

                except Exception as e:
                    logger.debug(f"[SmartDiscovery] Parameter analysis failed for {endpoint.path}: {e}")

            # Close analyzer
            await analyzer.close()

            # Log summary
            total_params = sum(len(r.parameters) for r in self._parameter_analysis.values())
            high_priority = sum(r.high_priority_count for r in self._parameter_analysis.values())
            reflected = sum(r.reflected_count for r in self._parameter_analysis.values())

            logger.info(f"[SmartDiscovery] Analyzed {total_params} parameters")
            logger.info(f"[SmartDiscovery] High-priority parameters: {high_priority}")
            if reflected > 0:
                logger.info(f"[SmartDiscovery] Reflected parameters: {reflected}")

        except Exception as e:
            logger.warning(f"[SmartDiscovery] Parameter analysis failed: {e}")

    def _update_endpoint_with_analysis(
        self,
        endpoint: DiscoveredEndpoint,
        analysis: AnalysisResult,
    ) -> None:
        """Update endpoint with parameter analysis results."""
        # Add newly discovered parameters
        existing_names = {p.name for p in endpoint.parameters}

        for param in analysis.parameters:
            if param.name not in existing_names:
                endpoint.parameters.append(DiscoveredParameter(
                    name=param.name,
                    location=param.location.value,
                    param_type=param.inferred_type.value,
                    required=False,
                    example_value=param.original_value[:50] if param.original_value else None,
                ))

        # Update raw evidence with analysis summary
        vuln_contexts = [v.value for v in analysis.potential_vulnerabilities]
        if vuln_contexts:
            evidence = f"Potential vulnerabilities: {', '.join(vuln_contexts[:5])}"
            if endpoint.raw_evidence:
                endpoint.raw_evidence += f"; {evidence}"
            else:
                endpoint.raw_evidence = evidence

    def _calculate_attack_surface(self) -> None:
        """Calculate and log attack surface score."""
        attack_surface = self.endpoint_map.get_attack_surface_score()

        logger.info(f"[SmartDiscovery] Attack Surface Score: {attack_surface['overall_score']}/10")

        # Log risk factors
        for risk in attack_surface.get('risk_factors', []):
            severity = risk.get('severity', 'info')
            factor = risk.get('factor', '')
            logger.info(f"[SmartDiscovery] Risk [{severity.upper()}]: {factor}")

        # Store for later retrieval
        self._attack_surface_score = attack_surface

    def get_fingerprint_result(self) -> Optional[FingerprintResult]:
        """Get the technology fingerprinting result (available after Phase 5)."""
        return getattr(self, '_fingerprint_result', None)

    def get_parameter_analysis(self) -> Dict[str, AnalysisResult]:
        """Get parameter analysis results (available after Phase 5)."""
        return getattr(self, '_parameter_analysis', {})

    def get_attack_surface_score(self) -> Dict[str, Any]:
        """Get the attack surface score (available after Phase 5)."""
        return getattr(self, '_attack_surface_score', self.endpoint_map.get_attack_surface_score())
