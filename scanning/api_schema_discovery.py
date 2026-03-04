"""
API Schema Discovery v1.0 - Parse OpenAPI/Swagger for Endpoints

PROBLEM:
APIs expose documentation that reveals:
- All endpoints (including hidden/admin ones)
- All parameters with types and validation
- Authentication schemes
- Example values
- Business logic flows

Scanner ignores this goldmine of information.

SOLUTION:
Parse OpenAPI 2.0 (Swagger) and OpenAPI 3.x specifications to extract:
1. All endpoints with methods
2. All parameters with types, constraints, examples
3. Security schemes (OAuth, API key, JWT)
4. Response schemas (for validation)
5. Tags and descriptions (for context)

Philosophy: "The API spec is an attacker's roadmap — read it."

Author: PHANTOM AI
Version: 1.0.0
"""

from __future__ import annotations

import json
import re
import yaml
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum
from urllib.parse import urljoin
import logging

logger = logging.getLogger(__name__)


class ParameterLocation(Enum):
    """Where the parameter appears in the request."""
    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    COOKIE = "cookie"
    BODY = "body"
    FORMDATA = "formData"


class SecurityType(Enum):
    """API security scheme types."""
    API_KEY = "apiKey"
    HTTP = "http"
    OAUTH2 = "oauth2"
    OPENID_CONNECT = "openIdConnect"
    BASIC = "basic"


@dataclass
class APIParameter:
    """Parameter extracted from API spec."""
    name: str
    location: ParameterLocation
    param_type: str = "string"
    required: bool = False
    description: str = ""
    example: Optional[str] = None
    default: Optional[str] = None
    enum: List[str] = field(default_factory=list)
    minimum: Optional[float] = None
    maximum: Optional[float] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    format: Optional[str] = None  # email, date, uuid, etc.
    nullable: bool = False

    # For objects/arrays
    schema: Dict[str, Any] = field(default_factory=dict)

    def get_injection_priority(self) -> int:
        """Calculate injection priority based on parameter characteristics."""
        priority = 5  # Base priority

        # High-value injection targets
        high_value_patterns = [
            r"id$", r"_id$", r"query", r"search", r"filter",
            r"redirect", r"url", r"file", r"path", r"name",
            r"email", r"user", r"admin", r"password", r"token",
            r"command", r"exec", r"template", r"callback",
        ]

        name_lower = self.name.lower()
        for pattern in high_value_patterns:
            if re.search(pattern, name_lower):
                priority += 3
                break

        # Location bonuses
        if self.location in (ParameterLocation.PATH, ParameterLocation.QUERY):
            priority += 1

        # Required parameters often more impactful
        if self.required:
            priority += 1

        return min(priority, 10)


@dataclass
class APIEndpoint:
    """Endpoint extracted from API spec."""
    path: str
    method: str
    operation_id: Optional[str] = None
    summary: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)
    parameters: List[APIParameter] = field(default_factory=list)
    request_body_schema: Dict[str, Any] = field(default_factory=dict)
    response_schemas: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    security_requirements: List[Dict[str, List[str]]] = field(default_factory=list)
    deprecated: bool = False

    def get_full_url(self, base_url: str) -> str:
        """Get full URL with base."""
        return urljoin(base_url, self.path)

    def get_injectable_params(self) -> List[APIParameter]:
        """Get parameters sorted by injection priority."""
        params = [p for p in self.parameters]
        params.sort(key=lambda p: p.get_injection_priority(), reverse=True)
        return params

    def has_auth_requirement(self) -> bool:
        """Check if endpoint requires authentication."""
        return len(self.security_requirements) > 0


@dataclass
class APISecurityScheme:
    """Security scheme from API spec."""
    name: str
    scheme_type: SecurityType
    description: str = ""

    # For API key
    key_name: Optional[str] = None
    key_location: Optional[str] = None  # header, query, cookie

    # For HTTP auth
    http_scheme: Optional[str] = None  # basic, bearer, digest

    # For OAuth2
    oauth_flows: Dict[str, Any] = field(default_factory=dict)

    # For OpenID Connect
    openid_url: Optional[str] = None


@dataclass
class APISpecification:
    """Complete API specification."""
    title: str = ""
    version: str = ""
    description: str = ""
    base_url: str = ""
    endpoints: List[APIEndpoint] = field(default_factory=list)
    security_schemes: Dict[str, APISecurityScheme] = field(default_factory=dict)
    global_security: List[Dict[str, List[str]]] = field(default_factory=list)
    tags: Dict[str, str] = field(default_factory=dict)  # tag_name -> description

    # Statistics
    spec_version: str = ""  # "2.0", "3.0.x", "3.1.x"
    parse_errors: List[str] = field(default_factory=list)

    def get_endpoints_by_tag(self, tag: str) -> List[APIEndpoint]:
        """Get endpoints with a specific tag."""
        return [e for e in self.endpoints if tag in e.tags]

    def get_auth_endpoints(self) -> List[APIEndpoint]:
        """Get endpoints that require auth."""
        return [e for e in self.endpoints if e.has_auth_requirement()]

    def get_unauth_endpoints(self) -> List[APIEndpoint]:
        """Get endpoints without auth requirements."""
        return [e for e in self.endpoints if not e.has_auth_requirement()]

    def get_admin_endpoints(self) -> List[APIEndpoint]:
        """Get endpoints that look like admin endpoints."""
        admin_patterns = [
            r"/admin", r"/manage", r"/internal", r"/system",
            r"/config", r"/settings", r"/users", r"/roles",
            r"/permissions", r"/audit", r"/logs",
        ]
        admin_endpoints = []
        for endpoint in self.endpoints:
            for pattern in admin_patterns:
                if re.search(pattern, endpoint.path, re.IGNORECASE):
                    admin_endpoints.append(endpoint)
                    break
        return admin_endpoints


class APISchemaDiscovery:
    """
    Parse OpenAPI/Swagger specifications.

    Usage:
        discovery = APISchemaDiscovery()

        # Parse from URL
        spec = await discovery.discover_from_url("https://api.example.com")

        # Or parse from content
        spec = discovery.parse_spec(openapi_json)

        # Get endpoints
        for endpoint in spec.endpoints:
            print(f"{endpoint.method} {endpoint.path}")
            for param in endpoint.get_injectable_params():
                print(f"  - {param.name} ({param.location.value})")
    """

    # Common OpenAPI/Swagger URL patterns
    SPEC_URL_PATTERNS = [
        "/swagger.json",
        "/swagger.yaml",
        "/swagger/v1/swagger.json",
        "/v1/swagger.json",
        "/v2/swagger.json",
        "/v3/swagger.json",
        "/api/swagger.json",
        "/api-docs",
        "/api-docs.json",
        "/openapi.json",
        "/openapi.yaml",
        "/openapi/v3/api-docs",
        "/api/v1/openapi.json",
        "/api/v2/openapi.json",
        "/api/v3/openapi.json",
        "/docs/swagger.json",
        "/spec/swagger.json",
        "/.well-known/openapi.json",
        "/graphql/schema.json",  # GraphQL schema
    ]

    def __init__(self):
        """Initialize API schema discovery."""
        self._parsed_specs: Dict[str, APISpecification] = {}

    async def discover_from_url(
        self,
        base_url: str,
        http_client: Any,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> Optional[APISpecification]:
        """
        Try to discover and parse API spec from common URLs.

        Args:
            base_url: Base URL of the API
            http_client: HTTP client for requests
            auth_headers: Optional auth headers

        Returns:
            APISpecification or None if not found
        """
        base = base_url.rstrip("/")
        headers = auth_headers or {}

        for pattern in self.SPEC_URL_PATTERNS:
            spec_url = f"{base}{pattern}"

            try:
                resp = await http_client.get(
                    spec_url,
                    headers=headers,
                    timeout=10.0,
                )

                status = getattr(resp, "status_code", getattr(resp, "status", 0))

                if status != 200:
                    continue

                # Get content
                content = ""
                if hasattr(resp, "text"):
                    content = await resp.text() if hasattr(resp.text, "__call__") else resp.text
                elif hasattr(resp, "content"):
                    content = resp.content.decode("utf-8", errors="replace")

                if not content:
                    continue

                # Try to parse
                spec = self.parse_spec(content, base)

                if spec and len(spec.endpoints) > 0:
                    logger.info(
                        f"[API_DISCOVERY] Found spec at {spec_url}: "
                        f"{len(spec.endpoints)} endpoints"
                    )
                    self._parsed_specs[base_url] = spec
                    return spec

            except Exception as e:
                logger.debug(f"[API_DISCOVERY] Error checking {spec_url}: {e}")
                continue

        logger.debug(f"[API_DISCOVERY] No API spec found at {base_url}")
        return None

    def parse_spec(
        self,
        content: str,
        base_url: str = "",
    ) -> Optional[APISpecification]:
        """
        Parse OpenAPI/Swagger specification content.

        Args:
            content: JSON or YAML spec content
            base_url: Base URL for the API

        Returns:
            APISpecification or None if parsing failed
        """
        # Parse content
        spec_data = self._parse_content(content)
        if not spec_data:
            return None

        # Detect version
        if "openapi" in spec_data:
            version = spec_data.get("openapi", "")
            if version.startswith("3."):
                return self._parse_openapi_3(spec_data, base_url)
        elif "swagger" in spec_data:
            version = spec_data.get("swagger", "")
            if version.startswith("2."):
                return self._parse_swagger_2(spec_data, base_url)

        logger.warning("[API_DISCOVERY] Unknown spec version")
        return None

    def _parse_content(self, content: str) -> Optional[Dict[str, Any]]:
        """Parse JSON or YAML content."""
        content = content.strip()

        # Try JSON first
        if content.startswith("{"):
            try:
                return json.loads(content)
            except json.JSONDecodeError:
                pass

        # Try YAML
        try:
            return yaml.safe_load(content)
        except yaml.YAMLError:
            pass

        return None

    def _parse_openapi_3(
        self,
        data: Dict[str, Any],
        base_url: str,
    ) -> APISpecification:
        """Parse OpenAPI 3.x specification."""
        spec = APISpecification(
            spec_version=data.get("openapi", "3.0.0"),
        )

        # Parse info
        info = data.get("info", {})
        spec.title = info.get("title", "")
        spec.version = info.get("version", "")
        spec.description = info.get("description", "")

        # Parse servers
        servers = data.get("servers", [])
        if servers:
            spec.base_url = servers[0].get("url", base_url)
        else:
            spec.base_url = base_url

        # Parse security schemes
        components = data.get("components", {})
        security_schemes = components.get("securitySchemes", {})
        for name, scheme_data in security_schemes.items():
            spec.security_schemes[name] = self._parse_security_scheme(name, scheme_data)

        # Parse global security
        spec.global_security = data.get("security", [])

        # Parse tags
        for tag in data.get("tags", []):
            spec.tags[tag.get("name", "")] = tag.get("description", "")

        # Parse paths
        paths = data.get("paths", {})
        for path, path_data in paths.items():
            # Get path-level parameters
            path_params = path_data.get("parameters", [])

            for method in ["get", "post", "put", "patch", "delete", "head", "options"]:
                if method not in path_data:
                    continue

                operation = path_data[method]
                endpoint = self._parse_operation_3(
                    path, method.upper(), operation, path_params, components
                )
                spec.endpoints.append(endpoint)

        logger.info(
            f"[API_DISCOVERY] Parsed OpenAPI 3.x: "
            f"{len(spec.endpoints)} endpoints, "
            f"{len(spec.security_schemes)} security schemes"
        )

        return spec

    def _parse_swagger_2(
        self,
        data: Dict[str, Any],
        base_url: str,
    ) -> APISpecification:
        """Parse Swagger 2.0 specification."""
        spec = APISpecification(
            spec_version="2.0",
        )

        # Parse info
        info = data.get("info", {})
        spec.title = info.get("title", "")
        spec.version = info.get("version", "")
        spec.description = info.get("description", "")

        # Parse base path
        host = data.get("host", "")
        base_path = data.get("basePath", "")
        schemes = data.get("schemes", ["https"])

        if host:
            scheme = schemes[0] if schemes else "https"
            spec.base_url = f"{scheme}://{host}{base_path}"
        else:
            spec.base_url = base_url

        # Parse security definitions
        security_defs = data.get("securityDefinitions", {})
        for name, def_data in security_defs.items():
            spec.security_schemes[name] = self._parse_security_scheme(name, def_data)

        # Parse global security
        spec.global_security = data.get("security", [])

        # Parse tags
        for tag in data.get("tags", []):
            spec.tags[tag.get("name", "")] = tag.get("description", "")

        # Parse paths
        definitions = data.get("definitions", {})
        paths = data.get("paths", {})

        for path, path_data in paths.items():
            path_params = path_data.get("parameters", [])

            for method in ["get", "post", "put", "patch", "delete", "head", "options"]:
                if method not in path_data:
                    continue

                operation = path_data[method]
                endpoint = self._parse_operation_2(
                    path, method.upper(), operation, path_params, definitions
                )
                spec.endpoints.append(endpoint)

        logger.info(
            f"[API_DISCOVERY] Parsed Swagger 2.0: "
            f"{len(spec.endpoints)} endpoints"
        )

        return spec

    def _parse_operation_3(
        self,
        path: str,
        method: str,
        operation: Dict[str, Any],
        path_params: List[Dict],
        components: Dict[str, Any],
    ) -> APIEndpoint:
        """Parse OpenAPI 3.x operation."""
        endpoint = APIEndpoint(
            path=path,
            method=method,
            operation_id=operation.get("operationId"),
            summary=operation.get("summary", ""),
            description=operation.get("description", ""),
            tags=operation.get("tags", []),
            security_requirements=operation.get("security", []),
            deprecated=operation.get("deprecated", False),
        )

        # Parse parameters
        all_params = path_params + operation.get("parameters", [])
        for param_data in all_params:
            # Resolve $ref
            if "$ref" in param_data:
                ref_path = param_data["$ref"]
                param_data = self._resolve_ref(ref_path, components)

            param = self._parse_parameter_3(param_data, components)
            if param:
                endpoint.parameters.append(param)

        # Parse request body
        request_body = operation.get("requestBody", {})
        if request_body:
            content = request_body.get("content", {})
            for media_type, media_data in content.items():
                schema = media_data.get("schema", {})

                # Extract body parameters from schema
                body_params = self._extract_params_from_schema(
                    schema, components.get("schemas", {})
                )

                for param in body_params:
                    param.location = ParameterLocation.BODY
                    endpoint.parameters.append(param)

                endpoint.request_body_schema = schema
                break  # Use first content type

        # Parse responses
        responses = operation.get("responses", {})
        for status_code, response_data in responses.items():
            try:
                code = int(status_code)
                content = response_data.get("content", {})
                if content:
                    first_schema = list(content.values())[0].get("schema", {})
                    endpoint.response_schemas[code] = first_schema
            except ValueError:
                continue

        return endpoint

    def _parse_operation_2(
        self,
        path: str,
        method: str,
        operation: Dict[str, Any],
        path_params: List[Dict],
        definitions: Dict[str, Any],
    ) -> APIEndpoint:
        """Parse Swagger 2.0 operation."""
        endpoint = APIEndpoint(
            path=path,
            method=method,
            operation_id=operation.get("operationId"),
            summary=operation.get("summary", ""),
            description=operation.get("description", ""),
            tags=operation.get("tags", []),
            security_requirements=operation.get("security", []),
            deprecated=operation.get("deprecated", False),
        )

        # Parse parameters
        all_params = path_params + operation.get("parameters", [])
        for param_data in all_params:
            param = self._parse_parameter_2(param_data, definitions)
            if param:
                endpoint.parameters.append(param)

        # Parse responses
        responses = operation.get("responses", {})
        for status_code, response_data in responses.items():
            try:
                code = int(status_code)
                schema = response_data.get("schema", {})
                if schema:
                    endpoint.response_schemas[code] = schema
            except ValueError:
                continue

        return endpoint

    def _parse_parameter_3(
        self,
        data: Dict[str, Any],
        components: Dict[str, Any],
    ) -> Optional[APIParameter]:
        """Parse OpenAPI 3.x parameter."""
        if not data or "name" not in data:
            return None

        location_map = {
            "path": ParameterLocation.PATH,
            "query": ParameterLocation.QUERY,
            "header": ParameterLocation.HEADER,
            "cookie": ParameterLocation.COOKIE,
        }

        location_str = data.get("in", "query")
        location = location_map.get(location_str, ParameterLocation.QUERY)

        schema = data.get("schema", {})

        # Resolve schema $ref
        if "$ref" in schema:
            schema = self._resolve_ref(schema["$ref"], components)

        return APIParameter(
            name=data.get("name", ""),
            location=location,
            param_type=schema.get("type", "string"),
            required=data.get("required", False),
            description=data.get("description", ""),
            example=str(data.get("example")) if data.get("example") else None,
            default=str(schema.get("default")) if schema.get("default") else None,
            enum=schema.get("enum", []),
            minimum=schema.get("minimum"),
            maximum=schema.get("maximum"),
            min_length=schema.get("minLength"),
            max_length=schema.get("maxLength"),
            pattern=schema.get("pattern"),
            format=schema.get("format"),
            nullable=schema.get("nullable", False),
            schema=schema,
        )

    def _parse_parameter_2(
        self,
        data: Dict[str, Any],
        definitions: Dict[str, Any],
    ) -> Optional[APIParameter]:
        """Parse Swagger 2.0 parameter."""
        if not data or "name" not in data:
            return None

        location_map = {
            "path": ParameterLocation.PATH,
            "query": ParameterLocation.QUERY,
            "header": ParameterLocation.HEADER,
            "formData": ParameterLocation.FORMDATA,
            "body": ParameterLocation.BODY,
        }

        location_str = data.get("in", "query")
        location = location_map.get(location_str, ParameterLocation.QUERY)

        # For body parameters, extract from schema
        if location == ParameterLocation.BODY:
            schema = data.get("schema", {})
            return APIParameter(
                name=data.get("name", "body"),
                location=location,
                param_type="object",
                required=data.get("required", False),
                description=data.get("description", ""),
                schema=schema,
            )

        return APIParameter(
            name=data.get("name", ""),
            location=location,
            param_type=data.get("type", "string"),
            required=data.get("required", False),
            description=data.get("description", ""),
            default=str(data.get("default")) if data.get("default") else None,
            enum=data.get("enum", []),
            minimum=data.get("minimum"),
            maximum=data.get("maximum"),
            min_length=data.get("minLength"),
            max_length=data.get("maxLength"),
            pattern=data.get("pattern"),
            format=data.get("format"),
        )

    def _parse_security_scheme(
        self,
        name: str,
        data: Dict[str, Any],
    ) -> APISecurityScheme:
        """Parse security scheme definition."""
        scheme_type_map = {
            "apiKey": SecurityType.API_KEY,
            "http": SecurityType.HTTP,
            "oauth2": SecurityType.OAUTH2,
            "openIdConnect": SecurityType.OPENID_CONNECT,
            "basic": SecurityType.BASIC,
        }

        type_str = data.get("type", "apiKey")
        scheme_type = scheme_type_map.get(type_str, SecurityType.API_KEY)

        return APISecurityScheme(
            name=name,
            scheme_type=scheme_type,
            description=data.get("description", ""),
            key_name=data.get("name"),
            key_location=data.get("in"),
            http_scheme=data.get("scheme"),
            oauth_flows=data.get("flows", {}),
            openid_url=data.get("openIdConnectUrl"),
        )

    def _resolve_ref(
        self,
        ref_path: str,
        components: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Resolve $ref reference."""
        # Format: "#/components/schemas/User"
        if not ref_path.startswith("#/"):
            return {}

        parts = ref_path[2:].split("/")

        current = {"components": components}
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return {}

        return current if isinstance(current, dict) else {}

    def _extract_params_from_schema(
        self,
        schema: Dict[str, Any],
        schemas: Dict[str, Any],
    ) -> List[APIParameter]:
        """Extract parameters from a JSON schema."""
        params = []

        # Resolve $ref
        if "$ref" in schema:
            ref_name = schema["$ref"].split("/")[-1]
            schema = schemas.get(ref_name, schema)

        schema_type = schema.get("type", "object")

        if schema_type == "object":
            properties = schema.get("properties", {})
            required = schema.get("required", [])

            for prop_name, prop_data in properties.items():
                # Resolve nested $ref
                if "$ref" in prop_data:
                    ref_name = prop_data["$ref"].split("/")[-1]
                    prop_data = schemas.get(ref_name, prop_data)

                param = APIParameter(
                    name=prop_name,
                    location=ParameterLocation.BODY,
                    param_type=prop_data.get("type", "string"),
                    required=prop_name in required,
                    description=prop_data.get("description", ""),
                    example=str(prop_data.get("example")) if prop_data.get("example") else None,
                    default=str(prop_data.get("default")) if prop_data.get("default") else None,
                    enum=prop_data.get("enum", []),
                    minimum=prop_data.get("minimum"),
                    maximum=prop_data.get("maximum"),
                    min_length=prop_data.get("minLength"),
                    max_length=prop_data.get("maxLength"),
                    pattern=prop_data.get("pattern"),
                    format=prop_data.get("format"),
                    schema=prop_data,
                )
                params.append(param)

        return params

    def get_summary(self) -> Dict[str, Any]:
        """Get discovery summary."""
        return {
            "parsed_specs": len(self._parsed_specs),
            "specs": [
                {
                    "title": spec.title,
                    "version": spec.version,
                    "endpoints": len(spec.endpoints),
                    "security_schemes": len(spec.security_schemes),
                }
                for spec in self._parsed_specs.values()
            ],
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


async def discover_api_spec(
    base_url: str,
    http_client: Any,
    auth_headers: Optional[Dict[str, str]] = None,
) -> Optional[APISpecification]:
    """
    Quick function to discover API spec.

    Args:
        base_url: Base URL
        http_client: HTTP client
        auth_headers: Optional auth headers

    Returns:
        APISpecification or None
    """
    discovery = APISchemaDiscovery()
    return await discovery.discover_from_url(base_url, http_client, auth_headers)


def parse_openapi_file(file_path: str) -> Optional[APISpecification]:
    """
    Parse OpenAPI spec from file.

    Args:
        file_path: Path to spec file

    Returns:
        APISpecification or None
    """
    with open(file_path, "r") as f:
        content = f.read()

    discovery = APISchemaDiscovery()
    return discovery.parse_spec(content)


def get_injectable_endpoints(
    spec: APISpecification,
) -> List[Tuple[APIEndpoint, List[APIParameter]]]:
    """
    Get endpoints with their injectable parameters sorted by priority.

    Args:
        spec: API specification

    Returns:
        List of (endpoint, injectable_params) tuples
    """
    results = []

    for endpoint in spec.endpoints:
        injectable = endpoint.get_injectable_params()
        if injectable:
            results.append((endpoint, injectable))

    return results


def get_auth_bypass_candidates(
    spec: APISpecification,
) -> List[APIEndpoint]:
    """
    Get endpoints that might be vulnerable to auth bypass.

    These are endpoints that require auth but have sensitive operations.

    Args:
        spec: API specification

    Returns:
        List of candidate endpoints
    """
    candidates = []

    sensitive_patterns = [
        r"/admin", r"/user", r"/account", r"/password",
        r"/transfer", r"/payment", r"/order", r"/checkout",
        r"/delete", r"/remove", r"/modify", r"/update",
    ]

    for endpoint in spec.endpoints:
        if not endpoint.has_auth_requirement():
            continue

        for pattern in sensitive_patterns:
            if re.search(pattern, endpoint.path, re.IGNORECASE):
                candidates.append(endpoint)
                break

    return candidates
