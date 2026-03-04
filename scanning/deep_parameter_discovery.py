"""
Deep Parameter Discovery - Find ALL injectable parameters.

PROBLEM: Scanner finds endpoints but misses parameters:
- Hidden form fields
- JavaScript-generated parameters
- API body parameters
- Custom header injection points
- Multi-part form fields

SOLUTION: Multi-layer parameter extraction.

Author: PHANTOM AI
Version: 1.0.0
"""

from __future__ import annotations

import re
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlparse, urlencode
from enum import Enum

logger = logging.getLogger(__name__)


class ParameterSource(Enum):
    """Where the parameter was discovered."""
    URL_QUERY = "url_query"
    URL_PATH = "url_path"
    FORM_VISIBLE = "form_visible"
    FORM_HIDDEN = "form_hidden"
    FORM_SELECT = "form_select"
    FORM_TEXTAREA = "form_textarea"
    JSON_BODY = "json_body"
    XML_BODY = "xml_body"
    MULTIPART = "multipart"
    HEADER_CUSTOM = "header_custom"
    COOKIE = "cookie"
    JS_EXTRACTED = "js_extracted"
    API_SPEC = "api_spec"
    REFLECTED = "reflected"  # Found by reflection testing


class ParameterType(Enum):
    """Type of parameter value."""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"
    FILE = "file"
    EMAIL = "email"
    URL = "url"
    DATE = "date"
    ID = "id"  # Looks like an ID (numeric, UUID, etc.)
    TOKEN = "token"  # Looks like a token/hash
    UNKNOWN = "unknown"


@dataclass
class DiscoveredParameter:
    """A discovered parameter with metadata."""
    name: str
    source: ParameterSource
    param_type: ParameterType = ParameterType.UNKNOWN
    sample_value: Optional[str] = None
    is_required: bool = False
    default_value: Optional[str] = None
    constraints: Dict[str, Any] = field(default_factory=dict)  # min, max, pattern, etc.
    endpoint: Optional[str] = None
    method: str = "GET"

    # Injection relevance
    is_injectable: bool = True  # Some params (CSRF tokens) shouldn't be tested
    injection_priority: int = 5  # 1-10, higher = test first

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source.value,
            "type": self.param_type.value,
            "sample_value": self.sample_value,
            "is_required": self.is_required,
            "endpoint": self.endpoint,
            "method": self.method,
            "is_injectable": self.is_injectable,
            "injection_priority": self.injection_priority,
        }


@dataclass
class FormContext:
    """Context for a form including all fields."""
    action: str
    method: str
    enctype: str = "application/x-www-form-urlencoded"
    parameters: List[DiscoveredParameter] = field(default_factory=list)
    submit_button: Optional[str] = None
    submit_value: Optional[str] = None
    csrf_field: Optional[str] = None
    csrf_value: Optional[str] = None

    def get_base_data(self) -> Dict[str, str]:
        """Get form data with default values (for testing one param at a time)."""
        data = {}
        for param in self.parameters:
            if param.default_value:
                data[param.name] = param.default_value
            elif param.sample_value:
                data[param.name] = param.sample_value
            elif param.is_required:
                # Generate placeholder based on type
                data[param.name] = self._generate_placeholder(param)

        # Always include submit button if present
        if self.submit_button and self.submit_value:
            data[self.submit_button] = self.submit_value

        return data

    def _generate_placeholder(self, param: DiscoveredParameter) -> str:
        """Generate a valid placeholder value for a parameter."""
        type_placeholders = {
            ParameterType.INTEGER: "1",
            ParameterType.FLOAT: "1.0",
            ParameterType.BOOLEAN: "true",
            ParameterType.EMAIL: "test@example.com",
            ParameterType.URL: "http://example.com",
            ParameterType.DATE: "2024-01-01",
            ParameterType.ID: "1",
        }
        return type_placeholders.get(param.param_type, "test")


class DeepParameterDiscovery:
    """
    Multi-layer parameter discovery engine.

    Extracts parameters from:
    1. URL query strings
    2. URL path segments (RESTful IDs)
    3. HTML forms (visible, hidden, select, textarea)
    4. JSON request bodies
    5. XML request bodies
    6. JavaScript code
    7. API specifications (OpenAPI/Swagger)
    8. Response reflection
    """

    # Patterns for extracting parameters from JavaScript
    JS_PARAM_PATTERNS = [
        # AJAX/Fetch parameters
        r'(?:fetch|axios|ajax)\s*\([^)]*\{[^}]*(?:params|data|body)\s*:\s*\{([^}]+)\}',
        r'\.(?:get|post|put|delete|patch)\s*\([^,]+,\s*\{([^}]+)\}',

        # URL building
        r'["\'](?:\/[\w-]+)+\/?\?([^"\']+)["\']',
        r'`[^`]*\$\{([^}]+)\}[^`]*`',  # Template literals

        # FormData
        r'\.append\s*\(\s*["\'](\w+)["\']',

        # Object properties that look like params
        r'(?:params|data|payload|body|request)\s*[=:]\s*\{([^}]+)\}',

        # Query string building
        r'(?:URLSearchParams|queryString|qs)\s*\([^)]*\)',
        r'["\'](\w+)["\']\s*:\s*["\']?[^,}]+["\']?',
    ]

    # Patterns for hidden/dynamic form fields
    FORM_FIELD_PATTERNS = [
        r'<input[^>]+name=["\']([^"\']+)["\'][^>]*>',
        r'<select[^>]+name=["\']([^"\']+)["\'][^>]*>',
        r'<textarea[^>]+name=["\']([^"\']+)["\'][^>]*>',
    ]

    # Fields that should NOT be tested (security tokens, etc.)
    NON_INJECTABLE_FIELDS = {
        "csrf", "csrf_token", "_csrf", "csrftoken", "csrfmiddlewaretoken",
        "_token", "authenticity_token", "__requestverificationtoken",
        "user_token", "security", "nonce", "state",
        "captcha", "recaptcha", "g-recaptcha-response",
        "honeypot", "timestamp", "signature", "sig",
    }

    # High-priority injection targets
    HIGH_PRIORITY_PARAMS = {
        "id", "user_id", "userid", "uid", "account_id",
        "page", "file", "path", "url", "redirect", "return",
        "query", "search", "q", "keyword", "term",
        "name", "username", "email", "password",
        "cmd", "exec", "command", "run",
        "template", "tpl", "view", "render",
        "sort", "order", "orderby", "sortby",
        "filter", "where", "limit", "offset",
        "callback", "jsonp", "func", "function",
    }

    def __init__(self):
        self._discovered: Dict[str, List[DiscoveredParameter]] = {}
        self._forms: Dict[str, FormContext] = {}
        self._js_routes: List[str] = []

    def discover_from_url(self, url: str, method: str = "GET") -> List[DiscoveredParameter]:
        """Extract parameters from URL."""
        params = []
        parsed = urlparse(url)

        # Query parameters
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        for name, values in query_params.items():
            value = values[0] if values else None
            params.append(DiscoveredParameter(
                name=name,
                source=ParameterSource.URL_QUERY,
                param_type=self._infer_type(value),
                sample_value=value,
                endpoint=url,
                method=method,
                injection_priority=self._get_priority(name),
                is_injectable=self._is_injectable(name),
            ))

        # Path parameters (RESTful IDs)
        path_params = self._extract_path_params(parsed.path)
        for name, value in path_params:
            params.append(DiscoveredParameter(
                name=name,
                source=ParameterSource.URL_PATH,
                param_type=self._infer_type(value),
                sample_value=value,
                endpoint=url,
                method=method,
                injection_priority=8,  # Path params are often high value
                is_injectable=True,
            ))

        return params

    def discover_from_html(self, html: str, base_url: str) -> Tuple[List[DiscoveredParameter], List[FormContext]]:
        """Extract parameters from HTML forms."""
        params = []
        forms = []

        # Find all forms
        form_pattern = r'<form[^>]*>(.*?)</form>'
        for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(0)
            form_content = form_match.group(1)

            # Extract form attributes
            action = self._extract_attr(form_html, 'action') or base_url
            method = self._extract_attr(form_html, 'method') or 'GET'
            enctype = self._extract_attr(form_html, 'enctype') or 'application/x-www-form-urlencoded'

            form_ctx = FormContext(
                action=self._resolve_url(base_url, action),
                method=method.upper(),
                enctype=enctype,
            )

            # Extract all input fields
            for input_match in re.finditer(
                r'<input([^>]*)>', form_content, re.IGNORECASE
            ):
                attrs = input_match.group(1)
                name = self._extract_attr_from_str(attrs, 'name')
                if not name:
                    continue

                input_type = self._extract_attr_from_str(attrs, 'type') or 'text'
                value = self._extract_attr_from_str(attrs, 'value')
                required = 'required' in attrs.lower()

                # Determine source based on type
                if input_type == 'hidden':
                    source = ParameterSource.FORM_HIDDEN
                elif input_type == 'file':
                    source = ParameterSource.MULTIPART
                    form_ctx.enctype = 'multipart/form-data'
                else:
                    source = ParameterSource.FORM_VISIBLE

                # Check for CSRF token
                if name.lower() in self.NON_INJECTABLE_FIELDS:
                    form_ctx.csrf_field = name
                    form_ctx.csrf_value = value

                # Check for submit button
                if input_type == 'submit':
                    form_ctx.submit_button = name
                    form_ctx.submit_value = value or 'Submit'
                    continue

                param = DiscoveredParameter(
                    name=name,
                    source=source,
                    param_type=self._infer_type_from_input(input_type, name, value),
                    sample_value=value,
                    default_value=value,
                    is_required=required,
                    endpoint=form_ctx.action,
                    method=form_ctx.method,
                    injection_priority=self._get_priority(name),
                    is_injectable=self._is_injectable(name),
                )
                params.append(param)
                form_ctx.parameters.append(param)

            # Extract select fields
            for select_match in re.finditer(
                r'<select[^>]*name=["\']([^"\']+)["\'][^>]*>(.*?)</select>',
                form_content, re.DOTALL | re.IGNORECASE
            ):
                name = select_match.group(1)
                select_content = select_match.group(2)

                # Get first option value as sample
                option_match = re.search(r'<option[^>]*value=["\']([^"\']*)["\']', select_content)
                value = option_match.group(1) if option_match else None

                param = DiscoveredParameter(
                    name=name,
                    source=ParameterSource.FORM_SELECT,
                    param_type=ParameterType.STRING,
                    sample_value=value,
                    default_value=value,
                    endpoint=form_ctx.action,
                    method=form_ctx.method,
                    injection_priority=self._get_priority(name),
                    is_injectable=self._is_injectable(name),
                )
                params.append(param)
                form_ctx.parameters.append(param)

            # Extract textarea fields
            for textarea_match in re.finditer(
                r'<textarea[^>]*name=["\']([^"\']+)["\'][^>]*>(.*?)</textarea>',
                form_content, re.DOTALL | re.IGNORECASE
            ):
                name = textarea_match.group(1)
                value = textarea_match.group(2).strip()

                param = DiscoveredParameter(
                    name=name,
                    source=ParameterSource.FORM_TEXTAREA,
                    param_type=ParameterType.STRING,
                    sample_value=value if value else None,
                    endpoint=form_ctx.action,
                    method=form_ctx.method,
                    injection_priority=self._get_priority(name) + 2,  # Textareas often injectable
                    is_injectable=True,
                )
                params.append(param)
                form_ctx.parameters.append(param)

            forms.append(form_ctx)

        return params, forms

    def discover_from_javascript(self, js_code: str, base_url: str) -> List[DiscoveredParameter]:
        """Extract parameters from JavaScript code."""
        params = []
        seen_names: Set[str] = set()

        for pattern in self.JS_PARAM_PATTERNS:
            for match in re.finditer(pattern, js_code, re.IGNORECASE):
                content = match.group(1) if match.lastindex else match.group(0)

                # Extract key-value pairs
                kv_pattern = r'["\']?(\w+)["\']?\s*[=:]\s*["\']?([^"\',}\s]+)?["\']?'
                for kv_match in re.finditer(kv_pattern, content):
                    name = kv_match.group(1)
                    value = kv_match.group(2) if kv_match.lastindex >= 2 else None

                    if name in seen_names:
                        continue
                    seen_names.add(name)

                    # Skip common JS keywords
                    if name.lower() in {'function', 'return', 'const', 'let', 'var', 'if', 'else', 'true', 'false'}:
                        continue

                    params.append(DiscoveredParameter(
                        name=name,
                        source=ParameterSource.JS_EXTRACTED,
                        param_type=self._infer_type(value),
                        sample_value=value,
                        endpoint=base_url,
                        method="POST",  # JS params often used in POST
                        injection_priority=self._get_priority(name),
                        is_injectable=self._is_injectable(name),
                    ))

        # Also extract API routes from JS
        self._extract_js_routes(js_code, base_url)

        return params

    def discover_from_json_body(self, json_str: str, endpoint: str, method: str = "POST") -> List[DiscoveredParameter]:
        """Extract parameters from JSON request body."""
        params = []

        try:
            data = json.loads(json_str)
            params.extend(self._extract_json_params(data, endpoint, method, ""))
        except json.JSONDecodeError:
            logger.debug(f"Failed to parse JSON: {json_str[:100]}")

        return params

    def discover_from_response_reflection(
        self,
        response: str,
        request_params: Dict[str, str],
        endpoint: str,
    ) -> List[DiscoveredParameter]:
        """
        Find parameters that are reflected in response (potential injection points).
        """
        params = []

        for name, value in request_params.items():
            if value and len(value) >= 3 and value in response:
                # Parameter value is reflected - high priority target
                params.append(DiscoveredParameter(
                    name=name,
                    source=ParameterSource.REFLECTED,
                    param_type=ParameterType.STRING,
                    sample_value=value,
                    endpoint=endpoint,
                    method="GET",
                    injection_priority=9,  # Reflected params are high priority
                    is_injectable=True,
                ))

        return params

    def discover_from_api_spec(self, spec: Dict[str, Any], base_url: str) -> List[DiscoveredParameter]:
        """Extract parameters from OpenAPI/Swagger specification."""
        params = []

        # Handle OpenAPI 3.x
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() not in {'get', 'post', 'put', 'patch', 'delete'}:
                    continue

                endpoint = f"{base_url.rstrip('/')}{path}"

                # Query/Path/Header parameters
                for param in details.get("parameters", []):
                    name = param.get("name")
                    if not name:
                        continue

                    in_type = param.get("in", "query")
                    source_map = {
                        "query": ParameterSource.URL_QUERY,
                        "path": ParameterSource.URL_PATH,
                        "header": ParameterSource.HEADER_CUSTOM,
                        "cookie": ParameterSource.COOKIE,
                    }

                    schema = param.get("schema", {})
                    param_type = self._openapi_type_to_param_type(schema.get("type"))

                    params.append(DiscoveredParameter(
                        name=name,
                        source=source_map.get(in_type, ParameterSource.URL_QUERY),
                        param_type=param_type,
                        sample_value=schema.get("example"),
                        is_required=param.get("required", False),
                        endpoint=endpoint,
                        method=method.upper(),
                        injection_priority=self._get_priority(name),
                        is_injectable=self._is_injectable(name),
                        constraints={
                            "min": schema.get("minimum"),
                            "max": schema.get("maximum"),
                            "pattern": schema.get("pattern"),
                            "enum": schema.get("enum"),
                        },
                    ))

                # Request body parameters
                request_body = details.get("requestBody", {})
                content = request_body.get("content", {})

                for content_type, content_spec in content.items():
                    schema = content_spec.get("schema", {})
                    properties = schema.get("properties", {})
                    required = schema.get("required", [])

                    source = ParameterSource.JSON_BODY
                    if "xml" in content_type:
                        source = ParameterSource.XML_BODY
                    elif "multipart" in content_type:
                        source = ParameterSource.MULTIPART

                    for prop_name, prop_schema in properties.items():
                        params.append(DiscoveredParameter(
                            name=prop_name,
                            source=source,
                            param_type=self._openapi_type_to_param_type(prop_schema.get("type")),
                            sample_value=prop_schema.get("example"),
                            is_required=prop_name in required,
                            endpoint=endpoint,
                            method=method.upper(),
                            injection_priority=self._get_priority(prop_name),
                            is_injectable=self._is_injectable(prop_name),
                        ))

        return params

    def get_all_parameters(self, endpoint: str = None) -> List[DiscoveredParameter]:
        """Get all discovered parameters, optionally filtered by endpoint."""
        all_params = []
        for ep, params in self._discovered.items():
            if endpoint is None or ep == endpoint:
                all_params.extend(params)
        return sorted(all_params, key=lambda p: -p.injection_priority)

    def get_forms(self, endpoint: str = None) -> List[FormContext]:
        """Get discovered forms."""
        if endpoint:
            return [f for f in self._forms.values() if f.action == endpoint]
        return list(self._forms.values())

    def get_js_routes(self) -> List[str]:
        """Get routes discovered from JavaScript."""
        return self._js_routes

    def add_parameters(self, params: List[DiscoveredParameter]) -> None:
        """Add discovered parameters to the store."""
        for param in params:
            endpoint = param.endpoint or "unknown"
            if endpoint not in self._discovered:
                self._discovered[endpoint] = []

            # Avoid duplicates
            existing_names = {p.name for p in self._discovered[endpoint]}
            if param.name not in existing_names:
                self._discovered[endpoint].append(param)

    def add_forms(self, forms: List[FormContext]) -> None:
        """Add discovered forms to the store."""
        for form in forms:
            key = f"{form.method}:{form.action}"
            if key not in self._forms:
                self._forms[key] = form

    def get_summary(self) -> Dict[str, Any]:
        """Get discovery summary."""
        all_params = self.get_all_parameters()

        by_source = {}
        for param in all_params:
            source = param.source.value
            by_source[source] = by_source.get(source, 0) + 1

        injectable = [p for p in all_params if p.is_injectable]
        high_priority = [p for p in injectable if p.injection_priority >= 7]

        return {
            "total_parameters": len(all_params),
            "injectable_parameters": len(injectable),
            "high_priority_parameters": len(high_priority),
            "by_source": by_source,
            "total_forms": len(self._forms),
            "total_endpoints": len(self._discovered),
            "js_routes_found": len(self._js_routes),
        }

    # === Private Methods ===

    def _extract_path_params(self, path: str) -> List[Tuple[str, str]]:
        """Extract parameters from URL path (e.g., /users/123 -> id=123)."""
        params = []
        segments = path.strip('/').split('/')

        for i, segment in enumerate(segments):
            # Check if segment looks like an ID
            if self._looks_like_id(segment):
                # Try to infer param name from previous segment
                prev_segment = segments[i-1] if i > 0 else "id"
                param_name = self._singularize(prev_segment) + "_id"
                params.append((param_name, segment))

        return params

    def _looks_like_id(self, value: str) -> bool:
        """Check if value looks like an ID."""
        if not value:
            return False
        # Numeric ID
        if value.isdigit():
            return True
        # UUID
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
            return True
        # Short hash
        if re.match(r'^[0-9a-f]{8,32}$', value, re.I):
            return True
        return False

    def _singularize(self, word: str) -> str:
        """Simple singularization (users -> user)."""
        if word.endswith('ies'):
            return word[:-3] + 'y'
        if word.endswith('es'):
            return word[:-2]
        if word.endswith('s') and not word.endswith('ss'):
            return word[:-1]
        return word

    def _infer_type(self, value: Optional[str]) -> ParameterType:
        """Infer parameter type from value."""
        if not value:
            return ParameterType.UNKNOWN

        # Check for common types
        if value.isdigit() or (value.startswith('-') and value[1:].isdigit()):
            return ParameterType.INTEGER
        if re.match(r'^-?\d+\.\d+$', value):
            return ParameterType.FLOAT
        if value.lower() in ('true', 'false', '0', '1'):
            return ParameterType.BOOLEAN
        if re.match(r'^[^@]+@[^@]+\.[^@]+$', value):
            return ParameterType.EMAIL
        if re.match(r'^https?://', value):
            return ParameterType.URL
        if re.match(r'^\d{4}-\d{2}-\d{2}', value):
            return ParameterType.DATE
        if self._looks_like_id(value):
            return ParameterType.ID
        if len(value) >= 20 and re.match(r'^[a-zA-Z0-9+/=_-]+$', value):
            return ParameterType.TOKEN

        return ParameterType.STRING

    def _infer_type_from_input(self, input_type: str, name: str, value: Optional[str]) -> ParameterType:
        """Infer type from HTML input attributes."""
        type_map = {
            'number': ParameterType.INTEGER,
            'email': ParameterType.EMAIL,
            'url': ParameterType.URL,
            'date': ParameterType.DATE,
            'datetime': ParameterType.DATE,
            'datetime-local': ParameterType.DATE,
            'file': ParameterType.FILE,
            'checkbox': ParameterType.BOOLEAN,
            'radio': ParameterType.STRING,
        }

        if input_type in type_map:
            return type_map[input_type]

        # Infer from name
        if 'id' in name.lower():
            return ParameterType.ID
        if 'email' in name.lower():
            return ParameterType.EMAIL
        if 'url' in name.lower() or 'link' in name.lower():
            return ParameterType.URL

        # Fallback to value inference
        return self._infer_type(value)

    def _is_injectable(self, name: str) -> bool:
        """Check if parameter should be tested for injection."""
        name_lower = name.lower()
        return name_lower not in self.NON_INJECTABLE_FIELDS

    def _get_priority(self, name: str) -> int:
        """Get injection priority for parameter."""
        name_lower = name.lower()

        # High priority targets
        if name_lower in self.HIGH_PRIORITY_PARAMS:
            return 9

        # Patterns that suggest high priority
        if any(x in name_lower for x in ['id', 'user', 'file', 'path', 'url', 'cmd', 'query', 'search']):
            return 8

        if any(x in name_lower for x in ['name', 'email', 'password', 'data', 'content', 'text']):
            return 7

        # Lower priority for common non-interesting params
        if any(x in name_lower for x in ['page', 'limit', 'offset', 'sort', 'order']):
            return 4

        return 5  # Default priority

    def _extract_attr(self, html: str, attr_name: str) -> Optional[str]:
        """Extract attribute value from HTML tag."""
        pattern = rf'{attr_name}\s*=\s*["\']([^"\']*)["\']'
        match = re.search(pattern, html, re.IGNORECASE)
        return match.group(1) if match else None

    def _extract_attr_from_str(self, attrs: str, attr_name: str) -> Optional[str]:
        """Extract attribute from attribute string."""
        return self._extract_attr(f"<x {attrs}>", attr_name)

    def _resolve_url(self, base: str, url: str) -> str:
        """Resolve relative URL against base."""
        if url.startswith('http'):
            return url
        if url.startswith('//'):
            return 'https:' + url
        if url.startswith('/'):
            parsed = urlparse(base)
            return f"{parsed.scheme}://{parsed.netloc}{url}"
        # Relative path
        base_path = base.rsplit('/', 1)[0]
        return f"{base_path}/{url}"

    def _extract_json_params(
        self,
        data: Any,
        endpoint: str,
        method: str,
        prefix: str
    ) -> List[DiscoveredParameter]:
        """Recursively extract parameters from JSON data."""
        params = []

        if isinstance(data, dict):
            for key, value in data.items():
                full_name = f"{prefix}.{key}" if prefix else key

                if isinstance(value, (dict, list)):
                    params.extend(self._extract_json_params(value, endpoint, method, full_name))
                else:
                    params.append(DiscoveredParameter(
                        name=full_name,
                        source=ParameterSource.JSON_BODY,
                        param_type=self._infer_type(str(value) if value is not None else None),
                        sample_value=str(value) if value is not None else None,
                        endpoint=endpoint,
                        method=method,
                        injection_priority=self._get_priority(key),
                        is_injectable=self._is_injectable(key),
                    ))

        elif isinstance(data, list) and data:
            # For arrays, extract params from first element
            params.extend(self._extract_json_params(data[0], endpoint, method, f"{prefix}[0]"))

        return params

    def _extract_js_routes(self, js_code: str, base_url: str) -> None:
        """Extract API routes from JavaScript code."""
        route_patterns = [
            r'["\']/(api|v\d+)/[^\s"\']+["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
            r'\.get\s*\(\s*["\']([^"\']+)["\']',
            r'\.post\s*\(\s*["\']([^"\']+)["\']',
            r'url\s*:\s*["\']([^"\']+)["\']',
            r'endpoint\s*:\s*["\']([^"\']+)["\']',
        ]

        for pattern in route_patterns:
            for match in re.finditer(pattern, js_code, re.IGNORECASE):
                route = match.group(1) if match.lastindex else match.group(0)
                route = route.strip('"\'')

                if route.startswith('/'):
                    full_url = self._resolve_url(base_url, route)
                    if full_url not in self._js_routes:
                        self._js_routes.append(full_url)

    def _openapi_type_to_param_type(self, openapi_type: Optional[str]) -> ParameterType:
        """Convert OpenAPI type to ParameterType."""
        type_map = {
            'string': ParameterType.STRING,
            'integer': ParameterType.INTEGER,
            'number': ParameterType.FLOAT,
            'boolean': ParameterType.BOOLEAN,
            'array': ParameterType.ARRAY,
            'object': ParameterType.OBJECT,
        }
        return type_map.get(openapi_type, ParameterType.UNKNOWN)


# === Convenience Functions ===

_global_discovery: Optional[DeepParameterDiscovery] = None


def get_parameter_discovery() -> DeepParameterDiscovery:
    """Get or create global parameter discovery instance."""
    global _global_discovery
    if _global_discovery is None:
        _global_discovery = DeepParameterDiscovery()
    return _global_discovery


def reset_parameter_discovery() -> None:
    """Reset parameter discovery for new scan."""
    global _global_discovery
    _global_discovery = DeepParameterDiscovery()
