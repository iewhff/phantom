"""
PHANTOM AI - Parameter Analyzer (Enterprise Edition)

Advanced parameter analysis engine for deep inspection of:
- Parameter type inference (string, integer, boolean, array, object, etc.)
- Injection potential scoring (0.0-1.0)
- Context-aware payload suggestions
- Reflection detection
- Response behavior analysis
- Parameter relationship mapping

Features:
- Multi-source parameter extraction (query, body, headers, cookies, path)
- Type inference with confidence scoring
- Vulnerability context analysis
- Payload prioritization based on context
- Reflection detection across response

Usage:
    from phantom.parameter_analyzer import ParameterAnalyzer, get_parameter_analyzer

    analyzer = get_parameter_analyzer()
    result = await analyzer.analyze(target_url, endpoint_path)

    for param in result.parameters:
        print(f"{param.name}: {param.inferred_type} - Injection: {param.injection_potential}")
        print(f"  Suggested payloads: {param.suggested_payload_categories}")

Author: PHANTOM AI Team
Version: 3.0.0 Enterprise
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import string
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple, Pattern
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import httpx

from utils.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# ENUMS AND DATA CLASSES
# =============================================================================

class ParameterLocation(Enum):
    """Where the parameter is located in the request."""
    QUERY = "query"           # URL query string (?param=value)
    BODY_FORM = "body_form"   # Form data (POST body)
    BODY_JSON = "body_json"   # JSON body
    BODY_XML = "body_xml"     # XML body
    PATH = "path"             # URL path segment (/users/{id})
    HEADER = "header"         # HTTP header
    COOKIE = "cookie"         # Cookie value
    FRAGMENT = "fragment"     # URL fragment (#param)


class InferredType(Enum):
    """Inferred data type of parameter."""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    EMAIL = "email"
    URL = "url"
    UUID = "uuid"
    DATE = "date"
    DATETIME = "datetime"
    JSON = "json"
    BASE64 = "base64"
    JWT = "jwt"
    HTML = "html"
    FILENAME = "filename"
    PATH = "path"
    IP_ADDRESS = "ip_address"
    PHONE = "phone"
    CREDIT_CARD = "credit_card"
    ARRAY = "array"
    OBJECT = "object"
    BINARY = "binary"
    UNKNOWN = "unknown"


class VulnerabilityContext(Enum):
    """Potential vulnerability context for the parameter."""
    SQL_INJECTION = "sqli"
    NOSQL_INJECTION = "nosqli"
    COMMAND_INJECTION = "cmdi"
    XSS = "xss"
    SSRF = "ssrf"
    LFI = "lfi"
    PATH_TRAVERSAL = "path_traversal"
    LDAP_INJECTION = "ldap"
    XPATH_INJECTION = "xpath"
    XXE = "xxe"
    SSTI = "ssti"
    IDOR = "idor"
    OPEN_REDIRECT = "open_redirect"
    JWT_ATTACK = "jwt"
    DESERIALIZATION = "deserialization"
    HTTP_HEADER_INJECTION = "header_injection"
    CRLF_INJECTION = "crlf"
    HOST_HEADER = "host_header"
    RACE_CONDITION = "race_condition"


class ReflectionType(Enum):
    """How the parameter value is reflected in the response."""
    NOT_REFLECTED = "not_reflected"
    HTML_BODY = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    JAVASCRIPT = "javascript"
    JSON_RESPONSE = "json_response"
    HTTP_HEADER = "http_header"
    SET_COOKIE = "set_cookie"
    REDIRECT = "redirect"
    ERROR_MESSAGE = "error_message"


@dataclass
class ParameterConstraint:
    """Discovered constraints on parameter values."""
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    pattern: Optional[str] = None
    enum_values: List[str] = field(default_factory=list)
    required: bool = False
    allows_null: bool = False
    allows_empty: bool = True


@dataclass
class ReflectionResult:
    """Result of reflection detection."""
    is_reflected: bool = False
    reflection_type: ReflectionType = ReflectionType.NOT_REFLECTED
    reflection_context: str = ""
    is_encoded: bool = False
    encoding_type: str = ""  # html, url, base64, etc.
    is_filtered: bool = False
    filtered_chars: List[str] = field(default_factory=list)
    injection_point: str = ""  # Where exactly it reflects


@dataclass
class AnalyzedParameter:
    """A fully analyzed parameter with all metadata."""
    name: str
    location: ParameterLocation
    original_value: str = ""

    # Type inference
    inferred_type: InferredType = InferredType.UNKNOWN
    type_confidence: float = 0.0  # 0.0-1.0

    # Injection potential
    injection_potential: float = 0.0  # 0.0-1.0
    vulnerability_contexts: List[VulnerabilityContext] = field(default_factory=list)

    # Payload suggestions
    suggested_payload_categories: List[str] = field(default_factory=list)
    priority_score: float = 0.0  # 0.0-1.0 (higher = test first)

    # Reflection
    reflection: Optional[ReflectionResult] = None

    # Constraints
    constraints: Optional[ParameterConstraint] = None

    # Behavior
    affects_output: bool = False
    affects_behavior: bool = False
    is_security_relevant: bool = False

    # Relationships
    related_parameters: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "location": self.location.value,
            "original_value": self.original_value[:50] if self.original_value else "",
            "inferred_type": self.inferred_type.value,
            "type_confidence": round(self.type_confidence, 2),
            "injection_potential": round(self.injection_potential, 2),
            "vulnerability_contexts": [v.value for v in self.vulnerability_contexts],
            "suggested_payload_categories": self.suggested_payload_categories,
            "priority_score": round(self.priority_score, 2),
            "is_reflected": self.reflection.is_reflected if self.reflection else False,
            "is_security_relevant": self.is_security_relevant,
        }


@dataclass
class AnalysisResult:
    """Complete parameter analysis result for an endpoint."""
    endpoint: str
    method: str = "GET"
    parameters: List[AnalyzedParameter] = field(default_factory=list)

    # Summary scores
    total_injection_potential: float = 0.0
    high_priority_count: int = 0
    reflected_count: int = 0
    security_relevant_count: int = 0

    # Detected contexts
    potential_vulnerabilities: List[VulnerabilityContext] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "parameters": [p.to_dict() for p in self.parameters],
            "total_injection_potential": round(self.total_injection_potential, 2),
            "high_priority_count": self.high_priority_count,
            "reflected_count": self.reflected_count,
            "security_relevant_count": self.security_relevant_count,
            "potential_vulnerabilities": [v.value for v in self.potential_vulnerabilities],
        }

    def get_high_priority_params(self, threshold: float = 0.7) -> List[AnalyzedParameter]:
        """Get parameters above priority threshold."""
        return [p for p in self.parameters if p.priority_score >= threshold]

    def get_by_context(self, context: VulnerabilityContext) -> List[AnalyzedParameter]:
        """Get parameters relevant to a specific vulnerability context."""
        return [p for p in self.parameters if context in p.vulnerability_contexts]


# =============================================================================
# TYPE INFERENCE PATTERNS
# =============================================================================

class TypePatterns:
    """Patterns for type inference."""

    # Email pattern
    EMAIL = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

    # URL patterns
    URL = re.compile(r'^https?://[^\s/$.?#].[^\s]*$', re.IGNORECASE)
    URL_PATH = re.compile(r'^/[a-zA-Z0-9/_.-]*$')

    # UUID pattern
    UUID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)

    # Date patterns
    DATE_ISO = re.compile(r'^\d{4}-\d{2}-\d{2}$')
    DATETIME_ISO = re.compile(r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}')

    # JWT pattern
    JWT = re.compile(r'^eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$')

    # Base64 pattern
    BASE64 = re.compile(r'^[A-Za-z0-9+/]+=*$')

    # Numeric patterns
    INTEGER = re.compile(r'^-?\d+$')
    FLOAT = re.compile(r'^-?\d+\.\d+$')

    # Boolean
    BOOLEAN = re.compile(r'^(true|false|0|1|yes|no|on|off)$', re.IGNORECASE)

    # IP Address
    IPV4 = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    IPV6 = re.compile(r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')

    # Phone
    PHONE = re.compile(r'^\+?[\d\s-]{10,}$')

    # Filename
    FILENAME = re.compile(r'^[a-zA-Z0-9_.-]+\.[a-zA-Z0-9]+$')

    # Path
    UNIX_PATH = re.compile(r'^(/[^/\0]+)+/?$')
    WINDOWS_PATH = re.compile(r'^[a-zA-Z]:\\[^<>:"|?*]*$')

    # Credit card (basic Luhn check needed separately)
    CREDIT_CARD = re.compile(r'^\d{13,19}$')


# =============================================================================
# PARAMETER NAME ANALYSIS
# =============================================================================

class ParameterNameAnalyzer:
    """Analyze parameter names to infer purpose and vulnerability context."""

    # SQL-related parameter names
    SQL_NAMES = {
        'id', 'user_id', 'userid', 'uid', 'pid', 'cid', 'order_id',
        'orderid', 'item_id', 'itemid', 'product_id', 'productid',
        'category_id', 'categoryid', 'page', 'offset', 'limit',
        'sort', 'order', 'orderby', 'sortby', 'filter', 'where',
        'column', 'table', 'field', 'select', 'from', 'group',
    }

    # XSS-related parameter names
    XSS_NAMES = {
        'name', 'username', 'user', 'title', 'description', 'desc',
        'comment', 'message', 'msg', 'content', 'body', 'text',
        'query', 'q', 'search', 's', 'keyword', 'keywords', 'term',
        'value', 'input', 'data', 'output', 'result', 'response',
        'error', 'success', 'warning', 'info', 'alert', 'label',
        'placeholder', 'hint', 'tooltip', 'bio', 'about', 'summary',
        'review', 'feedback', 'note', 'notes', 'status',
    }

    # SSRF/URL-related parameter names
    SSRF_NAMES = {
        'url', 'uri', 'link', 'href', 'src', 'source', 'target',
        'dest', 'destination', 'redirect', 'redirect_uri', 'redirect_url',
        'return', 'return_url', 'returnto', 'next', 'nexturl', 'goto',
        'callback', 'callback_url', 'continue', 'continueurl', 'forward',
        'to', 'rurl', 'domain', 'host', 'proxy', 'fetch', 'load',
        'image', 'img', 'icon', 'avatar', 'photo', 'picture', 'preview',
        'feed', 'rss', 'api', 'endpoint', 'webhook', 'postback',
    }

    # File/Path-related parameter names
    PATH_NAMES = {
        'file', 'filename', 'filepath', 'path', 'dir', 'directory',
        'folder', 'doc', 'document', 'pdf', 'download', 'upload',
        'attachment', 'template', 'view', 'include', 'require', 'read',
        'load', 'import', 'export', 'backup', 'log', 'logfile',
        'config', 'configuration', 'settings', 'ini', 'conf',
    }

    # Command injection-related parameter names
    CMD_NAMES = {
        'cmd', 'command', 'exec', 'execute', 'run', 'shell', 'bash',
        'ping', 'nslookup', 'dig', 'host', 'ip', 'process', 'daemon',
        'service', 'action', 'do', 'operation', 'script', 'batch',
        'job', 'task', 'cron', 'schedule', 'args', 'arguments', 'params',
        'options', 'flags', 'env', 'environment', 'var', 'variable',
    }

    # Auth-related parameter names
    AUTH_NAMES = {
        'password', 'passwd', 'pwd', 'pass', 'secret', 'token',
        'api_key', 'apikey', 'key', 'auth', 'authorization',
        'session', 'sessionid', 'sid', 'csrf', 'xsrf', 'nonce',
        'otp', 'code', 'pin', 'credential', 'credentials',
    }

    # IDOR-related parameter names
    IDOR_NAMES = {
        'id', 'user_id', 'userid', 'uid', 'account_id', 'accountid',
        'profile_id', 'profileid', 'order_id', 'orderid', 'transaction_id',
        'invoice_id', 'invoiceid', 'document_id', 'documentid', 'file_id',
        'fileid', 'record_id', 'recordid', 'ref', 'reference', 'number',
        'num', 'no', 'index', 'idx', 'seq', 'sequence',
    }

    @classmethod
    def analyze_name(cls, name: str) -> Tuple[List[VulnerabilityContext], float]:
        """
        Analyze parameter name to determine potential vulnerability contexts.

        Returns:
            Tuple of (vulnerability_contexts, base_injection_potential)
        """
        name_lower = name.lower().strip()
        contexts = []
        potential = 0.0

        # Check SQL injection potential
        if name_lower in cls.SQL_NAMES or any(s in name_lower for s in ['_id', 'id_', 'order', 'sort', 'filter']):
            contexts.append(VulnerabilityContext.SQL_INJECTION)
            potential = max(potential, 0.7)

        # Check XSS potential
        if name_lower in cls.XSS_NAMES or any(s in name_lower for s in ['name', 'text', 'content', 'message', 'search', 'query']):
            contexts.append(VulnerabilityContext.XSS)
            potential = max(potential, 0.6)

        # Check SSRF potential
        if name_lower in cls.SSRF_NAMES or any(s in name_lower for s in ['url', 'uri', 'link', 'src', 'redirect', 'callback']):
            contexts.append(VulnerabilityContext.SSRF)
            contexts.append(VulnerabilityContext.OPEN_REDIRECT)
            potential = max(potential, 0.8)

        # Check path traversal potential
        if name_lower in cls.PATH_NAMES or any(s in name_lower for s in ['file', 'path', 'dir', 'template', 'include']):
            contexts.append(VulnerabilityContext.LFI)
            contexts.append(VulnerabilityContext.PATH_TRAVERSAL)
            potential = max(potential, 0.75)

        # Check command injection potential
        if name_lower in cls.CMD_NAMES or any(s in name_lower for s in ['cmd', 'exec', 'run', 'shell', 'command']):
            contexts.append(VulnerabilityContext.COMMAND_INJECTION)
            potential = max(potential, 0.85)

        # Check IDOR potential
        if name_lower in cls.IDOR_NAMES:
            contexts.append(VulnerabilityContext.IDOR)
            potential = max(potential, 0.6)

        # Check auth parameters (lower potential as they're usually protected)
        if name_lower in cls.AUTH_NAMES:
            potential = max(potential, 0.4)

        # Default potential for unknown names
        if not contexts:
            potential = 0.3

        return contexts, potential


# =============================================================================
# PARAMETER ANALYZER ENGINE
# =============================================================================

class ParameterAnalyzer:
    """
    Advanced Parameter Analysis Engine.

    Performs deep analysis of HTTP parameters to:
    1. Infer data types with confidence scoring
    2. Calculate injection potential (0.0-1.0)
    3. Suggest appropriate payload categories
    4. Detect parameter reflection
    5. Map parameter relationships

    Usage:
        analyzer = ParameterAnalyzer()
        result = await analyzer.analyze("https://example.com", "/api/users")

        for param in result.parameters:
            print(f"{param.name}: injection_potential={param.injection_potential}")
    """

    VERSION = "3.0.0"

    def __init__(self, http_client: Optional[httpx.AsyncClient] = None):
        self._client = http_client
        self._owns_client = http_client is None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=15.0,
                verify=False,
                follow_redirects=True,
            )
        return self._client

    async def close(self) -> None:
        """Close HTTP client if we own it."""
        if self._owns_client and self._client:
            await self._client.aclose()
            self._client = None

    async def analyze(
        self,
        base_url: str,
        endpoint: str,
        method: str = "GET",
        sample_params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        test_reflection: bool = True,
        test_behavior: bool = False,
    ) -> AnalysisResult:
        """
        Analyze parameters for an endpoint.

        Args:
            base_url: Base URL of the target
            endpoint: Endpoint path (e.g., /api/users)
            method: HTTP method
            sample_params: Sample parameter values to analyze
            headers: Additional headers for requests
            test_reflection: Whether to test for parameter reflection
            test_behavior: Whether to test parameter behavior (more requests)

        Returns:
            AnalysisResult with analyzed parameters
        """
        result = AnalysisResult(endpoint=endpoint, method=method.upper())

        # Extract parameters from endpoint (path params and query string)
        extracted_params = self._extract_parameters(endpoint)

        # Merge with provided sample params
        if sample_params:
            for name, value in sample_params.items():
                if name not in extracted_params:
                    extracted_params[name] = {
                        "value": value,
                        "location": ParameterLocation.QUERY,
                    }

        # Analyze each parameter
        for name, param_info in extracted_params.items():
            analyzed = await self._analyze_parameter(
                name=name,
                value=param_info.get("value", ""),
                location=param_info.get("location", ParameterLocation.QUERY),
                base_url=base_url,
                endpoint=endpoint,
                method=method,
                headers=headers,
                test_reflection=test_reflection,
                test_behavior=test_behavior,
            )
            result.parameters.append(analyzed)

        # Calculate summary scores
        self._calculate_summary(result)

        return result

    def _extract_parameters(self, endpoint: str) -> Dict[str, Dict[str, Any]]:
        """Extract parameters from endpoint path and query string."""
        params = {}

        # Parse URL
        parsed = urlparse(endpoint)

        # Extract query parameters
        query_params = parse_qs(parsed.query)
        for name, values in query_params.items():
            params[name] = {
                "value": values[0] if values else "",
                "location": ParameterLocation.QUERY,
            }

        # Extract path parameters (e.g., /users/{id})
        path_param_pattern = re.compile(r'\{([^}]+)\}')
        for match in path_param_pattern.finditer(parsed.path):
            param_name = match.group(1)
            params[param_name] = {
                "value": "",
                "location": ParameterLocation.PATH,
            }

        # Also look for common path patterns like /users/123
        path_parts = parsed.path.strip('/').split('/')
        for i, part in enumerate(path_parts):
            if part.isdigit() or TypePatterns.UUID.match(part):
                # Infer parameter name from previous part
                if i > 0:
                    param_name = f"{path_parts[i-1]}_id"
                else:
                    param_name = "id"
                params[param_name] = {
                    "value": part,
                    "location": ParameterLocation.PATH,
                }

        return params

    async def _analyze_parameter(
        self,
        name: str,
        value: str,
        location: ParameterLocation,
        base_url: str,
        endpoint: str,
        method: str,
        headers: Optional[Dict[str, str]],
        test_reflection: bool,
        test_behavior: bool,
    ) -> AnalyzedParameter:
        """Perform deep analysis of a single parameter."""

        # Initialize
        analyzed = AnalyzedParameter(
            name=name,
            location=location,
            original_value=value,
        )

        # 1. Infer type from value
        if value:
            analyzed.inferred_type, analyzed.type_confidence = self._infer_type(value)

        # 2. Analyze name for vulnerability context
        contexts, base_potential = ParameterNameAnalyzer.analyze_name(name)
        analyzed.vulnerability_contexts = contexts
        analyzed.injection_potential = base_potential

        # 3. Adjust injection potential based on type
        analyzed.injection_potential = self._adjust_potential_by_type(
            analyzed.injection_potential,
            analyzed.inferred_type,
            contexts
        )

        # 4. Suggest payload categories
        analyzed.suggested_payload_categories = self._suggest_payloads(
            analyzed.inferred_type,
            contexts,
            location
        )

        # 5. Test reflection if enabled
        if test_reflection:
            try:
                analyzed.reflection = await self._test_reflection(
                    base_url=base_url,
                    endpoint=endpoint,
                    param_name=name,
                    param_location=location,
                    method=method,
                    headers=headers,
                )
                if analyzed.reflection and analyzed.reflection.is_reflected:
                    # Boost injection potential for reflected params
                    analyzed.injection_potential = min(1.0, analyzed.injection_potential + 0.2)
                    if VulnerabilityContext.XSS not in analyzed.vulnerability_contexts:
                        analyzed.vulnerability_contexts.append(VulnerabilityContext.XSS)
            except Exception as e:
                logger.debug(f"[ParameterAnalyzer] Reflection test failed for {name}: {e}")

        # 6. Determine if security relevant
        analyzed.is_security_relevant = self._is_security_relevant(
            name, location, contexts
        )

        # 7. Calculate priority score
        analyzed.priority_score = self._calculate_priority(analyzed)

        return analyzed

    def _infer_type(self, value: str) -> Tuple[InferredType, float]:
        """Infer type from parameter value."""
        if not value:
            return InferredType.UNKNOWN, 0.0

        # Try patterns in order of specificity
        checks = [
            (TypePatterns.JWT.match(value), InferredType.JWT, 0.95),
            (TypePatterns.UUID.match(value), InferredType.UUID, 0.95),
            (TypePatterns.EMAIL.match(value), InferredType.EMAIL, 0.9),
            (TypePatterns.DATETIME_ISO.match(value), InferredType.DATETIME, 0.9),
            (TypePatterns.DATE_ISO.match(value), InferredType.DATE, 0.9),
            (TypePatterns.IPV4.match(value), InferredType.IP_ADDRESS, 0.9),
            (TypePatterns.IPV6.match(value), InferredType.IP_ADDRESS, 0.9),
            (TypePatterns.URL.match(value), InferredType.URL, 0.85),
            (TypePatterns.URL_PATH.match(value), InferredType.PATH, 0.7),
            (TypePatterns.FILENAME.match(value), InferredType.FILENAME, 0.75),
            (TypePatterns.CREDIT_CARD.match(value), InferredType.CREDIT_CARD, 0.6),
            (TypePatterns.PHONE.match(value), InferredType.PHONE, 0.6),
            (TypePatterns.BOOLEAN.match(value), InferredType.BOOLEAN, 0.9),
            (TypePatterns.FLOAT.match(value), InferredType.FLOAT, 0.95),
            (TypePatterns.INTEGER.match(value), InferredType.INTEGER, 0.95),
        ]

        for match, inf_type, confidence in checks:
            if match:
                return inf_type, confidence

        # Check if it looks like JSON
        if value.startswith(('{', '[')):
            try:
                json.loads(value)
                return InferredType.JSON, 0.85
            except json.JSONDecodeError:
                pass

        # Check if it looks like base64
        if len(value) >= 4 and len(value) % 4 == 0:
            if TypePatterns.BASE64.match(value):
                return InferredType.BASE64, 0.6

        # Check if it contains HTML
        if '<' in value and '>' in value:
            return InferredType.HTML, 0.7

        # Default to string
        return InferredType.STRING, 0.5

    def _adjust_potential_by_type(
        self,
        base_potential: float,
        inferred_type: InferredType,
        contexts: List[VulnerabilityContext],
    ) -> float:
        """Adjust injection potential based on inferred type."""
        potential = base_potential

        # Higher potential for certain types
        high_risk_types = {
            InferredType.STRING: 0.1,
            InferredType.URL: 0.2,
            InferredType.PATH: 0.2,
            InferredType.FILENAME: 0.2,
            InferredType.HTML: 0.3,
            InferredType.JSON: 0.15,
        }

        # Lower potential for well-typed values
        low_risk_types = {
            InferredType.UUID: -0.2,
            InferredType.INTEGER: -0.1,
            InferredType.BOOLEAN: -0.3,
            InferredType.EMAIL: -0.1,
            InferredType.DATE: -0.2,
            InferredType.DATETIME: -0.2,
        }

        if inferred_type in high_risk_types:
            potential += high_risk_types[inferred_type]
        elif inferred_type in low_risk_types:
            potential += low_risk_types[inferred_type]

        # Boost for specific type/context combinations
        if inferred_type == InferredType.URL and VulnerabilityContext.SSRF in contexts:
            potential += 0.2
        if inferred_type == InferredType.PATH and VulnerabilityContext.LFI in contexts:
            potential += 0.2
        if inferred_type == InferredType.INTEGER and VulnerabilityContext.SQL_INJECTION in contexts:
            potential += 0.1

        return max(0.0, min(1.0, potential))

    def _suggest_payloads(
        self,
        inferred_type: InferredType,
        contexts: List[VulnerabilityContext],
        location: ParameterLocation,
    ) -> List[str]:
        """Suggest payload categories based on analysis."""
        suggestions = []

        # Map contexts to payload categories
        context_payloads = {
            VulnerabilityContext.SQL_INJECTION: ["sqli_generic", "sqli_time_based", "sqli_error_based"],
            VulnerabilityContext.NOSQL_INJECTION: ["nosqli_mongodb", "nosqli_json"],
            VulnerabilityContext.XSS: ["xss_basic", "xss_dom", "xss_polyglot"],
            VulnerabilityContext.COMMAND_INJECTION: ["cmdi_linux", "cmdi_windows", "cmdi_time_based"],
            VulnerabilityContext.SSRF: ["ssrf_internal", "ssrf_cloud_metadata", "ssrf_dns"],
            VulnerabilityContext.LFI: ["lfi_linux", "lfi_windows", "lfi_wrapper"],
            VulnerabilityContext.PATH_TRAVERSAL: ["path_traversal_simple", "path_traversal_encoded"],
            VulnerabilityContext.SSTI: ["ssti_jinja2", "ssti_twig", "ssti_generic"],
            VulnerabilityContext.XXE: ["xxe_oob", "xxe_error", "xxe_file"],
            VulnerabilityContext.LDAP_INJECTION: ["ldap_basic"],
            VulnerabilityContext.OPEN_REDIRECT: ["open_redirect_basic", "open_redirect_bypass"],
            VulnerabilityContext.IDOR: ["idor_numeric", "idor_uuid"],
        }

        for context in contexts:
            if context in context_payloads:
                suggestions.extend(context_payloads[context])

        # Add type-specific suggestions
        type_payloads = {
            InferredType.INTEGER: ["integer_overflow", "negative_numbers"],
            InferredType.JSON: ["json_injection", "prototype_pollution"],
            InferredType.JWT: ["jwt_none_algorithm", "jwt_weak_secret"],
            InferredType.BASE64: ["base64_deserialization"],
            InferredType.XML: ["xxe_basic"],
        }

        if inferred_type in type_payloads:
            suggestions.extend(type_payloads[inferred_type])

        # Add location-specific suggestions
        if location == ParameterLocation.HEADER:
            suggestions.extend(["header_injection", "crlf_injection"])
        elif location == ParameterLocation.COOKIE:
            suggestions.extend(["cookie_injection", "session_fixation"])

        return list(set(suggestions))  # Remove duplicates

    async def _test_reflection(
        self,
        base_url: str,
        endpoint: str,
        param_name: str,
        param_location: ParameterLocation,
        method: str,
        headers: Optional[Dict[str, str]],
    ) -> ReflectionResult:
        """Test if parameter value is reflected in response."""
        result = ReflectionResult()

        # Generate unique test value
        test_value = f"PHANTOM_REFLECT_{secrets.token_hex(8)}"

        try:
            client = await self._get_client()

            # Build request with test value
            url = urljoin(base_url, endpoint)

            if param_location == ParameterLocation.QUERY:
                # Add to query string
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query)
                query_params[param_name] = [test_value]
                url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(query_params, doseq=True)}"
                response = await client.request(method, url, headers=headers)

            elif param_location == ParameterLocation.BODY_FORM:
                data = {param_name: test_value}
                response = await client.request(method, url, data=data, headers=headers)

            elif param_location == ParameterLocation.BODY_JSON:
                json_data = {param_name: test_value}
                response = await client.request(method, url, json=json_data, headers=headers)

            else:
                # Default GET with query
                url = f"{url}?{param_name}={test_value}"
                response = await client.request(method, url, headers=headers)

            # Check for reflection in response
            body = response.text

            if test_value in body:
                result.is_reflected = True

                # Determine reflection context
                result.reflection_type = self._determine_reflection_context(body, test_value)

                # Check for encoding
                encoded_variations = [
                    (test_value.replace('<', '&lt;').replace('>', '&gt;'), "html"),
                    (test_value.replace(' ', '%20'), "url"),
                ]
                for encoded, encoding in encoded_variations:
                    if encoded in body and encoded != test_value:
                        result.is_encoded = True
                        result.encoding_type = encoding
                        break

            # Check headers for reflection
            for header_name, header_value in response.headers.items():
                if test_value in header_value:
                    result.is_reflected = True
                    result.reflection_type = ReflectionType.HTTP_HEADER
                    result.injection_point = header_name
                    break

        except Exception as e:
            logger.debug(f"[ParameterAnalyzer] Reflection test error: {e}")

        return result

    def _determine_reflection_context(self, body: str, value: str) -> ReflectionType:
        """Determine the context where the value is reflected."""
        # Find the position of the value
        pos = body.find(value)
        if pos == -1:
            return ReflectionType.NOT_REFLECTED

        # Get surrounding context
        start = max(0, pos - 100)
        end = min(len(body), pos + len(value) + 100)
        context = body[start:end]

        # Check for JavaScript context
        js_patterns = [r'<script[^>]*>', r'javascript:', r'on\w+\s*=']
        for pattern in js_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return ReflectionType.JAVASCRIPT

        # Check for HTML attribute
        attr_pattern = re.compile(r'=\s*["\']?[^"\']*' + re.escape(value), re.IGNORECASE)
        if attr_pattern.search(context):
            return ReflectionType.HTML_ATTRIBUTE

        # Check for JSON response
        try:
            json.loads(body)
            return ReflectionType.JSON_RESPONSE
        except json.JSONDecodeError:
            pass

        # Default to HTML body
        return ReflectionType.HTML_BODY

    def _is_security_relevant(
        self,
        name: str,
        location: ParameterLocation,
        contexts: List[VulnerabilityContext],
    ) -> bool:
        """Determine if parameter is security relevant."""
        # High priority contexts
        high_priority = {
            VulnerabilityContext.SQL_INJECTION,
            VulnerabilityContext.COMMAND_INJECTION,
            VulnerabilityContext.SSRF,
            VulnerabilityContext.LFI,
            VulnerabilityContext.XXE,
            VulnerabilityContext.DESERIALIZATION,
        }

        if any(c in high_priority for c in contexts):
            return True

        # Security-relevant parameter names
        name_lower = name.lower()
        security_names = {
            'token', 'key', 'secret', 'password', 'auth', 'session',
            'admin', 'role', 'permission', 'access', 'privilege',
        }

        if any(s in name_lower for s in security_names):
            return True

        # Security-relevant locations
        if location in {ParameterLocation.HEADER, ParameterLocation.COOKIE}:
            return True

        return False

    def _calculate_priority(self, param: AnalyzedParameter) -> float:
        """Calculate overall priority score for testing."""
        score = 0.0

        # Base on injection potential
        score += param.injection_potential * 0.4

        # Boost for reflected parameters
        if param.reflection and param.reflection.is_reflected:
            score += 0.2
            # Extra boost for unencoded reflection
            if not param.reflection.is_encoded:
                score += 0.1

        # Boost for security-relevant
        if param.is_security_relevant:
            score += 0.15

        # Boost for high-risk contexts
        high_risk = {
            VulnerabilityContext.COMMAND_INJECTION: 0.2,
            VulnerabilityContext.SQL_INJECTION: 0.15,
            VulnerabilityContext.SSRF: 0.15,
            VulnerabilityContext.LFI: 0.15,
        }
        for context in param.vulnerability_contexts:
            if context in high_risk:
                score += high_risk[context]

        # Boost for risky types
        if param.inferred_type in {InferredType.URL, InferredType.PATH, InferredType.FILENAME}:
            score += 0.1

        # Cap at 1.0
        return min(1.0, score)

    def _calculate_summary(self, result: AnalysisResult) -> None:
        """Calculate summary statistics for the analysis result."""
        if not result.parameters:
            return

        # Total injection potential (average)
        result.total_injection_potential = sum(
            p.injection_potential for p in result.parameters
        ) / len(result.parameters)

        # High priority count
        result.high_priority_count = len([
            p for p in result.parameters if p.priority_score >= 0.7
        ])

        # Reflected count
        result.reflected_count = len([
            p for p in result.parameters
            if p.reflection and p.reflection.is_reflected
        ])

        # Security relevant count
        result.security_relevant_count = len([
            p for p in result.parameters if p.is_security_relevant
        ])

        # Collect all vulnerability contexts
        all_contexts = set()
        for param in result.parameters:
            all_contexts.update(param.vulnerability_contexts)
        result.potential_vulnerabilities = list(all_contexts)

    # =========================================================================
    # BATCH ANALYSIS
    # =========================================================================

    async def analyze_batch(
        self,
        base_url: str,
        endpoints: List[Dict[str, Any]],
        test_reflection: bool = True,
    ) -> List[AnalysisResult]:
        """
        Analyze multiple endpoints in batch.

        Args:
            base_url: Base URL of the target
            endpoints: List of endpoint dicts with 'path', 'method', 'params'
            test_reflection: Whether to test for reflection

        Returns:
            List of AnalysisResult objects
        """
        results = []

        for ep in endpoints:
            result = await self.analyze(
                base_url=base_url,
                endpoint=ep.get('path', ''),
                method=ep.get('method', 'GET'),
                sample_params=ep.get('params', {}),
                test_reflection=test_reflection,
            )
            results.append(result)

        return results

    async def quick_analysis(
        self,
        params: Dict[str, str],
    ) -> List[AnalyzedParameter]:
        """
        Quick analysis of parameters without making HTTP requests.

        Args:
            params: Dictionary of parameter name -> value

        Returns:
            List of AnalyzedParameter objects
        """
        analyzed = []

        for name, value in params.items():
            param = AnalyzedParameter(
                name=name,
                location=ParameterLocation.QUERY,
                original_value=value,
            )

            # Infer type
            param.inferred_type, param.type_confidence = self._infer_type(value)

            # Analyze name
            contexts, base_potential = ParameterNameAnalyzer.analyze_name(name)
            param.vulnerability_contexts = contexts
            param.injection_potential = self._adjust_potential_by_type(
                base_potential, param.inferred_type, contexts
            )

            # Suggest payloads
            param.suggested_payload_categories = self._suggest_payloads(
                param.inferred_type, contexts, ParameterLocation.QUERY
            )

            # Security relevance
            param.is_security_relevant = self._is_security_relevant(
                name, ParameterLocation.QUERY, contexts
            )

            # Priority
            param.priority_score = self._calculate_priority(param)

            analyzed.append(param)

        return analyzed


# =============================================================================
# SINGLETON AND FACTORY FUNCTIONS
# =============================================================================

_analyzer_instance: Optional[ParameterAnalyzer] = None
_analyzer_lock = asyncio.Lock()


async def get_parameter_analyzer() -> ParameterAnalyzer:
    """Get singleton ParameterAnalyzer instance (async)."""
    global _analyzer_instance

    async with _analyzer_lock:
        if _analyzer_instance is None:
            _analyzer_instance = ParameterAnalyzer()
            logger.debug("[ParameterAnalyzer] Instance created")

        return _analyzer_instance


def get_parameter_analyzer_sync() -> ParameterAnalyzer:
    """Get ParameterAnalyzer instance (sync)."""
    global _analyzer_instance

    if _analyzer_instance is None:
        _analyzer_instance = ParameterAnalyzer()
        logger.debug("[ParameterAnalyzer] Instance created")

    return _analyzer_instance


# Export
__all__ = [
    "ParameterLocation",
    "InferredType",
    "VulnerabilityContext",
    "ReflectionType",
    "ParameterConstraint",
    "ReflectionResult",
    "AnalyzedParameter",
    "AnalysisResult",
    "TypePatterns",
    "ParameterNameAnalyzer",
    "ParameterAnalyzer",
    "get_parameter_analyzer",
    "get_parameter_analyzer_sync",
]
