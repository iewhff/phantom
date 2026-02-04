"""
Method Discovery Engine v1.0.0-ENTERPRISE
==========================================

Descoberta REAL de métodos HTTP - não testes cegos!

Features:
- OPTIONS request (RFC 7231 compliance)
- HEAD request analysis
- Form discovery (HTML parsing)
- JavaScript endpoint extraction
- API pattern detection
- OpenAPI/Swagger discovery
- CORS method detection

Princípio: NÃO TESTES O QUE NÃO EXISTE
"""

import asyncio
import re
import json
import warnings
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, List, Dict, Set, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import httpx
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

# Suppress XML parsed as HTML warnings - we handle both formats
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)


class HTTPMethod(Enum):
    """HTTP Methods with risk profiles"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"
    CONNECT = "CONNECT"
    
    @property
    def is_safe(self) -> bool:
        """Safe methods don't modify state"""
        return self in {HTTPMethod.GET, HTTPMethod.HEAD, HTTPMethod.OPTIONS, HTTPMethod.TRACE}
    
    @property
    def is_idempotent(self) -> bool:
        """Idempotent methods can be repeated safely"""
        return self in {
            HTTPMethod.GET, HTTPMethod.HEAD, HTTPMethod.OPTIONS,
            HTTPMethod.PUT, HTTPMethod.DELETE, HTTPMethod.TRACE
        }
    
    @property
    def risk_level(self) -> str:
        """Risk level for testing"""
        risk_map = {
            HTTPMethod.GET: "low",
            HTTPMethod.HEAD: "none",
            HTTPMethod.OPTIONS: "none",
            HTTPMethod.POST: "medium",
            HTTPMethod.PUT: "high",
            HTTPMethod.PATCH: "high",
            HTTPMethod.DELETE: "critical",
            HTTPMethod.TRACE: "low",
            HTTPMethod.CONNECT: "high"
        }
        return risk_map.get(self, "unknown")


class EndpointSource(Enum):
    """Where the endpoint was discovered"""
    OPTIONS_HEADER = auto()
    HEAD_ANALYSIS = auto()
    HTML_FORM = auto()
    HTML_LINK = auto()
    JAVASCRIPT = auto()
    AJAX_CALL = auto()
    API_PATTERN = auto()
    OPENAPI_SPEC = auto()
    SITEMAP = auto()
    ROBOTS_TXT = auto()
    CORS_HEADER = auto()
    RESPONSE_HEADER = auto()


@dataclass
class FormInfo:
    """Information about discovered HTML form"""
    action: str
    method: str
    enctype: str
    inputs: List[Dict[str, Any]]
    id: Optional[str] = None
    name: Optional[str] = None
    has_file_upload: bool = False
    has_csrf_token: bool = False
    csrf_param: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "method": self.method,
            "enctype": self.enctype,
            "inputs": self.inputs,
            "id": self.id,
            "name": self.name,
            "has_file_upload": self.has_file_upload,
            "has_csrf_token": self.has_csrf_token,
            "csrf_param": self.csrf_param
        }


@dataclass
class DiscoveredEndpoint:
    """A discovered endpoint with all metadata"""
    url: str
    methods: Set[HTTPMethod]
    source: EndpointSource
    confidence: float  # 0.0 - 1.0
    parameters: Dict[str, str] = field(default_factory=dict)
    content_type: Optional[str] = None
    form_info: Optional[FormInfo] = None
    requires_auth: bool = False
    raw_evidence: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "methods": [m.value for m in self.methods],
            "source": self.source.name,
            "confidence": self.confidence,
            "parameters": self.parameters,
            "content_type": self.content_type,
            "form_info": self.form_info.to_dict() if self.form_info else None,
            "requires_auth": self.requires_auth
        }


@dataclass
class MethodDiscoveryResult:
    """Complete method discovery result for a URL"""
    target_url: str
    allowed_methods: Set[HTTPMethod]
    discovered_endpoints: List[DiscoveredEndpoint]
    cors_config: Dict[str, Any]
    server_info: Dict[str, str]
    api_specs: List[str]
    error: Optional[str] = None
    
    def get_testable_methods(self) -> List[HTTPMethod]:
        """Get methods that should be tested"""
        # Exclude HEAD and OPTIONS (info only)
        testable = {HTTPMethod.GET, HTTPMethod.POST, HTTPMethod.PUT, 
                   HTTPMethod.PATCH, HTTPMethod.DELETE}
        return list(self.allowed_methods & testable)
    
    def get_endpoints_by_method(self, method: HTTPMethod) -> List[DiscoveredEndpoint]:
        """Get all endpoints that support a specific method"""
        return [ep for ep in self.discovered_endpoints if method in ep.methods]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "allowed_methods": [m.value for m in self.allowed_methods],
            "discovered_endpoints": [ep.to_dict() for ep in self.discovered_endpoints],
            "cors_config": self.cors_config,
            "server_info": self.server_info,
            "api_specs": self.api_specs,
            "error": self.error
        }


class MethodDiscoveryEngine:
    """
    Method Discovery Engine - Real HTTP Method Detection
    
    Implements intelligent discovery:
    1. OPTIONS request (RFC 7231)
    2. HEAD analysis
    3. Form discovery
    4. JavaScript parsing
    5. API pattern detection
    """
    
    VERSION = "1.0.0-ENTERPRISE"
    
    # JavaScript patterns for endpoint extraction
    JS_ENDPOINT_PATTERNS = [
        # fetch/axios calls
        r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
        r'axios\s*\.\s*(get|post|put|patch|delete)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
        r'axios\s*\(\s*\{[^}]*url\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
        
        # XMLHttpRequest
        r'\.open\s*\(\s*[\'"`](GET|POST|PUT|DELETE|PATCH)[\'"`]\s*,\s*[\'"`]([^\'"`]+)[\'"`]',
        
        # jQuery AJAX
        r'\$\s*\.\s*(get|post|ajax)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
        r'url\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
        
        # API base URLs
        r'(api|API)_?(URL|BASE|ENDPOINT)\s*[=:]\s*[\'"`]([^\'"`]+)[\'"`]',
        
        # Route definitions
        r'(router|route|path)\s*\.\s*(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
        
        # GraphQL
        r'(query|mutation)\s*[\'"`]([^\'"`]+)[\'"`]',
        r'/graphql',
        
        # Generic API patterns
        r'[\'"`](/api/v?\d*/[^\'"`]+)[\'"`]',
        r'[\'"`](/v\d+/[^\'"`]+)[\'"`]',
    ]
    
    # API spec paths to check
    API_SPEC_PATHS = [
        "/openapi.json",
        "/openapi.yaml",
        "/swagger.json",
        "/swagger.yaml",
        "/swagger/v1/swagger.json",
        "/api-docs",
        "/api-docs.json",
        "/v1/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/.well-known/openapi.json",
        "/docs",
        "/redoc",
    ]
    
    # Common API patterns
    API_PATTERNS = [
        (r'/api/v?\d*/', ["GET", "POST"]),
        (r'/api/\w+/\d+', ["GET", "PUT", "PATCH", "DELETE"]),
        (r'/graphql', ["POST"]),
        (r'/rest/', ["GET", "POST", "PUT", "DELETE"]),
        (r'/json/', ["GET", "POST"]),
        (r'/ajax/', ["GET", "POST"]),
        (r'/ws/', ["GET"]),  # WebSocket upgrade
    ]
    
    # CSRF token patterns
    CSRF_PATTERNS = [
        r'csrf[_-]?token',
        r'_token',
        r'authenticity_token',
        r'__RequestVerificationToken',
        r'csrfmiddlewaretoken',
        r'_csrf',
        r'XSRF-TOKEN',
    ]
    
    def __init__(
        self,
        timeout: float = 10.0,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        user_agent: str = "PenTestAI-MethodDiscovery/1.0"
    ):
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        self._client: Optional[httpx.AsyncClient] = None
    
    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=self.follow_redirects,
            max_redirects=self.max_redirects,
            headers={"User-Agent": self.user_agent}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()
    
    async def discover(
        self,
        url: str,
        include_js_parsing: bool = True,
        check_api_specs: bool = True,
        deep_form_analysis: bool = True
    ) -> MethodDiscoveryResult:
        """
        Main discovery method - finds all methods and endpoints
        
        Args:
            url: Target URL
            include_js_parsing: Parse JavaScript for endpoints
            check_api_specs: Check for OpenAPI/Swagger specs
            deep_form_analysis: Analyze forms in detail
            
        Returns:
            MethodDiscoveryResult with all discovered methods/endpoints
        """
        if not self._client:
            async with self:
                return await self.discover(url, include_js_parsing, check_api_specs, deep_form_analysis)
        
        discovered_endpoints: List[DiscoveredEndpoint] = []
        allowed_methods: Set[HTTPMethod] = set()
        cors_config: Dict[str, Any] = {}
        server_info: Dict[str, str] = {}
        api_specs: List[str] = []
        error: Optional[str] = None
        
        try:
            # 1. OPTIONS request (RFC 7231)
            options_methods, options_cors = await self._options_discovery(url)
            allowed_methods.update(options_methods)
            cors_config = options_cors
            
            # 2. HEAD request analysis
            head_info, head_methods = await self._head_analysis(url)
            server_info = head_info
            allowed_methods.update(head_methods)
            
            # 3. GET the page for form/JS analysis
            response = await self._client.get(url)
            
            # 4. Form discovery
            if deep_form_analysis:
                form_endpoints = self._discover_forms(url, response.text)
                discovered_endpoints.extend(form_endpoints)
                for ep in form_endpoints:
                    allowed_methods.update(ep.methods)
            
            # 5. Link discovery
            link_endpoints = self._discover_links(url, response.text)
            discovered_endpoints.extend(link_endpoints)
            
            # 6. JavaScript parsing
            if include_js_parsing:
                js_endpoints = await self._parse_javascript(url, response.text)
                discovered_endpoints.extend(js_endpoints)
                for ep in js_endpoints:
                    allowed_methods.update(ep.methods)
            
            # 7. API spec discovery
            if check_api_specs:
                api_specs = await self._discover_api_specs(url)
            
            # 8. API pattern detection
            api_endpoints = self._detect_api_patterns(url)
            discovered_endpoints.extend(api_endpoints)
            
            # Ensure at least GET is in allowed methods if response was successful
            if response.status_code < 400:
                allowed_methods.add(HTTPMethod.GET)
            
        except httpx.TimeoutException:
            error = "Timeout during method discovery"
        except httpx.ConnectError as e:
            error = f"Connection error: {str(e)}"
        except Exception as e:
            error = f"Discovery error: {str(e)}"
        
        # Deduplicate endpoints
        discovered_endpoints = self._deduplicate_endpoints(discovered_endpoints)
        
        return MethodDiscoveryResult(
            target_url=url,
            allowed_methods=allowed_methods,
            discovered_endpoints=discovered_endpoints,
            cors_config=cors_config,
            server_info=server_info,
            api_specs=api_specs,
            error=error
        )
    
    async def _options_discovery(self, url: str) -> Tuple[Set[HTTPMethod], Dict[str, Any]]:
        """
        Send OPTIONS request to discover allowed methods
        
        RFC 7231: OPTIONS method requests information about 
        communication options available for the target resource
        """
        allowed_methods: Set[HTTPMethod] = set()
        cors_config: Dict[str, Any] = {}
        
        try:
            response = await self._client.options(url)
            
            # Parse Allow header
            allow_header = response.headers.get("Allow", "")
            if allow_header:
                for method in allow_header.upper().split(","):
                    method = method.strip()
                    try:
                        allowed_methods.add(HTTPMethod(method))
                    except ValueError:
                        pass  # Unknown method
            
            # Parse CORS headers
            cors_headers = [
                "Access-Control-Allow-Methods",
                "Access-Control-Allow-Origin",
                "Access-Control-Allow-Headers",
                "Access-Control-Allow-Credentials",
                "Access-Control-Max-Age",
                "Access-Control-Expose-Headers"
            ]
            
            for header in cors_headers:
                value = response.headers.get(header)
                if value:
                    cors_config[header] = value
                    
                    # Parse methods from CORS header
                    if header == "Access-Control-Allow-Methods":
                        for method in value.upper().split(","):
                            method = method.strip()
                            try:
                                allowed_methods.add(HTTPMethod(method))
                            except ValueError:
                                pass
                                
        except Exception:
            pass  # OPTIONS may not be supported
        
        return allowed_methods, cors_config
    
    async def _head_analysis(self, url: str) -> Tuple[Dict[str, str], Set[HTTPMethod]]:
        """
        Send HEAD request to gather server information
        
        Also detects:
        - Server software
        - Content type expectations
        - Authentication requirements
        """
        server_info: Dict[str, str] = {}
        allowed_methods: Set[HTTPMethod] = set()
        
        try:
            response = await self._client.head(url)
            
            # Extract server info
            info_headers = [
                "Server",
                "X-Powered-By",
                "X-AspNet-Version",
                "X-AspNetMvc-Version",
                "X-Runtime",
                "X-Version",
                "Via"
            ]
            
            for header in info_headers:
                value = response.headers.get(header)
                if value:
                    server_info[header] = value
            
            # Check for authentication
            if response.status_code == 401:
                auth_header = response.headers.get("WWW-Authenticate", "")
                server_info["auth_required"] = auth_header
            
            # Content-Type hints
            content_type = response.headers.get("Content-Type", "")
            server_info["content_type"] = content_type
            
            # If HEAD works, GET likely works too
            if response.status_code < 400:
                allowed_methods.add(HTTPMethod.HEAD)
                allowed_methods.add(HTTPMethod.GET)
            
            # Check Allow header (might be present)
            allow_header = response.headers.get("Allow", "")
            if allow_header:
                for method in allow_header.upper().split(","):
                    method = method.strip()
                    try:
                        allowed_methods.add(HTTPMethod(method))
                    except ValueError:
                        pass
                        
        except Exception:
            pass
        
        return server_info, allowed_methods
    
    def _get_parser(self, content: str) -> str:
        """Detect if content is XML or HTML and return appropriate parser."""
        content_start = content.strip()[:100].lower()
        if content_start.startswith('<?xml') or '<rss' in content_start or '<feed' in content_start:
            return "lxml-xml" if self._has_lxml() else "html.parser"
        return "html.parser"
    
    def _has_lxml(self) -> bool:
        """Check if lxml is available."""
        try:
            import lxml
            return True
        except ImportError:
            return False
    
    def _discover_forms(self, base_url: str, html: str) -> List[DiscoveredEndpoint]:
        """
        Parse HTML to discover forms and their submission methods
        """
        endpoints: List[DiscoveredEndpoint] = []
        
        try:
            parser = self._get_parser(html)
            soup = BeautifulSoup(html, parser)
            forms = soup.find_all("form")
            
            for form in forms:
                # Extract form attributes
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                enctype = form.get("enctype", "application/x-www-form-urlencoded")
                form_id = form.get("id")
                form_name = form.get("name")
                
                # Resolve action URL
                if not action:
                    action = base_url
                elif not action.startswith(("http://", "https://", "//")):
                    action = urljoin(base_url, action)
                elif action.startswith("//"):
                    parsed = urlparse(base_url)
                    action = f"{parsed.scheme}:{action}"
                
                # Parse inputs
                inputs = []
                has_file_upload = False
                has_csrf_token = False
                csrf_param = None
                
                for input_elem in form.find_all(["input", "textarea", "select"]):
                    input_info = {
                        "tag": input_elem.name,
                        "name": input_elem.get("name", ""),
                        "type": input_elem.get("type", "text"),
                        "value": input_elem.get("value", ""),
                        "required": input_elem.has_attr("required"),
                        "placeholder": input_elem.get("placeholder", ""),
                        "pattern": input_elem.get("pattern", ""),
                        "maxlength": input_elem.get("maxlength"),
                        "minlength": input_elem.get("minlength"),
                    }
                    
                    # Check for file upload
                    if input_info["type"] == "file":
                        has_file_upload = True
                    
                    # Check for CSRF token
                    input_name = input_info["name"].lower()
                    for pattern in self.CSRF_PATTERNS:
                        if re.search(pattern, input_name, re.IGNORECASE):
                            has_csrf_token = True
                            csrf_param = input_info["name"]
                            break
                    
                    if input_info["name"]:  # Only include named inputs
                        inputs.append(input_info)
                
                # Create FormInfo
                form_info = FormInfo(
                    action=action,
                    method=method,
                    enctype=enctype,
                    inputs=inputs,
                    id=form_id,
                    name=form_name,
                    has_file_upload=has_file_upload,
                    has_csrf_token=has_csrf_token,
                    csrf_param=csrf_param
                )
                
                # Determine HTTP method
                try:
                    http_method = HTTPMethod(method)
                except ValueError:
                    http_method = HTTPMethod.GET
                
                # Create parameters dict
                params = {inp["name"]: inp["type"] for inp in inputs if inp["name"]}
                
                endpoint = DiscoveredEndpoint(
                    url=action,
                    methods={http_method},
                    source=EndpointSource.HTML_FORM,
                    confidence=0.95,  # Forms are highly reliable
                    parameters=params,
                    content_type=enctype,
                    form_info=form_info
                )
                
                endpoints.append(endpoint)
                
        except Exception as e:
            pass  # Continue on parse errors
        
        return endpoints
    
    def _discover_links(self, base_url: str, html: str) -> List[DiscoveredEndpoint]:
        """
        Parse HTML to discover links (potential GET endpoints)
        """
        endpoints: List[DiscoveredEndpoint] = []
        seen_urls: Set[str] = set()
        
        try:
            parser = self._get_parser(html)
            soup = BeautifulSoup(html, parser)
            
            # Find all links
            for tag, attr in [("a", "href"), ("link", "href"), ("script", "src"), ("img", "src")]:
                for elem in soup.find_all(tag):
                    url = elem.get(attr, "")
                    if not url or url.startswith(("#", "javascript:", "mailto:", "tel:")):
                        continue
                    
                    # Resolve URL
                    if not url.startswith(("http://", "https://", "//")):
                        url = urljoin(base_url, url)
                    elif url.startswith("//"):
                        parsed = urlparse(base_url)
                        url = f"{parsed.scheme}:{url}"
                    
                    # Skip external URLs
                    if not self._is_same_origin(base_url, url):
                        continue
                    
                    # Skip duplicates
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)
                    
                    # Parse query parameters
                    parsed = urlparse(url)
                    params = {}
                    if parsed.query:
                        for key, values in parse_qs(parsed.query).items():
                            params[key] = "string"  # Default type
                    
                    endpoint = DiscoveredEndpoint(
                        url=url,
                        methods={HTTPMethod.GET},
                        source=EndpointSource.HTML_LINK,
                        confidence=0.7,
                        parameters=params
                    )
                    endpoints.append(endpoint)
                    
        except Exception:
            pass
        
        return endpoints
    
    async def _parse_javascript(self, base_url: str, html: str) -> List[DiscoveredEndpoint]:
        """
        Parse JavaScript for API endpoints and AJAX calls
        """
        endpoints: List[DiscoveredEndpoint] = []
        seen_urls: Set[str] = set()
        
        try:
            parser = self._get_parser(html)
            soup = BeautifulSoup(html, parser)
            
            # Collect all JavaScript
            js_content = ""
            
            # Inline scripts
            for script in soup.find_all("script"):
                if script.string:
                    js_content += script.string + "\n"
            
            # External scripts (same origin)
            for script in soup.find_all("script", src=True):
                src = script["src"]
                if not src.startswith(("http://", "https://")):
                    src = urljoin(base_url, src)
                
                if self._is_same_origin(base_url, src):
                    try:
                        response = await self._client.get(src)
                        if response.status_code == 200:
                            js_content += response.text + "\n"
                    except Exception:
                        pass
            
            # Extract endpoints from JS
            for pattern in self.JS_ENDPOINT_PATTERNS:
                matches = re.findall(pattern, js_content, re.IGNORECASE)
                
                for match in matches:
                    # Handle tuple matches (method, url)
                    if isinstance(match, tuple):
                        if len(match) == 2:
                            method_str, url = match
                        elif len(match) == 3:
                            _, method_str, url = match
                        else:
                            url = match[-1]
                            method_str = "GET"
                    else:
                        url = match
                        method_str = "GET"
                    
                    # Skip non-URLs
                    if not url or not isinstance(url, str):
                        continue
                    if url.startswith(("data:", "blob:", "javascript:")):
                        continue
                    
                    # Resolve URL
                    if not url.startswith(("http://", "https://")):
                        if url.startswith("/"):
                            url = urljoin(base_url, url)
                        else:
                            continue  # Skip relative without /
                    
                    # Skip duplicates
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)
                    
                    # Determine method
                    methods = {HTTPMethod.GET}  # Default
                    if isinstance(method_str, str):
                        method_upper = method_str.upper()
                        if method_upper in ("POST", "PUT", "DELETE", "PATCH"):
                            try:
                                methods = {HTTPMethod(method_upper)}
                            except ValueError:
                                pass
                    
                    endpoint = DiscoveredEndpoint(
                        url=url,
                        methods=methods,
                        source=EndpointSource.JAVASCRIPT,
                        confidence=0.6,  # JS parsing is less reliable
                        raw_evidence=f"Pattern match: {pattern}"
                    )
                    endpoints.append(endpoint)
                    
        except Exception:
            pass
        
        return endpoints
    
    async def _discover_api_specs(self, base_url: str) -> List[str]:
        """
        Check for OpenAPI/Swagger specifications
        """
        found_specs: List[str] = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for spec_path in self.API_SPEC_PATHS:
            spec_url = base + spec_path
            try:
                response = await self._client.get(spec_url)
                if response.status_code == 200:
                    content_type = response.headers.get("Content-Type", "")
                    
                    # Check if it looks like a spec
                    if "json" in content_type or "yaml" in content_type:
                        found_specs.append(spec_url)
                    elif response.text.strip().startswith(("{", "openapi", "swagger")):
                        found_specs.append(spec_url)
                        
            except Exception:
                pass
        
        return found_specs
    
    def _detect_api_patterns(self, url: str) -> List[DiscoveredEndpoint]:
        """
        Detect API patterns in URL and suggest methods
        """
        endpoints: List[DiscoveredEndpoint] = []
        
        for pattern, methods in self.API_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                method_set = set()
                for m in methods:
                    try:
                        method_set.add(HTTPMethod(m))
                    except ValueError:
                        pass
                
                endpoint = DiscoveredEndpoint(
                    url=url,
                    methods=method_set,
                    source=EndpointSource.API_PATTERN,
                    confidence=0.5,  # Pattern detection is least reliable
                    raw_evidence=f"Matched pattern: {pattern}"
                )
                endpoints.append(endpoint)
                break  # Only match first pattern
        
        return endpoints
    
    def _deduplicate_endpoints(self, endpoints: List[DiscoveredEndpoint]) -> List[DiscoveredEndpoint]:
        """
        Deduplicate endpoints, merging methods from different sources
        """
        url_to_endpoint: Dict[str, DiscoveredEndpoint] = {}
        
        for ep in endpoints:
            # Normalize URL
            parsed = urlparse(ep.url)
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            if normalized in url_to_endpoint:
                # Merge
                existing = url_to_endpoint[normalized]
                existing.methods.update(ep.methods)
                existing.parameters.update(ep.parameters)
                
                # Keep higher confidence
                if ep.confidence > existing.confidence:
                    existing.confidence = ep.confidence
                    existing.source = ep.source
                
                # Keep form info if present
                if ep.form_info and not existing.form_info:
                    existing.form_info = ep.form_info
            else:
                url_to_endpoint[normalized] = ep
        
        return list(url_to_endpoint.values())
    
    def _is_same_origin(self, base_url: str, test_url: str) -> bool:
        """Check if two URLs have the same origin"""
        try:
            base_parsed = urlparse(base_url)
            test_parsed = urlparse(test_url)
            
            return (
                base_parsed.scheme == test_parsed.scheme and
                base_parsed.netloc == test_parsed.netloc
            )
        except Exception:
            return False
    
    async def quick_method_check(self, url: str) -> Set[HTTPMethod]:
        """
        Quick check for allowed methods without full discovery
        
        Just OPTIONS + HEAD
        """
        if not self._client:
            async with self:
                return await self.quick_method_check(url)
        
        methods: Set[HTTPMethod] = set()
        
        # OPTIONS
        options_methods, _ = await self._options_discovery(url)
        methods.update(options_methods)
        
        # HEAD
        _, head_methods = await self._head_analysis(url)
        methods.update(head_methods)
        
        return methods if methods else {HTTPMethod.GET, HTTPMethod.POST}


# Convenience function
async def discover_methods(url: str, **kwargs) -> MethodDiscoveryResult:
    """Quick method discovery function"""
    async with MethodDiscoveryEngine(**kwargs) as engine:
        return await engine.discover(url)


# Export types
__all__ = [
    "MethodDiscoveryEngine",
    "MethodDiscoveryResult",
    "DiscoveredEndpoint",
    "FormInfo",
    "HTTPMethod",
    "EndpointSource",
    "discover_methods"
]
