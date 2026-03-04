"""
PHANTOM AI - Validation Pipeline Models & Constants
====================================================

Extracted from phantom/validation_pipeline.py (lines 1-677).

Contains:
- All enums: ValidationStage, ValidationResult, FindingConfidence, VulnerabilityType
- All dataclasses: RawFinding, StageResult, ValidatedFinding, ValidationConfig
- All confidence adjustment constants
- Static asset filtering utilities
"""

from __future__ import annotations

import re
import hashlib
import time
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Tuple

logger = logging.getLogger("phantom.validation.models")

# =============================================================================
# PUBLIC API
# =============================================================================

__all__ = [
    # Data classes
    "ValidationConfig",
    "RawFinding",
    "ValidatedFinding",
    "StageResult",
    # Enums
    "ValidationStage",
    "ValidationResult",
    "VulnerabilityType",
    "FindingConfidence",
    # Functions
    "is_static_asset_url",
    # Constants - sets
    "VULN_TYPES_IMPOSSIBLE_ON_STATIC",
    "STATIC_ASSET_EXTENSIONS",
    "STATIC_ASSET_PATH_PATTERNS",
    "STATIC_ASSET_CONTENT_TYPES",
    # Confidence adjustment constants (M1 fix)
    "CONFIDENCE_BOOST_PATTERN_MATCH",
    "CONFIDENCE_BOOST_BLIND_VULN",
    "CONFIDENCE_BOOST_BEHAVIOR_EVIDENCE",
    "CONFIDENCE_BOOST_NEGATIVE_CONTROL",
    "CONFIDENCE_BOOST_SQL_ERROR",
    "CONFIDENCE_BOOST_CONTEXT_QUALITY",
    "CONFIDENCE_BOOST_IDOR_INDICATOR",
    "CONFIDENCE_BOOST_USER_DATA",
    "CONFIDENCE_BOOST_AUTHZ_DATA",
    "CONFIDENCE_BOOST_SAFE_REPLAY",
    "CONFIDENCE_PENALTY_MISSING_DATA",
    "CONFIDENCE_PENALTY_UNCERTAINTY",
    "CONFIDENCE_PENALTY_IDENTICAL_RESPONSE",
    "CONFIDENCE_PENALTY_SIMILAR_RESPONSE",
    "CONFIDENCE_PENALTY_IDENTICAL_BASELINE",
    # Threshold constants
    "TOKEN_OVERLAP_THRESHOLD",
    "SIGNIFICANT_NEW_TOKENS_PERCENT",
    "LENGTH_SIMILARITY_THRESHOLD",
    "SIGNIFICANT_NEW_TOKENS_MIN",
    "MAX_UNCERTAINTY_PENALTY",
    "DEFAULT_RAW_CONFIDENCE",
    "MAX_IDOR_BOOST",
    "MAX_BEHAVIOR_BOOST",
    # Context validation constants
    "CONTEXT_BOOST_QUALITY_EVIDENCE",
    "CONTEXT_BOOST_SQLI_EXFIL",
    "CONTEXT_BOOST_XSS_EXEC",
    "CONTEXT_BOOST_CMDI_EXEC",
    "CONTEXT_BOOST_SSRF_INTERNAL",
    "CONTEXT_BOOST_IDOR_STRONG",
    "CONTEXT_BOOST_IDOR_WEAK",
    "CONTEXT_BOOST_BIZLOGIC_STRONG",
    "CONTEXT_BOOST_BIZLOGIC_WEAK",
    "CONTEXT_BOOST_CREATIVE_EXPLOIT",
    "CONTEXT_BOOST_SESSION_ABUSE",
    "CONTEXT_BOOST_STATUS_EVIDENCE",
    "CONTEXT_PENALTY_NO_EVIDENCE",
    # Proof engine constants
    "PROOF_BOOST_CAN_REPEAT",
    "PROOF_BOOST_CAN_MUTATE",
    "PROOF_BOOST_CAN_ESCALATE",
    "PROOF_BOOST_CAN_CHAIN",
    "PROOF_BOOST_DATA_EXTRACTION",
    "PROOF_BOOST_STATE_CHANGE",
    "PROOF_BOOST_PRIVILEGE_ESCALATION",
    "PROOF_BOOST_DEMONSTRATED",
]

# =============================================================================
# CONFIDENCE ADJUSTMENT CONSTANTS (M1 fix)
# =============================================================================

# Positive adjustments (boosts)
CONFIDENCE_BOOST_PATTERN_MATCH = 0.10      # Pattern verification matched indicators
CONFIDENCE_BOOST_BLIND_VULN = 0.10         # Blind vulns (time/boolean-based) - harder to fake
CONFIDENCE_BOOST_BEHAVIOR_EVIDENCE = 0.10  # Behavior-based finding with evidence
CONFIDENCE_BOOST_NEGATIVE_CONTROL = 0.15   # Attack response contains unique content
CONFIDENCE_BOOST_SQL_ERROR = 0.20          # SQL/DB error signature detected
CONFIDENCE_BOOST_CONTEXT_QUALITY = 0.05    # Quality evidence in context validation
CONFIDENCE_BOOST_IDOR_INDICATOR = 0.15     # IDOR access indicator detected
CONFIDENCE_BOOST_USER_DATA = 0.10          # User data exposure detected
CONFIDENCE_BOOST_AUTHZ_DATA = 0.10         # Authorization data exposure detected
CONFIDENCE_BOOST_SAFE_REPLAY = 0.10        # Safe replay confirmed different behavior

# Negative adjustments (penalties)
CONFIDENCE_PENALTY_MISSING_DATA = -0.02    # Missing data (response, parameter, etc.)
CONFIDENCE_PENALTY_UNCERTAINTY = -0.02     # INCONCLUSIVE result
CONFIDENCE_PENALTY_IDENTICAL_RESPONSE = -0.25  # Safe replay produced identical response
CONFIDENCE_PENALTY_SIMILAR_RESPONSE = -0.20    # Safe replay produced similar response
CONFIDENCE_PENALTY_IDENTICAL_BASELINE = -0.15  # Attack response identical to baseline

# Thresholds
TOKEN_OVERLAP_THRESHOLD = 0.92             # Token overlap above this = FP
LENGTH_SIMILARITY_THRESHOLD = 0.85         # Length similarity threshold
# FIX 2026-02-18: Use both absolute and percentage-based thresholds for new tokens
SIGNIFICANT_NEW_TOKENS_MIN = 5             # Minimum new tokens (absolute) - lowered from 10
SIGNIFICANT_NEW_TOKENS_PERCENT = 0.02      # Minimum new tokens (2% of response tokens)
MAX_UNCERTAINTY_PENALTY = 0.10             # Maximum cumulative uncertainty penalty
DEFAULT_RAW_CONFIDENCE = 0.65              # Default confidence for RawFinding

# Behavior module validation caps
MAX_IDOR_BOOST = 0.25                      # Maximum boost for IDOR/authz findings
MAX_BEHAVIOR_BOOST = 0.25                  # Maximum boost for behavior-based findings

# Context validation stage boosts
CONTEXT_BOOST_QUALITY_EVIDENCE = 0.05      # Quality evidence present
CONTEXT_BOOST_SQLI_EXFIL = 0.10            # SQLi data exfiltration indicator
CONTEXT_BOOST_XSS_EXEC = 0.10              # XSS execution indicator (alert())
CONTEXT_BOOST_CMDI_EXEC = 0.15             # Command execution indicator (uid=, root:)
CONTEXT_BOOST_SSRF_INTERNAL = 0.10         # SSRF internal access indicator
CONTEXT_BOOST_IDOR_STRONG = 0.15           # IDOR indicator (2+ matches)
CONTEXT_BOOST_IDOR_WEAK = 0.05             # IDOR indicator (single match)
CONTEXT_BOOST_BIZLOGIC_STRONG = 0.15       # Business logic indicator (2+ matches)
CONTEXT_BOOST_BIZLOGIC_WEAK = 0.05         # Business logic indicator (single match)
CONTEXT_BOOST_CREATIVE_EXPLOIT = 0.10      # Creative exploit indicator
CONTEXT_BOOST_SESSION_ABUSE = 0.10         # Session abuse indicator
CONTEXT_BOOST_STATUS_EVIDENCE = 0.05       # HTTP status evidence with other indicators
CONTEXT_PENALTY_NO_EVIDENCE = -0.05        # Behavior-based without evidence

# Proof engine boosts
PROOF_BOOST_CAN_REPEAT = 0.05              # Finding is deterministic/reliable
PROOF_BOOST_CAN_MUTATE = 0.05              # Multiple payloads work
PROOF_BOOST_CAN_ESCALATE = 0.10            # Escalation proven (most valuable)
PROOF_BOOST_CAN_CHAIN = 0.05               # Chain potential verified
PROOF_BOOST_DATA_EXTRACTION = 0.05         # Data extraction confirmed
PROOF_BOOST_STATE_CHANGE = 0.05            # State change confirmed
PROOF_BOOST_PRIVILEGE_ESCALATION = 0.10    # Privilege escalation confirmed
PROOF_BOOST_DEMONSTRATED = 0.03            # General demonstrated/verified

# =============================================================================
# STATIC ASSET FILTERING - Early rejection of false positives
# =============================================================================

# File extensions that are static assets (cannot have dynamic vulnerabilities)
STATIC_ASSET_EXTENSIONS = {
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp', '.bmp', '.tiff', '.avif',
    # Stylesheets
    '.css', '.scss', '.sass', '.less',
    # Client-side scripts (not server-side injectable)
    '.js', '.mjs', '.ts', '.jsx', '.tsx',
    # Fonts
    '.woff', '.woff2', '.ttf', '.otf', '.eot',
    # Documents
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    # Media
    '.mp3', '.mp4', '.wav', '.ogg', '.webm', '.avi', '.mov', '.flv',
    # Archives
    '.zip', '.tar', '.gz', '.rar', '.7z',
    # Data files
    '.xml', '.json', '.yaml', '.yml', '.csv',
    # Source maps
    '.map',
}

# URL patterns indicating static assets
# ISSUE-4 FIX 2026-02-11: Removed /public/ - too generic, catches APIs like /api/v1/public/users
# FIX #10 2026-02-12: Added CDN paths (Cloudfront, Akamai, Fastly, etc.)
STATIC_ASSET_PATH_PATTERNS = [
    # Framework static paths
    r'/static/', r'/assets/', r'/images/', r'/img/', r'/css/', r'/js/',
    r'/fonts/', r'/media/', r'/dist/', r'/build/', r'/vendor/',
    r'/node_modules/', r'/_next/static/', r'/__webpack/',
    # CDN paths and signatures
    r'\.cloudfront\.net/', r'/cloudfront/', r'cdn\.', r'/cdn/',
    r'\.akamai\.', r'/akamaihd/', r'\.akamaized\.',
    r'\.fastly\.', r'/fastly/', r'\.fastlylb\.',
    r'\.cloudflare\.com/', r'/cdn-cgi/', r'cdnjs\.cloudflare\.com',
    r'\.jsdelivr\.net/', r'/npm/', r'unpkg\.com/',
    r'\.bunny\.net/', r'\.bunnycdn\.com/',
    r'\.stackpath\.com/', r'\.stackpathcdn\.com/',
    r'\.azureedge\.net/', r'\.msecnd\.net/',
    r'\.googleusercontent\.com/', r'\.gstatic\.com/',
    r'\.twimg\.com/', r'\.fbcdn\.net/', r'\.cdninstagram\.com/',
]

# Content-Types that are definitely static assets
# ISSUE-4 FIX 2026-02-11: Check Content-Type, not just URL pattern
STATIC_ASSET_CONTENT_TYPES = frozenset({
    'image/', 'font/', 'text/css', 'application/javascript',
    'application/x-javascript', 'text/javascript',
    'audio/', 'video/', 'application/font',
})


def is_static_asset_url(url: str) -> bool:
    """
    Check if a URL points to a static asset.

    Static assets cannot have server-side vulnerabilities like SSTI, SQLi, etc.
    This function helps filter out false positives early in the pipeline.

    Args:
        url: The URL to check

    Returns:
        True if the URL is a static asset (finding should be rejected)
    """
    if not url:
        return False

    url_lower = url.lower()

    # DEF-3 FIX: API endpoints should NEVER be considered static assets
    # Even if they end in .json, .xml, .yaml - they're dynamic endpoints
    api_indicators = ['/api/', '/rest/', '/graphql', '/v1/', '/v2/', '/v3/']
    is_api_endpoint = any(ind in url_lower for ind in api_indicators)

    # Check file extension (but NOT for API endpoints)
    if not is_api_endpoint:
        # DEF-3 FIX: Only block truly static extensions, not data formats
        # .json, .xml, .yaml, .yml are valid API response formats
        # FIX 2026-02-12: Added .js, .mjs, .ts - JS bundles cannot have SQLi!
        # Files like /vendor.js, /main.js, /polyfills.js are static bundles
        truly_static_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp', '.bmp', '.tiff', '.avif',
            '.css', '.scss', '.sass', '.less',
            # JavaScript bundles - CANNOT have server-side injection
            '.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx',
            '.woff', '.woff2', '.ttf', '.otf', '.eot',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.mp3', '.mp4', '.wav', '.ogg', '.webm', '.avi', '.mov', '.flv',
            '.zip', '.tar', '.gz', '.rar', '.7z',
            '.map',
        }
        for ext in truly_static_extensions:
            if url_lower.endswith(ext):
                return True
            # Check with query string
            if f"{ext}?" in url_lower or f"{ext}#" in url_lower:
                return True

    # Check path patterns (also skip for API endpoints)
    if not is_api_endpoint:
        for pattern in STATIC_ASSET_PATH_PATTERNS:
            if re.search(pattern, url_lower, re.IGNORECASE):
                return True

    return False


# Vulnerability types that cannot exist on static assets
VULN_TYPES_IMPOSSIBLE_ON_STATIC = {
    'ssti', 'sqli', 'nosql', 'cmdi', 'lfi', 'ssrf', 'xxe',
    'idor', 'authentication', 'authorization', 'csrf', 'rce',
    'deserialization', 'template_injection', 'code_injection',
}


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class ValidationStage(Enum):
    """Validation pipeline stages."""
    DEDUPLICATION = 1
    PATTERN_VERIFICATION = 2
    SAFE_REPLAY = 3
    NEGATIVE_CONTROL = 4
    CONTEXT_VALIDATION = 5
    AI_VERIFICATION = 6


class ValidationResult(Enum):
    """Result of a validation check."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"
    INCONCLUSIVE = "inconclusive"


class FindingConfidence(Enum):
    """Confidence levels for findings."""
    SUSPECTED = 0.30       # 30-59%: Internal only
    DETECTED = 0.60        # 60-74%: Internal + analyst review
    CONFIRMED = 0.75       # 75-94%: Reported to user
    EXPLOITABLE = 0.95     # 95-100%: Priority report


class VulnerabilityType(Enum):
    """Types of vulnerabilities for validation."""
    # Injection vulnerabilities
    SQLI = "sqli"
    XSS = "xss"
    CMDI = "cmdi"
    LFI = "lfi"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    NOSQL = "nosql"
    CRLF = "crlf"
    CRLF_INJECTION = "crlf_injection"  # Alternative name

    # Access control
    IDOR = "idor"
    OPEN_REDIRECT = "open_redirect"
    CSRF = "csrf"
    CORS = "cors"

    # Authentication/Authorization
    JWT = "jwt"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"

    # API Security
    API = "api"
    API_SECURITY = "api_security"
    GRAPHQL = "graphql"

    # File/Directory exposure
    DIRECTORY = "directory"
    SENSITIVE_FILE = "sensitive_file"
    PATH_TRAVERSAL = "path_traversal"

    # Code execution
    RCE = "rce"
    DESERIALIZATION = "deserialization"

    # Information disclosure
    INFORMATION_DISCLOSURE = "info_disclosure"
    INFO_DISCLOSURE = "info_disclosure"  # Alias

    # Other
    MISCONFIGURATION = "misconfiguration"
    RATE_LIMIT = "rate_limit"
    OTHER = "other"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class RawFinding:
    """
    Raw finding from a scanner module.
    Input to the validation pipeline.
    """
    id: str
    title: str
    vulnerability_type: VulnerabilityType
    severity: str
    url: str
    parameter: Optional[str] = None
    method: str = "GET"
    payload: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    evidence: str = ""
    description: str = ""
    module_name: str = ""
    # FIX 2026-02-12: Raised from 0.5 to 0.65 - default was below MEDIUM threshold (0.65)
    # Findings need to pass validation stages to reach threshold, not be penalized down
    confidence: float = 0.65
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "vulnerability_type": self.vulnerability_type.value,
            "severity": self.severity,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "payload": self.payload,
            "request": self.request,
            "response": self.response,
            "evidence": self.evidence,
            "description": self.description,
            "module_name": self.module_name,
            "confidence": self.confidence,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }

    def get_fingerprint(self) -> str:
        """Generate unique fingerprint for deduplication."""
        # FIX 2026-02-12: Don't include payload for injection types
        # Same SQLi on same param with different payloads should be ONE finding
        INJECTION_TYPES = {"sqli", "xss", "cmdi", "ssti", "nosql", "xxe", "lfi", "ssrf", "crlf"}

        vuln_type = self.vulnerability_type.value if hasattr(self.vulnerability_type, 'value') else str(self.vulnerability_type)

        if vuln_type.lower() in INJECTION_TYPES:
            # For injection types: dedupe by type+url+param only
            components = [
                vuln_type,
                self.url or "",
                self.parameter or "",
                self.method or "GET",
                # NO payload - different payloads = same vuln
            ]
        else:
            # For other types: include payload for more granular dedup
            components = [
                vuln_type,
                self.url or "",
                self.parameter or "",
                self.method or "GET",
                self.payload or "",
            ]
        content = "|".join(components)
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class StageResult:
    """Result from a single validation stage."""
    stage: ValidationStage
    result: ValidationResult
    confidence_delta: float  # Change to confidence score
    message: str = ""
    evidence: str = ""
    duration_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    # THEME-10 FIX: Track uncertainty explicitly
    uncertainty_reason: str = ""  # Why this stage couldn't fully execute

    def is_uncertain(self) -> bool:
        """
        Check if this stage result represents uncertainty.

        THEME-10: Explicit distinction between:
        - "Tested, passed" (confident positive)
        - "Tested, failed" (confident negative)
        - "Couldn't test" (uncertain)
        """
        return self.result in (ValidationResult.SKIPPED, ValidationResult.INCONCLUSIVE, ValidationResult.ERROR)


@dataclass
class ValidatedFinding:
    """
    Finding that has passed through the validation pipeline.
    Output of the validation pipeline.
    """
    raw_finding: RawFinding
    is_valid: bool
    final_confidence: float
    confidence_level: FindingConfidence
    stage_results: List[StageResult] = field(default_factory=list)
    validation_time_ms: float = 0.0
    should_report: bool = False
    suppression_reason: Optional[str] = None

    # THEME-10 FIX: Uncertainty tracking
    uncertainty_score: float = 0.0  # 0.0 = fully tested, 1.0 = completely untested
    uncertainty_reasons: List[str] = field(default_factory=list)

    def calculate_uncertainty(self) -> float:
        """
        Calculate uncertainty score based on stage results.

        THEME-10: Makes explicit how much of the validation was inconclusive.
        """
        if not self.stage_results:
            return 1.0  # No stages = complete uncertainty

        uncertain_count = sum(1 for s in self.stage_results if s.is_uncertain())
        self.uncertainty_score = uncertain_count / len(self.stage_results)

        # Collect uncertainty reasons
        self.uncertainty_reasons = [
            f"{s.stage.name}: {s.message}"
            for s in self.stage_results
            if s.is_uncertain()
        ]

        return self.uncertainty_score

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (nested structure for validation details)."""
        result = {
            "finding": self.raw_finding.to_dict(),
            "is_valid": self.is_valid,
            "final_confidence": round(self.final_confidence, 4),
            "confidence_level": self.confidence_level.name,
            "validation_time_ms": round(self.validation_time_ms, 2),
            "should_report": self.should_report,
            "suppression_reason": self.suppression_reason,
            # THEME-10: Include uncertainty metrics
            "uncertainty_score": round(self.uncertainty_score, 4),
            "uncertainty_reasons": self.uncertainty_reasons,
            "stages": [
                {
                    "stage": sr.stage.name,
                    "result": sr.result.value,
                    "confidence_delta": round(sr.confidence_delta, 4),
                    "message": sr.message,
                    "is_uncertain": sr.is_uncertain(),
                }
                for sr in self.stage_results
            ],
        }
        # Include CVSS data if available
        metadata = self.raw_finding.metadata or {}
        if "cvss_score" in metadata:
            result["cvss"] = {
                "score": metadata.get("cvss_score"),
                "vector": metadata.get("cvss_vector"),
                "severity": metadata.get("cvss_severity"),
                "cia_impact": metadata.get("cia_impact"),
                "financial_impact": metadata.get("financial_impact"),
                "regulatory_impact": metadata.get("regulatory_impact"),
                "remediation_priority": metadata.get("remediation_priority"),
                "recommendations": metadata.get("recommendations"),
            }
        return result

    def to_flat_dict(self) -> Dict[str, Any]:
        """Convert to flat dictionary for downstream processing.

        Merges raw finding fields with validation metadata, avoiding nesting.
        Use this for chain detection, report generation, and deduplication.
        """
        flat = self.raw_finding.to_dict()
        # Add validation metadata without nesting
        flat["is_valid"] = self.is_valid
        flat["final_confidence"] = round(self.final_confidence, 4)
        flat["confidence_level"] = self.confidence_level.name
        flat["validation_time_ms"] = round(self.validation_time_ms, 2)
        flat["should_report"] = self.should_report
        if self.suppression_reason:
            flat["suppression_reason"] = self.suppression_reason
        # Include top-level CVSS data for easy access
        metadata = self.raw_finding.metadata or {}
        if "cvss_score" in metadata:
            flat["cvss_score"] = metadata.get("cvss_score")
            flat["cvss_vector"] = metadata.get("cvss_vector")
            flat["cvss_severity"] = metadata.get("cvss_severity")
            flat["remediation_priority"] = metadata.get("remediation_priority")
        return flat


@dataclass
class ValidationConfig:
    """Configuration for the validation pipeline."""
    # Stage toggles
    enable_deduplication: bool = True
    enable_pattern_verification: bool = True
    enable_safe_replay: bool = True
    enable_negative_control: bool = True
    enable_context_validation: bool = True
    enable_ai_verification: bool = True  # Auditor only, not blocker

    # Thresholds
    min_confidence_to_report: float = 0.70
    # CRITICAL severity requires higher confidence (RCE-class vulns)
    # FN-FIX 2026-02-08: Lowered from 85% to 80% - black-box scanners rarely achieve 85%+
    min_confidence_critical: float = 0.80
    # Severity-specific thresholds (fallback to min_confidence_to_report if not specified)
    # FN-FIX 2026-02-08: Lowered all thresholds by 5% to reduce false negatives
    severity_confidence_thresholds: Dict[str, float] = field(default_factory=lambda: {
        "CRITICAL": 0.80,  # FN-FIX: Was 0.85 - too high for black-box
        "HIGH": 0.70,      # FN-FIX: Was 0.75
        "MEDIUM": 0.65,    # FN-FIX: Was 0.70
        "LOW": 0.60,       # FN-FIX: Was 0.65
        "INFO": 0.50,      # FN-FIX: Was 0.55
    })
    dedup_similarity_threshold: float = 0.90
    pattern_match_threshold: float = 0.60

    # Timing
    replay_timeout: float = 10.0
    max_retries: int = 2
    retry_delay: float = 0.5

    # AI settings
    ai_verification_is_blocking: bool = False  # AI is auditor, not gate

    # Rate limiting
    max_concurrent_validations: int = 5
