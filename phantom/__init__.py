"""
PHANTOM AI - Professional Heuristic Automated Network Threat Operations Module

Enterprise-grade AI-powered penetration testing framework.
Built on top of PetNTester AI foundation.

Version: 3.0.0
Date: 2026-01-30
License: MIT

PHANTOM AI Philosophy:
1. Intelligence Before Force - Understand the target completely before testing
2. Vulnerabilities Discover Vulnerabilities - Chain findings to uncover deeper issues
3. Detection, Not Destruction - Prove impact without causing harm

Core Modules:
- network_protection: Kill switch, OPSEC, traffic monitoring
- tech_fingerprinter: 500+ technology signatures with version detection
- parameter_analyzer: Deep parameter analysis for injection points
- waf_bypass_engine: 50+ WAF detection and bypass techniques
- context_payload_selector: AI-driven payload selection
- module_executor: Unified scanner execution framework (75+ modules)
- validation_pipeline: 6-stage finding validation for zero false positives
- negative_control: False positive reduction through baseline comparison
- ai_validator: LLM-based finding verification
- chain_actions: Vulnerability chain execution engine
- impact_assessment: Business impact and CIA triad scoring
- chain_visualization: NetworkX-based attack path visualization
- sarif_generator: SARIF 2.1.0 output for DevSecOps integration
- bounty_estimator: Bug bounty value estimation
- compliance_mapper: CWE, OWASP, PCI DSS, NIST mapping
- knowledge_loader: Security knowledge base loader
- adaptive_payload_engine: Self-learning payload system

Usage:
    from phantom import PhantomAI

    phantom = PhantomAI()
    result = await phantom.scan("https://target.com", mode="full")
"""

from __future__ import annotations

__version__ = "3.0.0"
__author__ = "PHANTOM AI Team"
__license__ = "MIT"

# PHANTOM AI Constants
PHANTOM_VERSION = "3.0.0"
PHANTOM_CODENAME = "Enterprise Edition"

# Scan Modes
class ScanMode:
    """PHANTOM AI scan modes."""

    QUICK = "quick"           # Fast scan (5 modules)
    STANDARD = "standard"     # Standard scan (20 modules)
    THOROUGH = "thorough"     # Thorough scan (50+ modules)
    FULL = "full"             # Full scan (all 75+ modules)
    STEALTH = "stealth"       # Stealth mode with low rate limits
    BOUNTY = "bounty"         # Optimized for bug bounty platforms
    CLIENT = "client"         # Professional client engagement
    RECON = "recon"           # Reconnaissance only
    CHAIN = "chain"           # Vulnerability chaining focus


# Safety Levels
class SafetyLevel:
    """PHANTOM AI safety levels for ethical operation."""

    PASSIVE = "passive"       # No active testing, only observation
    SAFE = "safe"             # Safe payloads only, no exploitation
    CAUTIOUS = "cautious"     # Careful testing with rate limits
    STANDARD = "standard"     # Standard testing (default)
    AGGRESSIVE = "aggressive" # Aggressive testing (requires consent)


# Validation Stages
class ValidationStage:
    """6-stage validation pipeline stages."""

    DEDUPLICATION = 1         # Remove duplicate findings
    PATTERN_VERIFICATION = 2  # Verify response patterns
    SAFE_REPLAY = 3           # Replay with harmless payload
    NEGATIVE_CONTROL = 4      # Confirm baseline behavior
    CONTEXT_VALIDATION = 5    # Validate in application context
    AI_VERIFICATION = 6       # LLM-based final check


# Finding Confidence Thresholds
class ConfidenceThreshold:
    """Confidence thresholds for finding states."""

    SUSPECTED = 0.30          # 30-59%: Internal only
    DETECTED = 0.60           # 60-74%: Internal + analyst review
    CONFIRMED = 0.75          # 75-94%: Reported to user
    EXPLOITABLE = 0.95        # 95-100%: Priority report
    MINIMUM_REPORT = 0.75     # Minimum confidence to report


# Chain Priority Levels
class ChainPriority:
    """Priority levels for vulnerability chains."""

    CRITICAL = 10             # RCE chains, full compromise
    HIGH = 8                  # Credential extraction, data access
    MEDIUM = 5                # Access control bypass
    LOW = 3                   # Information disclosure
    INFO = 1                  # Informational only


# Target Metrics
class TargetMetrics:
    """PHANTOM AI success metrics targets."""

    FALSE_POSITIVE_RATE = 0.001    # < 0.1%
    DETECTION_COVERAGE = 0.95      # > 95% OWASP Top 10
    CHAIN_DEPTH = 3                # 3+ levels
    REQUEST_404_RATE = 0.05        # < 5%
    WAF_BYPASS_RATE = 0.70         # 70%+ WAFs


# Module categories - MUST match full_scanner.py CATEGORIES
MODULE_CATEGORIES = {
    # Basic categories
    "quick": ["headers", "ssl", "cors", "dir", "backend"],
    "web": ["sqli", "xss", "dom_xss", "cmdi", "lfi", "xxe", "ssrf", "csrf", "headers", "ssl", "cors"],
    "api": ["api", "graphql", "grpc", "websocket", "sse", "auth", "oauth", "ratelimit", "idor", "mass_assign"],
    "injection": ["sqli", "xss", "dom_xss", "cmdi", "xxe", "nosql", "ssti", "ldap", "crlf"],
    "auth": ["auth", "oauth", "saml", "mfa", "authz", "ratelimit", "idor", "csrf"],
    "infra": ["ssl", "headers", "cors", "cloud", "k8s", "dns_rebind", "supabase", "firebase"],
    "advanced": ["smuggling", "cache", "deser", "prototype", "dns_rebind", "rls_bypass"],

    # Standard scan - comprehensive web app testing (default for PHANTOM)
    "standard": [
        "headers", "ssl", "cors",           # Infrastructure basics
        "sqli", "xss", "dom_xss",           # Classic injections
        "csrf", "idor", "authz",            # Access control
        "api", "graphql",                   # API security
        "jwt", "auth", "oauth",             # Authentication
        "business",                         # Logic flaws
        "race",                             # Race conditions
        "ssrf", "lfi",                      # Server-side
        "open_redirect",                    # Redirect issues
        "info_disclosure",                  # Info leaks
        "clickjacking",                     # UI redressing
    ],

    # Smart scan - quick high-value modules
    "smart": ["sqli", "xss", "headers", "ssl", "cors", "dir", "auth", "api", "idor"],

    # TOP TIER BOUNTY HUNTING - Maximum bounty potential modules
    "bounty": [
        "idor",           # IDOR/BOLA detection - TOP VALUE $3k-$20k
        "sqli",           # SQL Injection - HIGH VALUE
        "xss",            # Reflected/Stored XSS
        "dom_xss",        # DOM-based XSS with browser execution
        "csrf",           # Cross-Site Request Forgery
        "authz",          # Authorization bypass
        "auth",           # Authentication vulnerabilities
        "jwt",            # JWT misconfigurations - HIGH VALUE
        "ssrf",           # Server-Side Request Forgery
        "business",       # Business logic flaws - HIGH VALUE
        "race",           # Race conditions - HIGH VALUE
        "mass_assign",    # Mass assignment
        "api",            # API security issues
        "graphql",        # GraphQL introspection/injection
        "open_redirect",  # Open redirects (chain potential)
        "cache_deception",  # Web cache deception
        "host_header",    # Host header attacks
        "supabase",       # Supabase RLS bypass
        "firebase",       # Firebase misconfigurations
        "rls_bypass",     # Row Level Security bypass
        "mobile",         # Mobile API vulnerabilities
    ],

    # BaaS focused scan
    "baas": ["supabase", "firebase", "rls_bypass", "backend", "third_party", "api"],

    # CLIENT - Professional engagement with ALL critical modules
    # For authorized pentests with no restrictions
    "client": [
        # Critical Injections (MUST run)
        "sqli", "xss", "dom_xss", "cmdi", "xxe", "ssrf", "lfi",
        "nosql", "ssti", "ldap", "crlf",
        # Authentication & Authorization
        "auth", "oauth", "saml", "mfa", "jwt", "authz", "idor",
        # API Security
        "api", "graphql", "grpc", "websocket", "sse",
        # Infrastructure
        "ssl", "headers", "cors", "cloud", "k8s", "dns_rebind",
        # Advanced Attacks
        "smuggling", "cache", "deser", "prototype", "cache_deception",
        # Business Logic
        "business", "race", "mass_assign", "ratelimit",
        # Discovery
        "dir", "cms", "nuclei", "backend", "third_party",
        # BaaS
        "supabase", "firebase", "rls_bypass",
        # Specialized
        "mobile", "email", "host_header", "clickjacking",
        "info_disclosure", "open_redirect", "file_upload",
        "cookie", "subdomain_takeover", "csrf",
    ],
}

# All module names (75+)
ALL_MODULES = [
    module
    for category_modules in MODULE_CATEGORIES.values()
    for module in category_modules
]


def get_version() -> str:
    """Get PHANTOM AI version string."""
    return f"PHANTOM AI v{PHANTOM_VERSION} ({PHANTOM_CODENAME})"


def get_module_count() -> int:
    """Get total number of available modules."""
    return len(ALL_MODULES)


# Module availability check
_initialized = False

def _ensure_initialized() -> None:
    """Ensure PHANTOM AI is properly initialized."""
    global _initialized
    if not _initialized:
        # Future: Initialize knowledge base, model manager, etc.
        _initialized = True


# =============================================================================
# LAZY IMPORTS - PHANTOM AI MODULES
# =============================================================================

# Network Protection
from phantom.network_protection import (
    PhantomNetworkProtection,
    PhantomNetworkConfig,
    KillSwitchConfig,
    KillSwitchTrigger,
    RequestOutcome,
    RequestRecord,
    DomainStatistics,
    get_phantom_protection,
    verify_target_and_protection,
    record_request_outcome,
)

# Technology Fingerprinter
from phantom.tech_fingerprinter import (
    TechFingerprinter,
    FingerprintResult,
    DetectedTechnology,
    TechCategory,
    SignatureDatabase,
)

# Parameter Analyzer
from phantom.parameter_analyzer import (
    ParameterAnalyzer,
    AnalyzedParameter,
    AnalysisResult,
    InferredType,
    VulnerabilityContext,
    ReflectionType,
)

# WAF Bypass Engine
from phantom.waf_bypass_engine import (
    WAFBypassEngine,
    WAFDetectionResult,
    WAFSignature,
    WAFSignatureDatabase,
    BehaviourFamily,
    BypassStrategy,
    BypassTechnique,
)

# Context Payload Selector
from phantom.context_payload_selector import (
    ContextPayloadSelector,
    PayloadContext,
    RankedPayload,
    SelectionResult,
    SelectionStrategy,
    PayloadPriority,
    TechPayloadMapper,
    ContextualPayloadGenerator,
    select_payloads_for_parameter,
)

# Module Executor
from phantom.module_executor import (
    ModuleExecutor,
    ModuleRegistry,
    ModuleConfig,
    ModuleResult,
    ModuleCategory,
    ModulePriority,
    ModuleState,
    ExecutionMode,
    ExecutorConfig,
    ExecutionProgress,
    BaseSecurityModule,
    register_module,
    get_module_executor,
    get_registry,
    execute_modules,
)

# Validation Pipeline
from phantom.validation_pipeline import (
    ValidationPipeline,
    ValidationConfig,
    ValidationStage,
    ValidationResult,
    FindingConfidence,
    VulnerabilityType,
    RawFinding,
    ValidatedFinding,
    StageResult,
    PatternMatcher,
    create_raw_finding,
    validate_findings,
)

# Impact Assessment
from phantom.impact_assessment import (
    ImpactAssessmentEngine,
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    ImpactLevel,
    SeverityLevel,
    IndustryContext,
    DataClassification,
    AssetCriticality,
    CIATriad,
    CVSSVector,
    FinancialImpact,
    RegulatoryImpact,
    BusinessContext,
    ImpactAssessmentResult,
    VULNERABILITY_PROFILES,
    REGULATORY_PROFILES,
    COST_PER_RECORD,
    BASE_BREACH_COST,
    assess_vulnerability,
    get_vulnerability_profile,
    calculate_cvss_score,
)

# Chain Visualization
from phantom.chain_visualization import (
    ChainVisualizationEngine,
    OutputFormat,
    NodeType,
    EdgeType,
    SeverityColor,
    LayoutAlgorithm,
    GraphNode,
    GraphEdge,
    AttackGraph,
    VisualizationConfig,
    create_chain_graph,
    visualize_chain,
    visualize_chains,
)

# SARIF Generator
from phantom.sarif_generator import (
    SARIFGenerator,
    SARIFLocation,
    SARIFWebLocation,
    SARIFFix,
    SARIFRule,
    SARIFResult,
    SARIFInvocation,
    SARIFArtifact,
    SARIFLevel,
    SARIFKind,
    SARIF_VERSION,
    VULNERABILITY_RULES,
    findings_to_sarif,
    create_sarif_generator,
)

# Bounty Estimator
from phantom.bounty_estimator import (
    BountyEstimator,
    ProgramConfig,
    BountyEstimate,
    ChainBountyEstimate,
    BountyPlatform,
    ProgramTier,
    VulnerabilityImpact,
    PLATFORM_RANGES,
    VULNERABILITY_MODIFIERS,
    IMPACT_MODIFIERS,
    CHAIN_BONUSES,
    estimate_bounty,
    create_program_config,
)

# Compliance Mapper
from phantom.compliance_mapper import (
    ComplianceMapper,
    CWEMapping,
    ComplianceMapping,
    ComplianceReport,
    ComplianceFramework,
    OWASPCategory,
    PCIDSSRequirement,
    NISTControlFamily,
    VULNERABILITY_TO_CWE,
    CWE_TO_OWASP,
    OWASP_TO_PCI_DSS,
    OWASP_TO_NIST,
    CWE_DATABASE,
    map_to_compliance,
    get_cwe_mapping,
    get_owasp_category,
)

# Knowledge Loader
from phantom.knowledge_loader import (
    KnowledgeLoader,
    KnowledgeEntry,
    PayloadCollection,
    TechniqueEntry,
    CVEEntry,
    LoaderStatistics,
    KnowledgeSource,
    KnowledgeType,
    VulnerabilityCategory,
    get_knowledge_loader,
    load_knowledge,
    search_knowledge,
    get_payloads,
)

# Adaptive Payload Engine
from phantom.adaptive_payload_engine import (
    AdaptivePayloadEngine,
    AdaptivePayload,
    PayloadResult,
    PayloadStats,
    PayloadMutator,
    PayloadType,
    EncodingType,
    MutationType,
    ContextType,
    encode_payload,
    get_adaptive_engine,
    get_adaptive_payloads,
    record_payload_result,
)


# Public API
__all__ = [
    # Version info
    "__version__",
    "PHANTOM_VERSION",
    "PHANTOM_CODENAME",
    "get_version",
    "get_module_count",

    # Enums/Constants
    "ScanMode",
    "SafetyLevel",
    "ValidationStage",
    "ConfidenceThreshold",
    "ChainPriority",
    "TargetMetrics",

    # Module info
    "MODULE_CATEGORIES",
    "ALL_MODULES",

    # Network Protection
    "PhantomNetworkProtection",
    "PhantomNetworkConfig",
    "KillSwitchConfig",
    "KillSwitchTrigger",
    "RequestOutcome",
    "RequestRecord",
    "DomainStatistics",
    "get_phantom_protection",
    "verify_target_and_protection",
    "record_request_outcome",

    # Technology Fingerprinter
    "TechFingerprinter",
    "FingerprintResult",
    "DetectedTechnology",
    "TechCategory",
    "SignatureDatabase",

    # Parameter Analyzer
    "ParameterAnalyzer",
    "AnalyzedParameter",
    "AnalysisResult",
    "InferredType",
    "VulnerabilityContext",
    "ReflectionType",

    # WAF Bypass Engine
    "WAFBypassEngine",
    "WAFDetectionResult",
    "WAFSignature",
    "WAFSignatureDatabase",
    "BehaviourFamily",
    "BypassStrategy",
    "BypassTechnique",

    # Context Payload Selector
    "ContextPayloadSelector",
    "PayloadContext",
    "RankedPayload",
    "SelectionResult",
    "SelectionStrategy",
    "PayloadPriority",
    "TechPayloadMapper",
    "ContextualPayloadGenerator",
    "select_payloads_for_parameter",

    # Module Executor
    "ModuleExecutor",
    "ModuleRegistry",
    "ModuleConfig",
    "ModuleResult",
    "ModuleCategory",
    "ModulePriority",
    "ModuleState",
    "ExecutionMode",
    "ExecutorConfig",
    "ExecutionProgress",
    "BaseSecurityModule",
    "register_module",
    "get_module_executor",
    "get_registry",
    "execute_modules",

    # Validation Pipeline
    "ValidationPipeline",
    "ValidationConfig",
    "ValidationStage",
    "ValidationResult",
    "FindingConfidence",
    "VulnerabilityType",
    "RawFinding",
    "ValidatedFinding",
    "StageResult",
    "PatternMatcher",
    "create_raw_finding",
    "validate_findings",

    # Impact Assessment
    "ImpactAssessmentEngine",
    "AttackVector",
    "AttackComplexity",
    "PrivilegesRequired",
    "UserInteraction",
    "Scope",
    "ImpactLevel",
    "SeverityLevel",
    "IndustryContext",
    "DataClassification",
    "AssetCriticality",
    "CIATriad",
    "CVSSVector",
    "FinancialImpact",
    "RegulatoryImpact",
    "BusinessContext",
    "ImpactAssessmentResult",
    "VULNERABILITY_PROFILES",
    "REGULATORY_PROFILES",
    "COST_PER_RECORD",
    "BASE_BREACH_COST",
    "assess_vulnerability",
    "get_vulnerability_profile",
    "calculate_cvss_score",

    # Chain Visualization
    "ChainVisualizationEngine",
    "OutputFormat",
    "NodeType",
    "EdgeType",
    "SeverityColor",
    "LayoutAlgorithm",
    "GraphNode",
    "GraphEdge",
    "AttackGraph",
    "VisualizationConfig",
    "create_chain_graph",
    "visualize_chain",
    "visualize_chains",

    # SARIF Generator
    "SARIFGenerator",
    "SARIFLocation",
    "SARIFWebLocation",
    "SARIFFix",
    "SARIFRule",
    "SARIFResult",
    "SARIFInvocation",
    "SARIFArtifact",
    "SARIFLevel",
    "SARIFKind",
    "SARIF_VERSION",
    "VULNERABILITY_RULES",
    "findings_to_sarif",
    "create_sarif_generator",

    # Bounty Estimator
    "BountyEstimator",
    "ProgramConfig",
    "BountyEstimate",
    "ChainBountyEstimate",
    "BountyPlatform",
    "ProgramTier",
    "VulnerabilityImpact",
    "PLATFORM_RANGES",
    "VULNERABILITY_MODIFIERS",
    "IMPACT_MODIFIERS",
    "CHAIN_BONUSES",
    "estimate_bounty",
    "create_program_config",

    # Compliance Mapper
    "ComplianceMapper",
    "CWEMapping",
    "ComplianceMapping",
    "ComplianceReport",
    "ComplianceFramework",
    "OWASPCategory",
    "PCIDSSRequirement",
    "NISTControlFamily",
    "VULNERABILITY_TO_CWE",
    "CWE_TO_OWASP",
    "OWASP_TO_PCI_DSS",
    "OWASP_TO_NIST",
    "CWE_DATABASE",
    "map_to_compliance",
    "get_cwe_mapping",
    "get_owasp_category",

    # Knowledge Loader
    "KnowledgeLoader",
    "KnowledgeEntry",
    "PayloadCollection",
    "TechniqueEntry",
    "CVEEntry",
    "LoaderStatistics",
    "KnowledgeSource",
    "KnowledgeType",
    "VulnerabilityCategory",
    "get_knowledge_loader",
    "load_knowledge",
    "search_knowledge",
    "get_payloads",

    # Adaptive Payload Engine
    "AdaptivePayloadEngine",
    "AdaptivePayload",
    "PayloadResult",
    "PayloadStats",
    "PayloadMutator",
    "PayloadType",
    "EncodingType",
    "MutationType",
    "ContextType",
    "encode_payload",
    "get_adaptive_engine",
    "get_adaptive_payloads",
    "record_payload_result",
]
