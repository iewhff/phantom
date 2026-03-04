"""
🤖 PATHFINDER AI - Your Friendly Neighborhood Security Scout

"Hi friends! I'm here to help you find vulnerabilities!" 🪝

Enterprise-grade AI-powered penetration testing framework.
Inspired by Apex Legends' favorite MRVN unit - always positive, always grappling!

Version: 3.0.0
Date: 2026-02-18
License: MIT

PATHFINDER AI Philosophy:
1. Intelligence Before Force - "First I scan, then I grapple!"
2. Vulnerabilities Discover Vulnerabilities - "Like a zipline connecting two points!"
3. Detection, Not Destruction - "I'm a lover, not a fighter! ...well, maybe both."

Usage:
    from pathfinder import PathfinderNetworkProtection, get_version

    protection = get_pathfinder_protection()
    print(get_version())  # "PATHFINDER AI v3.0.0 (Apex Edition)"

"Who's ready to fly on a zipline? I AM!" 🪝
"""

from __future__ import annotations

# =============================================================================
# PATHFINDER AI CONSTANTS
# =============================================================================

__version__ = "3.0.0"
__author__ = "PATHFINDER AI Team"
__license__ = "MIT"

PATHFINDER_VERSION = "3.0.0"
PATHFINDER_CODENAME = "Apex Edition"

# Legacy aliases for backwards compatibility
PHANTOM_VERSION = PATHFINDER_VERSION
PHANTOM_CODENAME = PATHFINDER_CODENAME


def get_version() -> str:
    """Get PATHFINDER AI version string."""
    return f"PATHFINDER AI v{PATHFINDER_VERSION} ({PATHFINDER_CODENAME})"


def get_module_count() -> int:
    """Get total number of available modules."""
    from phantom import get_module_count as _get_count
    return _get_count()


# =============================================================================
# RE-EXPORT EVERYTHING FROM PHANTOM WITH PATHFINDER NAMES
# =============================================================================

# Import all from phantom (the actual implementation)
from phantom import (
    # Enums/Constants
    ScanMode,
    SafetyLevel,
    ValidationStage,
    ConfidenceThreshold,
    ChainPriority,
    TargetMetrics,
    MODULE_CATEGORIES,
    ALL_MODULES,

    # Network Protection - import and alias
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

    # Tech Fingerprinter
    TechFingerprinter,
    FingerprintResult,
    DetectedTechnology,
    TechCategory,
    SignatureDatabase,

    # Parameter Analyzer
    ParameterAnalyzer,
    AnalyzedParameter,
    AnalysisResult,
    InferredType,
    VulnerabilityContext,
    ReflectionType,

    # WAF Bypass Engine
    WAFBypassEngine,
    WAFDetectionResult,
    WAFSignature,
    WAFSignatureDatabase,
    BehaviourFamily,
    BypassStrategy,
    BypassTechnique,

    # Context Payload Selector
    ContextPayloadSelector,
    PayloadContext,
    RankedPayload,
    SelectionResult,
    SelectionStrategy,
    PayloadPriority,
    TechPayloadMapper,
    ContextualPayloadGenerator,
    select_payloads_for_parameter,

    # Module Executor
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

    # Validation Pipeline
    ValidationPipeline,
    ValidationConfig,
    ValidationResult,
    FindingConfidence,
    VulnerabilityType,
    RawFinding,
    ValidatedFinding,
    StageResult,
    PatternMatcher,
    create_raw_finding,
    validate_findings,

    # Impact Assessment
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

    # Chain Visualization
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

    # SARIF Generator
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

    # Bounty Estimator
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

    # Compliance Mapper
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

    # Knowledge Loader
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

    # Adaptive Payload Engine
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

# =============================================================================
# PATHFINDER ALIASES - The New Hotness! 🤖
# =============================================================================

# Network Protection - Pathfinder branded aliases
PathfinderNetworkProtection = PhantomNetworkProtection
PathfinderNetworkConfig = PhantomNetworkConfig
get_pathfinder_protection = get_phantom_protection

# =============================================================================
# PATHFINDER SUBMODULE ACCESS
# =============================================================================

# Allow importing submodules like: from pathfinder.hackerone_report_generator import ...
import sys
import importlib

class PathfinderModuleProxy:
    """Proxy to redirect pathfinder.X imports to phantom.X"""

    def __init__(self, name):
        self._name = name

    def __getattr__(self, attr):
        # Import the actual phantom module
        phantom_module = f"phantom.{attr}"
        try:
            return importlib.import_module(phantom_module)
        except ImportError:
            raise AttributeError(f"module 'pathfinder' has no attribute '{attr}'")

# Install the proxy for submodule imports
sys.modules['pathfinder.hackerone_report_generator'] = importlib.import_module('phantom.hackerone_report_generator')
sys.modules['pathfinder.client_report_generator'] = importlib.import_module('phantom.client_report_generator')
sys.modules['pathfinder.network_protection'] = importlib.import_module('phantom.network_protection')
sys.modules['pathfinder.tech_fingerprinter'] = importlib.import_module('phantom.tech_fingerprinter')
sys.modules['pathfinder.parameter_analyzer'] = importlib.import_module('phantom.parameter_analyzer')
sys.modules['pathfinder.waf_bypass_engine'] = importlib.import_module('phantom.waf_bypass_engine')
sys.modules['pathfinder.context_payload_selector'] = importlib.import_module('phantom.context_payload_selector')
sys.modules['pathfinder.module_executor'] = importlib.import_module('phantom.module_executor')
sys.modules['pathfinder.validation_pipeline'] = importlib.import_module('phantom.validation_pipeline')
sys.modules['pathfinder.impact_assessment'] = importlib.import_module('phantom.impact_assessment')
sys.modules['pathfinder.chain_visualization'] = importlib.import_module('phantom.chain_visualization')
sys.modules['pathfinder.sarif_generator'] = importlib.import_module('phantom.sarif_generator')
sys.modules['pathfinder.bounty_estimator'] = importlib.import_module('phantom.bounty_estimator')
sys.modules['pathfinder.compliance_mapper'] = importlib.import_module('phantom.compliance_mapper')
sys.modules['pathfinder.knowledge_loader'] = importlib.import_module('phantom.knowledge_loader')
sys.modules['pathfinder.adaptive_payload_engine'] = importlib.import_module('phantom.adaptive_payload_engine')
sys.modules['pathfinder.chain_actions'] = importlib.import_module('phantom.chain_actions')
sys.modules['pathfinder.handoff_generator'] = importlib.import_module('phantom.handoff_generator')

# =============================================================================
# PUBLIC API
# =============================================================================

__all__ = [
    # Pathfinder branded
    "__version__",
    "PATHFINDER_VERSION",
    "PATHFINDER_CODENAME",
    "get_version",
    "get_module_count",
    "PathfinderNetworkProtection",
    "PathfinderNetworkConfig",
    "get_pathfinder_protection",

    # Legacy aliases
    "PHANTOM_VERSION",
    "PHANTOM_CODENAME",
    "PhantomNetworkProtection",
    "PhantomNetworkConfig",
    "get_phantom_protection",

    # All the rest from phantom
    "ScanMode",
    "SafetyLevel",
    "ValidationStage",
    "ConfidenceThreshold",
    "ChainPriority",
    "TargetMetrics",
    "MODULE_CATEGORIES",
    "ALL_MODULES",
    "KillSwitchConfig",
    "KillSwitchTrigger",
    "RequestOutcome",
    "RequestRecord",
    "DomainStatistics",
    "verify_target_and_protection",
    "record_request_outcome",
    "TechFingerprinter",
    "FingerprintResult",
    "DetectedTechnology",
    "TechCategory",
    "SignatureDatabase",
    "ParameterAnalyzer",
    "AnalyzedParameter",
    "AnalysisResult",
    "InferredType",
    "VulnerabilityContext",
    "ReflectionType",
    "WAFBypassEngine",
    "WAFDetectionResult",
    "WAFSignature",
    "WAFSignatureDatabase",
    "BehaviourFamily",
    "BypassStrategy",
    "BypassTechnique",
    "ContextPayloadSelector",
    "PayloadContext",
    "RankedPayload",
    "SelectionResult",
    "SelectionStrategy",
    "PayloadPriority",
    "TechPayloadMapper",
    "ContextualPayloadGenerator",
    "select_payloads_for_parameter",
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
    "ValidationPipeline",
    "ValidationConfig",
    "ValidationResult",
    "FindingConfidence",
    "VulnerabilityType",
    "RawFinding",
    "ValidatedFinding",
    "StageResult",
    "PatternMatcher",
    "create_raw_finding",
    "validate_findings",
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
