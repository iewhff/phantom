"""
Phase Definitions - Scan Phase Metadata and Constants.

Defines all scan phases with their metadata:
- Phase ID and display name
- Category (discovery, intelligence, execution, validation, reporting)
- Expected duration ranges
- Dependencies and skip conditions

Extracted from full_scanner.py for centralized phase management.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class PhaseCategory(Enum):
    """Categories of scan phases."""

    DISCOVERY = "discovery"         # Target discovery and classification
    INTELLIGENCE = "intelligence"   # Technology fingerprinting and analysis
    PREPARATION = "preparation"     # Auth acquisition, crawling, setup
    EXECUTION = "execution"         # Module execution
    ANALYSIS = "analysis"           # Finding analysis and enhancement
    VALIDATION = "validation"       # FP elimination and verification
    REPORTING = "reporting"         # Report generation and metrics


@dataclass
class PhaseInfo:
    """Metadata for a scan phase."""

    phase_id: str                           # e.g., "0", "0.5", "4.2"
    name: str                               # e.g., "Target Classification"
    category: PhaseCategory
    description: str = ""
    emoji: str = ""                         # Log emoji

    # Timing hints (seconds)
    min_duration: float = 0.0               # Minimum expected duration
    typical_duration: float = 5.0           # Typical duration
    max_duration: float = 60.0              # Maximum before warning

    # Dependencies
    requires_auth: bool = False             # Requires authenticated session
    requires_intelligent_mode: bool = False # Only in intelligent mode
    requires_modules: list[str] = field(default_factory=list)  # Required components

    # Skip conditions
    can_skip: bool = True                   # Can this phase be skipped?
    skip_in_safe_mode: bool = False         # Skip in safe mode?

    @property
    def log_prefix(self) -> str:
        """Get formatted log prefix."""
        return f"{self.emoji} Phase {self.phase_id}: {self.name}"

    @property
    def evidence_phase_id(self) -> str:
        """Get phase ID for evidence engine."""
        return f"{self.phase_id}_{self.name.lower().replace(' ', '_')}"


# ═══════════════════════════════════════════════════════════════════════════════
# Phase Definitions
# ═══════════════════════════════════════════════════════════════════════════════

PHASE_0 = PhaseInfo(
    phase_id="0",
    name="Target Classification",
    category=PhaseCategory.DISCOVERY,
    description="Classify target type and determine scan strategy",
    emoji="🎯",
    typical_duration=5.0,
    max_duration=30.0,
    requires_intelligent_mode=True,
    requires_modules=["target_classifier"],
)

PHASE_0_5 = PhaseInfo(
    phase_id="0.5",
    name="Enterprise Technology Intelligence",
    category=PhaseCategory.INTELLIGENCE,
    description="Enhanced technology stack detection",
    emoji="🔬",
    typical_duration=10.0,
    max_duration=60.0,
    requires_intelligent_mode=True,
    requires_modules=["tech_intelligence"],
)

PHASE_0_6 = PhaseInfo(
    phase_id="0.6",
    name="TechFingerprinter",
    category=PhaseCategory.INTELLIGENCE,
    description="Deep fingerprinting with 500+ signatures",
    emoji="🔬",
    typical_duration=15.0,
    max_duration=90.0,
    requires_intelligent_mode=True,
    requires_modules=["tech_fingerprinter"],
)

PHASE_0_7 = PhaseInfo(
    phase_id="0.7",
    name="Smart Endpoint Discovery",
    category=PhaseCategory.DISCOVERY,
    description="Intelligent endpoint mapping based on tech stack",
    emoji="🗺️",
    typical_duration=20.0,
    max_duration=120.0,
    requires_intelligent_mode=True,
    requires_modules=["smart_discovery"],
)

PHASE_0_75 = PhaseInfo(
    phase_id="0.75",
    name="Subdomain Enumeration",
    category=PhaseCategory.DISCOVERY,
    description="Discover subdomains for expanded attack surface",
    emoji="🌐",
    typical_duration=30.0,
    max_duration=180.0,
    can_skip=True,
    requires_modules=["subdomain_enum"],
)

PHASE_0_8 = PhaseInfo(
    phase_id="0.8",
    name="Domain Classification",
    category=PhaseCategory.INTELLIGENCE,
    description="Classify domain type and business context",
    emoji="🏢",
    typical_duration=5.0,
    max_duration=30.0,
    requires_modules=["domain_classifier"],
)

PHASE_0_9 = PhaseInfo(
    phase_id="0.9",
    name="Runtime Stack Profiling",
    category=PhaseCategory.INTELLIGENCE,
    description="Detect runtime environment and frameworks",
    emoji="🎯",
    typical_duration=10.0,
    max_duration=60.0,
    requires_modules=["runtime_awareness"],
)

PHASE_0_95 = PhaseInfo(
    phase_id="0.95",
    name="WAF Detection",
    category=PhaseCategory.INTELLIGENCE,
    description="Detect WAF presence for OPSEC considerations",
    emoji="🛡️",
    typical_duration=5.0,
    max_duration=30.0,
)

PHASE_1 = PhaseInfo(
    phase_id="1",
    name="Network Protection Verification",
    category=PhaseCategory.PREPARATION,
    description="Verify network safety guards are active",
    emoji="🛡️",
    typical_duration=1.0,
    max_duration=10.0,
    can_skip=False,
)

PHASE_1_5 = PhaseInfo(
    phase_id="1.5",
    name="Adaptive Timeout Calibration",
    category=PhaseCategory.PREPARATION,
    description="Measure target response times for timeout tuning",
    emoji="⏱️",
    typical_duration=5.0,
    max_duration=30.0,
    requires_modules=["timeout_manager"],
)

PHASE_2 = PhaseInfo(
    phase_id="2",
    name="Intelligent Pre-Scan Analysis",
    category=PhaseCategory.PREPARATION,
    description="Gather context before module execution",
    emoji="🔍",
    typical_duration=30.0,
    max_duration=180.0,
    requires_intelligent_mode=True,
)

PHASE_2_5_LINUX = PhaseInfo(
    phase_id="2.5",
    name="Linux Tools Orchestration",
    category=PhaseCategory.PREPARATION,
    description="Run external security tools (nmap, nuclei, etc.)",
    emoji="🔧",
    typical_duration=120.0,
    max_duration=600.0,
    skip_in_safe_mode=True,
    requires_modules=["linux_tools"],
)

PHASE_2_5_AUTH = PhaseInfo(
    phase_id="2.5",
    name="Auth Acquisition",
    category=PhaseCategory.PREPARATION,
    description="Acquire authentication tokens for testing",
    emoji="🔐",
    typical_duration=30.0,
    max_duration=120.0,
    requires_modules=["auth_context"],
)

PHASE_2_55 = PhaseInfo(
    phase_id="2.55",
    name="Session Watchdog",
    category=PhaseCategory.PREPARATION,
    description="Monitor authentication health during scan",
    emoji="👁️",
    typical_duration=1.0,
    max_duration=5.0,
    requires_auth=True,
)

PHASE_2_56 = PhaseInfo(
    phase_id="2.56",
    name="Auth Refresher",
    category=PhaseCategory.PREPARATION,
    description="Setup automatic token refresh",
    emoji="🔄",
    typical_duration=1.0,
    max_duration=5.0,
    requires_auth=True,
)

PHASE_2_6 = PhaseInfo(
    phase_id="2.6",
    name="Authenticated Re-Crawl",
    category=PhaseCategory.DISCOVERY,
    description="Crawl with auth to discover protected endpoints",
    emoji="🕷️",
    typical_duration=60.0,
    max_duration=300.0,
    requires_auth=True,
)

PHASE_2_7 = PhaseInfo(
    phase_id="2.7",
    name="Semantic Analyzer",
    category=PhaseCategory.INTELLIGENCE,
    description="Analyze endpoint semantics for business logic",
    emoji="🧠",
    typical_duration=10.0,
    max_duration=60.0,
    requires_modules=["semantic_analyzer"],
)

PHASE_2_9 = PhaseInfo(
    phase_id="2.9",
    name="Intent-Driven Module Prioritization",
    category=PhaseCategory.PREPARATION,
    description="Reorder modules based on attacker intent model",
    emoji="🎯",
    typical_duration=5.0,
    max_duration=30.0,
    requires_modules=["attacker_intent_engine"],
)

PHASE_3 = PhaseInfo(
    phase_id="3",
    name="Module Execution",
    category=PhaseCategory.EXECUTION,
    description="Execute scanning modules",
    emoji="🔄",
    typical_duration=300.0,
    max_duration=900.0,
    can_skip=False,
)

PHASE_3_5 = PhaseInfo(
    phase_id="3.5",
    name="Smart Retry",
    category=PhaseCategory.EXECUTION,
    description="Retry failed modules with backoff",
    emoji="🔄",
    typical_duration=60.0,
    max_duration=300.0,
)

PHASE_4_1 = PhaseInfo(
    phase_id="4.1",
    name="Early Finding Share",
    category=PhaseCategory.ANALYSIS,
    description="Share findings for cross-module feedback",
    emoji="📤",
    typical_duration=1.0,
    max_duration=5.0,
)

PHASE_4_2 = PhaseInfo(
    phase_id="4.2",
    name="Exploitation Proof Engine",
    category=PhaseCategory.ANALYSIS,
    description="Verify and prove exploitability",
    emoji="💥",
    typical_duration=60.0,
    max_duration=300.0,
    requires_modules=["exploit_proof_engine"],
)

PHASE_4_3 = PhaseInfo(
    phase_id="4.3",
    name="Impact Validation",
    category=PhaseCategory.ANALYSIS,
    description="Validate business impact of findings",
    emoji="⚡",
    typical_duration=30.0,
    max_duration=120.0,
    requires_modules=["impact_validator"],
)

PHASE_4_35 = PhaseInfo(
    phase_id="4.35",
    name="Vulnerability Chain Processing",
    category=PhaseCategory.ANALYSIS,
    description="Discover attack chains (SQLi→RCE, etc.)",
    emoji="🔗",
    typical_duration=30.0,
    max_duration=120.0,
    requires_modules=["vuln_chain_engine"],
)

PHASE_4_45 = PhaseInfo(
    phase_id="4.45",
    name="Exploitability Classification",
    category=PhaseCategory.ANALYSIS,
    description="Classify exposure level (PARTIAL/FULL)",
    emoji="🎯",
    typical_duration=10.0,
    max_duration=60.0,
    requires_modules=["exploitability_classifier"],
)

PHASE_4_46 = PhaseInfo(
    phase_id="4.46",
    name="Attacker Intent Analysis",
    category=PhaseCategory.ANALYSIS,
    description="Enhance findings with attacker perspective",
    emoji="🎯",
    typical_duration=10.0,
    max_duration=60.0,
    requires_modules=["attacker_intent_engine"],
)

PHASE_4_47 = PhaseInfo(
    phase_id="4.47",
    name="Attack Chain Analysis",
    category=PhaseCategory.ANALYSIS,
    description="Intent-aware chain discovery",
    emoji="🔗",
    typical_duration=20.0,
    max_duration=90.0,
    requires_modules=["attack_chain_analyzer"],
)

PHASE_4_49 = PhaseInfo(
    phase_id="4.49",
    name="Attacker Cost Model",
    category=PhaseCategory.ANALYSIS,
    description="Prioritize by time×risk×payoff",
    emoji="💰",
    typical_duration=5.0,
    max_duration=30.0,
    requires_modules=["attacker_intent_engine"],
)

PHASE_4_5 = PhaseInfo(
    phase_id="4.5",
    name="Cross-Module Deduplication",
    category=PhaseCategory.ANALYSIS,
    description="Remove duplicate findings across modules",
    emoji="🔄",
    typical_duration=5.0,
    max_duration=30.0,
)

PHASE_4_52 = PhaseInfo(
    phase_id="4.52",
    name="Scan Amplification",
    category=PhaseCategory.ANALYSIS,
    description="Execute pending amplification actions",
    emoji="🔄",
    typical_duration=60.0,
    max_duration=300.0,
    requires_modules=["amplification_engine"],
)

PHASE_4_53 = PhaseInfo(
    phase_id="4.53",
    name="Post-Amplification Dedup",
    category=PhaseCategory.ANALYSIS,
    description="Deduplicate after amplification",
    emoji="🔄",
    typical_duration=2.0,
    max_duration=10.0,
)

PHASE_4_55 = PhaseInfo(
    phase_id="4.55",
    name="State-Aware Retest",
    category=PhaseCategory.VALIDATION,
    description="Compare auth vs no-auth behavior",
    emoji="🔄",
    typical_duration=30.0,
    max_duration=120.0,
    requires_auth=True,
)

PHASE_4_56 = PhaseInfo(
    phase_id="4.56",
    name="Cross-User Identity Variation",
    category=PhaseCategory.VALIDATION,
    description="Test cross-user access patterns",
    emoji="🔄",
    typical_duration=30.0,
    max_duration=120.0,
    requires_auth=True,
)

PHASE_4_6 = PhaseInfo(
    phase_id="4.6",
    name="Exploit Escalation",
    category=PhaseCategory.ANALYSIS,
    description="Escalate CRITICAL findings for exploitation",
    emoji="🚀",
    typical_duration=60.0,
    max_duration=300.0,
    skip_in_safe_mode=True,
)

PHASE_4_65 = PhaseInfo(
    phase_id="4.65",
    name="Share Validated Findings",
    category=PhaseCategory.ANALYSIS,
    description="Share validated findings to store",
    emoji="📤",
    typical_duration=1.0,
    max_duration=5.0,
)

PHASE_4_7 = PhaseInfo(
    phase_id="4.7",
    name="Neural Attack Analysis",
    category=PhaseCategory.ANALYSIS,
    description="AI-driven attack planning from signals",
    emoji="🧠",
    typical_duration=60.0,
    max_duration=300.0,
    requires_modules=["neural_attack_planner"],
)

PHASE_5 = PhaseInfo(
    phase_id="5",
    name="Finalize Intelligent Scan",
    category=PhaseCategory.VALIDATION,
    description="Finalize scan and prepare for validation",
    emoji="✅",
    typical_duration=5.0,
    max_duration=30.0,
)

PHASE_5_1 = PhaseInfo(
    phase_id="5.1",
    name="ValidationPipeline",
    category=PhaseCategory.VALIDATION,
    description="6-stage false positive elimination",
    emoji="🔬",
    typical_duration=30.0,
    max_duration=180.0,
    requires_modules=["validation_pipeline"],
)

PHASE_5_2 = PhaseInfo(
    phase_id="5.2",
    name="Second-Order Detection",
    category=PhaseCategory.VALIDATION,
    description="Detect second-order vulnerabilities",
    emoji="🔍",
    typical_duration=30.0,
    max_duration=120.0,
    requires_modules=["second_order_tracker"],
)

PHASE_5_5 = PhaseInfo(
    phase_id="5.5",
    name="Evidence Compilation",
    category=PhaseCategory.REPORTING,
    description="Compile evidence packages for report",
    emoji="📦",
    typical_duration=10.0,
    max_duration=60.0,
    requires_modules=["evidence_engine"],
)

PHASE_6_5 = PhaseInfo(
    phase_id="6.5",
    name="Coverage Metrics",
    category=PhaseCategory.REPORTING,
    description="Calculate coverage and explosion metrics",
    emoji="📊",
    typical_duration=5.0,
    max_duration=30.0,
)


# ═══════════════════════════════════════════════════════════════════════════════
# Phase Registry
# ═══════════════════════════════════════════════════════════════════════════════

# All phases in execution order
ALL_PHASES: list[PhaseInfo] = [
    PHASE_0,
    PHASE_0_5,
    PHASE_0_6,
    PHASE_0_7,
    PHASE_0_75,
    PHASE_0_8,
    PHASE_0_9,
    PHASE_0_95,
    PHASE_1,
    PHASE_1_5,
    PHASE_2,
    PHASE_2_5_LINUX,
    PHASE_2_5_AUTH,
    PHASE_2_55,
    PHASE_2_56,
    PHASE_2_6,
    PHASE_2_7,
    PHASE_2_9,
    PHASE_3,
    PHASE_3_5,
    PHASE_4_1,
    PHASE_4_2,
    PHASE_4_3,
    PHASE_4_35,
    PHASE_4_45,
    PHASE_4_46,
    PHASE_4_47,
    PHASE_4_49,
    PHASE_4_5,
    PHASE_4_52,
    PHASE_4_53,
    PHASE_4_55,
    PHASE_4_56,
    PHASE_4_6,
    PHASE_4_65,
    PHASE_4_7,
    PHASE_5,
    PHASE_5_1,
    PHASE_5_2,
    PHASE_5_5,
    PHASE_6_5,
]

# Phase lookup by ID
PHASES_BY_ID: dict[str, PhaseInfo] = {p.phase_id: p for p in ALL_PHASES}

# Phases by category
PHASES_BY_CATEGORY: dict[PhaseCategory, list[PhaseInfo]] = {}
for phase in ALL_PHASES:
    if phase.category not in PHASES_BY_CATEGORY:
        PHASES_BY_CATEGORY[phase.category] = []
    PHASES_BY_CATEGORY[phase.category].append(phase)


def get_phase(phase_id: str) -> Optional[PhaseInfo]:
    """Get phase info by ID.

    Args:
        phase_id: Phase identifier (e.g., "0", "4.2")

    Returns:
        PhaseInfo or None if not found
    """
    return PHASES_BY_ID.get(phase_id)


def get_phases_for_category(category: PhaseCategory) -> list[PhaseInfo]:
    """Get all phases in a category.

    Args:
        category: Phase category

    Returns:
        List of phases in category
    """
    return PHASES_BY_CATEGORY.get(category, [])


def get_phase_count() -> int:
    """Get total number of defined phases."""
    return len(ALL_PHASES)


def get_typical_scan_duration() -> float:
    """Get sum of typical durations for all phases."""
    return sum(p.typical_duration for p in ALL_PHASES)
