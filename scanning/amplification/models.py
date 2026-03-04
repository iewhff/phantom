"""
Amplification Models - Data classes and enums for the amplification system.

Extracted from full_scanner.py for modularization.
"""

from dataclasses import dataclass, field
from enum import Enum


@dataclass
class AmplificationAction:
    """An action to take based on a discovered finding."""
    trigger_type: str           # What type of finding triggered this
    action: str                 # "retest_endpoint", "expand_ids", "try_method", etc.
    target: str                 # URL or endpoint to act on
    params: dict = field(default_factory=dict)  # Action-specific parameters
    priority: int = 5           # 1-10, higher = more important
    # Guardrail tracking
    finding_id: str = ""        # Which finding triggered this
    retry_count: int = 0        # How many times this action was retried
    cost: int = 1               # Budget cost (heavy actions cost more)


class GuardrailBlockReason(Enum):
    """
    Reasons why an action was blocked by guardrails.

    Used for:
    - Tuning guardrail parameters
    - Reporting to client ("não testámos X porque...")
    - Debugging amplification issues
    """
    BUDGET_EXCEEDED = "global_budget_exceeded"
    PER_FINDING_LIMIT = "max_actions_per_finding_reached"
    RETRY_LIMIT = "max_retries_exceeded"
    DUPLICATE_ACTION = "action_in_dedup_window"
    LOOP_DETECTED = "max_graph_depth_exceeded"
    SOFT_SUSPENDED = "finding_soft_suspended"
    HARD_SUSPENDED = "finding_hard_suspended"
    NO_STATE_CHANGE = "no_state_change_detected"
    BACKOFF_ACTIVE = "exponential_backoff_active"
    LOW_PROGRESS_SCORE = "progress_score_too_low"


class SuspensionLevel(Enum):
    """
    Suspension levels for findings.

    SOFT: Priority drops to near-zero, can be revived with new surface
    HARD: Finding is dead, no further actions allowed
    """
    NONE = "none"
    SOFT = "soft"       # Priority near zero, can revive
    HARD = "hard"       # Dead, no actions allowed


@dataclass
class ProgressMetrics:
    """
    Tracks progress metrics for a finding to detect "dead" targets.

    Philosophy: "Don't insist on dead targets"

    progress_score = new_state_changes * 3 + new_endpoints * 2 + new_headers * 1 - retries * 2
    If progress_score <= -5 → early suspension
    """
    new_state_changes: int = 0
    new_endpoints: int = 0
    new_headers: int = 0
    new_findings: int = 0
    retries: int = 0
    actions_total: int = 0

    @property
    def progress_score(self) -> int:
        """Calculate progress score. Negative = target is dead."""
        return (
            self.new_state_changes * 3 +
            self.new_endpoints * 2 +
            self.new_headers * 1 +
            self.new_findings * 5 -  # New findings are very valuable
            self.retries * 2
        )

    @property
    def is_dead_target(self) -> bool:
        """Check if target should be considered dead."""
        return self.progress_score <= -5 and self.actions_total >= 3


@dataclass
class AmplificationGuardrails:
    """
    Safety guardrails for the feedback loop between modules.

    Philosophy: "Feedback loops are powerful but dangerous. Without limits,
    they cause resource exhaustion, state explosion, and cascading failures."

    These guardrails prevent:
    - Resource exhaustion / DoS on target
    - State explosion from combinatorial growth
    - Oscillation (A triggers B, B fails, A retries → chaos)
    - Report spam from excessive attempts
    - Cascading failures from dependent modules
    """

    # === CAPS ===
    max_actions_per_finding: int = 20     # Limit actions from single finding
    max_retries_per_action: int = 3       # Don't retry same action forever
    max_concurrent_per_finding: int = 4   # Limit parallel amplifications
    global_action_budget: int = 1000      # Total budget per scan

    # === TIME LIMITS ===
    action_ttl_seconds: int = 600         # Don't re-apply action within this window
    focus_lock_timeout: int = 300         # Already implemented in FocusLock

    # === DECAY & BACKOFF ===
    priority_decay_on_failure: float = 0.8   # Multiply priority by this on each failure
    exponential_backoff_base: int = 2        # Retry wait = base^n seconds
    soft_suspend_threshold: int = 5          # After N consecutive failures → SOFT suspend
    hard_suspend_threshold: int = 10         # After N consecutive failures → HARD suspend
    progress_score_suspend: int = -5         # Suspend if progress_score <= this

    # Legacy alias
    @property
    def failure_threshold_to_suspend(self) -> int:
        return self.soft_suspend_threshold

    # === DEDUP ===
    same_action_dedup_window: int = 300      # Seconds before allowing same action again
    max_technical_chains: int = 3            # Already implemented in chain analyzer

    # === COST WEIGHTING ===
    # Heavy actions cost more budget (higher = more expensive)
    action_costs: dict = field(default_factory=lambda: {
        # IDOR & Access Control
        "expand_idor_range": 3,              # Tests many IDs
        "test_method_escalation": 2,         # Tests HTTP methods (4 requests max)

        # Auth
        "probe_admin_endpoints": 3,          # Runs authz module
        "try_auth_bypass_variants": 2,       # Tests path variants (7 max)
        "auth_bypass_via_smuggling": 4,      # Smuggling + auth test

        # SQLi
        "expand_sqli_extraction": 3,         # Multiple extraction queries
        "try_sqli_post": 1,                  # Single POST request

        # XSS
        "try_xss_alternatives": 2,           # Tests 5 payloads max
        "xss_via_smuggling": 3,              # Crafted smuggled requests

        # Business Logic
        "test_race_condition": 5,            # Many concurrent requests

        # HTTP Smuggling amplifications
        "cache_poison_via_smuggling": 4,     # Crafted + verification request
        "rescan_with_desync": 4,             # Re-runs multiple modules

        # Cross-module
        "run_cross_module": 2,               # Runs another module

        # Default cost for unlisted actions
        "default": 1,
    })


@dataclass
class ActionFingerprint:
    """Unique identifier for an action to prevent duplicates."""
    finding_id: str
    action_type: str
    target: str
    param_hash: str  # Hash of params for comparison

    def __hash__(self) -> int:
        return hash((self.finding_id, self.action_type, self.target, self.param_hash))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ActionFingerprint):
            return False
        return (
            self.finding_id == other.finding_id and
            self.action_type == other.action_type and
            self.target == other.target and
            self.param_hash == other.param_hash
        )
