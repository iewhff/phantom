"""
PHANTOM AI - Focus Lock System

Philosophy: "Um pentester não dispersa. Quando encontra ouro, cava até ao fim."

When a promising finding is discovered, the scanner enters "focus mode"
for that vulnerability category, prioritizing all related testing until
the hypothesis is exhausted.

This implements GAP-A: Strategic depth, not just tactical depth.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# EXHAUSTION HEURISTICS CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

# Maximum time to stay in focus mode (seconds)
MAX_FOCUS_DURATION_SECONDS = 300  # 5 minutes

# Maximum consecutive failures before reducing priority
MAX_CONSECUTIVE_FAILURES = 5

# Priority reduction per consecutive failure
PRIORITY_REDUCTION_PER_FAILURE = 10

# Minimum priority boost (never go below this)
MIN_PRIORITY_BOOST = 10

# Success rate threshold below which we reduce priority
LOW_SUCCESS_RATE_THRESHOLD = 0.1  # 10%

# Minimum vectors to try before considering success rate
MIN_VECTORS_FOR_RATE_CALC = 3


class FocusCategory(Enum):
    """Categories that can receive focus lock."""
    JWT_ABUSE = auto()
    AUTH_BYPASS = auto()
    INJECTION = auto()
    BUSINESS_LOGIC = auto()
    DATA_ACCESS = auto()
    SESSION_ABUSE = auto()
    PRIVILEGE_ESCALATION = auto()
    # Infrastructure-grade findings (GAP-2.4: Exploit Escalation Phase)
    INFRASTRUCTURE = auto()


@dataclass
class FocusHypothesis:
    """
    A hypothesis being tested during focus mode.

    Example: "This application has weak JWT validation"
    - Vectors tried: alg_none, kid_injection, replay
    - Vectors succeeded: replay
    - Confidence in hypothesis: 75%

    Enhanced with exhaustion heuristics:
    - Time tracking for timeout-based release
    - Consecutive failure tracking for adaptive priority
    - Cross-endpoint tracking for persistence
    """
    category: FocusCategory
    description: str
    trigger_finding: dict
    vectors_tried: list[str] = field(default_factory=list)
    vectors_succeeded: list[str] = field(default_factory=list)
    vectors_remaining: list[str] = field(default_factory=list)
    confidence: float = 50.0  # 0-100, increases with successes
    is_exhausted: bool = False

    # Exhaustion heuristics
    start_time: float = field(default_factory=time.time)
    consecutive_failures: int = 0
    endpoints_tested: set[str] = field(default_factory=set)
    current_priority_boost: int = 50  # Starts at max, decreases on failures

    def try_vector(self, vector: str, succeeded: bool, endpoint: str = "") -> None:
        """Record a vector attempt with adaptive feedback."""
        if vector in self.vectors_remaining:
            self.vectors_remaining.remove(vector)
        if vector not in self.vectors_tried:
            self.vectors_tried.append(vector)

        # Track endpoint for cross-endpoint persistence
        if endpoint:
            self.endpoints_tested.add(endpoint)

        if succeeded and vector not in self.vectors_succeeded:
            self.vectors_succeeded.append(vector)
            # Increase confidence on success
            self.confidence = min(100.0, self.confidence + 15)
            # Reset consecutive failures on success
            self.consecutive_failures = 0
            # Restore priority boost on success
            self.current_priority_boost = min(
                50, self.current_priority_boost + 10
            )
        elif not succeeded:
            # Slight decrease on failure
            self.confidence = max(20.0, self.confidence - 5)
            # Track consecutive failures
            self.consecutive_failures += 1
            # Reduce priority if too many consecutive failures
            if self.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                self.current_priority_boost = max(
                    MIN_PRIORITY_BOOST,
                    self.current_priority_boost - PRIORITY_REDUCTION_PER_FAILURE
                )
                logger.debug(
                    f"[FOCUS] {self.consecutive_failures} consecutive failures, "
                    f"priority boost reduced to {self.current_priority_boost}"
                )

        # Check if exhausted
        if not self.vectors_remaining:
            self.is_exhausted = True
            logger.info(
                f"[FOCUS] Hypothesis '{self.description}' EXHAUSTED. "
                f"Tried: {len(self.vectors_tried)}, Succeeded: {len(self.vectors_succeeded)}"
            )

    def is_timed_out(self) -> bool:
        """Check if focus has exceeded maximum duration."""
        elapsed = time.time() - self.start_time
        return elapsed > MAX_FOCUS_DURATION_SECONDS

    def should_reduce_priority(self) -> bool:
        """Check if priority should be reduced due to low success rate."""
        if len(self.vectors_tried) < MIN_VECTORS_FOR_RATE_CALC:
            return False
        success_rate = len(self.vectors_succeeded) / len(self.vectors_tried)
        return success_rate < LOW_SUCCESS_RATE_THRESHOLD

    @property
    def elapsed_seconds(self) -> float:
        """Time since focus was activated."""
        return time.time() - self.start_time

    @property
    def success_rate(self) -> float:
        """Percentage of vectors that succeeded."""
        if not self.vectors_tried:
            return 0.0
        return (len(self.vectors_succeeded) / len(self.vectors_tried)) * 100

    @property
    def progress(self) -> float:
        """Percentage of vectors tried."""
        total = len(self.vectors_tried) + len(self.vectors_remaining)
        if total == 0:
            return 100.0
        return (len(self.vectors_tried) / total) * 100


class FocusLock:
    """
    Strategic focus system.

    When a promising finding is discovered, the scanner enters
    "focus mode" for that vulnerability category, prioritizing
    all related testing until exhausted.

    Key behaviors:
    1. Activate focus when HIGH+ finding in a category
    2. Boost priority for all modules in that category
    3. Track hypothesis and vectors tried
    4. Only release focus when exhausted or budget exceeded
    """

    # Map focus categories to related modules
    CATEGORY_MODULES: dict[FocusCategory, list[str]] = {
        FocusCategory.JWT_ABUSE: [
            "jwt", "session_abuse", "auth", "creative_exploiter",
            "auth_jwt", "oauth",
        ],
        FocusCategory.AUTH_BYPASS: [
            "authz", "auth", "creative_exploiter", "session_abuse",
            "auth_bypass", "auth_login", "mfa_bypass",
        ],
        FocusCategory.INJECTION: [
            "sqli", "nosql", "cmdi", "ssti", "xss", "xxe", "lfi",
            "ssrf", "ldap_xpath", "dom_xss",
        ],
        FocusCategory.BUSINESS_LOGIC: [
            "business", "race", "creative_exploiter", "idor",
            "api_logic", "workflow_inference",
        ],
        FocusCategory.DATA_ACCESS: [
            "idor", "authz", "business", "api_logic", "mass_assignment",
            "info_disclosure",
        ],
        FocusCategory.SESSION_ABUSE: [
            "session_abuse", "jwt", "auth", "csrf", "cookie_security",
        ],
        FocusCategory.PRIVILEGE_ESCALATION: [
            "authz", "auth_privesc", "mass_assignment", "idor",
            "creative_exploiter",
        ],
        # Infrastructure-grade modules (GAP-2.4: Exploit Escalation Phase)
        FocusCategory.INFRASTRUCTURE: [
            "smuggling", "deserialization", "kubernetes", "cloud",
            "file_upload", "subdomain_takeover", "ssl", "header_security",
            "config_exposure", "git_exposure", "cicd", "container",
        ],
    }

    # Map finding types to focus categories
    FINDING_TO_CATEGORY: dict[str, FocusCategory] = {
        # JWT findings
        "jwt": FocusCategory.JWT_ABUSE,
        "jwt_weakness": FocusCategory.JWT_ABUSE,
        "jwt_none_alg": FocusCategory.JWT_ABUSE,
        "session_abuse": FocusCategory.SESSION_ABUSE,

        # Auth findings
        "auth_bypass": FocusCategory.AUTH_BYPASS,
        "authentication_bypass": FocusCategory.AUTH_BYPASS,
        "mfa_bypass": FocusCategory.AUTH_BYPASS,

        # Injection findings
        "sqli": FocusCategory.INJECTION,
        "sql_injection": FocusCategory.INJECTION,
        "xss": FocusCategory.INJECTION,
        "cmdi": FocusCategory.INJECTION,
        "command_injection": FocusCategory.INJECTION,
        "ssti": FocusCategory.INJECTION,
        "xxe": FocusCategory.INJECTION,
        "lfi": FocusCategory.INJECTION,
        "ssrf": FocusCategory.INJECTION,

        # Business logic
        "business_logic": FocusCategory.BUSINESS_LOGIC,
        "race_condition": FocusCategory.BUSINESS_LOGIC,

        # Data access
        "idor": FocusCategory.DATA_ACCESS,
        "authorization": FocusCategory.DATA_ACCESS,
        "access_control": FocusCategory.DATA_ACCESS,

        # Privilege escalation
        "privilege_escalation": FocusCategory.PRIVILEGE_ESCALATION,
        "vertical_escalation": FocusCategory.PRIVILEGE_ESCALATION,

        # Infrastructure findings (GAP-2.4: Exploit Escalation Phase)
        "http_smuggling": FocusCategory.INFRASTRUCTURE,
        "request_smuggling": FocusCategory.INFRASTRUCTURE,
        "cl_te": FocusCategory.INFRASTRUCTURE,
        "te_cl": FocusCategory.INFRASTRUCTURE,
        "deserialization": FocusCategory.INFRASTRUCTURE,
        "insecure_deserialization": FocusCategory.INFRASTRUCTURE,
        "kubernetes": FocusCategory.INFRASTRUCTURE,
        "k8s": FocusCategory.INFRASTRUCTURE,
        "container_exposure": FocusCategory.INFRASTRUCTURE,
        "container_escape": FocusCategory.INFRASTRUCTURE,
        "file_upload": FocusCategory.INFRASTRUCTURE,
        "unrestricted_upload": FocusCategory.INFRASTRUCTURE,
        "git_exposure": FocusCategory.INFRASTRUCTURE,
        "source_exposure": FocusCategory.INFRASTRUCTURE,
        "subdomain_takeover": FocusCategory.INFRASTRUCTURE,
        "cicd_exposure": FocusCategory.INFRASTRUCTURE,
        "prototype_pollution": FocusCategory.INFRASTRUCTURE,
    }

    # Exhaustion vectors per category
    EXHAUSTION_VECTORS: dict[FocusCategory, list[str]] = {
        FocusCategory.JWT_ABUSE: [
            "alg_none",
            "alg_confusion",
            "kid_injection",
            "jku_spoofing",
            "x5u_spoofing",
            "expired_clock_skew",
            "cross_audience",
            "cross_issuer",
            "role_manipulation",
            "token_replay",
            "token_refresh_abuse",
            "signature_stripping",
        ],
        FocusCategory.AUTH_BYPASS: [
            "path_traversal",
            "case_variation",
            "extension_bypass",
            "header_injection",
            "method_override",
            "verb_tampering",
            "null_byte",
            "unicode_normalization",
            "double_encoding",
            "parameter_pollution",
        ],
        FocusCategory.INJECTION: [
            "union_based",
            "error_based",
            "blind_boolean",
            "blind_time",
            "stacked_queries",
            "out_of_band",
            "second_order",
            "encoding_bypass",
        ],
        FocusCategory.BUSINESS_LOGIC: [
            "negative_values",
            "zero_values",
            "max_int_overflow",
            "race_condition",
            "workflow_skip",
            "state_manipulation",
            "price_manipulation",
            "quantity_manipulation",
        ],
        FocusCategory.DATA_ACCESS: [
            "horizontal_5_ids",
            "vertical_admin_ids",
            "method_escalation",
            "encoded_ids",
            "uuid_prediction",
            "negative_ids",
            "parameter_pollution",
            "mass_assignment",
        ],
        FocusCategory.SESSION_ABUSE: [
            "session_fixation",
            "session_prediction",
            "concurrent_sessions",
            "session_timeout",
            "logout_invalidation",
            "cookie_security",
            "token_leakage",
        ],
        FocusCategory.PRIVILEGE_ESCALATION: [
            "role_parameter",
            "admin_flag",
            "user_id_swap",
            "group_membership",
            "permission_bits",
            "function_access",
            "api_version_bypass",
        ],
        # Infrastructure exhaustion vectors (GAP-2.4)
        FocusCategory.INFRASTRUCTURE: [
            # HTTP Smuggling vectors
            "cl_te_basic",
            "te_cl_basic",
            "te_te_obfuscation",
            "smuggle_to_xss",
            "smuggle_to_cache_poison",
            "smuggle_to_auth_bypass",
            "smuggle_request_splitting",
            # Deserialization vectors
            "java_gadget_commons_collections",
            "java_gadget_spring",
            "java_gadget_hibernate",
            "php_phar_polyglot",
            "dotnet_objectdataprovider",
            "python_pickle",
            # Container vectors
            "k8s_api_unauth",
            "k8s_secrets",
            "k8s_rbac_bypass",
            "container_escape_mount",
            "docker_socket_access",
            # File upload vectors
            "polyglot_webshell",
            "double_extension",
            "content_type_bypass",
            "null_byte_extension",
            # Subdomain takeover
            "dangling_cname",
            "expired_service",
            "azure_takeover",
            "aws_s3_takeover",
        ],
    }

    # Priority boost for focused modules
    FOCUS_PRIORITY_BOOST = 50

    def __init__(self) -> None:
        self._active_focus: FocusCategory | None = None
        self._hypothesis: FocusHypothesis | None = None
        self._focus_history: list[FocusHypothesis] = []
        self._priority_overrides: dict[str, int] = {}

        # Track per-module exhaustion
        self._module_vectors_tried: dict[str, set[str]] = {}

        logger.debug("[FOCUS] FocusLock initialized")

    @property
    def is_focused(self) -> bool:
        """Check if a focus lock is active."""
        return self._active_focus is not None

    @property
    def active_category(self) -> FocusCategory | None:
        """Get the active focus category."""
        return self._active_focus

    @property
    def hypothesis(self) -> FocusHypothesis | None:
        """Get the current hypothesis being tested."""
        return self._hypothesis

    def should_activate_focus(self, finding: dict) -> bool:
        """
        Determine if a finding should activate focus lock.

        Criteria:
        - Severity is HIGH or CRITICAL
        - Finding type maps to a focus category
        - No focus is currently active OR finding is in different category
        """
        severity = finding.get("severity", "").upper()
        if severity not in ("HIGH", "CRITICAL"):
            return False

        finding_type = finding.get("type", "").lower()
        category = self.FINDING_TO_CATEGORY.get(finding_type)

        if category is None:
            return False

        # If no focus active, activate
        if not self.is_focused:
            return True

        # If different category with CRITICAL severity, consider switching
        if category != self._active_focus and severity == "CRITICAL":
            # Only switch if current hypothesis has low confidence
            if self._hypothesis and self._hypothesis.confidence < 50:
                return True

        return False

    def activate(self, finding: dict) -> None:
        """
        Activate focus lock for a finding.

        Creates a hypothesis and sets up exhaustion tracking.
        """
        finding_type = finding.get("type", "").lower()
        category = self.FINDING_TO_CATEGORY.get(finding_type)

        if category is None:
            logger.warning(f"[FOCUS] Cannot activate: unknown type {finding_type}")
            return

        # Save previous hypothesis if exists
        if self._hypothesis:
            self._focus_history.append(self._hypothesis)

        # Create new hypothesis
        vectors = self.EXHAUSTION_VECTORS.get(category, []).copy()
        self._hypothesis = FocusHypothesis(
            category=category,
            description=f"Testing {category.name} based on {finding_type} finding",
            trigger_finding=finding,
            vectors_remaining=vectors,
        )

        self._active_focus = category

        # Set priority overrides for focused modules
        self._priority_overrides.clear()
        focused_modules = self.CATEGORY_MODULES.get(category, [])
        for module in focused_modules:
            self._priority_overrides[module] = self.FOCUS_PRIORITY_BOOST

        logger.info(
            f"[FOCUS] 🎯 FOCUS LOCK ACTIVATED: {category.name}\n"
            f"         Trigger: {finding_type} at {finding.get('matched_at', 'unknown')}\n"
            f"         Vectors to try: {len(vectors)}\n"
            f"         Priority boost for: {focused_modules}"
        )

    def deactivate(self, reason: str = "completed") -> None:
        """Deactivate focus lock."""
        if self._hypothesis:
            self._focus_history.append(self._hypothesis)

        old_category = self._active_focus
        self._active_focus = None
        self._hypothesis = None
        self._priority_overrides.clear()

        logger.info(
            f"[FOCUS] 🔓 FOCUS LOCK RELEASED: {old_category.name if old_category else 'none'}\n"
            f"         Reason: {reason}"
        )

    def record_vector_attempt(
        self,
        vector: str,
        succeeded: bool,
        module: str = "",
        endpoint: str = "",
    ) -> None:
        """
        Record an exhaustion vector attempt with adaptive feedback.

        This is called by modules/provers to track progress.
        Checks exhaustion heuristics (timeout, success rate) after each attempt.
        """
        if self._hypothesis:
            self._hypothesis.try_vector(vector, succeeded, endpoint)

            logger.debug(
                f"[FOCUS] Vector '{vector}': {'✅' if succeeded else '❌'} "
                f"(progress: {self._hypothesis.progress:.0f}%, "
                f"success_rate: {self._hypothesis.success_rate:.0f}%, "
                f"priority: {self._hypothesis.current_priority_boost})"
            )

            # Update priority overrides based on hypothesis state
            self._update_priority_overrides()

            # Check exhaustion heuristics
            release_reason = self._check_exhaustion_heuristics()
            if release_reason:
                self.deactivate(release_reason)
            elif self._hypothesis.is_exhausted:
                self.deactivate("exhausted")

        # Track per-module
        if module:
            if module not in self._module_vectors_tried:
                self._module_vectors_tried[module] = set()
            self._module_vectors_tried[module].add(vector)

    def _update_priority_overrides(self) -> None:
        """Update priority overrides based on hypothesis state."""
        if not self._hypothesis or not self._active_focus:
            return

        # Use hypothesis's dynamic priority instead of static
        current_boost = self._hypothesis.current_priority_boost
        focused_modules = self.CATEGORY_MODULES.get(self._active_focus, [])

        for module in focused_modules:
            self._priority_overrides[module] = current_boost

    def _check_exhaustion_heuristics(self) -> str | None:
        """
        Check if focus should be released due to exhaustion heuristics.

        Returns reason string if should release, None otherwise.
        """
        if not self._hypothesis:
            return None

        # Check timeout
        if self._hypothesis.is_timed_out():
            elapsed = self._hypothesis.elapsed_seconds
            logger.info(
                f"[FOCUS] ⏱️ Focus timeout after {elapsed:.0f}s "
                f"(max: {MAX_FOCUS_DURATION_SECONDS}s)"
            )
            return f"timeout_{elapsed:.0f}s"

        # Check low success rate (only if enough vectors tried)
        if self._hypothesis.should_reduce_priority():
            rate = self._hypothesis.success_rate
            logger.info(
                f"[FOCUS] 📉 Low success rate ({rate:.0f}%), "
                f"reducing priority but continuing"
            )
            # Don't release, just reduce priority (already done in try_vector)
            return None

        # Check if too many consecutive failures
        if self._hypothesis.consecutive_failures >= MAX_CONSECUTIVE_FAILURES * 2:
            logger.info(
                f"[FOCUS] ❌ Too many consecutive failures "
                f"({self._hypothesis.consecutive_failures}), releasing focus"
            )
            return "excessive_failures"

        return None

    def get_priority_boost(self, module_name: str) -> int:
        """Get priority boost for a module based on focus and hypothesis state."""
        return self._priority_overrides.get(module_name, 0)

    def get_remaining_vectors(self) -> list[str]:
        """Get vectors that still need to be tried."""
        if self._hypothesis:
            return self._hypothesis.vectors_remaining.copy()
        return []

    def get_focus_summary(self) -> dict[str, Any]:
        """Get summary of focus lock state including exhaustion heuristics."""
        hypothesis_data = None
        if self._hypothesis:
            hypothesis_data = {
                "description": self._hypothesis.description,
                "vectors_tried": len(self._hypothesis.vectors_tried),
                "vectors_succeeded": len(self._hypothesis.vectors_succeeded),
                "vectors_remaining": len(self._hypothesis.vectors_remaining),
                "confidence": self._hypothesis.confidence,
                "progress": self._hypothesis.progress,
                "is_exhausted": self._hypothesis.is_exhausted,
                # Exhaustion heuristics
                "elapsed_seconds": self._hypothesis.elapsed_seconds,
                "success_rate": self._hypothesis.success_rate,
                "consecutive_failures": self._hypothesis.consecutive_failures,
                "current_priority_boost": self._hypothesis.current_priority_boost,
                "endpoints_tested": list(self._hypothesis.endpoints_tested),
                "is_timed_out": self._hypothesis.is_timed_out(),
            }

        return {
            "is_focused": self.is_focused,
            "active_category": self._active_focus.name if self._active_focus else None,
            "hypothesis": hypothesis_data,
            "priority_overrides": dict(self._priority_overrides),
            "focus_history_count": len(self._focus_history),
            "module_vectors_tried": {
                k: list(v) for k, v in self._module_vectors_tried.items()
            },
        }

    def get_focused_modules(self) -> list[str]:
        """Get list of modules that have priority boost."""
        if not self._active_focus:
            return []
        return self.CATEGORY_MODULES.get(self._active_focus, [])

    def get_endpoints_tested(self) -> set[str]:
        """Get set of endpoints tested during current focus (cross-endpoint persistence)."""
        if self._hypothesis:
            return self._hypothesis.endpoints_tested.copy()
        return set()

    def is_endpoint_tested(self, endpoint: str) -> bool:
        """Check if an endpoint has been tested during current focus."""
        if self._hypothesis:
            return endpoint in self._hypothesis.endpoints_tested
        return False


# Global instance
_focus_lock: FocusLock | None = None


def get_focus_lock() -> FocusLock:
    """Get the global focus lock instance."""
    global _focus_lock
    if _focus_lock is None:
        _focus_lock = FocusLock()
    return _focus_lock


def reset_focus_lock() -> FocusLock:
    """Reset and return a new focus lock."""
    global _focus_lock
    _focus_lock = FocusLock()
    return _focus_lock
