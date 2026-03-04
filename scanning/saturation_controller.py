"""
PHANTOM AI - Saturation Controller (Theme 9 Fix)

Prevents cognitive saturation through three mechanisms:
1. Request Budget - Hard cap on requests per module
2. Hypothesis Coordination - Avoid testing same hypothesis twice
3. Finding Budget - Limit findings per module to prevent noise

Philosophy: "Too many indistinct attempts obscure weak signals."

The problem is NOT volume. The problem is:
- Uncoordinated testing (SQLi found injection, XSS still tests same param)
- Weak signals buried (timing SQLi under 2000 other responses)
- Output noise (500 findings before dedup → important vulns lost)

Usage:
    from scanning.saturation_controller import (
        get_saturation_controller,
        SaturationController,
        ModuleBudget,
        ModuleBudgetExhausted,
    )

    controller = get_saturation_controller()
    budget = controller.get_module_budget("xss_scanner")

    # Check before each request
    if not budget.can_request():
        raise ModuleBudgetExhausted("XSS scanner request limit reached")
    budget.record_request()

    # Check if hypothesis already tested
    if controller.is_hypothesis_tested(endpoint, param, "injectable"):
        continue  # Skip, another module already tested this

    # Record hypothesis tested
    controller.record_hypothesis(endpoint, param, "injectable", result=True)

Version: 1.0.0
Date: 2026-02-08
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

from utils.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# CONFIGURATION - Tunable limits
# =============================================================================

# Per-module limits
DEFAULT_MAX_REQUESTS_PER_MODULE = 500  # Hard cap on HTTP requests
DEFAULT_MAX_FINDINGS_PER_MODULE = 50   # Hard cap on findings reported
DEFAULT_MAX_PAYLOADS_PER_PARAM = 100   # Limit payload variations per parameter

# Global limits
DEFAULT_MAX_TOTAL_REQUESTS = 10000     # Total across all modules
DEFAULT_MAX_TOTAL_FINDINGS = 500       # Total before mandatory dedup

# Module-specific overrides (some modules need more/less budget)
MODULE_BUDGET_OVERRIDES = {
    # High-budget modules (need more tests)
    "xss_scanner": {"requests": 800, "findings": 75, "payloads_per_param": 150},
    "sqli_scanner": {"requests": 600, "findings": 60, "payloads_per_param": 120},
    "auth_scanner": {"requests": 400, "findings": 40},

    # Low-budget modules (quick checks)
    "cors_checker": {"requests": 100, "findings": 20, "payloads_per_param": 10},
    "header_security": {"requests": 50, "findings": 30, "payloads_per_param": 5},
    "ssl_checker": {"requests": 20, "findings": 15, "payloads_per_param": 5},
    "cookie_security_scanner": {"requests": 100, "findings": 25},

    # Medium-budget modules
    "business_logic_scanner": {"requests": 400, "findings": 50, "payloads_per_param": 50},
    "api_logic_profiler": {"requests": 500, "findings": 60, "payloads_per_param": 80},
    "race_condition_scanner": {"requests": 300, "findings": 30},
}


class BudgetExhaustionReason(Enum):
    """Reason why a module budget was exhausted."""
    REQUESTS_EXCEEDED = auto()
    FINDINGS_EXCEEDED = auto()
    PAYLOADS_PER_PARAM_EXCEEDED = auto()
    GLOBAL_REQUESTS_EXCEEDED = auto()
    GLOBAL_FINDINGS_EXCEEDED = auto()
    HYPOTHESIS_ALREADY_TESTED = auto()


class ModuleBudgetExhausted(Exception):
    """Raised when a module exceeds its budget."""

    def __init__(self, message: str, reason: BudgetExhaustionReason, module: str):
        super().__init__(message)
        self.reason = reason
        self.module = module


# =============================================================================
# MODULE BUDGET TRACKING
# =============================================================================

@dataclass
class ModuleBudget:
    """
    Tracks budget for a single module.

    THEME-9: Prevents request saturation by enforcing hard limits.
    """
    module_name: str
    max_requests: int = DEFAULT_MAX_REQUESTS_PER_MODULE
    max_findings: int = DEFAULT_MAX_FINDINGS_PER_MODULE
    max_payloads_per_param: int = DEFAULT_MAX_PAYLOADS_PER_PARAM

    # Current usage
    request_count: int = 0
    finding_count: int = 0
    payloads_by_param: Dict[str, int] = field(default_factory=dict)  # param -> count

    # Tracking
    started_at: datetime = field(default_factory=datetime.now)
    exhausted_at: Optional[datetime] = None
    exhaustion_reason: Optional[BudgetExhaustionReason] = None

    # Lock for thread safety
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def can_request(self) -> bool:
        """Check if module can make another request."""
        return self.request_count < self.max_requests

    def can_add_finding(self) -> bool:
        """Check if module can add another finding."""
        return self.finding_count < self.max_findings

    def can_test_param(self, param: str) -> bool:
        """Check if module can test another payload on this param."""
        current = self.payloads_by_param.get(param, 0)
        return current < self.max_payloads_per_param

    def record_request(self, param: Optional[str] = None) -> bool:
        """
        Record a request. Returns True if successful, False if budget exceeded.
        """
        with self._lock:
            if self.request_count >= self.max_requests:
                self._mark_exhausted(BudgetExhaustionReason.REQUESTS_EXCEEDED)
                return False

            self.request_count += 1

            if param:
                current = self.payloads_by_param.get(param, 0)
                if current >= self.max_payloads_per_param:
                    # Don't count this request, param is saturated
                    self.request_count -= 1
                    return False
                self.payloads_by_param[param] = current + 1

            return True

    def record_finding(self) -> bool:
        """
        Record a finding. Returns True if successful, False if budget exceeded.
        """
        with self._lock:
            if self.finding_count >= self.max_findings:
                self._mark_exhausted(BudgetExhaustionReason.FINDINGS_EXCEEDED)
                return False

            self.finding_count += 1
            return True

    def _mark_exhausted(self, reason: BudgetExhaustionReason) -> None:
        """Mark budget as exhausted with reason."""
        if self.exhausted_at is None:
            self.exhausted_at = datetime.now()
            self.exhaustion_reason = reason
            logger.warning(
                f"[THEME-9] Module {self.module_name} budget EXHAUSTED: "
                f"{reason.name} (requests={self.request_count}/{self.max_requests}, "
                f"findings={self.finding_count}/{self.max_findings})"
            )

    def get_remaining(self) -> Dict[str, int]:
        """Get remaining budget."""
        return {
            "requests": max(0, self.max_requests - self.request_count),
            "findings": max(0, self.max_findings - self.finding_count),
        }

    def get_utilization(self) -> Dict[str, float]:
        """Get budget utilization percentages."""
        return {
            "requests_pct": (self.request_count / self.max_requests * 100) if self.max_requests > 0 else 0,
            "findings_pct": (self.finding_count / self.max_findings * 100) if self.max_findings > 0 else 0,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get budget statistics."""
        return {
            "module": self.module_name,
            "requests": self.request_count,
            "max_requests": self.max_requests,
            "findings": self.finding_count,
            "max_findings": self.max_findings,
            "params_tested": len(self.payloads_by_param),
            "exhausted": self.exhausted_at is not None,
            "exhaustion_reason": self.exhaustion_reason.name if self.exhaustion_reason else None,
            "utilization": self.get_utilization(),
        }


# =============================================================================
# HYPOTHESIS COORDINATION
# =============================================================================

@dataclass
class TestedHypothesis:
    """
    Record of a tested hypothesis.

    THEME-9: Prevents hypothesis saturation by sharing test results.
    """
    endpoint: str
    param: str
    hypothesis_type: str  # "injectable", "reflectable", "traversable", etc.
    tested_by: str        # Module that tested it
    tested_at: datetime
    result: Optional[bool]  # True = vulnerable, False = not, None = inconclusive
    evidence: str = ""


class HypothesisRegistry:
    """
    Registry of tested hypotheses across modules.

    THEME-9: If SQLi scanner found param injectable, XSS doesn't need to
    test same basic injection hypothesis. Modules can still test their
    specific vectors, but skip redundant hypothesis testing.
    """

    # Hypothesis types that can be shared across modules
    SHAREABLE_HYPOTHESES = {
        "injectable": ["sqli_scanner", "nosql_scanner", "cmdi_scanner", "ssti_scanner"],
        "reflectable": ["xss_scanner", "ssti_scanner"],
        "traversable": ["lfi_scanner", "ssrf_scanner"],
        "xxe_vulnerable": ["xxe_scanner"],
        "auth_bypass_possible": ["auth_scanner", "jwt_scanner", "oauth_scanner"],
    }

    def __init__(self):
        self._hypotheses: Dict[str, TestedHypothesis] = {}  # key -> hypothesis
        self._lock = threading.Lock()

    def _make_key(self, endpoint: str, param: str, hypothesis_type: str) -> str:
        """Create unique key for hypothesis."""
        return f"{endpoint}|{param}|{hypothesis_type}"

    def is_tested(
        self,
        endpoint: str,
        param: str,
        hypothesis_type: str,
        by_module: Optional[str] = None,
    ) -> bool:
        """
        Check if hypothesis has been tested.

        Args:
            endpoint: The endpoint URL
            param: The parameter name
            hypothesis_type: Type of hypothesis (injectable, reflectable, etc.)
            by_module: If specified, check if tested by this specific module

        Returns:
            True if already tested
        """
        key = self._make_key(endpoint, param, hypothesis_type)

        with self._lock:
            if key not in self._hypotheses:
                return False

            if by_module:
                return self._hypotheses[key].tested_by == by_module

            return True

    def get_result(
        self,
        endpoint: str,
        param: str,
        hypothesis_type: str,
    ) -> Optional[bool]:
        """
        Get result of tested hypothesis.

        Returns:
            True = vulnerable, False = not vulnerable, None = not tested or inconclusive
        """
        key = self._make_key(endpoint, param, hypothesis_type)

        with self._lock:
            if key in self._hypotheses:
                return self._hypotheses[key].result
            return None

    def record(
        self,
        endpoint: str,
        param: str,
        hypothesis_type: str,
        tested_by: str,
        result: Optional[bool],
        evidence: str = "",
    ) -> None:
        """
        Record a tested hypothesis.

        Args:
            endpoint: The endpoint URL
            param: The parameter name
            hypothesis_type: Type of hypothesis
            tested_by: Module that tested it
            result: True = vulnerable, False = not, None = inconclusive
            evidence: Optional evidence string
        """
        key = self._make_key(endpoint, param, hypothesis_type)

        hypothesis = TestedHypothesis(
            endpoint=endpoint,
            param=param,
            hypothesis_type=hypothesis_type,
            tested_by=tested_by,
            tested_at=datetime.now(),
            result=result,
            evidence=evidence,
        )

        with self._lock:
            # Only record if not already tested, or if new result is definitive
            existing = self._hypotheses.get(key)
            if existing is None or (existing.result is None and result is not None):
                self._hypotheses[key] = hypothesis

                if result is True:
                    logger.info(
                        f"[THEME-9] Hypothesis confirmed: {hypothesis_type} on "
                        f"{param}@{endpoint[:50]} by {tested_by}"
                    )

    def should_skip(
        self,
        endpoint: str,
        param: str,
        hypothesis_type: str,
        requesting_module: str,
    ) -> Tuple[bool, str]:
        """
        Check if module should skip testing this hypothesis.

        Returns:
            Tuple of (should_skip, reason)
        """
        key = self._make_key(endpoint, param, hypothesis_type)

        with self._lock:
            if key not in self._hypotheses:
                return False, ""

            hyp = self._hypotheses[key]

            # If same module tested it, skip
            if hyp.tested_by == requesting_module:
                return True, f"Already tested by this module"

            # If hypothesis confirmed vulnerable, other modules can leverage
            if hyp.result is True:
                return True, f"Already confirmed vulnerable by {hyp.tested_by}"

            # If hypothesis conclusively negative, skip
            if hyp.result is False:
                return True, f"Already ruled out by {hyp.tested_by}"

            # Inconclusive - let other modules try
            return False, ""

    def get_stats(self) -> Dict[str, Any]:
        """Get hypothesis registry statistics."""
        with self._lock:
            total = len(self._hypotheses)
            by_type = {}
            by_result = {"vulnerable": 0, "not_vulnerable": 0, "inconclusive": 0}

            for hyp in self._hypotheses.values():
                by_type[hyp.hypothesis_type] = by_type.get(hyp.hypothesis_type, 0) + 1
                if hyp.result is True:
                    by_result["vulnerable"] += 1
                elif hyp.result is False:
                    by_result["not_vulnerable"] += 1
                else:
                    by_result["inconclusive"] += 1

            return {
                "total_hypotheses": total,
                "by_type": by_type,
                "by_result": by_result,
            }

    def reset(self) -> None:
        """Reset registry for new scan."""
        with self._lock:
            self._hypotheses.clear()


# =============================================================================
# SATURATION CONTROLLER
# =============================================================================

class SaturationController:
    """
    Central controller for preventing cognitive saturation.

    THEME-9 FIX: Coordinates budgets and hypotheses across all modules.

    Three saturation types addressed:
    1. Request Saturation - Hard caps per module
    2. Hypothesis Saturation - Share test results, skip redundant tests
    3. Result Saturation - Limit findings per module
    """

    def __init__(self):
        self._module_budgets: Dict[str, ModuleBudget] = {}
        self._hypothesis_registry = HypothesisRegistry()
        self._lock = threading.Lock()

        # Global counters
        self._total_requests = 0
        self._total_findings = 0
        self._max_total_requests = DEFAULT_MAX_TOTAL_REQUESTS
        self._max_total_findings = DEFAULT_MAX_TOTAL_FINDINGS

        # Tracking
        self._started_at: Optional[datetime] = None
        self._modules_exhausted: List[str] = []

    def start_scan(self) -> None:
        """Initialize controller for new scan."""
        with self._lock:
            self._module_budgets.clear()
            self._hypothesis_registry.reset()
            self._total_requests = 0
            self._total_findings = 0
            self._modules_exhausted.clear()
            self._started_at = datetime.now()

            logger.info(
                f"[THEME-9] Saturation controller initialized: "
                f"max_requests={self._max_total_requests}, "
                f"max_findings={self._max_total_findings}"
            )

    def get_module_budget(self, module_name: str) -> ModuleBudget:
        """
        Get or create budget for a module.

        Args:
            module_name: Name of the module

        Returns:
            ModuleBudget instance
        """
        with self._lock:
            if module_name not in self._module_budgets:
                # Get module-specific overrides
                overrides = MODULE_BUDGET_OVERRIDES.get(module_name, {})

                budget = ModuleBudget(
                    module_name=module_name,
                    max_requests=overrides.get("requests", DEFAULT_MAX_REQUESTS_PER_MODULE),
                    max_findings=overrides.get("findings", DEFAULT_MAX_FINDINGS_PER_MODULE),
                    max_payloads_per_param=overrides.get("payloads_per_param", DEFAULT_MAX_PAYLOADS_PER_PARAM),
                )

                self._module_budgets[module_name] = budget

                logger.debug(
                    f"[THEME-9] Budget created for {module_name}: "
                    f"requests={budget.max_requests}, findings={budget.max_findings}"
                )

            return self._module_budgets[module_name]

    def record_request(self, module_name: str, param: Optional[str] = None) -> bool:
        """
        Record a request from a module.

        Args:
            module_name: Name of the module
            param: Optional parameter being tested

        Returns:
            True if request allowed, False if budget exceeded
        """
        budget = self.get_module_budget(module_name)

        # Check global limit first
        with self._lock:
            if self._total_requests >= self._max_total_requests:
                logger.warning(
                    f"[THEME-9] Global request limit reached ({self._max_total_requests})"
                )
                return False

        # Check module limit
        if not budget.record_request(param):
            with self._lock:
                if module_name not in self._modules_exhausted:
                    self._modules_exhausted.append(module_name)
            return False

        # Increment global counter
        with self._lock:
            self._total_requests += 1

        return True

    def record_finding(self, module_name: str) -> bool:
        """
        Record a finding from a module.

        Args:
            module_name: Name of the module

        Returns:
            True if finding allowed, False if budget exceeded
        """
        budget = self.get_module_budget(module_name)

        # Check global limit first
        with self._lock:
            if self._total_findings >= self._max_total_findings:
                logger.warning(
                    f"[THEME-9] Global finding limit reached ({self._max_total_findings})"
                )
                return False

        # Check module limit
        if not budget.record_finding():
            return False

        # Increment global counter
        with self._lock:
            self._total_findings += 1

        return True

    def can_test_param(self, module_name: str, param: str) -> bool:
        """Check if module can test another payload on this param."""
        budget = self.get_module_budget(module_name)
        return budget.can_test_param(param)

    def is_hypothesis_tested(
        self,
        endpoint: str,
        param: str,
        hypothesis_type: str,
    ) -> bool:
        """Check if hypothesis has been tested by any module."""
        return self._hypothesis_registry.is_tested(endpoint, param, hypothesis_type)

    def get_hypothesis_result(
        self,
        endpoint: str,
        param: str,
        hypothesis_type: str,
    ) -> Optional[bool]:
        """Get result of previously tested hypothesis."""
        return self._hypothesis_registry.get_result(endpoint, param, hypothesis_type)

    def record_hypothesis(
        self,
        endpoint: str,
        param: str,
        hypothesis_type: str,
        module_name: str,
        result: Optional[bool],
        evidence: str = "",
    ) -> None:
        """Record a tested hypothesis."""
        self._hypothesis_registry.record(
            endpoint=endpoint,
            param=param,
            hypothesis_type=hypothesis_type,
            tested_by=module_name,
            result=result,
            evidence=evidence,
        )

    def should_skip_hypothesis(
        self,
        endpoint: str,
        param: str,
        hypothesis_type: str,
        module_name: str,
    ) -> Tuple[bool, str]:
        """Check if module should skip testing this hypothesis."""
        return self._hypothesis_registry.should_skip(
            endpoint=endpoint,
            param=param,
            hypothesis_type=hypothesis_type,
            requesting_module=module_name,
        )

    def get_stats(self) -> Dict[str, Any]:
        """Get saturation controller statistics."""
        with self._lock:
            module_stats = {
                name: budget.get_stats()
                for name, budget in self._module_budgets.items()
            }

            return {
                "total_requests": self._total_requests,
                "max_total_requests": self._max_total_requests,
                "total_findings": self._total_findings,
                "max_total_findings": self._max_total_findings,
                "modules_tracked": len(self._module_budgets),
                "modules_exhausted": self._modules_exhausted.copy(),
                "hypothesis_stats": self._hypothesis_registry.get_stats(),
                "module_stats": module_stats,
                "global_utilization": {
                    "requests_pct": (self._total_requests / self._max_total_requests * 100),
                    "findings_pct": (self._total_findings / self._max_total_findings * 100),
                },
            }

    def get_report_section(self) -> str:
        """Generate report section for saturation metrics."""
        stats = self.get_stats()

        lines = [
            "### Budget Utilization Summary",
            "",
            f"| Metric | Used | Limit | Utilization |",
            f"|--------|------|-------|-------------|",
            f"| Total Requests | {stats['total_requests']:,} | {stats['max_total_requests']:,} | {stats['global_utilization']['requests_pct']:.1f}% |",
            f"| Total Findings | {stats['total_findings']:,} | {stats['max_total_findings']:,} | {stats['global_utilization']['findings_pct']:.1f}% |",
            "",
        ]

        # Modules that hit limits
        if stats['modules_exhausted']:
            lines.append("**Modules That Reached Budget Limits:**")
            for mod in stats['modules_exhausted']:
                mod_stat = stats['module_stats'].get(mod, {})
                reason = mod_stat.get('exhaustion_reason', 'Unknown')
                lines.append(f"- `{mod}`: {reason}")
            lines.append("")

        # Hypothesis sharing
        hyp_stats = stats['hypothesis_stats']
        if hyp_stats['total_hypotheses'] > 0:
            lines.append(f"**Hypothesis Sharing:**")
            lines.append(f"- Total hypotheses tested: {hyp_stats['total_hypotheses']}")
            lines.append(f"- Confirmed vulnerable: {hyp_stats['by_result']['vulnerable']}")
            lines.append(f"- Ruled out: {hyp_stats['by_result']['not_vulnerable']}")
            lines.append(f"- Inconclusive: {hyp_stats['by_result']['inconclusive']}")
            lines.append("")

        return "\n".join(lines)

    def reset(self) -> None:
        """Reset controller for new scan."""
        self.start_scan()


# =============================================================================
# SINGLETON INSTANCE
# =============================================================================

_controller: Optional[SaturationController] = None
_controller_lock = threading.Lock()


def get_saturation_controller() -> SaturationController:
    """Get the singleton saturation controller."""
    global _controller
    with _controller_lock:
        if _controller is None:
            _controller = SaturationController()
        return _controller


def reset_saturation_controller() -> None:
    """Reset the saturation controller for new scan."""
    global _controller
    with _controller_lock:
        if _controller is not None:
            _controller.reset()
        else:
            _controller = SaturationController()


# =============================================================================
# CONVENIENCE DECORATORS
# =============================================================================

def with_budget_check(module_name: str):
    """
    Decorator that enforces budget limits on scanner methods.

    Usage:
        @with_budget_check("xss_scanner")
        async def test_payload(self, endpoint, param, payload):
            # Will raise ModuleBudgetExhausted if limit reached
            ...
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            controller = get_saturation_controller()

            # Extract param if available
            param = kwargs.get("param") or (args[2] if len(args) > 2 else None)

            if not controller.record_request(module_name, param):
                raise ModuleBudgetExhausted(
                    f"{module_name} request budget exhausted",
                    BudgetExhaustionReason.REQUESTS_EXCEEDED,
                    module_name,
                )

            return await func(*args, **kwargs)
        return wrapper
    return decorator


def skip_if_hypothesis_tested(hypothesis_type: str, module_name: str):
    """
    Decorator that skips if hypothesis already tested by another module.

    Usage:
        @skip_if_hypothesis_tested("injectable", "xss_scanner")
        async def test_injection(self, endpoint, param):
            # Will return None if already tested
            ...
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            controller = get_saturation_controller()

            endpoint = kwargs.get("endpoint") or (args[1] if len(args) > 1 else "")
            param = kwargs.get("param") or (args[2] if len(args) > 2 else "")

            should_skip, reason = controller.should_skip_hypothesis(
                endpoint=endpoint,
                param=param,
                hypothesis_type=hypothesis_type,
                module_name=module_name,
            )

            if should_skip:
                logger.debug(
                    f"[THEME-9] Skipping {hypothesis_type} test on {param}: {reason}"
                )
                return None

            return await func(*args, **kwargs)
        return wrapper
    return decorator
