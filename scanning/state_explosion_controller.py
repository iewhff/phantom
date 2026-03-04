"""
PHANTOM AI - State Explosion Controller

Philosophy: "Infinite depth with finite resources."

The problem: Adaptive scanning can explode - one IDOR leads to 1000 ID tests,
each ID could have 10 params, each param could have 5 vuln types...
That's 50,000 tests from ONE finding.

The solution: Intelligent limits, cut heuristics, impact-based priority.

This module provides:
1. BUDGET SYSTEM — Global request budget with per-type allocation
2. PRIORITY QUEUE — Impact-based prioritization of what to test next
3. CUT HEURISTICS — When to stop expanding (diminishing returns)
4. IMPACT ESTIMATION — Predict value before spending budget
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable

from utils.logger import get_logger

logger = get_logger(__name__)


class ActionType(Enum):
    """Types of scanning actions."""
    INITIAL_SCAN = auto()       # First scan of an endpoint
    AMPLIFICATION = auto()      # Expanding based on finding
    CHAIN_EXPLORATION = auto()  # Following attack chains
    PROOF_ATTEMPT = auto()      # Proving/escalating findings
    MUTATION_TEST = auto()      # Testing payload variants
    METHOD_VARIATION = auto()   # Testing different HTTP methods
    ID_ENUMERATION = auto()     # IDOR ID expansion


class Priority(Enum):
    """Priority levels for actions."""
    CRITICAL = 100   # Must do - proven high impact
    HIGH = 75        # Should do - likely high impact
    MEDIUM = 50      # Normal - standard testing
    LOW = 25         # Can skip - diminishing returns
    DEFER = 0        # Skip unless budget allows


@dataclass(order=True)
class PrioritizedAction:
    """An action in the priority queue."""
    priority: int  # Negative for max-heap behavior
    action_id: str = field(compare=False)
    action_type: ActionType = field(compare=False)
    target: str = field(compare=False)
    vuln_type: str = field(compare=False)
    params: dict = field(default_factory=dict, compare=False)
    estimated_requests: int = field(default=1, compare=False)
    estimated_impact: float = field(default=0.5, compare=False)  # 0-1
    depth: int = field(default=0, compare=False)  # How deep in the expansion tree

    def __post_init__(self) -> None:
        # Negate priority for max-heap (heapq is min-heap)
        self.priority = -self.priority


@dataclass
class BudgetAllocation:
    """Budget for a specific action type."""
    allocated: int       # Max requests for this type
    used: int = 0        # Requests used
    findings: int = 0    # Findings produced

    @property
    def remaining(self) -> int:
        return max(0, self.allocated - self.used)

    @property
    def efficiency(self) -> float:
        """Findings per request (higher = better)."""
        if self.used == 0:
            return 0.0
        return self.findings / self.used


@dataclass
class ExplosionMetrics:
    """Metrics for tracking state explosion."""
    actions_queued: int = 0
    actions_executed: int = 0
    actions_pruned: int = 0
    actions_deferred: int = 0
    max_depth_reached: int = 0
    budget_exhaustion_events: int = 0
    high_value_skips: int = 0  # High-priority actions we had to skip


class StateExplosionController:
    """
    Controls state explosion during adaptive scanning.

    Key principles:
    1. BUDGET FIRST — Never exceed total request budget
    2. IMPACT PRIORITY — High-impact actions run first
    3. DIMINISHING RETURNS — Cut expansion when returns drop
    4. DEPTH LIMITS — Prevent infinite recursion
    """

    # Default budget allocation percentages by action type
    DEFAULT_BUDGET_ALLOCATION = {
        ActionType.INITIAL_SCAN: 40,      # 40% for initial scanning
        ActionType.AMPLIFICATION: 25,     # 25% for expanding findings
        ActionType.CHAIN_EXPLORATION: 15, # 15% for chain analysis
        ActionType.PROOF_ATTEMPT: 10,     # 10% for proof engine
        ActionType.MUTATION_TEST: 5,      # 5% for mutations
        ActionType.METHOD_VARIATION: 3,   # 3% for method tests
        ActionType.ID_ENUMERATION: 2,     # 2% for ID expansion
    }

    # Depth limits by action type
    MAX_DEPTH = {
        ActionType.INITIAL_SCAN: 1,
        ActionType.AMPLIFICATION: 3,
        ActionType.CHAIN_EXPLORATION: 4,
        ActionType.PROOF_ATTEMPT: 2,
        ActionType.MUTATION_TEST: 2,
        ActionType.METHOD_VARIATION: 1,
        ActionType.ID_ENUMERATION: 2,
    }

    # Minimum efficiency threshold before cutting
    MIN_EFFICIENCY_THRESHOLD = 0.01  # 1 finding per 100 requests

    def __init__(
        self,
        total_budget: int = 10000,
        max_queue_size: int = 1000,
        custom_allocation: dict[ActionType, int] | None = None,
    ) -> None:
        self._total_budget = total_budget
        self._max_queue_size = max_queue_size

        # Initialize budget allocations
        allocation_pcts = custom_allocation or self.DEFAULT_BUDGET_ALLOCATION
        self._budgets: dict[ActionType, BudgetAllocation] = {}
        for action_type, pct in allocation_pcts.items():
            allocated = int(total_budget * pct / 100)
            self._budgets[action_type] = BudgetAllocation(allocated=allocated)

        # Priority queue (min-heap with negated priorities)
        self._queue: list[PrioritizedAction] = []
        self._executed: set[str] = set()  # action_ids we've run
        self._pruned: set[str] = set()    # action_ids we've cut

        # Metrics
        self._metrics = ExplosionMetrics()

        # Impact estimators by vuln type
        self._impact_estimators: dict[str, Callable[[dict], float]] = {}

        # Track findings per target for diminishing returns
        self._findings_per_target: dict[str, int] = {}

        logger.info(
            f"[EXPLOSION] Controller initialized: budget={total_budget}, "
            f"queue_limit={max_queue_size}"
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # BUDGET MANAGEMENT
    # ═══════════════════════════════════════════════════════════════════════════

    def get_remaining_budget(self, action_type: ActionType) -> int:
        """Get remaining budget for an action type."""
        return self._budgets[action_type].remaining

    def get_total_remaining(self) -> int:
        """Get total remaining budget across all types."""
        return sum(b.remaining for b in self._budgets.values())

    def consume_budget(
        self,
        action_type: ActionType,
        requests: int,
        findings: int = 0,
    ) -> bool:
        """
        Consume budget for an action. Returns False if over budget.
        """
        budget = self._budgets[action_type]

        if budget.remaining < requests:
            # Try to borrow from lower priority types
            borrowed = self._borrow_budget(action_type, requests - budget.remaining)
            if borrowed < requests - budget.remaining:
                self._metrics.budget_exhaustion_events += 1
                return False

        budget.used += requests
        budget.findings += findings
        return True

    def _borrow_budget(self, needing_type: ActionType, amount: int) -> int:
        """Try to borrow budget from lower-priority action types."""
        borrowed = 0

        # Priority order for borrowing (steal from least important first)
        borrow_order = [
            ActionType.ID_ENUMERATION,
            ActionType.METHOD_VARIATION,
            ActionType.MUTATION_TEST,
        ]

        for donor_type in borrow_order:
            if donor_type == needing_type:
                continue

            available = self._budgets[donor_type].remaining
            take = min(available, amount - borrowed)

            if take > 0:
                self._budgets[donor_type].used += take
                self._budgets[needing_type].allocated += take
                borrowed += take
                logger.debug(
                    f"[EXPLOSION] Borrowed {take} from {donor_type.name} to {needing_type.name}"
                )

            if borrowed >= amount:
                break

        return borrowed

    def reallocate_budget(self) -> None:
        """
        Dynamically reallocate budget based on efficiency.

        Called periodically to shift budget from inefficient to efficient types.
        """
        # Calculate efficiency for each type
        efficiencies = {}
        for action_type, budget in self._budgets.items():
            efficiencies[action_type] = budget.efficiency

        if not efficiencies:
            return

        # Find most and least efficient
        most_efficient = max(efficiencies, key=lambda k: efficiencies[k])
        least_efficient = min(efficiencies, key=lambda k: efficiencies[k])

        # If difference is significant, reallocate
        if efficiencies[most_efficient] > 2 * efficiencies[least_efficient]:
            transfer = self._budgets[least_efficient].remaining // 4
            if transfer > 0:
                self._budgets[least_efficient].allocated -= transfer
                self._budgets[most_efficient].allocated += transfer
                logger.info(
                    f"[EXPLOSION] Reallocated {transfer} from {least_efficient.name} "
                    f"to {most_efficient.name}"
                )

    # ═══════════════════════════════════════════════════════════════════════════
    # PRIORITY QUEUE
    # ═══════════════════════════════════════════════════════════════════════════

    def enqueue(self, action: PrioritizedAction) -> bool:
        """
        Add an action to the priority queue.

        Returns False if action was pruned or queue is full.
        """
        # Check if already executed or pruned
        if action.action_id in self._executed:
            return False
        if action.action_id in self._pruned:
            return False

        # Check queue size limit
        if len(self._queue) >= self._max_queue_size:
            # Prune lowest priority action
            if self._queue:
                lowest = heapq.nsmallest(1, self._queue)[0]
                if -action.priority > -lowest.priority:
                    # New action is higher priority, remove lowest
                    self._queue.remove(lowest)
                    self._pruned.add(lowest.action_id)
                    self._metrics.actions_pruned += 1
                else:
                    # New action is lower priority, reject it
                    self._pruned.add(action.action_id)
                    self._metrics.actions_pruned += 1
                    return False

        # Check depth limit
        max_depth = self.MAX_DEPTH.get(action.action_type, 3)
        if action.depth > max_depth:
            self._pruned.add(action.action_id)
            self._metrics.actions_pruned += 1
            logger.debug(
                f"[EXPLOSION] Pruned {action.action_id}: depth {action.depth} > max {max_depth}"
            )
            return False

        # Check if should cut due to diminishing returns
        if self._should_cut(action):
            self._pruned.add(action.action_id)
            self._metrics.actions_pruned += 1
            return False

        # Add to queue
        heapq.heappush(self._queue, action)
        self._metrics.actions_queued += 1

        if action.depth > self._metrics.max_depth_reached:
            self._metrics.max_depth_reached = action.depth

        return True

    def dequeue(self) -> PrioritizedAction | None:
        """
        Get the highest priority action from the queue.

        Returns None if queue is empty or budget exhausted.
        """
        while self._queue:
            action = heapq.heappop(self._queue)

            # Check budget
            budget = self._budgets.get(action.action_type)
            if budget and budget.remaining < action.estimated_requests:
                # Try to borrow
                if not self._borrow_budget(action.action_type, action.estimated_requests):
                    self._metrics.actions_deferred += 1
                    if -action.priority >= Priority.HIGH.value:
                        self._metrics.high_value_skips += 1
                    continue

            # Check if already executed
            if action.action_id in self._executed:
                continue

            self._executed.add(action.action_id)
            self._metrics.actions_executed += 1
            return action

        return None

    def queue_size(self) -> int:
        """Get current queue size."""
        return len(self._queue)

    def is_empty(self) -> bool:
        """Check if queue is empty."""
        return len(self._queue) == 0

    # ═══════════════════════════════════════════════════════════════════════════
    # CUT HEURISTICS
    # ═══════════════════════════════════════════════════════════════════════════

    def _should_cut(self, action: PrioritizedAction) -> bool:
        """
        Determine if an action should be cut (not queued).

        Cut when:
        1. Target has many findings already (diminishing returns)
        2. Action type efficiency is very low
        3. Estimated impact is low and budget is tight
        """
        # Diminishing returns on target
        target_findings = self._findings_per_target.get(action.target, 0)
        if target_findings >= 5:
            # Already found 5+ vulns on this target, cut low-priority expansions
            if action.action_type in (
                ActionType.MUTATION_TEST,
                ActionType.ID_ENUMERATION,
            ):
                return True

        if target_findings >= 10:
            # 10+ findings, only allow critical actions
            if -action.priority < Priority.HIGH.value:
                return True

        # Low efficiency action type
        budget = self._budgets.get(action.action_type)
        if budget and budget.used > 100:
            if budget.efficiency < self.MIN_EFFICIENCY_THRESHOLD:
                # This action type is not finding anything
                if action.action_type not in (
                    ActionType.INITIAL_SCAN,
                    ActionType.PROOF_ATTEMPT,
                ):
                    logger.debug(
                        f"[EXPLOSION] Cutting {action.action_type.name} due to low efficiency "
                        f"({budget.efficiency:.4f})"
                    )
                    return True

        # Budget pressure + low impact
        total_remaining = self.get_total_remaining()
        if total_remaining < self._total_budget * 0.1:  # <10% budget left
            if action.estimated_impact < 0.3:
                return True

        return False

    def record_finding(self, target: str) -> None:
        """Record that a finding was discovered on a target."""
        self._findings_per_target[target] = (
            self._findings_per_target.get(target, 0) + 1
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # IMPACT ESTIMATION
    # ═══════════════════════════════════════════════════════════════════════════

    def register_impact_estimator(
        self,
        vuln_type: str,
        estimator: Callable[[dict], float],
    ) -> None:
        """Register a custom impact estimator for a vuln type."""
        self._impact_estimators[vuln_type] = estimator

    def estimate_impact(self, action: PrioritizedAction) -> float:
        """
        Estimate the impact of an action before executing it.

        Returns 0.0-1.0 where 1.0 is maximum impact.
        """
        # Use custom estimator if available
        if action.vuln_type in self._impact_estimators:
            return self._impact_estimators[action.vuln_type](action.params)

        # Default estimation based on action type and context
        base_impact = {
            ActionType.INITIAL_SCAN: 0.5,
            ActionType.AMPLIFICATION: 0.6,
            ActionType.CHAIN_EXPLORATION: 0.7,
            ActionType.PROOF_ATTEMPT: 0.8,
            ActionType.MUTATION_TEST: 0.3,
            ActionType.METHOD_VARIATION: 0.4,
            ActionType.ID_ENUMERATION: 0.4,
        }.get(action.action_type, 0.5)

        # Adjust based on vuln type severity
        severity_multiplier = {
            "sqli": 1.0,
            "sql_injection": 1.0,
            "rce": 1.0,
            "cmdi": 0.95,
            "ssti": 0.9,
            "xss": 0.7,
            "idor": 0.7,
            "ssrf": 0.8,
            "xxe": 0.8,
            "lfi": 0.75,
            "business_logic": 0.6,
            "cors": 0.5,
            "csrf": 0.5,
        }.get(action.vuln_type.lower(), 0.5)

        # Reduce impact at greater depths
        depth_penalty = 1.0 / (1 + action.depth * 0.2)

        return min(1.0, base_impact * severity_multiplier * depth_penalty)

    # ═══════════════════════════════════════════════════════════════════════════
    # ACTION CREATION HELPERS
    # ═══════════════════════════════════════════════════════════════════════════

    def create_action(
        self,
        action_type: ActionType,
        target: str,
        vuln_type: str,
        priority: Priority = Priority.MEDIUM,
        params: dict | None = None,
        estimated_requests: int = 1,
        parent_depth: int = 0,
    ) -> PrioritizedAction:
        """Helper to create a properly configured action."""
        action_id = f"{action_type.name}:{vuln_type}:{target}:{hash(str(params))}"

        action = PrioritizedAction(
            priority=priority.value,
            action_id=action_id,
            action_type=action_type,
            target=target,
            vuln_type=vuln_type,
            params=params or {},
            estimated_requests=estimated_requests,
            depth=parent_depth + 1,
        )

        # Set estimated impact
        action.estimated_impact = self.estimate_impact(action)

        return action

    def create_amplification(
        self,
        trigger_finding: dict,
        target: str,
        vuln_type: str,
        params: dict | None = None,
        estimated_requests: int = 5,
    ) -> PrioritizedAction:
        """Create an amplification action based on a triggering finding."""
        # Higher priority if trigger was high severity
        trigger_severity = trigger_finding.get("severity", "MEDIUM")
        priority_map = {
            "CRITICAL": Priority.CRITICAL,
            "HIGH": Priority.HIGH,
            "MEDIUM": Priority.MEDIUM,
            "LOW": Priority.LOW,
        }
        priority = priority_map.get(trigger_severity, Priority.MEDIUM)

        # Get depth from trigger
        trigger_depth = trigger_finding.get("metadata", {}).get("discovery_depth", 0)

        return self.create_action(
            action_type=ActionType.AMPLIFICATION,
            target=target,
            vuln_type=vuln_type,
            priority=priority,
            params=params,
            estimated_requests=estimated_requests,
            parent_depth=trigger_depth,
        )

    # ═══════════════════════════════════════════════════════════════════════════
    # METRICS & REPORTING
    # ═══════════════════════════════════════════════════════════════════════════

    def get_metrics(self) -> dict[str, Any]:
        """Get explosion control metrics."""
        return {
            "actions": {
                "queued": self._metrics.actions_queued,
                "executed": self._metrics.actions_executed,
                "pruned": self._metrics.actions_pruned,
                "deferred": self._metrics.actions_deferred,
                "pending": len(self._queue),
            },
            "budget": {
                action_type.name: {
                    "allocated": budget.allocated,
                    "used": budget.used,
                    "remaining": budget.remaining,
                    "findings": budget.findings,
                    "efficiency": round(budget.efficiency, 4),
                }
                for action_type, budget in self._budgets.items()
            },
            "total_budget": {
                "total": self._total_budget,
                "remaining": self.get_total_remaining(),
                "used_pct": round(
                    (1 - self.get_total_remaining() / self._total_budget) * 100, 1
                ),
            },
            "health": {
                "max_depth_reached": self._metrics.max_depth_reached,
                "budget_exhaustion_events": self._metrics.budget_exhaustion_events,
                "high_value_skips": self._metrics.high_value_skips,
                "targets_with_many_findings": sum(
                    1 for v in self._findings_per_target.values() if v >= 5
                ),
            },
        }

    def log_summary(self) -> None:
        """Log explosion control summary."""
        metrics = self.get_metrics()

        logger.info(
            f"[EXPLOSION] Summary: "
            f"queued={metrics['actions']['queued']}, "
            f"executed={metrics['actions']['executed']}, "
            f"pruned={metrics['actions']['pruned']}"
        )
        logger.info(
            f"[EXPLOSION] Budget: {metrics['total_budget']['used_pct']}% used, "
            f"{metrics['total_budget']['remaining']} remaining"
        )

        if metrics['health']['high_value_skips'] > 0:
            logger.warning(
                f"[EXPLOSION] Skipped {metrics['health']['high_value_skips']} high-value actions "
                "due to budget constraints"
            )


# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL INSTANCE
# ═══════════════════════════════════════════════════════════════════════════════

_controller: StateExplosionController | None = None


def get_explosion_controller() -> StateExplosionController:
    """Get the global state explosion controller."""
    global _controller
    if _controller is None:
        _controller = StateExplosionController()
    return _controller


def reset_explosion_controller(
    total_budget: int = 10000,
    max_queue_size: int = 1000,
) -> StateExplosionController:
    """Reset and return a new explosion controller."""
    global _controller
    _controller = StateExplosionController(
        total_budget=total_budget,
        max_queue_size=max_queue_size,
    )
    return _controller
