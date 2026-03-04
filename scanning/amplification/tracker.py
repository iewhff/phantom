"""
Amplification Tracker - State tracking for guardrail enforcement.

Extracted from full_scanner.py for modularization.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from urllib.parse import urlparse

from .models import (
    AmplificationAction,
    AmplificationGuardrails,
    ActionFingerprint,
    GuardrailBlockReason,
    ProgressMetrics,
    SuspensionLevel,
)

logger = logging.getLogger("phantom.amplification")


class AmplificationTracker:
    """
    Tracks amplification state for guardrail enforcement.

    Implements:
    - Action fingerprinting and deduplication
    - Per-finding action counting (using canonical IDs for hard limits)
    - Loop detection via directed graph
    - Retry tracking with backoff
    - Budget consumption monitoring
    - Progress score tracking for dead target detection
    - Soft/hard suspension levels
    - Block reason tagging for reporting
    """

    def __init__(self, guardrails: AmplificationGuardrails) -> None:
        self._guardrails = guardrails
        self._budget_used: int = 0
        self._actions_per_finding: dict[str, int] = {}        # finding_id → count
        self._actions_per_canonical: dict[str, int] = {}      # canonical_id → count (hard limits)
        self._retries_per_action: dict[ActionFingerprint, int] = {}
        self._recent_actions: dict[ActionFingerprint, float] = {}  # fingerprint → timestamp
        self._consecutive_failures: dict[str, int] = {}       # finding_id → failure count
        self._action_priorities: dict[ActionFingerprint, float] = {}  # decayed priorities

        # Soft/Hard suspension tracking
        self._suspension_levels: dict[str, SuspensionLevel] = {}  # finding_id → level
        self._soft_suspended: set[str] = set()            # Findings with low priority
        self._hard_suspended: set[str] = set()            # Findings completely blocked

        # Progress tracking per finding
        self._progress_metrics: dict[str, ProgressMetrics] = {}  # finding_id → metrics

        # Block reason tracking for reporting
        self._block_reasons: dict[GuardrailBlockReason, int] = {r: 0 for r in GuardrailBlockReason}
        self._block_details: list[dict] = []  # Detailed block log for client reports

        # Loop detection: directed graph of finding → action → finding
        self._action_graph: dict[str, set[str]] = {}  # finding_id → set of resulting finding_ids
        self._graph_depth: dict[str, int] = {}        # finding_id → depth in graph

        # State tracking for "state change requirement"
        self._state_snapshot: dict[str, set[str]] = {}  # Tracks discovered state (endpoints, headers, etc.)

        # Canonical ID mapping for hard limits
        self._finding_to_canonical: dict[str, str] = {}  # finding_id → canonical_id

    def _compute_fingerprint(self, action: AmplificationAction, finding_id: str) -> ActionFingerprint:
        """Create unique fingerprint for an action."""
        # Stable hash of params
        param_str = json.dumps(action.params, sort_keys=True)
        param_hash = hashlib.md5(param_str.encode()).hexdigest()[:8]

        return ActionFingerprint(
            finding_id=finding_id,
            action_type=action.action,
            target=action.target,
            param_hash=param_hash,
        )

    def _compute_canonical_id(self, finding: dict) -> str:
        """
        Compute canonical finding ID for hard limits.

        Uses vuln_type + normalized_endpoint to prevent bypass via granular IDs.
        """
        vuln_type = finding.get("type", "unknown").lower()
        url = finding.get("matched_at", "") or finding.get("url", "")

        # Normalize endpoint: strip query params and fragments
        if url:
            parsed = urlparse(url)
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        else:
            normalized = ""

        key = f"{vuln_type}:{normalized}"
        return hashlib.md5(key.encode()).hexdigest()[:12]

    def register_finding_canonical(self, finding_id: str, finding: dict) -> str:
        """Register the canonical ID for a finding."""
        canonical = self._compute_canonical_id(finding)
        self._finding_to_canonical[finding_id] = canonical
        return canonical

    def get_canonical_id(self, finding_id: str) -> str:
        """Get canonical ID for a finding (or return finding_id if not registered)."""
        return self._finding_to_canonical.get(finding_id, finding_id)

    def _get_progress_metrics(self, finding_id: str) -> ProgressMetrics:
        """Get or create progress metrics for a finding."""
        if finding_id not in self._progress_metrics:
            self._progress_metrics[finding_id] = ProgressMetrics()
        return self._progress_metrics[finding_id]

    def _record_block(
        self,
        reason: GuardrailBlockReason,
        action: AmplificationAction,
        finding_id: str,
        detail: str = "",
    ) -> None:
        """Record a blocked action for reporting."""
        self._block_reasons[reason] = self._block_reasons.get(reason, 0) + 1
        self._block_details.append({
            "reason": reason.value,
            "action": action.action,
            "target": action.target[:50] if action.target else "",
            "finding_id": finding_id[:8],
            "detail": detail,
        })

    def can_execute_action(
        self,
        action: AmplificationAction,
        finding_id: str,
    ) -> tuple[bool, GuardrailBlockReason | None, str]:
        """
        Check if an action can be executed based on guardrails.

        Returns (allowed, block_reason, reason_detail) tuple.
        block_reason is None if allowed.
        """
        fingerprint = self._compute_fingerprint(action, finding_id)
        canonical_id = self.get_canonical_id(finding_id)

        # 1. Check HARD suspension (completely blocked)
        if finding_id in self._hard_suspended:
            reason = GuardrailBlockReason.HARD_SUSPENDED
            detail = f"Finding {finding_id[:8]} HARD suspended (dead target)"
            self._record_block(reason, action, finding_id, detail)
            return False, reason, detail

        # 2. Check SOFT suspension (very low priority, only allow if new surface)
        if finding_id in self._soft_suspended:
            # Soft suspended findings can only proceed if state changed
            current_state = self._state_snapshot.get(finding_id, set())
            if not self.has_state_changed(finding_id, current_state):
                reason = GuardrailBlockReason.SOFT_SUSPENDED
                detail = f"Finding {finding_id[:8]} SOFT suspended, no new surface"
                self._record_block(reason, action, finding_id, detail)
                return False, reason, detail
            else:
                # New surface detected! Revive the finding
                self._soft_suspended.discard(finding_id)
                self._suspension_levels[finding_id] = SuspensionLevel.NONE
                logger.info(f"[GUARDRAILS] Finding {finding_id[:8]} REVIVED due to new surface")

        # 3. Check progress score (early suspension for dead targets)
        metrics = self._get_progress_metrics(finding_id)
        if metrics.is_dead_target:
            reason = GuardrailBlockReason.LOW_PROGRESS_SCORE
            detail = f"Progress score too low ({metrics.progress_score}), target appears dead"
            self._record_block(reason, action, finding_id, detail)
            # Apply soft suspension
            self._apply_soft_suspension(finding_id, "low_progress_score")
            return False, reason, detail

        # 4. Check global budget
        action_cost = self._guardrails.action_costs.get(
            action.action,
            self._guardrails.action_costs.get("default", 1)
        )
        if self._budget_used + action_cost > self._guardrails.global_action_budget:
            reason = GuardrailBlockReason.BUDGET_EXCEEDED
            detail = f"Global budget exhausted ({self._budget_used}/{self._guardrails.global_action_budget})"
            self._record_block(reason, action, finding_id, detail)
            return False, reason, detail

        # 5. Check per-canonical-ID limit (hard limits to prevent bypass)
        canonical_actions = self._actions_per_canonical.get(canonical_id, 0)
        if canonical_actions >= self._guardrails.max_actions_per_finding:
            reason = GuardrailBlockReason.PER_FINDING_LIMIT
            detail = f"Max actions per canonical finding reached ({canonical_actions}/{self._guardrails.max_actions_per_finding})"
            self._record_block(reason, action, finding_id, detail)
            return False, reason, detail

        # 6. Check retry limit
        retries = self._retries_per_action.get(fingerprint, 0)
        if retries >= self._guardrails.max_retries_per_action:
            reason = GuardrailBlockReason.RETRY_LIMIT
            detail = f"Max retries reached ({retries}/{self._guardrails.max_retries_per_action})"
            self._record_block(reason, action, finding_id, detail)
            return False, reason, detail

        # 7. Check dedup window (TTL)
        if fingerprint in self._recent_actions:
            last_time = self._recent_actions[fingerprint]
            elapsed = time.time() - last_time
            if elapsed < self._guardrails.same_action_dedup_window:
                remaining = self._guardrails.same_action_dedup_window - elapsed
                reason = GuardrailBlockReason.DUPLICATE_ACTION
                detail = f"Action in dedup window ({int(remaining)}s remaining)"
                self._record_block(reason, action, finding_id, detail)
                return False, reason, detail

        # 8. Check graph depth (loop prevention)
        if finding_id in self._graph_depth:
            depth = self._graph_depth[finding_id]
            if depth > 6:  # Max depth limit
                reason = GuardrailBlockReason.LOOP_DETECTED
                detail = f"Max graph depth exceeded (depth={depth})"
                self._record_block(reason, action, finding_id, detail)
                return False, reason, detail

        return True, None, "OK"

    def _apply_soft_suspension(self, finding_id: str, reason: str) -> None:
        """Apply soft suspension to a finding."""
        if finding_id not in self._hard_suspended:
            self._soft_suspended.add(finding_id)
            self._suspension_levels[finding_id] = SuspensionLevel.SOFT
            logger.info(
                f"[GUARDRAILS] Finding {finding_id[:8]} SOFT SUSPENDED ({reason})"
            )

    def _apply_hard_suspension(self, finding_id: str, reason: str) -> None:
        """Apply hard suspension to a finding."""
        self._hard_suspended.add(finding_id)
        self._soft_suspended.discard(finding_id)
        self._suspension_levels[finding_id] = SuspensionLevel.HARD
        logger.info(
            f"[GUARDRAILS] Finding {finding_id[:8]} HARD SUSPENDED ({reason})"
        )

    def record_action_start(self, action: AmplificationAction, finding_id: str) -> None:
        """Record that an action has started executing."""
        fingerprint = self._compute_fingerprint(action, finding_id)
        canonical_id = self.get_canonical_id(finding_id)

        # Update counters (both regular and canonical)
        self._actions_per_finding[finding_id] = self._actions_per_finding.get(finding_id, 0) + 1
        self._actions_per_canonical[canonical_id] = self._actions_per_canonical.get(canonical_id, 0) + 1

        # Update progress metrics
        metrics = self._get_progress_metrics(finding_id)
        metrics.actions_total += 1

        # Update budget
        action_cost = self._guardrails.action_costs.get(
            action.action,
            self._guardrails.action_costs.get("default", 1)
        )
        self._budget_used += action_cost

        # Record timestamp
        self._recent_actions[fingerprint] = time.time()

        logger.debug(
            f"[GUARDRAILS] Action started: {action.action} for {finding_id[:8]}... "
            f"(budget: {self._budget_used}/{self._guardrails.global_action_budget}, "
            f"progress_score: {metrics.progress_score})"
        )

    def record_action_result(
        self,
        action: AmplificationAction,
        finding_id: str,
        success: bool,
        new_finding_ids: list[str] | None = None,
        state_changed: bool = False,
        new_endpoints: int = 0,
        new_headers: int = 0,
    ) -> tuple[float, bool]:
        """
        Record the result of an action.

        RISCO 1 Fix: Distinguishes between real success and success_but_no_progress.
        A success is only "real" if:
        - state_changed is True, OR
        - new_finding_ids has entries, OR
        - new_endpoints or new_headers > 0

        Returns (adjusted_priority, is_real_progress) tuple.
        """
        fingerprint = self._compute_fingerprint(action, finding_id)
        metrics = self._get_progress_metrics(finding_id)

        # Determine if this is REAL progress or just a superficial success
        has_new_findings = bool(new_finding_ids)
        is_real_progress = state_changed or has_new_findings or new_endpoints > 0 or new_headers > 0

        if success and is_real_progress:
            # === REAL SUCCESS ===
            # Reset consecutive failures
            self._consecutive_failures[finding_id] = 0

            # Update progress metrics positively
            if state_changed:
                metrics.new_state_changes += 1
            if has_new_findings:
                metrics.new_findings += len(new_finding_ids or [])
            metrics.new_endpoints += new_endpoints
            metrics.new_headers += new_headers

            # Update graph with new findings
            if new_finding_ids:
                if finding_id not in self._action_graph:
                    self._action_graph[finding_id] = set()
                for new_id in new_finding_ids:
                    self._action_graph[finding_id].add(new_id)
                    # Propagate depth
                    parent_depth = self._graph_depth.get(finding_id, 0)
                    self._graph_depth[new_id] = parent_depth + 1

            # If finding was soft-suspended, consider reviving
            if finding_id in self._soft_suspended:
                self._soft_suspended.discard(finding_id)
                self._suspension_levels[finding_id] = SuspensionLevel.NONE
                logger.info(f"[GUARDRAILS] Finding {finding_id[:8]} REVIVED due to real progress")

            logger.debug(
                f"[GUARDRAILS] REAL SUCCESS: {action.action} "
                f"(progress_score: {metrics.progress_score})"
            )
            return float(action.priority), True

        elif success and not is_real_progress:
            # === SUCCESS BUT NO PROGRESS ===
            # HTTP 200 but no actual change - treat as mild failure
            metrics.retries += 1  # Count as retry for progress score

            # Don't reset failures, just don't increment them
            current_priority = self._action_priorities.get(fingerprint, float(action.priority))
            # Mild decay (less than failure)
            decayed_priority = current_priority * 0.95
            self._action_priorities[fingerprint] = decayed_priority

            logger.debug(
                f"[GUARDRAILS] SUCCESS_NO_PROGRESS: {action.action} "
                f"(progress_score: {metrics.progress_score}, priority: {decayed_priority:.1f})"
            )
            return decayed_priority, False

        else:
            # === FAILURE ===
            # Increment retry count and progress penalty
            self._retries_per_action[fingerprint] = self._retries_per_action.get(fingerprint, 0) + 1
            metrics.retries += 1

            # Increment consecutive failures
            failures = self._consecutive_failures.get(finding_id, 0) + 1
            self._consecutive_failures[finding_id] = failures

            # Check suspension thresholds
            if failures >= self._guardrails.hard_suspend_threshold:
                # HARD suspend - target is dead
                self._apply_hard_suspension(finding_id, f"{failures}_consecutive_failures")
            elif failures >= self._guardrails.soft_suspend_threshold:
                # SOFT suspend - can revive with new surface
                self._apply_soft_suspension(finding_id, f"{failures}_consecutive_failures")

            # Apply priority decay
            current_priority = self._action_priorities.get(fingerprint, float(action.priority))
            decayed_priority = current_priority * self._guardrails.priority_decay_on_failure
            self._action_priorities[fingerprint] = decayed_priority

            logger.debug(
                f"[GUARDRAILS] FAILURE: {action.action} "
                f"(failures: {failures}, progress_score: {metrics.progress_score}, "
                f"priority: {current_priority:.1f} → {decayed_priority:.1f})"
            )

            return decayed_priority, False

    def get_backoff_seconds(self, action: AmplificationAction, finding_id: str) -> float:
        """Get exponential backoff time for retrying an action."""
        fingerprint = self._compute_fingerprint(action, finding_id)
        retries = self._retries_per_action.get(fingerprint, 0)
        return float(self._guardrails.exponential_backoff_base ** retries)

    def has_state_changed(self, finding_id: str, new_state: set[str]) -> bool:
        """
        Check if state has changed since last action on this finding.

        Philosophy: "Only re-execute action if something NEW appeared"
        (new header, new cookie, new endpoint discovered, etc.)
        """
        old_state = self._state_snapshot.get(finding_id, set())
        self._state_snapshot[finding_id] = new_state
        return bool(new_state - old_state)  # True if there's new state

    def get_summary(self) -> dict:
        """Get summary of guardrail state."""
        # Calculate progress score stats
        progress_scores = [m.progress_score for m in self._progress_metrics.values()]
        avg_progress = sum(progress_scores) / len(progress_scores) if progress_scores else 0
        dead_targets = sum(1 for m in self._progress_metrics.values() if m.is_dead_target)

        return {
            "budget_used": self._budget_used,
            "budget_total": self._guardrails.global_action_budget,
            "budget_remaining": self._guardrails.global_action_budget - self._budget_used,
            "findings_tracked": len(self._actions_per_finding),
            "canonical_findings_tracked": len(self._actions_per_canonical),
            # Suspension stats
            "soft_suspended": len(self._soft_suspended),
            "hard_suspended": len(self._hard_suspended),
            "total_suspended": len(self._soft_suspended) + len(self._hard_suspended),
            # Progress stats
            "avg_progress_score": round(avg_progress, 1),
            "dead_targets": dead_targets,
            # Dedup and depth
            "actions_deduped": len(self._recent_actions),
            "max_graph_depth": max(self._graph_depth.values()) if self._graph_depth else 0,
            # Block reasons for reporting
            "block_reasons": {r.value: count for r, count in self._block_reasons.items() if count > 0},
            "total_blocked": sum(self._block_reasons.values()),
        }

    def get_block_report(self) -> dict:
        """
        Get detailed block report for client reports.

        Explains "não testámos X porque..."
        """
        # Group blocks by reason
        by_reason: dict[str, list[dict]] = {}
        for detail in self._block_details:
            reason = detail["reason"]
            if reason not in by_reason:
                by_reason[reason] = []
            by_reason[reason].append(detail)

        return {
            "summary": {r.value: count for r, count in self._block_reasons.items() if count > 0},
            "details_by_reason": by_reason,
            "explanation": self._generate_block_explanation(),
        }

    def _generate_block_explanation(self) -> list[str]:
        """Generate human-readable explanations for blocks."""
        explanations = []

        if self._block_reasons.get(GuardrailBlockReason.BUDGET_EXCEEDED, 0) > 0:
            explanations.append(
                f"• Budget exhausted: {self._block_reasons[GuardrailBlockReason.BUDGET_EXCEEDED]} "
                f"actions blocked due to scan budget limits"
            )

        if self._block_reasons.get(GuardrailBlockReason.HARD_SUSPENDED, 0) > 0:
            explanations.append(
                f"• Dead targets: {self._block_reasons[GuardrailBlockReason.HARD_SUSPENDED]} "
                f"actions blocked on targets that showed no progress after multiple attempts"
            )

        if self._block_reasons.get(GuardrailBlockReason.SOFT_SUSPENDED, 0) > 0:
            explanations.append(
                f"• Low-priority targets: {self._block_reasons[GuardrailBlockReason.SOFT_SUSPENDED]} "
                f"actions skipped on targets with low success rate (can be revived with new surfaces)"
            )

        if self._block_reasons.get(GuardrailBlockReason.DUPLICATE_ACTION, 0) > 0:
            explanations.append(
                f"• Deduplication: {self._block_reasons[GuardrailBlockReason.DUPLICATE_ACTION]} "
                f"duplicate actions skipped (same action within time window)"
            )

        if self._block_reasons.get(GuardrailBlockReason.LOOP_DETECTED, 0) > 0:
            explanations.append(
                f"• Loop prevention: {self._block_reasons[GuardrailBlockReason.LOOP_DETECTED]} "
                f"actions blocked to prevent infinite amplification loops"
            )

        if self._block_reasons.get(GuardrailBlockReason.LOW_PROGRESS_SCORE, 0) > 0:
            explanations.append(
                f"• Low progress: {self._block_reasons[GuardrailBlockReason.LOW_PROGRESS_SCORE]} "
                f"actions blocked on targets showing no meaningful progress"
            )

        return explanations
