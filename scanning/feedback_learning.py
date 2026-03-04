"""
PHANTOM AI - Feedback Learning Engine

Continuous learning from validation outcomes to adapt heuristics over time.

Key Capabilities:
1. Feedback Store — Persist TP/FP outcomes with finding signatures
2. Pattern Learning — Track which payloads/patterns produce TPs vs FPs
3. Confidence Adjustment — Dynamic confidence based on historical accuracy
4. Heuristic Tuning — Adjust detection thresholds per module/target type
5. Payload Reputation — Score payloads by effectiveness and FP rate

Learning Signals:
- Validation pipeline outcomes (6-stage pass/fail)
- User-provided feedback (manual TP/FP marking)
- Cross-module correlation (findings that chain = higher confidence)
- Target type patterns (e-commerce vs SaaS behavior differences)

The system learns:
- Which modules are most accurate for which target types
- Which payload patterns produce false positives
- Optimal confidence thresholds per vulnerability type
- Which validation stage failures are predictive of FPs
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)

# Feedback storage directory
FEEDBACK_DIR = Path.home() / ".phantom" / "feedback"
FEEDBACK_FILE = FEEDBACK_DIR / "validation_feedback.jsonl"
LEARNING_STATE_FILE = FEEDBACK_DIR / "learning_state.json"
PAYLOAD_REPUTATION_FILE = FEEDBACK_DIR / "payload_reputation.json"


class ValidationOutcome(Enum):
    """Outcome of finding validation."""
    TRUE_POSITIVE = "tp"      # Confirmed vulnerability
    FALSE_POSITIVE = "fp"     # Not a real vulnerability
    TRUE_NEGATIVE = "tn"      # Correctly rejected
    FALSE_NEGATIVE = "fn"     # Missed vulnerability (rare, from manual review)
    UNKNOWN = "unknown"       # Not yet validated
    USER_CONFIRMED = "user_tp"  # User manually confirmed as TP
    USER_REJECTED = "user_fp"   # User manually rejected as FP


@dataclass
class ValidationFeedback:
    """A single validation outcome record."""
    finding_signature: str      # Hash of (module, vuln_type, payload_pattern)
    target_signature: str       # Hash of target domain characteristics
    module_name: str
    vulnerability_type: str
    outcome: str                # ValidationOutcome value
    confidence_original: float
    confidence_final: float
    validation_stages_passed: list[str] = field(default_factory=list)
    validation_stages_failed: list[str] = field(default_factory=list)
    payload_hash: str = ""      # Hash of the actual payload used
    target_stack: str = ""      # Detected stack (e.g., "Node.js/Express/SQLite")
    target_domain_type: str = ""  # Business domain (e-commerce, saas, etc.)
    timestamp: float = field(default_factory=time.time)
    user_override: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ValidationFeedback":
        return cls(**data)


@dataclass
class ModuleStats:
    """Statistics for a specific module."""
    total_findings: int = 0
    true_positives: int = 0
    false_positives: int = 0
    accuracy: float = 0.0
    avg_confidence_tp: float = 0.0
    avg_confidence_fp: float = 0.0
    confidence_adjustment: float = 0.0  # Boost or penalty to apply


@dataclass
class PayloadReputation:
    """Reputation score for a payload pattern."""
    payload_hash: str
    pattern_description: str
    times_used: int = 0
    true_positives: int = 0
    false_positives: int = 0
    effectiveness: float = 0.5  # 0-1 score
    fp_rate: float = 0.0
    recommended: bool = True  # Should we use this payload?


@dataclass
class LearningState:
    """Current state of the learning engine."""
    total_feedback_entries: int = 0
    last_retrain_timestamp: float = 0.0
    module_stats: dict[str, dict] = field(default_factory=dict)
    vuln_type_stats: dict[str, dict] = field(default_factory=dict)
    target_type_adjustments: dict[str, dict] = field(default_factory=dict)
    validation_stage_weights: dict[str, float] = field(default_factory=dict)
    version: str = "1.0.0"


class FeedbackStore:
    """
    Persistent store for validation feedback.

    Stores feedback in JSONL format for append-only writes.
    Supports querying by module, target, payload, etc.
    """

    def __init__(self):
        self._ensure_dirs()
        self._feedback_cache: list[ValidationFeedback] = []
        self._loaded = False

    def _ensure_dirs(self) -> None:
        """Ensure feedback directory exists."""
        FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)

    def _load_feedback(self) -> None:
        """Load all feedback from file into cache."""
        if self._loaded:
            return

        self._feedback_cache = []

        if FEEDBACK_FILE.exists():
            try:
                with open(FEEDBACK_FILE, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                self._feedback_cache.append(
                                    ValidationFeedback.from_dict(data)
                                )
                            except (json.JSONDecodeError, TypeError):
                                continue
            except Exception as e:
                logger.warning(f"[FEEDBACK] Error loading feedback: {e}")

        self._loaded = True
        logger.debug(f"[FEEDBACK] Loaded {len(self._feedback_cache)} feedback entries")

    def record(self, feedback: ValidationFeedback) -> None:
        """Record a new validation feedback entry."""
        self._ensure_dirs()

        # Append to file
        try:
            with open(FEEDBACK_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(feedback.to_dict()) + "\n")
        except Exception as e:
            logger.warning(f"[FEEDBACK] Error saving feedback: {e}")

        # Update cache
        if self._loaded:
            self._feedback_cache.append(feedback)

    def query(
        self,
        module_name: str | None = None,
        vuln_type: str | None = None,
        outcome: ValidationOutcome | None = None,
        since_days: int | None = None,
    ) -> list[ValidationFeedback]:
        """Query feedback entries with filters."""
        self._load_feedback()

        results = self._feedback_cache

        if module_name:
            results = [f for f in results if f.module_name == module_name]

        if vuln_type:
            results = [f for f in results if f.vulnerability_type == vuln_type]

        if outcome:
            results = [f for f in results if f.outcome == outcome.value]

        if since_days:
            cutoff = time.time() - (since_days * 86400)
            results = [f for f in results if f.timestamp >= cutoff]

        return results

    def get_all(self) -> list[ValidationFeedback]:
        """Get all feedback entries."""
        self._load_feedback()
        return self._feedback_cache

    def get_stats(self) -> dict:
        """Get summary statistics."""
        self._load_feedback()

        stats = {
            "total": len(self._feedback_cache),
            "by_outcome": defaultdict(int),
            "by_module": defaultdict(int),
        }

        for f in self._feedback_cache:
            stats["by_outcome"][f.outcome] += 1
            stats["by_module"][f.module_name] += 1

        return stats


class PayloadReputationTracker:
    """
    Tracks reputation of payload patterns.

    Learns which payloads are effective and which produce FPs.
    """

    def __init__(self):
        self._reputations: dict[str, PayloadReputation] = {}
        self._load()

    def _load(self) -> None:
        """Load payload reputations from file."""
        if PAYLOAD_REPUTATION_FILE.exists():
            try:
                with open(PAYLOAD_REPUTATION_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for payload_hash, rep_data in data.items():
                        self._reputations[payload_hash] = PayloadReputation(
                            payload_hash=payload_hash,
                            **rep_data
                        )
            except Exception as e:
                logger.debug(f"[PAYLOAD_REP] Error loading: {e}")

    def _save(self) -> None:
        """Save payload reputations to file."""
        FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
        try:
            data = {}
            for payload_hash, rep in self._reputations.items():
                data[payload_hash] = {
                    "pattern_description": rep.pattern_description,
                    "times_used": rep.times_used,
                    "true_positives": rep.true_positives,
                    "false_positives": rep.false_positives,
                    "effectiveness": rep.effectiveness,
                    "fp_rate": rep.fp_rate,
                    "recommended": rep.recommended,
                }
            with open(PAYLOAD_REPUTATION_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.debug(f"[PAYLOAD_REP] Error saving: {e}")

    def record_outcome(
        self,
        payload_hash: str,
        pattern_description: str,
        is_true_positive: bool,
    ) -> None:
        """Record an outcome for a payload."""
        if payload_hash not in self._reputations:
            self._reputations[payload_hash] = PayloadReputation(
                payload_hash=payload_hash,
                pattern_description=pattern_description,
            )

        rep = self._reputations[payload_hash]
        rep.times_used += 1

        if is_true_positive:
            rep.true_positives += 1
        else:
            rep.false_positives += 1

        # Recalculate effectiveness
        total = rep.true_positives + rep.false_positives
        if total > 0:
            rep.effectiveness = rep.true_positives / total
            rep.fp_rate = rep.false_positives / total

        # Mark as not recommended if FP rate too high
        rep.recommended = rep.fp_rate < 0.3 or rep.times_used < 5

        self._save()

    def get_reputation(self, payload_hash: str) -> PayloadReputation | None:
        """Get reputation for a payload."""
        return self._reputations.get(payload_hash)

    def get_recommended_payloads(self, top_n: int = 20) -> list[PayloadReputation]:
        """Get top recommended payloads by effectiveness."""
        recommended = [r for r in self._reputations.values() if r.recommended]
        return sorted(recommended, key=lambda r: r.effectiveness, reverse=True)[:top_n]

    def get_problematic_payloads(self, min_fp_rate: float = 0.3) -> list[PayloadReputation]:
        """Get payloads with high FP rates."""
        return [
            r for r in self._reputations.values()
            if r.fp_rate >= min_fp_rate and r.times_used >= 3
        ]


class LearningEngine:
    """
    Core learning engine that adapts heuristics based on feedback.

    Responsibilities:
    1. Analyze feedback to compute pattern effectiveness
    2. Compute per-module accuracy rates
    3. Adjust confidence based on historical patterns
    4. Retrain periodically as feedback accumulates
    """

    # Minimum samples before adjusting confidence
    MIN_SAMPLES_FOR_ADJUSTMENT = 5

    # Maximum confidence adjustment (positive or negative)
    MAX_CONFIDENCE_ADJUSTMENT = 0.20

    # Weight for validation stage failures
    STAGE_FAILURE_WEIGHTS = {
        "signature": 0.15,     # Signature mismatch is weak signal
        "context": 0.10,       # Context issues are weak signal
        "safe_replay": 0.25,   # Replay failure is moderate signal
        "negative_control": 0.20,  # Negative control failure is moderate
        "semantic": 0.15,      # Semantic analysis
        "behavior": 0.15,      # Behavior-based
    }

    def __init__(self):
        self._store = FeedbackStore()
        self._payload_tracker = PayloadReputationTracker()
        self._state = self._load_state()

    def _load_state(self) -> LearningState:
        """Load learning state from file."""
        if LEARNING_STATE_FILE.exists():
            try:
                with open(LEARNING_STATE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return LearningState(
                        total_feedback_entries=data.get("total_feedback_entries", 0),
                        last_retrain_timestamp=data.get("last_retrain_timestamp", 0),
                        module_stats=data.get("module_stats", {}),
                        vuln_type_stats=data.get("vuln_type_stats", {}),
                        target_type_adjustments=data.get("target_type_adjustments", {}),
                        validation_stage_weights=data.get(
                            "validation_stage_weights",
                            self.STAGE_FAILURE_WEIGHTS
                        ),
                        version=data.get("version", "1.0.0"),
                    )
            except Exception as e:
                logger.debug(f"[LEARNING] Error loading state: {e}")

        return LearningState(validation_stage_weights=self.STAGE_FAILURE_WEIGHTS)

    def _save_state(self) -> None:
        """Save learning state to file."""
        FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
        try:
            with open(LEARNING_STATE_FILE, "w", encoding="utf-8") as f:
                json.dump({
                    "total_feedback_entries": self._state.total_feedback_entries,
                    "last_retrain_timestamp": self._state.last_retrain_timestamp,
                    "module_stats": self._state.module_stats,
                    "vuln_type_stats": self._state.vuln_type_stats,
                    "target_type_adjustments": self._state.target_type_adjustments,
                    "validation_stage_weights": self._state.validation_stage_weights,
                    "version": self._state.version,
                }, f, indent=2)
        except Exception as e:
            logger.debug(f"[LEARNING] Error saving state: {e}")

    def record_validation_outcome(
        self,
        finding: dict,
        outcome: ValidationOutcome,
        validation_stages_passed: list[str],
        validation_stages_failed: list[str],
        user_override: bool = False,
    ) -> None:
        """
        Record a validation outcome for learning.

        Called after validation pipeline completes for each finding.
        """
        # Extract finding signature
        module_name = finding.get("module_name", "unknown")
        vuln_type = finding.get("vulnerability_type", "unknown")
        payload = finding.get("metadata", {}).get("payload", "")

        finding_sig = self._compute_finding_signature(module_name, vuln_type, payload)
        payload_hash = hashlib.sha256(str(payload).encode()).hexdigest()[:16]

        # Extract target signature
        host = finding.get("host", "") or finding.get("matched_at", "")
        target_sig = hashlib.sha256(host.encode()).hexdigest()[:16]

        # Create feedback record
        feedback = ValidationFeedback(
            finding_signature=finding_sig,
            target_signature=target_sig,
            module_name=module_name,
            vulnerability_type=vuln_type,
            outcome=outcome.value,
            confidence_original=finding.get("confidence_score", finding.get("confidence", 0.0)),
            confidence_final=finding.get("confidence_score", finding.get("confidence", 0.0)),
            validation_stages_passed=validation_stages_passed,
            validation_stages_failed=validation_stages_failed,
            payload_hash=payload_hash,
            target_stack=finding.get("metadata", {}).get("target_stack", ""),
            target_domain_type=finding.get("metadata", {}).get("domain_type", ""),
            user_override=user_override,
        )

        # Store feedback
        self._store.record(feedback)
        self._state.total_feedback_entries += 1

        # Update payload reputation
        is_tp = outcome in (ValidationOutcome.TRUE_POSITIVE, ValidationOutcome.USER_CONFIRMED)
        if payload:
            self._payload_tracker.record_outcome(
                payload_hash=payload_hash,
                pattern_description=str(payload)[:100],
                is_true_positive=is_tp,
            )

        # Periodic retrain
        if self._should_retrain():
            self.retrain()

    def _compute_finding_signature(
        self,
        module_name: str,
        vuln_type: str,
        payload: str,
    ) -> str:
        """Compute a signature for a finding pattern."""
        # Normalize payload to capture pattern, not exact value
        normalized_payload = self._normalize_payload(payload)
        sig_input = f"{module_name}:{vuln_type}:{normalized_payload}"
        return hashlib.sha256(sig_input.encode()).hexdigest()[:24]

    def _normalize_payload(self, payload: str) -> str:
        """Normalize payload to extract pattern."""
        if not payload:
            return ""

        payload_str = str(payload)

        # Replace dynamic values with placeholders
        import re
        # Replace numbers
        normalized = re.sub(r'\d+', 'N', payload_str)
        # Replace UUIDs
        normalized = re.sub(r'[a-f0-9-]{36}', 'UUID', normalized)
        # Replace email-like patterns
        normalized = re.sub(r'[\w.-]+@[\w.-]+', 'EMAIL', normalized)

        return normalized[:100]

    def _should_retrain(self) -> bool:
        """Check if we should retrain the model."""
        # Retrain every 50 new feedback entries
        feedback_threshold = 50

        # Or every 24 hours
        time_threshold = 86400

        entries_since_retrain = (
            self._state.total_feedback_entries -
            getattr(self._state, '_last_retrain_entries', 0)
        )

        time_since_retrain = time.time() - self._state.last_retrain_timestamp

        return (
            entries_since_retrain >= feedback_threshold or
            (time_since_retrain >= time_threshold and entries_since_retrain > 10)
        )

    def retrain(self) -> None:
        """
        Retrain heuristics from accumulated feedback.

        Updates:
        - Module accuracy stats
        - Vulnerability type adjustments
        - Target type patterns
        - Validation stage weights
        """
        logger.info("[LEARNING] Starting retrain from feedback...")

        all_feedback = self._store.get_all()

        if len(all_feedback) < self.MIN_SAMPLES_FOR_ADJUSTMENT:
            logger.debug(f"[LEARNING] Not enough samples ({len(all_feedback)}), skipping retrain")
            return

        # Compute module stats
        self._compute_module_stats(all_feedback)

        # Compute vulnerability type stats
        self._compute_vuln_type_stats(all_feedback)

        # Compute target type adjustments
        self._compute_target_adjustments(all_feedback)

        # Update validation stage weights
        self._update_stage_weights(all_feedback)

        # Save state
        self._state.last_retrain_timestamp = time.time()
        self._state._last_retrain_entries = self._state.total_feedback_entries
        self._save_state()

        logger.info(
            f"[LEARNING] Retrain complete. Processed {len(all_feedback)} entries. "
            f"Modules: {len(self._state.module_stats)}, "
            f"VulnTypes: {len(self._state.vuln_type_stats)}"
        )

    def _compute_module_stats(self, feedback: list[ValidationFeedback]) -> None:
        """Compute accuracy stats per module."""
        module_data: dict[str, dict] = defaultdict(lambda: {
            "total": 0, "tp": 0, "fp": 0, "conf_tp": [], "conf_fp": []
        })

        for f in feedback:
            module_data[f.module_name]["total"] += 1

            if f.outcome in ("tp", "user_tp"):
                module_data[f.module_name]["tp"] += 1
                module_data[f.module_name]["conf_tp"].append(f.confidence_original)
            elif f.outcome in ("fp", "user_fp"):
                module_data[f.module_name]["fp"] += 1
                module_data[f.module_name]["conf_fp"].append(f.confidence_original)

        for module, data in module_data.items():
            if isinstance(data, dict):
                total = data["tp"] + data["fp"]
            if total < self.MIN_SAMPLES_FOR_ADJUSTMENT:
                continue

            if isinstance(data, dict):
                accuracy = data["tp"] / total if total > 0 else 0.5
            if isinstance(data, dict):
                avg_conf_tp = sum(data["conf_tp"]) / len(data["conf_tp"]) if data["conf_tp"] else 0.5
            if isinstance(data, dict):
                avg_conf_fp = sum(data["conf_fp"]) / len(data["conf_fp"]) if data["conf_fp"] else 0.5

            # Compute confidence adjustment
            # High accuracy = boost confidence, low accuracy = penalize
            if accuracy >= 0.9:
                adjustment = min(0.10, (accuracy - 0.8) * 0.5)
            elif accuracy >= 0.7:
                adjustment = 0.0
            else:
                adjustment = max(-0.15, (accuracy - 0.7) * 0.5)

            self._state.module_stats[module] = {
                "total": total,
                "accuracy": round(accuracy, 3),
                "avg_conf_tp": round(avg_conf_tp, 3),
                "avg_conf_fp": round(avg_conf_fp, 3),
                "adjustment": round(adjustment, 3),
            }

    def _compute_vuln_type_stats(self, feedback: list[ValidationFeedback]) -> None:
        """Compute stats per vulnerability type."""
        vuln_data: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fp": 0})

        for f in feedback:
            if f.outcome in ("tp", "user_tp"):
                vuln_data[f.vulnerability_type]["tp"] += 1
            elif f.outcome in ("fp", "user_fp"):
                vuln_data[f.vulnerability_type]["fp"] += 1

        for vuln_type, data in vuln_data.items():
            if isinstance(data, dict):
                total = data["tp"] + data["fp"]
            if total < self.MIN_SAMPLES_FOR_ADJUSTMENT:
                continue

            if isinstance(data, dict):
                accuracy = data["tp"] / total
            adjustment = (accuracy - 0.5) * 0.2  # Small adjustment based on accuracy

            self._state.vuln_type_stats[vuln_type] = {
                "total": total,
                "accuracy": round(accuracy, 3),
                "adjustment": round(max(-0.10, min(0.10, adjustment)), 3),
            }

    def _compute_target_adjustments(self, feedback: list[ValidationFeedback]) -> None:
        """Compute adjustments based on target type patterns."""
        target_data: dict[str, dict] = defaultdict(lambda: {"tp": 0, "fp": 0})

        for f in feedback:
            if not f.target_domain_type:
                continue

            if f.outcome in ("tp", "user_tp"):
                target_data[f.target_domain_type]["tp"] += 1
            elif f.outcome in ("fp", "user_fp"):
                target_data[f.target_domain_type]["fp"] += 1

        for target_type, data in target_data.items():
            if isinstance(data, dict):
                total = data["tp"] + data["fp"]
            if total < 3:
                continue

            if isinstance(data, dict):
                accuracy = data["tp"] / total
            self._state.target_type_adjustments[target_type] = {
                "accuracy": round(accuracy, 3),
                "samples": total,
            }

    def _update_stage_weights(self, feedback: list[ValidationFeedback]) -> None:
        """Update validation stage weights based on predictive power."""
        stage_predictions: dict[str, dict] = defaultdict(lambda: {"tp_when_passed": 0, "fp_when_failed": 0, "total": 0})

        for f in feedback:
            for stage in f.validation_stages_passed:
                stage_predictions[stage]["total"] += 1
                if f.outcome in ("tp", "user_tp"):
                    stage_predictions[stage]["tp_when_passed"] += 1

            for stage in f.validation_stages_failed:
                stage_predictions[stage]["total"] += 1
                if f.outcome in ("fp", "user_fp"):
                    stage_predictions[stage]["fp_when_failed"] += 1

        for stage, data in stage_predictions.items():
            if isinstance(data, dict):
                if data["total"] < 10:
                    continue

            # Compute predictive power: how often does failure predict FP?
            if isinstance(data, dict):
                predictive_power = data["fp_when_failed"] / data["total"] if data["total"] > 0 else 0.5

            # Update weight: higher predictive power = higher weight
            new_weight = 0.1 + (predictive_power * 0.3)
            self._state.validation_stage_weights[stage] = round(new_weight, 3)

    def get_confidence_adjustment(
        self,
        module_name: str,
        vuln_type: str,
        target_domain_type: str = "",
        payload_hash: str = "",
    ) -> float:
        """
        Get the confidence adjustment for a finding.

        Returns a value to ADD to the original confidence.
        Positive = boost, Negative = penalize.
        """
        adjustment = 0.0

        # Module-level adjustment
        if module_name in self._state.module_stats:
            module_adj = self._state.module_stats[module_name].get("adjustment", 0.0)
            adjustment += module_adj

        # Vulnerability type adjustment
        if vuln_type in self._state.vuln_type_stats:
            vuln_adj = self._state.vuln_type_stats[vuln_type].get("adjustment", 0.0)
            adjustment += vuln_adj

        # Payload reputation adjustment
        if payload_hash:
            rep = self._payload_tracker.get_reputation(payload_hash)
            if rep and rep.times_used >= 3:
                # Penalize high FP rate payloads
                if rep.fp_rate > 0.3:
                    adjustment -= 0.10
                elif rep.effectiveness > 0.8:
                    adjustment += 0.05

        # Cap adjustment
        return max(-self.MAX_CONFIDENCE_ADJUSTMENT, min(self.MAX_CONFIDENCE_ADJUSTMENT, adjustment))

    def should_skip_payload(self, payload_hash: str) -> bool:
        """Check if a payload should be skipped due to poor reputation."""
        rep = self._payload_tracker.get_reputation(payload_hash)
        if rep and not rep.recommended:
            return True
        return False

    def get_module_accuracy(self, module_name: str) -> float:
        """Get historical accuracy for a module."""
        if module_name in self._state.module_stats:
            return self._state.module_stats[module_name].get("accuracy", 0.5)
        return 0.5

    def get_learning_summary(self) -> dict:
        """Get a summary of learning state."""
        return {
            "total_feedback": self._state.total_feedback_entries,
            "last_retrain": datetime.fromtimestamp(
                self._state.last_retrain_timestamp
            ).isoformat() if self._state.last_retrain_timestamp else "never",
            "modules_tracked": len(self._state.module_stats),
            "vuln_types_tracked": len(self._state.vuln_type_stats),
            "top_accurate_modules": sorted(
                [
                    (m, s.get("accuracy", 0))
                    for m, s in self._state.module_stats.items()
                ],
                key=lambda x: x[1],
                reverse=True,
            )[:5],
            "problematic_modules": [
                (m, s.get("accuracy", 0))
                for m, s in self._state.module_stats.items()
                if s.get("accuracy", 1.0) < 0.6
            ],
            "problematic_payloads": len(self._payload_tracker.get_problematic_payloads()),
        }


# Global learning engine instance
_global_engine: LearningEngine | None = None


def get_learning_engine() -> LearningEngine:
    """Get the global learning engine instance."""
    global _global_engine
    if _global_engine is None:
        _global_engine = LearningEngine()
    return _global_engine


def record_finding_outcome(
    finding: dict,
    is_valid: bool,
    validation_stages_passed: list[str] | None = None,
    validation_stages_failed: list[str] | None = None,
    user_override: bool = False,
) -> None:
    """
    Convenience function to record a finding outcome.

    Called from validation pipeline after each finding is processed.
    """
    engine = get_learning_engine()

    outcome = (
        ValidationOutcome.USER_CONFIRMED if user_override and is_valid else
        ValidationOutcome.USER_REJECTED if user_override and not is_valid else
        ValidationOutcome.TRUE_POSITIVE if is_valid else
        ValidationOutcome.FALSE_POSITIVE
    )

    engine.record_validation_outcome(
        finding=finding,
        outcome=outcome,
        validation_stages_passed=validation_stages_passed or [],
        validation_stages_failed=validation_stages_failed or [],
        user_override=user_override,
    )


def apply_learned_confidence(finding: dict) -> dict:
    """
    Apply learned confidence adjustment to a finding.

    Called before final validation to adjust confidence based on
    historical patterns.
    """
    engine = get_learning_engine()

    module_name = finding.get("module_name", "")
    vuln_type = finding.get("vulnerability_type", "")
    domain_type = finding.get("metadata", {}).get("domain_type", "")
    payload = finding.get("metadata", {}).get("payload", "")
    payload_hash = hashlib.sha256(str(payload).encode()).hexdigest()[:16] if payload else ""

    adjustment = engine.get_confidence_adjustment(
        module_name=module_name,
        vuln_type=vuln_type,
        target_domain_type=domain_type,
        payload_hash=payload_hash,
    )

    if adjustment != 0:
        original_conf = finding.get("confidence_score", finding.get("confidence", 0.5))
        if isinstance(original_conf, str):
            original_conf = {"critical": 0.95, "high": 0.85, "medium": 0.65, "low": 0.40}.get(original_conf.lower(), 0.5)
        new_conf = max(0.0, min(1.0, original_conf + adjustment))
        finding["confidence_score"] = new_conf
        finding["confidence"] = new_conf
        finding.setdefault("metadata", {})["learning_adjustment"] = round(adjustment, 3)

        logger.debug(
            f"[LEARNING] Adjusted {module_name}/{vuln_type} confidence: "
            f"{original_conf:.2f} -> {new_conf:.2f} ({adjustment:+.2f})"
        )

    return finding
