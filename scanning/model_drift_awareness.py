"""
PHANTOM AI - Model Drift Awareness (Theme 14)

Philosophy: "O perigo não é não saber. É não saber que não sabes."
(The danger is not not-knowing. It's not knowing that you don't know.)

This module provides epistemic awareness for the scanner:
1. PATTERN VERSIONING — When were detection patterns last updated?
2. SUCCESS RATE TRACKING — Are our patterns still working?
3. STALENESS DETECTION — Is the scanner's model outdated?
4. UNKNOWN RATE TRACKING — How often do we fail to recognize frameworks?

Unlike Theme 11 (adding new patterns), Theme 14 is about making
the scanner AWARE of when its patterns might be outdated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)


class PatternCategory(Enum):
    """Categories of detection patterns for freshness tracking."""
    DB_ERROR = auto()           # Database error messages
    XSS_CONTEXT = auto()        # XSS context detection
    WAF_DETECTION = auto()      # WAF/CDN fingerprinting
    TECH_FINGERPRINT = auto()   # Framework/technology detection
    SPA_DETECTION = auto()      # SPA framework indicators
    VULN_SIGNATURE = auto()     # Vulnerability signatures
    AUTH_PATTERN = auto()       # Authentication patterns
    API_PATTERN = auto()        # API endpoint patterns


class StalenessLevel(Enum):
    """How stale is the scanner's model?"""
    FRESH = 0           # Updated within 30 days
    AGING = 1           # 30-90 days since update
    STALE = 2           # 90-180 days since update
    OUTDATED = 3        # 180+ days since update
    UNKNOWN = 4         # No version info available


@dataclass
class PatternVersionInfo:
    """Version metadata for a category of detection patterns."""
    category: PatternCategory
    last_updated: datetime
    pattern_count: int
    description: str = ""
    source: str = ""  # e.g., "Theme 11 update", "Manual patch"


@dataclass
class DetectionOutcome:
    """Outcome of a single detection attempt."""
    category: PatternCategory
    pattern_name: str
    matched: bool
    validated: bool  # Was the match confirmed (not FP)?
    target_type: str = ""  # e.g., "modern_spa", "legacy", "api"
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class DriftMetrics:
    """Metrics for model drift detection."""
    # Per-category tracking
    match_counts: dict[str, int] = field(default_factory=dict)
    validation_counts: dict[str, int] = field(default_factory=dict)
    unknown_counts: dict[str, int] = field(default_factory=dict)

    # Running totals
    total_matches: int = 0
    total_validated: int = 0
    total_unknown: int = 0
    total_attempts: int = 0

    def success_rate(self, category: str | None = None) -> float:
        """Calculate validation success rate (matched AND confirmed)."""
        if category:
            matches = self.match_counts.get(category, 0)
            validated = self.validation_counts.get(category, 0)
        else:
            matches = self.total_matches
            validated = self.total_validated

        if matches == 0:
            return 0.0
        return (validated / matches) * 100

    def unknown_rate(self) -> float:
        """Percentage of detection attempts that failed to recognize target."""
        if self.total_attempts == 0:
            return 0.0
        return (self.total_unknown / self.total_attempts) * 100


class ModelDriftAwareness:
    """
    Tracks whether the scanner's detection model is up-to-date.

    This provides "epistemic awareness" — the scanner knowing
    what it doesn't know.
    """

    # Pattern version metadata — last known good update dates
    # These dates represent when patterns were last significantly updated
    PATTERN_VERSIONS: dict[PatternCategory, PatternVersionInfo] = {
        PatternCategory.DB_ERROR: PatternVersionInfo(
            category=PatternCategory.DB_ERROR,
            last_updated=datetime(2026, 2, 8),  # Theme 11 update
            pattern_count=48,  # MariaDB 10.5+, SQLite 3.37+, PostgreSQL 15+
            description="Database error patterns for SQLi detection",
            source="Theme 11 - Heuristic Ossification Fix",
        ),
        PatternCategory.XSS_CONTEXT: PatternVersionInfo(
            category=PatternCategory.XSS_CONTEXT,
            last_updated=datetime(2026, 2, 8),  # Theme 11 update
            pattern_count=12,  # 7 original + 5 new (Alpine, HTMX, Vue, Svelte, Angular)
            description="XSS context detection for reactive frameworks",
            source="Theme 11 - Heuristic Ossification Fix",
        ),
        PatternCategory.WAF_DETECTION: PatternVersionInfo(
            category=PatternCategory.WAF_DETECTION,
            last_updated=datetime(2026, 2, 8),  # Theme 11 update
            pattern_count=35,  # +20 from Theme 11
            description="WAF/CDN/Bot protection signatures",
            source="Theme 11 - Heuristic Ossification Fix",
        ),
        PatternCategory.TECH_FINGERPRINT: PatternVersionInfo(
            category=PatternCategory.TECH_FINGERPRINT,
            last_updated=datetime(2026, 2, 8),  # Theme 11 update
            pattern_count=50,  # +5 from Theme 11 (Fresh, Leptos, Inertia, Million, Marko)
            description="Framework/technology fingerprinting",
            source="Theme 11 - Heuristic Ossification Fix",
        ),
        PatternCategory.SPA_DETECTION: PatternVersionInfo(
            category=PatternCategory.SPA_DETECTION,
            last_updated=datetime(2026, 2, 8),  # Theme 11 update
            pattern_count=23,  # +12 from Theme 11 (HTMX, Alpine, Turbo, etc.)
            description="SPA framework detection",
            source="Theme 11 - Heuristic Ossification Fix",
        ),
        PatternCategory.VULN_SIGNATURE: PatternVersionInfo(
            category=PatternCategory.VULN_SIGNATURE,
            last_updated=datetime(2026, 1, 15),  # Older patterns
            pattern_count=200,
            description="General vulnerability signatures",
            source="Core scanner patterns",
        ),
        PatternCategory.AUTH_PATTERN: PatternVersionInfo(
            category=PatternCategory.AUTH_PATTERN,
            last_updated=datetime(2026, 2, 6),  # Auth acquisition phase
            pattern_count=30,
            description="Authentication flow patterns",
            source="Auth Acquisition Phase implementation",
        ),
        PatternCategory.API_PATTERN: PatternVersionInfo(
            category=PatternCategory.API_PATTERN,
            last_updated=datetime(2026, 2, 5),
            pattern_count=40,
            description="API endpoint and GraphQL patterns",
            source="API Scanner enhancements",
        ),
    }

    # Staleness thresholds (days)
    STALENESS_THRESHOLDS = {
        StalenessLevel.FRESH: 30,
        StalenessLevel.AGING: 90,
        StalenessLevel.STALE: 180,
        StalenessLevel.OUTDATED: 365,
    }

    # Success rate thresholds for alerting
    SUCCESS_RATE_WARNING = 70.0   # Below this → patterns may be stale
    SUCCESS_RATE_CRITICAL = 50.0  # Below this → patterns are definitely stale

    # Unknown rate thresholds
    UNKNOWN_RATE_WARNING = 15.0   # More than 15% unknown → model gaps
    UNKNOWN_RATE_CRITICAL = 30.0  # More than 30% unknown → major blind spots

    def __init__(self) -> None:
        self._metrics = DriftMetrics()
        self._outcomes: list[DetectionOutcome] = []
        self._scan_start: datetime = datetime.now()
        self._target_type: str = "unknown"

    def start_scan(self, target_type: str = "unknown") -> None:
        """Initialize drift tracking for a new scan."""
        self._metrics = DriftMetrics()
        self._outcomes = []
        self._scan_start = datetime.now()
        self._target_type = target_type

    def record_detection(
        self,
        category: PatternCategory,
        pattern_name: str,
        matched: bool,
        validated: bool = True,
    ) -> None:
        """Record the outcome of a detection attempt."""
        outcome = DetectionOutcome(
            category=category,
            pattern_name=pattern_name,
            matched=matched,
            validated=validated,
            target_type=self._target_type,
        )
        self._outcomes.append(outcome)

        cat_name = category.name

        # Update counts
        self._metrics.total_attempts += 1

        if matched:
            self._metrics.total_matches += 1
            self._metrics.match_counts[cat_name] = (
                self._metrics.match_counts.get(cat_name, 0) + 1
            )

            if validated:
                self._metrics.total_validated += 1
                self._metrics.validation_counts[cat_name] = (
                    self._metrics.validation_counts.get(cat_name, 0) + 1
                )

    def record_unknown(self, category: PatternCategory, context: str = "") -> None:
        """Record when detection failed to recognize a target."""
        cat_name = category.name

        self._metrics.total_unknown += 1
        self._metrics.total_attempts += 1
        self._metrics.unknown_counts[cat_name] = (
            self._metrics.unknown_counts.get(cat_name, 0) + 1
        )

        if context:
            logger.debug(f"[MODEL_DRIFT] Unknown {cat_name}: {context[:100]}")

    def get_pattern_staleness(self, category: PatternCategory) -> StalenessLevel:
        """Check how stale a pattern category is."""
        version = self.PATTERN_VERSIONS.get(category)
        if not version:
            return StalenessLevel.UNKNOWN

        age_days = (datetime.now() - version.last_updated).days

        if age_days <= self.STALENESS_THRESHOLDS[StalenessLevel.FRESH]:
            return StalenessLevel.FRESH
        if age_days <= self.STALENESS_THRESHOLDS[StalenessLevel.AGING]:
            return StalenessLevel.AGING
        if age_days <= self.STALENESS_THRESHOLDS[StalenessLevel.STALE]:
            return StalenessLevel.STALE
        return StalenessLevel.OUTDATED

    def get_overall_staleness(self) -> StalenessLevel:
        """Calculate overall model staleness across all categories."""
        staleness_values = [
            self.get_pattern_staleness(cat) for cat in PatternCategory
        ]

        # Return the worst staleness level
        worst = max(s.value for s in staleness_values)
        return StalenessLevel(worst)

    def get_staleness_summary(self) -> dict[str, Any]:
        """Get summary of pattern staleness by category."""
        summary = {}

        for category in PatternCategory:
            version = self.PATTERN_VERSIONS.get(category)
            staleness = self.get_pattern_staleness(category)

            if version:
                age_days = (datetime.now() - version.last_updated).days
                summary[category.name] = {
                    "last_updated": version.last_updated.isoformat(),
                    "age_days": age_days,
                    "pattern_count": version.pattern_count,
                    "staleness": staleness.name,
                    "source": version.source,
                }
            else:
                summary[category.name] = {
                    "last_updated": None,
                    "age_days": None,
                    "pattern_count": 0,
                    "staleness": StalenessLevel.UNKNOWN.name,
                    "source": "Unknown",
                }

        return summary

    def check_model_health(self) -> dict[str, Any]:
        """
        Comprehensive model health check.

        Returns indicators of whether the scanner's model is still valid
        for the targets being scanned.
        """
        overall_staleness = self.get_overall_staleness()
        success_rate = self._metrics.success_rate()
        unknown_rate = self._metrics.unknown_rate()

        # Calculate category-specific issues
        categories_with_issues = []
        for category in PatternCategory:
            staleness = self.get_pattern_staleness(category)
            cat_success = self._metrics.success_rate(category.name)
            cat_unknown = self._metrics.unknown_counts.get(category.name, 0)

            if staleness.value >= StalenessLevel.STALE.value:
                categories_with_issues.append({
                    "category": category.name,
                    "issue": "stale",
                    "detail": f"Patterns {(datetime.now() - self.PATTERN_VERSIONS[category].last_updated).days} days old",
                })
            elif cat_success < self.SUCCESS_RATE_WARNING and cat_success > 0:
                categories_with_issues.append({
                    "category": category.name,
                    "issue": "low_success_rate",
                    "detail": f"Only {cat_success:.0f}% of matches validated",
                })
            elif cat_unknown > self._metrics.total_attempts * 0.1:  # >10% unknown in category
                categories_with_issues.append({
                    "category": category.name,
                    "issue": "high_unknown",
                    "detail": f"{cat_unknown} detection failures",
                })

        # Determine overall health
        if overall_staleness.value >= StalenessLevel.OUTDATED.value:
            health = "CRITICAL"
            recommendation = "Update detection patterns immediately - model is outdated"
        elif overall_staleness.value >= StalenessLevel.STALE.value:
            health = "WARNING"
            recommendation = "Consider updating patterns - some categories are stale"
        elif unknown_rate >= self.UNKNOWN_RATE_CRITICAL:
            health = "WARNING"
            recommendation = f"High unknown rate ({unknown_rate:.0f}%) - scanner may have blind spots"
        elif success_rate < self.SUCCESS_RATE_WARNING and success_rate > 0:
            health = "WARNING"
            recommendation = f"Low validation rate ({success_rate:.0f}%) - patterns may be outdated"
        else:
            health = "OK"
            recommendation = "Model is fresh and performing well"

        return {
            "health": health,
            "overall_staleness": overall_staleness.name,
            "success_rate": round(success_rate, 1),
            "unknown_rate": round(unknown_rate, 1),
            "total_detections": self._metrics.total_attempts,
            "total_matches": self._metrics.total_matches,
            "total_validated": self._metrics.total_validated,
            "total_unknown": self._metrics.total_unknown,
            "categories_with_issues": categories_with_issues,
            "recommendation": recommendation,
            "pattern_staleness": self.get_staleness_summary(),
        }

    def log_health_summary(self) -> None:
        """Log model health summary at INFO level."""
        health = self.check_model_health()

        if health["health"] == "CRITICAL":
            logger.warning(
                f"[MODEL_DRIFT] CRITICAL: {health['recommendation']}"
            )
            for issue in health["categories_with_issues"]:
                logger.warning(
                    f"[MODEL_DRIFT]   - {issue['category']}: {issue['issue']} ({issue['detail']})"
                )
        elif health["health"] == "WARNING":
            logger.info(
                f"[MODEL_DRIFT] Warning: {health['recommendation']}"
            )
        else:
            logger.debug(
                f"[MODEL_DRIFT] Model health OK. "
                f"Success rate: {health['success_rate']:.0f}%, "
                f"Unknown rate: {health['unknown_rate']:.0f}%"
            )

    def to_dict(self) -> dict[str, Any]:
        """Export drift awareness data as dictionary."""
        health = self.check_model_health()

        return {
            "model_health": health,
            "metrics": {
                "match_counts": self._metrics.match_counts,
                "validation_counts": self._metrics.validation_counts,
                "unknown_counts": self._metrics.unknown_counts,
                "total_attempts": self._metrics.total_attempts,
                "total_matches": self._metrics.total_matches,
                "total_validated": self._metrics.total_validated,
                "total_unknown": self._metrics.total_unknown,
            },
            "target_type": self._target_type,
            "scan_duration_seconds": (datetime.now() - self._scan_start).total_seconds(),
        }


# ═══════════════════════════════════════════════════════════════════════════════
# GLOBAL INSTANCE
# ═══════════════════════════════════════════════════════════════════════════════

_drift_awareness: ModelDriftAwareness | None = None


def get_drift_awareness() -> ModelDriftAwareness:
    """Get the global drift awareness instance."""
    global _drift_awareness
    if _drift_awareness is None:
        _drift_awareness = ModelDriftAwareness()
    return _drift_awareness


def reset_drift_awareness() -> ModelDriftAwareness:
    """Reset and return a new drift awareness instance."""
    global _drift_awareness
    _drift_awareness = ModelDriftAwareness()
    return _drift_awareness
