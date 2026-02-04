"""
Metrics Collector - Track Scanner Effectiveness.

Tracks precision, recall, F1-score, false positives, and false negatives
for each module and overall framework performance.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)


class FindingOutcome(Enum):
    """Outcome classification for findings."""
    TRUE_POSITIVE = "TP"      # Real vulnerability found
    FALSE_POSITIVE = "FP"     # False alarm
    TRUE_NEGATIVE = "TN"      # Correctly identified as safe
    FALSE_NEGATIVE = "FN"     # Missed vulnerability


@dataclass
class FindingValidation:
    """Validation result for a single finding."""
    finding_id: str
    module: str
    vulnerability_type: str
    target: str
    outcome: FindingOutcome
    confidence: float  # Scanner's confidence (0-1)
    verified_by: str = "manual"  # manual, automated, external_tool
    notes: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "module": self.module,
            "vulnerability_type": self.vulnerability_type,
            "target": self.target,
            "outcome": self.outcome.value,
            "confidence": self.confidence,
            "verified_by": self.verified_by,
            "notes": self.notes,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ModuleMetrics:
    """Metrics for a single scanner module."""
    module_name: str
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    total_scans: int = 0
    avg_scan_time_ms: float = 0
    validations: list[FindingValidation] = field(default_factory=list)
    
    @property
    def precision(self) -> float:
        """Precision = TP / (TP + FP) - How accurate are positive findings?"""
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total > 0 else 0.0
    
    @property
    def recall(self) -> float:
        """Recall = TP / (TP + FN) - How many real vulns did we find?"""
        total = self.true_positives + self.false_negatives
        return self.true_positives / total if total > 0 else 0.0
    
    @property
    def f1_score(self) -> float:
        """F1 = 2 * (precision * recall) / (precision + recall)"""
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)
    
    @property
    def accuracy(self) -> float:
        """Accuracy = (TP + TN) / Total"""
        total = self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        return (self.true_positives + self.true_negatives) / total if total > 0 else 0.0
    
    @property
    def false_positive_rate(self) -> float:
        """FPR = FP / (FP + TN)"""
        total = self.false_positives + self.true_negatives
        return self.false_positives / total if total > 0 else 0.0
    
    @property
    def false_negative_rate(self) -> float:
        """FNR = FN / (FN + TP)"""
        total = self.false_negatives + self.true_positives
        return self.false_negatives / total if total > 0 else 0.0
    
    @property
    def effectiveness_score(self) -> float:
        """Overall effectiveness (0-100) based on F1 and low FP rate."""
        # Penalize high false positive rates heavily
        fp_penalty = 1 - (self.false_positive_rate * 0.5)
        return self.f1_score * fp_penalty * 100
    
    @property
    def grade(self) -> str:
        """Letter grade based on effectiveness score."""
        score = self.effectiveness_score
        if score >= 90: return "A+"
        if score >= 85: return "A"
        if score >= 80: return "A-"
        if score >= 75: return "B+"
        if score >= 70: return "B"
        if score >= 65: return "B-"
        if score >= 60: return "C+"
        if score >= 55: return "C"
        if score >= 50: return "C-"
        if score >= 40: return "D"
        return "F"
    
    def add_validation(self, validation: FindingValidation) -> None:
        """Add a validation result."""
        self.validations.append(validation)
        
        if validation.outcome == FindingOutcome.TRUE_POSITIVE:
            self.true_positives += 1
        elif validation.outcome == FindingOutcome.FALSE_POSITIVE:
            self.false_positives += 1
        elif validation.outcome == FindingOutcome.TRUE_NEGATIVE:
            self.true_negatives += 1
        elif validation.outcome == FindingOutcome.FALSE_NEGATIVE:
            self.false_negatives += 1
    
    def to_dict(self) -> dict:
        return {
            "module_name": self.module_name,
            "counts": {
                "true_positives": self.true_positives,
                "false_positives": self.false_positives,
                "true_negatives": self.true_negatives,
                "false_negatives": self.false_negatives,
                "total_scans": self.total_scans,
            },
            "metrics": {
                "precision": round(self.precision, 4),
                "recall": round(self.recall, 4),
                "f1_score": round(self.f1_score, 4),
                "accuracy": round(self.accuracy, 4),
                "false_positive_rate": round(self.false_positive_rate, 4),
                "false_negative_rate": round(self.false_negative_rate, 4),
                "effectiveness_score": round(self.effectiveness_score, 2),
                "grade": self.grade,
            },
            "performance": {
                "avg_scan_time_ms": round(self.avg_scan_time_ms, 2),
            },
        }


@dataclass
class ScanMetrics:
    """Overall scan metrics across all modules."""
    scan_id: str
    target: str
    started_at: datetime
    completed_at: datetime | None = None
    modules_run: list[str] = field(default_factory=list)
    module_metrics: dict[str, ModuleMetrics] = field(default_factory=dict)
    total_findings: int = 0
    validated_findings: int = 0
    
    @property
    def duration_seconds(self) -> float:
        if not self.completed_at:
            return 0.0
        return (self.completed_at - self.started_at).total_seconds()
    
    @property
    def overall_precision(self) -> float:
        total_tp = sum(m.true_positives for m in self.module_metrics.values())
        total_fp = sum(m.false_positives for m in self.module_metrics.values())
        return total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    
    @property
    def overall_recall(self) -> float:
        total_tp = sum(m.true_positives for m in self.module_metrics.values())
        total_fn = sum(m.false_negatives for m in self.module_metrics.values())
        return total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    
    @property
    def overall_f1(self) -> float:
        if self.overall_precision + self.overall_recall == 0:
            return 0.0
        return 2 * (self.overall_precision * self.overall_recall) / (self.overall_precision + self.overall_recall)
    
    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": round(self.duration_seconds, 2),
            "modules_run": self.modules_run,
            "total_findings": self.total_findings,
            "validated_findings": self.validated_findings,
            "overall_metrics": {
                "precision": round(self.overall_precision, 4),
                "recall": round(self.overall_recall, 4),
                "f1_score": round(self.overall_f1, 4),
            },
            "module_metrics": {k: v.to_dict() for k, v in self.module_metrics.items()},
        }


class MetricsCollector:
    """
    Centralized metrics collection and analysis.
    
    Features:
    - Track all scan results
    - Aggregate metrics per module
    - Calculate framework-wide statistics
    - Export metrics for dashboards
    - Historical trend analysis
    """
    
    def __init__(self, storage_path: str = "data/metrics"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.scan_history: list[ScanMetrics] = []
        self.module_aggregates: dict[str, ModuleMetrics] = {}
        
        self._load_history()
    
    def _load_history(self) -> None:
        """Load historical metrics from storage."""
        history_file = self.storage_path / "scan_history.json"
        if history_file.exists():
            try:
                data = json.loads(history_file.read_text())
                
                # Reconstruct module aggregates from JSON
                for name, metrics_data in data.get("module_aggregates", {}).items():
                    counts = metrics_data.get("counts", {})
                    metrics = ModuleMetrics(
                        module_name=name,
                        true_positives=counts.get("true_positives", 0),
                        false_positives=counts.get("false_positives", 0),
                        true_negatives=counts.get("true_negatives", 0),
                        false_negatives=counts.get("false_negatives", 0),
                        total_scans=counts.get("total_scans", 0),
                    )
                    self.module_aggregates[name] = metrics
                
                logger.info(f"Loaded {len(data.get('scans', []))} historical scans, {len(self.module_aggregates)} modules")
            except Exception as e:
                logger.warning(f"Could not load metrics history: {e}")
    
    def _save_history(self) -> None:
        """Persist metrics to storage."""
        history_file = self.storage_path / "scan_history.json"
        try:
            data = {
                "last_updated": datetime.now().isoformat(),
                "total_scans": len(self.scan_history),
                "scans": [s.to_dict() for s in self.scan_history[-100:]],  # Keep last 100
                "module_aggregates": {k: v.to_dict() for k, v in self.module_aggregates.items()},
            }
            history_file.write_text(json.dumps(data, indent=2))
        except Exception as e:
            logger.error(f"Could not save metrics: {e}")
    
    def record_scan(self, scan_metrics: ScanMetrics) -> None:
        """Record a completed scan."""
        self.scan_history.append(scan_metrics)
        
        # Update module aggregates
        for module_name, metrics in scan_metrics.module_metrics.items():
            if module_name not in self.module_aggregates:
                self.module_aggregates[module_name] = ModuleMetrics(module_name=module_name)
            
            agg = self.module_aggregates[module_name]
            agg.true_positives += metrics.true_positives
            agg.false_positives += metrics.false_positives
            agg.true_negatives += metrics.true_negatives
            agg.false_negatives += metrics.false_negatives
            agg.total_scans += 1
        
        self._save_history()
        logger.info(f"Recorded scan metrics: {scan_metrics.scan_id}")
    
    def validate_finding(
        self,
        scan_id: str,
        finding_id: str,
        outcome: FindingOutcome,
        verified_by: str = "manual",
        notes: str = "",
    ) -> None:
        """Validate a specific finding from a scan."""
        # Find the scan
        scan = next((s for s in self.scan_history if s.scan_id == scan_id), None)
        if not scan:
            logger.warning(f"Scan {scan_id} not found")
            return
        
        # This would update the finding status
        scan.validated_findings += 1
        self._save_history()
    
    def get_module_report(self, module_name: str) -> dict:
        """Get detailed metrics report for a module."""
        if module_name not in self.module_aggregates:
            return {"error": f"No data for module: {module_name}"}
        
        metrics = self.module_aggregates[module_name]
        return {
            "module": module_name,
            "status": self._get_module_status(metrics),
            **metrics.to_dict(),
            "recommendations": self._get_recommendations(metrics),
        }
    
    def _get_module_status(self, metrics: ModuleMetrics) -> str:
        """Determine module health status."""
        if metrics.total_scans < 10:
            return "⚠️ INSUFFICIENT_DATA"
        if metrics.effectiveness_score >= 80:
            return "✅ PRODUCTION_READY"
        if metrics.effectiveness_score >= 60:
            return "🔶 NEEDS_IMPROVEMENT"
        return "🔴 UNRELIABLE"
    
    def _get_recommendations(self, metrics: ModuleMetrics) -> list[str]:
        """Generate recommendations based on metrics."""
        recs = []
        
        if metrics.false_positive_rate > 0.3:
            recs.append("🎯 High FP rate - improve detection accuracy, add more validation checks")
        
        if metrics.false_negative_rate > 0.2:
            recs.append("🔍 Missing vulnerabilities - expand test coverage, add more signatures")
        
        if metrics.precision < 0.7:
            recs.append("📊 Low precision - refine detection rules to reduce noise")
        
        if metrics.recall < 0.7:
            recs.append("📈 Low recall - add more detection patterns and edge cases")
        
        if metrics.total_scans < 50:
            recs.append("🧪 More testing needed - run against more diverse targets")
        
        if not recs:
            recs.append("✅ Module performing well - continue monitoring")
        
        return recs
    
    def get_framework_health(self) -> dict:
        """Get overall framework health report."""
        if not self.module_aggregates:
            return {
                "status": "NO_DATA",
                "message": "No validation data yet. Run benchmark tests first.",
            }
        
        total_modules = len(self.module_aggregates)
        production_ready = sum(1 for m in self.module_aggregates.values() 
                               if m.effectiveness_score >= 80 and m.total_scans >= 10)
        needs_work = sum(1 for m in self.module_aggregates.values() 
                        if 60 <= m.effectiveness_score < 80)
        unreliable = sum(1 for m in self.module_aggregates.values() 
                        if m.effectiveness_score < 60 and m.total_scans >= 10)
        insufficient_data = sum(1 for m in self.module_aggregates.values() 
                               if m.total_scans < 10)
        
        # Calculate overall scores
        all_tp = sum(m.true_positives for m in self.module_aggregates.values())
        all_fp = sum(m.false_positives for m in self.module_aggregates.values())
        all_fn = sum(m.false_negatives for m in self.module_aggregates.values())
        
        overall_precision = all_tp / (all_tp + all_fp) if (all_tp + all_fp) > 0 else 0
        overall_recall = all_tp / (all_tp + all_fn) if (all_tp + all_fn) > 0 else 0
        
        return {
            "status": "HEALTHY" if production_ready > total_modules * 0.7 else "NEEDS_ATTENTION",
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_modules": total_modules,
                "production_ready": production_ready,
                "needs_improvement": needs_work,
                "unreliable": unreliable,
                "insufficient_data": insufficient_data,
            },
            "overall_metrics": {
                "precision": round(overall_precision, 4),
                "recall": round(overall_recall, 4),
                "total_scans": len(self.scan_history),
                "total_findings_validated": sum(s.validated_findings for s in self.scan_history),
            },
            "module_grades": {
                name: m.grade for name, m in self.module_aggregates.items()
            },
            "top_performers": [
                name for name, m in sorted(
                    self.module_aggregates.items(),
                    key=lambda x: x[1].effectiveness_score,
                    reverse=True
                )[:5] if m.total_scans >= 10
            ],
            "need_attention": [
                name for name, m in self.module_aggregates.items()
                if m.effectiveness_score < 60 and m.total_scans >= 10
            ],
        }
    
    def export_dashboard_data(self) -> dict:
        """Export data for visualization dashboard."""
        return {
            "generated_at": datetime.now().isoformat(),
            "framework_health": self.get_framework_health(),
            "modules": {
                name: metrics.to_dict() 
                for name, metrics in self.module_aggregates.items()
            },
            "trends": self._calculate_trends(),
        }
    
    def _calculate_trends(self) -> dict:
        """Calculate trend data from scan history."""
        if len(self.scan_history) < 2:
            return {"message": "Insufficient data for trends"}
        
        # Group by week
        weekly_precision = {}
        for scan in self.scan_history:
            week = scan.started_at.strftime("%Y-W%W")
            if week not in weekly_precision:
                weekly_precision[week] = []
            weekly_precision[week].append(scan.overall_precision)
        
        return {
            "weekly_precision": {
                week: round(sum(vals) / len(vals), 4)
                for week, vals in weekly_precision.items()
            }
        }
