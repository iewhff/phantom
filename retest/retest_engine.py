"""
Retest and Regression Engine.
Tracks vulnerability remediation and performs retests.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


@dataclass
class VulnerabilityState:
    """Tracks state of a vulnerability over time."""
    vuln_id: str
    name: str
    severity: str
    first_found: datetime
    last_seen: datetime
    status: str  # open, remediated, false_positive, accepted
    endpoint: str
    evidence_hash: str
    retest_count: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass
class RetestResult:
    """Result of a retest."""
    vuln_id: str
    original_status: str
    new_status: str
    tested_at: datetime
    still_vulnerable: bool
    details: str


@dataclass
class RiskDelta:
    """Tracks risk changes between scans."""
    scan_date: datetime
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    total_risk_score: float


class RetestEngine:
    """
    Retest and Regression Engine.
    
    Features:
    - Track vulnerability state over time
    - Re-scan after fixes
    - Compare risk before/after
    - Generate remediation reports
    - Track regression (reintroduced vulns)
    """
    
    def __init__(self, settings: Settings, storage_path: str = "./retest_data"):
        self.settings = settings
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True)
        
        self.vulnerability_db: dict[str, VulnerabilityState] = {}
        self.risk_history: list[RiskDelta] = []
        self.retest_results: list[RetestResult] = []
        
        self._load_state()
    
    def _load_state(self) -> None:
        """Load previous state from storage."""
        state_file = self.storage_path / "vulnerability_state.json"
        
        if state_file.exists():
            try:
                with open(state_file) as f:
                    data = json.load(f)
                    
                for vuln_id, vuln_data in data.get("vulnerabilities", {}).items():
                    self.vulnerability_db[vuln_id] = VulnerabilityState(
                        vuln_id=vuln_data["vuln_id"],
                        name=vuln_data["name"],
                        severity=vuln_data["severity"],
                        first_found=datetime.fromisoformat(vuln_data["first_found"]),
                        last_seen=datetime.fromisoformat(vuln_data["last_seen"]),
                        status=vuln_data["status"],
                        endpoint=vuln_data["endpoint"],
                        evidence_hash=vuln_data["evidence_hash"],
                        retest_count=vuln_data.get("retest_count", 0),
                        notes=vuln_data.get("notes", []),
                    )
                    
                for risk_data in data.get("risk_history", []):
                    self.risk_history.append(RiskDelta(
                        scan_date=datetime.fromisoformat(risk_data["scan_date"]),
                        critical_count=risk_data["critical_count"],
                        high_count=risk_data["high_count"],
                        medium_count=risk_data["medium_count"],
                        low_count=risk_data["low_count"],
                        total_risk_score=risk_data["total_risk_score"],
                    ))
                    
            except Exception as e:
                logger.warning(f"Failed to load retest state: {e}")
    
    def _save_state(self) -> None:
        """Save current state to storage."""
        state_file = self.storage_path / "vulnerability_state.json"
        
        data = {
            "vulnerabilities": {
                vid: {
                    "vuln_id": v.vuln_id,
                    "name": v.name,
                    "severity": v.severity,
                    "first_found": v.first_found.isoformat(),
                    "last_seen": v.last_seen.isoformat(),
                    "status": v.status,
                    "endpoint": v.endpoint,
                    "evidence_hash": v.evidence_hash,
                    "retest_count": v.retest_count,
                    "notes": v.notes,
                }
                for vid, v in self.vulnerability_db.items()
            },
            "risk_history": [
                {
                    "scan_date": r.scan_date.isoformat(),
                    "critical_count": r.critical_count,
                    "high_count": r.high_count,
                    "medium_count": r.medium_count,
                    "low_count": r.low_count,
                    "total_risk_score": r.total_risk_score,
                }
                for r in self.risk_history
            ],
        }
        
        with open(state_file, "w") as f:
            json.dump(data, f, indent=2)
    
    def _generate_vuln_id(self, finding: dict[str, Any]) -> str:
        """Generate unique ID for a vulnerability."""
        # Hash based on type, endpoint, and key characteristics
        key_parts = [
            finding.get("type", ""),
            finding.get("name", ""),
            finding.get("matched_at", ""),
            finding.get("cwe", ""),
        ]
        
        return hashlib.sha256(
            "|".join(key_parts).encode()
        ).hexdigest()[:16]
    
    def _generate_evidence_hash(self, finding: dict[str, Any]) -> str:
        """Generate hash of evidence for comparison."""
        evidence = finding.get("evidence", [])
        return hashlib.sha256(
            json.dumps(evidence, sort_keys=True).encode()
        ).hexdigest()[:16]
    
    def record_scan_results(
        self,
        findings: list[dict[str, Any]],
        target: str,
    ) -> dict[str, Any]:
        """Record results from a new scan."""
        now = datetime.now()
        new_vulns = []
        still_open = []
        regression = []
        
        current_vuln_ids = set()
        
        # Process new findings
        for finding in findings:
            vuln_id = self._generate_vuln_id(finding)
            evidence_hash = self._generate_evidence_hash(finding)
            current_vuln_ids.add(vuln_id)
            
            if vuln_id in self.vulnerability_db:
                existing = self.vulnerability_db[vuln_id]
                
                # Check if it was marked remediated but is back
                if existing.status == "remediated":
                    existing.status = "regression"
                    existing.notes.append(f"Regression detected on {now.isoformat()}")
                    regression.append(finding)
                else:
                    still_open.append(finding)
                
                existing.last_seen = now
                existing.evidence_hash = evidence_hash
            else:
                # New vulnerability
                self.vulnerability_db[vuln_id] = VulnerabilityState(
                    vuln_id=vuln_id,
                    name=finding.get("name", "Unknown"),
                    severity=finding.get("severity", "MEDIUM"),
                    first_found=now,
                    last_seen=now,
                    status="open",
                    endpoint=finding.get("matched_at", target),
                    evidence_hash=evidence_hash,
                )
                new_vulns.append(finding)
        
        # Check for remediated vulnerabilities
        remediated = []
        for vuln_id, vuln in self.vulnerability_db.items():
            if vuln_id not in current_vuln_ids and vuln.status == "open":
                # Vulnerability not found in latest scan - potentially remediated
                vuln.status = "potentially_remediated"
                remediated.append(vuln)
        
        # Calculate risk delta
        risk = self._calculate_risk(findings)
        self.risk_history.append(risk)
        
        self._save_state()
        
        return {
            "scan_date": now.isoformat(),
            "target": target,
            "summary": {
                "new_vulnerabilities": len(new_vulns),
                "still_open": len(still_open),
                "regression": len(regression),
                "potentially_remediated": len(remediated),
                "total_findings": len(findings),
            },
            "new_vulnerabilities": [f.get("name") for f in new_vulns],
            "regression_issues": [f.get("name") for f in regression],
            "remediated_candidates": [v.name for v in remediated],
            "risk_score": risk.total_risk_score,
            "risk_delta": self._calculate_risk_delta(),
        }
    
    def _calculate_risk(self, findings: list[dict[str, Any]]) -> RiskDelta:
        """Calculate risk metrics from findings."""
        severity_scores = {
            "CRITICAL": 10,
            "HIGH": 7,
            "MEDIUM": 4,
            "LOW": 1,
            "INFO": 0,
        }
        
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low = sum(1 for f in findings if f.get("severity") == "LOW")
        
        total_score = sum(
            severity_scores.get(f.get("severity", "MEDIUM"), 4)
            for f in findings
        )
        
        return RiskDelta(
            scan_date=datetime.now(),
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            total_risk_score=total_score,
        )
    
    def _calculate_risk_delta(self) -> dict[str, Any]:
        """Calculate change in risk from previous scan."""
        if len(self.risk_history) < 2:
            return {"message": "Not enough data for comparison"}
        
        current = self.risk_history[-1]
        previous = self.risk_history[-2]
        
        score_change = current.total_risk_score - previous.total_risk_score
        
        return {
            "score_change": score_change,
            "direction": "increased" if score_change > 0 else "decreased" if score_change < 0 else "unchanged",
            "percentage_change": round(
                (score_change / previous.total_risk_score * 100) if previous.total_risk_score > 0 else 0,
                1
            ),
            "critical_change": current.critical_count - previous.critical_count,
            "high_change": current.high_count - previous.high_count,
            "previous_scan": previous.scan_date.isoformat(),
        }
    
    def mark_as_remediated(self, vuln_id: str, notes: str = "") -> bool:
        """Mark a vulnerability as remediated."""
        if vuln_id in self.vulnerability_db:
            vuln = self.vulnerability_db[vuln_id]
            vuln.status = "remediated"
            vuln.notes.append(f"Marked remediated: {notes}" if notes else "Marked remediated")
            self._save_state()
            return True
        return False
    
    def mark_as_false_positive(self, vuln_id: str, reason: str) -> bool:
        """Mark a vulnerability as false positive."""
        if vuln_id in self.vulnerability_db:
            vuln = self.vulnerability_db[vuln_id]
            vuln.status = "false_positive"
            vuln.notes.append(f"False positive: {reason}")
            self._save_state()
            return True
        return False
    
    def mark_as_accepted(self, vuln_id: str, justification: str) -> bool:
        """Mark a vulnerability as accepted risk."""
        if vuln_id in self.vulnerability_db:
            vuln = self.vulnerability_db[vuln_id]
            vuln.status = "accepted"
            vuln.notes.append(f"Risk accepted: {justification}")
            self._save_state()
            return True
        return False
    
    def get_open_vulnerabilities(self) -> list[VulnerabilityState]:
        """Get all currently open vulnerabilities."""
        return [
            v for v in self.vulnerability_db.values()
            if v.status in ["open", "regression"]
        ]
    
    def get_remediation_progress(self) -> dict[str, Any]:
        """Get remediation progress statistics."""
        vulns = list(self.vulnerability_db.values())
        
        if not vulns:
            return {"message": "No vulnerabilities tracked"}
        
        statuses = {}
        for v in vulns:
            statuses[v.status] = statuses.get(v.status, 0) + 1
        
        total = len(vulns)
        remediated = statuses.get("remediated", 0) + statuses.get("false_positive", 0)
        
        return {
            "total_tracked": total,
            "status_breakdown": statuses,
            "remediation_rate": round(remediated / total * 100, 1),
            "open_critical": sum(
                1 for v in vulns 
                if v.status == "open" and v.severity == "CRITICAL"
            ),
            "open_high": sum(
                1 for v in vulns 
                if v.status == "open" and v.severity == "HIGH"
            ),
            "oldest_open": min(
                (v.first_found for v in vulns if v.status == "open"),
                default=None
            ),
            "average_age_days": self._calculate_average_age(),
        }
    
    def _calculate_average_age(self) -> float:
        """Calculate average age of open vulnerabilities in days."""
        open_vulns = [v for v in self.vulnerability_db.values() if v.status == "open"]
        
        if not open_vulns:
            return 0
        
        now = datetime.now()
        total_days = sum((now - v.first_found).days for v in open_vulns)
        
        return round(total_days / len(open_vulns), 1)
    
    def generate_remediation_report(self) -> dict[str, Any]:
        """Generate comprehensive remediation report."""
        progress = self.get_remediation_progress()
        open_vulns = self.get_open_vulnerabilities()
        
        # Group by severity
        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
        for vuln in open_vulns:
            if vuln.severity in by_severity:
                by_severity[vuln.severity].append({
                    "id": vuln.vuln_id,
                    "name": vuln.name,
                    "endpoint": vuln.endpoint,
                    "age_days": (datetime.now() - vuln.first_found).days,
                })
        
        # Risk trend
        risk_trend = []
        for risk in self.risk_history[-10:]:
            risk_trend.append({
                "date": risk.scan_date.isoformat(),
                "score": risk.total_risk_score,
            })
        
        return {
            "generated_at": datetime.now().isoformat(),
            "progress": progress,
            "open_by_severity": by_severity,
            "risk_trend": risk_trend,
            "recommendations": self._generate_recommendations(by_severity),
        }
    
    def _generate_recommendations(
        self,
        by_severity: dict[str, list],
    ) -> list[str]:
        """Generate prioritized recommendations."""
        recommendations = []
        
        if by_severity["CRITICAL"]:
            recommendations.append(
                f"🚨 IMMEDIATE: Address {len(by_severity['CRITICAL'])} critical vulnerabilities first"
            )
            for vuln in by_severity["CRITICAL"][:3]:
                recommendations.append(f"  - Fix: {vuln['name']} at {vuln['endpoint']}")
        
        if by_severity["HIGH"]:
            recommendations.append(
                f"⚠️ HIGH PRIORITY: {len(by_severity['HIGH'])} high severity issues pending"
            )
        
        # Check for old vulnerabilities
        old_vulns = [
            v for vulns in by_severity.values() 
            for v in vulns 
            if v.get("age_days", 0) > 30
        ]
        if old_vulns:
            recommendations.append(
                f"📅 OVERDUE: {len(old_vulns)} vulnerabilities are older than 30 days"
            )
        
        return recommendations
    
    def compare_scans(
        self,
        scan1_date: str | None = None,
        scan2_date: str | None = None,
    ) -> dict[str, Any]:
        """Compare two scan results."""
        if len(self.risk_history) < 2:
            return {"error": "Not enough scan history"}
        
        # Default to comparing last two scans
        if scan1_date is None:
            risk1 = self.risk_history[-2]
        else:
            risk1 = next(
                (r for r in self.risk_history if r.scan_date.isoformat().startswith(scan1_date)),
                self.risk_history[-2]
            )
        
        if scan2_date is None:
            risk2 = self.risk_history[-1]
        else:
            risk2 = next(
                (r for r in self.risk_history if r.scan_date.isoformat().startswith(scan2_date)),
                self.risk_history[-1]
            )
        
        return {
            "scan1": {
                "date": risk1.scan_date.isoformat(),
                "critical": risk1.critical_count,
                "high": risk1.high_count,
                "medium": risk1.medium_count,
                "low": risk1.low_count,
                "risk_score": risk1.total_risk_score,
            },
            "scan2": {
                "date": risk2.scan_date.isoformat(),
                "critical": risk2.critical_count,
                "high": risk2.high_count,
                "medium": risk2.medium_count,
                "low": risk2.low_count,
                "risk_score": risk2.total_risk_score,
            },
            "delta": {
                "critical": risk2.critical_count - risk1.critical_count,
                "high": risk2.high_count - risk1.high_count,
                "medium": risk2.medium_count - risk1.medium_count,
                "low": risk2.low_count - risk1.low_count,
                "risk_score": risk2.total_risk_score - risk1.total_risk_score,
            },
            "improvement": risk2.total_risk_score < risk1.total_risk_score,
        }
