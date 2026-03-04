"""
Audit Logger for Professional Pentesting
=========================================

Comprehensive audit logging for legal defense and compliance.

Features:
- Log all HTTP requests with timestamps
- Log authorization acceptance events
- Log scope violations and blocked requests
- Export audit trail for engagement reports
- Support for tamper detection (hash chains)

IMPORTANT: This is CRITICAL for professional pentesting.
"Se tiveres de provar em tribunal que só testaste o que devias..."

Version: 1.0.0
"""

import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

from utils.logger import get_logger

logger = get_logger(__name__)


class AuditEventType(Enum):
    """Types of audit events"""
    # Authorization
    DISCLAIMER_ACCEPTED = "disclaimer_accepted"
    DISCLAIMER_DECLINED = "disclaimer_declined"
    SCOPE_CONFIRMED = "scope_confirmed"
    AUTHORIZATION_GRANTED = "authorization_granted"

    # Scan lifecycle
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_ABORTED = "scan_aborted"

    # HTTP activity
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"

    # Safety
    SCOPE_VIOLATION = "scope_violation"
    SAFETY_BLOCK = "safety_block"
    PAYLOAD_BLOCKED = "payload_blocked"

    # Findings
    VULNERABILITY_FOUND = "vulnerability_found"
    FINDING_VALIDATED = "finding_validated"
    FINDING_REJECTED = "finding_rejected"


@dataclass
class AuditEvent:
    """
    Single audit event with tamper detection.
    """
    timestamp: str
    event_type: str
    target: str
    details: Dict[str, Any]
    operator: str = "phantom-ai"
    engagement_id: Optional[str] = None
    previous_hash: Optional[str] = None  # Hash chain for tamper detection

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "target": self.target,
            "operator": self.operator,
            "engagement_id": self.engagement_id,
            "details": self.details,
            "previous_hash": self.previous_hash,
        }

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of this event for tamper detection."""
        # Serialize event to JSON with sorted keys for deterministic hashing
        event_str = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(event_str.encode()).hexdigest()


class AuditLogger:
    """
    Professional audit logger for penetration testing engagements.

    Usage:
        audit = AuditLogger(engagement_id="PHANTOM-20260207-ABC123")
        audit.log_authorization(target, operator, accepted=True)
        audit.log_http_request(url, method, status)
        audit.log_scope_violation(url, reason)
        audit.export_report(output_path)
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        engagement_id: Optional[str] = None,
        log_dir: Optional[Path] = None,
        operator: str = "phantom-ai",
    ):
        """
        Initialize audit logger.

        Args:
            engagement_id: Unique engagement identifier
            log_dir: Directory for audit logs (default: logs/audit/)
            operator: Operator name/username
        """
        self.engagement_id = engagement_id or f"PHANTOM-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        self.operator = operator
        self.log_dir = log_dir or Path("logs/audit")
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.events: List[AuditEvent] = []
        self.last_hash: Optional[str] = None

        # Primary log file (JSONL for easy appending)
        self.log_file = self.log_dir / f"{self.engagement_id}_audit.jsonl"

        # Initialize log file with header
        self._write_header()

    def _write_header(self) -> None:
        """Write audit log header."""
        header = {
            "type": "audit_log_header",
            "version": self.VERSION,
            "engagement_id": self.engagement_id,
            "operator": self.operator,
            "started_at": datetime.now().isoformat(),
            "machine_id": self._get_machine_id(),
        }
        self._append_to_log(header)

    def _get_machine_id(self) -> str:
        """Get anonymized machine identifier for audit purposes."""
        try:
            # Use hostname hash for privacy
            import socket
            hostname = socket.gethostname()
            return hashlib.sha256(hostname.encode()).hexdigest()[:16]
        except Exception:
            return "unknown"

    def _append_to_log(self, event: Dict[str, Any]) -> None:
        """Append event to audit log file."""
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.error(f"Failed to write to audit log: {e}")

    def _create_event(
        self,
        event_type: AuditEventType,
        target: str,
        details: Dict[str, Any],
    ) -> AuditEvent:
        """Create audit event with hash chain."""
        event = AuditEvent(
            timestamp=datetime.now().isoformat(),
            event_type=event_type.value,
            target=target,
            details=details,
            operator=self.operator,
            engagement_id=self.engagement_id,
            previous_hash=self.last_hash,
        )

        # Update hash chain
        self.last_hash = event.compute_hash()
        self.events.append(event)

        # Persist immediately
        self._append_to_log(event.to_dict())

        return event

    # =========================================================================
    # Authorization Events
    # =========================================================================

    def log_authorization(
        self,
        target: str,
        accepted: bool,
        scope: Optional[List[str]] = None,
        mode: str = "safe",
        rate_limit: float = 2.0,
    ) -> None:
        """Log authorization acceptance/decline."""
        event_type = (
            AuditEventType.AUTHORIZATION_GRANTED if accepted
            else AuditEventType.DISCLAIMER_DECLINED
        )

        self._create_event(
            event_type=event_type,
            target=target,
            details={
                "accepted": accepted,
                "scope": scope or [],
                "mode": mode,
                "rate_limit": rate_limit,
                "legal_disclaimer_shown": True,
            },
        )

        if accepted:
            logger.info(f"[AUDIT] Authorization granted for {target}")
        else:
            logger.warning(f"[AUDIT] Authorization declined for {target}")

    def log_scope_confirmed(
        self,
        targets: List[str],
        scope: List[str],
        program_name: str = "",
    ) -> None:
        """Log scope confirmation."""
        self._create_event(
            event_type=AuditEventType.SCOPE_CONFIRMED,
            target=",".join(targets),
            details={
                "targets": targets,
                "scope": scope,
                "program_name": program_name,
            },
        )

    # =========================================================================
    # Scan Lifecycle Events
    # =========================================================================

    def log_scan_started(
        self,
        target: str,
        modules: Optional[List[str]] = None,
        safe_mode: str = "safe",
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log scan start."""
        self._create_event(
            event_type=AuditEventType.SCAN_STARTED,
            target=target,
            details={
                "modules": modules or [],
                "safe_mode": safe_mode,
                "config": config or {},
            },
        )
        logger.info(f"[AUDIT] Scan started: {target}")

    def log_scan_completed(
        self,
        target: str,
        findings_count: int,
        duration_seconds: float,
        scope_violations: int = 0,
    ) -> None:
        """Log scan completion."""
        self._create_event(
            event_type=AuditEventType.SCAN_COMPLETED,
            target=target,
            details={
                "findings_count": findings_count,
                "duration_seconds": duration_seconds,
                "scope_violations": scope_violations,
            },
        )
        logger.info(f"[AUDIT] Scan completed: {target} ({findings_count} findings)")

    def log_scan_aborted(
        self,
        target: str,
        reason: str,
    ) -> None:
        """Log scan abort."""
        self._create_event(
            event_type=AuditEventType.SCAN_ABORTED,
            target=target,
            details={
                "reason": reason,
            },
        )
        logger.warning(f"[AUDIT] Scan aborted: {target} - {reason}")

    # =========================================================================
    # HTTP Activity Events
    # =========================================================================

    def log_http_request(
        self,
        url: str,
        method: str,
        status_code: Optional[int] = None,
        module: str = "",
        payload_type: str = "",
    ) -> None:
        """Log HTTP request for audit trail."""
        self._create_event(
            event_type=AuditEventType.HTTP_REQUEST,
            target=url,
            details={
                "method": method,
                "status_code": status_code,
                "module": module,
                "payload_type": payload_type,
            },
        )

    # =========================================================================
    # Safety Events
    # =========================================================================

    def log_scope_violation(
        self,
        url: str,
        reason: str,
        blocked: bool = True,
    ) -> None:
        """Log scope violation."""
        self._create_event(
            event_type=AuditEventType.SCOPE_VIOLATION,
            target=url,
            details={
                "reason": reason,
                "blocked": blocked,
            },
        )
        logger.warning(f"[AUDIT] Scope violation: {url} - {reason}")

    def log_safety_block(
        self,
        url: str,
        reason: str,
        payload: str = "",
    ) -> None:
        """Log safety system blocking a request."""
        self._create_event(
            event_type=AuditEventType.SAFETY_BLOCK,
            target=url,
            details={
                "reason": reason,
                "payload_preview": payload[:100] if payload else "",
            },
        )

    # =========================================================================
    # Finding Events
    # =========================================================================

    def log_vulnerability_found(
        self,
        url: str,
        vuln_type: str,
        severity: str,
        confidence: float,
        module: str = "",
    ) -> None:
        """Log vulnerability discovery."""
        self._create_event(
            event_type=AuditEventType.VULNERABILITY_FOUND,
            target=url,
            details={
                "vuln_type": vuln_type,
                "severity": severity,
                "confidence": confidence,
                "module": module,
            },
        )

    # =========================================================================
    # Export & Reporting
    # =========================================================================

    def get_statistics(self) -> Dict[str, Any]:
        """Get audit log statistics."""
        by_type: Dict[str, int] = {}
        for event in self.events:
            by_type[event.event_type] = by_type.get(event.event_type, 0) + 1

        return {
            "engagement_id": self.engagement_id,
            "operator": self.operator,
            "total_events": len(self.events),
            "events_by_type": by_type,
            "scope_violations": by_type.get(AuditEventType.SCOPE_VIOLATION.value, 0),
            "safety_blocks": by_type.get(AuditEventType.SAFETY_BLOCK.value, 0),
            "http_requests": by_type.get(AuditEventType.HTTP_REQUEST.value, 0),
            "log_file": str(self.log_file),
        }

    def export_report(self, output_path: Optional[Path] = None) -> str:
        """Export audit report in human-readable format."""
        output_path = output_path or self.log_dir / f"{self.engagement_id}_audit_report.md"

        stats = self.get_statistics()

        report = f"""# Audit Report

## Engagement Details

| Field | Value |
|-------|-------|
| Engagement ID | {self.engagement_id} |
| Operator | {self.operator} |
| Generated | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
| Log File | {self.log_file} |

## Statistics

| Metric | Count |
|--------|-------|
| Total Events | {stats['total_events']} |
| HTTP Requests | {stats['http_requests']} |
| Scope Violations | {stats['scope_violations']} |
| Safety Blocks | {stats['safety_blocks']} |

## Events by Type

"""
        for event_type, count in stats['events_by_type'].items():
            report += f"- **{event_type}**: {count}\n"

        report += "\n## Hash Chain Integrity\n\n"
        if self.last_hash:
            report += f"✅ Hash chain intact (last hash: `{self.last_hash[:16]}...`)\n"
        else:
            report += "⚠️ No events logged\n"

        report += f"""

---

*This audit report was generated by PHANTOM AI Audit Logger v{self.VERSION}*
*For professional penetration testing engagements*
"""

        with open(output_path, "w") as f:
            f.write(report)

        logger.info(f"[AUDIT] Exported report to {output_path}")
        return str(output_path)

    def verify_integrity(self) -> tuple:
        """
        Verify hash chain integrity for tamper detection.

        Returns:
            Tuple of (is_valid: bool, message: str)
        """
        if len(self.events) == 0:
            return (True, "No events to verify")

        # Recompute hash chain
        previous_hash = None
        for i, event in enumerate(self.events):
            if event.previous_hash != previous_hash:
                return (
                    False,
                    f"Hash chain broken at event {i}: expected {previous_hash}, got {event.previous_hash}"
                )
            previous_hash = event.compute_hash()

        return (True, f"Hash chain verified ({len(self.events)} events)")


# Singleton instance for global access
_audit_logger: Optional[AuditLogger] = None


def get_audit_logger() -> Optional[AuditLogger]:
    """Get the global audit logger instance."""
    return _audit_logger


def init_audit_logger(
    engagement_id: Optional[str] = None,
    operator: str = "phantom-ai",
) -> AuditLogger:
    """Initialize the global audit logger."""
    global _audit_logger
    _audit_logger = AuditLogger(engagement_id=engagement_id, operator=operator)
    return _audit_logger


def reset_audit_logger() -> None:
    """Reset the global audit logger."""
    global _audit_logger
    _audit_logger = None


__all__ = [
    "AuditLogger",
    "AuditEvent",
    "AuditEventType",
    "get_audit_logger",
    "init_audit_logger",
    "reset_audit_logger",
]
