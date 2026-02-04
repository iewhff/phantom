"""
PHANTOM AI - GDPR Compliance Module
====================================

Implements GDPR requirements for data protection:

- Art. 5: Data minimization and purpose limitation
- Art. 15: Right of access (data export)
- Art. 17: Right to erasure (data deletion)
- Art. 20: Right to data portability
- Art. 25: Data protection by design
- Art. 30: Records of processing activities
- Art. 32: Security of processing (PII protection)

Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# PII PATTERNS - Common patterns for personal data detection
# =============================================================================

PII_PATTERNS: dict[str, re.Pattern] = {
    # Email addresses
    "email": re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        re.IGNORECASE
    ),
    # Phone numbers (international formats)
    "phone": re.compile(
        r'\b(?:\+?[1-9]\d{0,2}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b'
    ),
    # Credit card numbers (basic pattern)
    "credit_card": re.compile(
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
    ),
    # Social Security Numbers (US)
    "ssn": re.compile(
        r'\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b'
    ),
    # IP addresses
    "ip_address": re.compile(
        r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    ),
    # Portuguese NIF/NIPC
    "nif_pt": re.compile(
        r'\b[0-9]{9}\b'
    ),
    # Passwords in logs (common patterns)
    "password_field": re.compile(
        r'(?i)(?:password|passwd|pwd|secret|token|api_key|apikey|auth|bearer)[\s]*[:=][\s]*["\']?([^"\'\s,}{]+)',
    ),
    # JWT tokens
    "jwt": re.compile(
        r'\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b'
    ),
    # Names (basic - first + last)
    "name": re.compile(
        r'\b[A-Z][a-z]+\s+[A-Z][a-z]+\b'
    ),
    # Addresses (basic street patterns)
    "address": re.compile(
        r'\b\d+\s+[A-Za-z]+\s+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Way|Court|Ct)\b',
        re.IGNORECASE
    ),
}

# Redaction placeholder
REDACTED = "[REDACTED-PII]"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class ProcessingRecord:
    """GDPR Art. 30 - Record of processing activity."""

    record_id: str
    timestamp: datetime
    purpose: str
    data_categories: list[str]
    data_subjects: str  # e.g., "website users", "target system"
    recipients: list[str]  # Who receives the data
    retention_period_days: int
    legal_basis: str
    controller: str = "PHANTOM AI User"
    processor: str = "PHANTOM AI"

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "timestamp": self.timestamp.isoformat(),
            "purpose": self.purpose,
            "data_categories": self.data_categories,
            "data_subjects": self.data_subjects,
            "recipients": self.recipients,
            "retention_period_days": self.retention_period_days,
            "legal_basis": self.legal_basis,
            "controller": self.controller,
            "processor": self.processor,
        }


@dataclass
class DataSubjectRequest:
    """Data subject request (access, deletion, portability)."""

    request_id: str
    request_type: str  # access, erasure, portability
    identifier: str  # Email, IP, or other identifier
    timestamp: datetime
    status: str = "pending"  # pending, processing, completed, rejected
    completed_at: Optional[datetime] = None
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "request_type": self.request_type,
            "identifier": self.identifier,
            "timestamp": self.timestamp.isoformat(),
            "status": self.status,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "notes": self.notes,
        }


@dataclass
class GDPRConfig:
    """GDPR compliance configuration."""

    # Data retention
    default_retention_days: int = 90
    scan_data_retention_days: int = 30
    log_retention_days: int = 180

    # PII handling
    anonymize_pii_in_logs: bool = True
    anonymize_pii_in_reports: bool = False  # Reports may need PII for evidence
    redact_sensitive_fields: bool = True

    # Data minimization
    store_full_responses: bool = False  # Only store relevant excerpts
    max_evidence_length: int = 1000  # Truncate evidence

    # Paths
    data_root: Path = field(default_factory=lambda: Path("data"))
    processing_records_file: Path = field(default_factory=lambda: Path("data/gdpr/processing_records.jsonl"))
    subject_requests_file: Path = field(default_factory=lambda: Path("data/gdpr/subject_requests.jsonl"))

    # Cleanup
    auto_cleanup_enabled: bool = True
    cleanup_on_startup: bool = True


# =============================================================================
# PII ANONYMIZER
# =============================================================================

class PIIAnonymizer:
    """
    Detects and anonymizes PII in text.

    Supports:
    - Email addresses
    - Phone numbers
    - Credit cards
    - IP addresses
    - JWT tokens
    - Passwords
    - Custom patterns
    """

    def __init__(
        self,
        patterns: Optional[dict[str, re.Pattern]] = None,
        custom_patterns: Optional[dict[str, re.Pattern]] = None,
    ):
        self.patterns = patterns or PII_PATTERNS.copy()
        if custom_patterns:
            self.patterns.update(custom_patterns)

        # Statistics
        self._stats = {ptype: 0 for ptype in self.patterns}

    def anonymize(
        self,
        text: str,
        preserve_types: Optional[list[str]] = None,
    ) -> tuple[str, dict[str, int]]:
        """
        Anonymize PII in text.

        Args:
            text: Input text to anonymize
            preserve_types: PII types to NOT anonymize (e.g., ["ip_address"])

        Returns:
            Tuple of (anonymized_text, counts_per_type)
        """
        if not text:
            return text, {}

        preserve_types = preserve_types or []
        counts: dict[str, int] = {}
        result = text

        for pii_type, pattern in self.patterns.items():
            if pii_type in preserve_types:
                continue

            matches = pattern.findall(result)
            if matches:
                counts[pii_type] = len(matches)
                self._stats[pii_type] += len(matches)

                # Replace with type-specific redaction
                result = pattern.sub(f"[REDACTED-{pii_type.upper()}]", result)

        return result, counts

    def detect_pii(self, text: str) -> dict[str, list[str]]:
        """
        Detect PII in text without anonymizing.

        Returns:
            Dict of PII type -> list of found values
        """
        if not text:
            return {}

        found: dict[str, list[str]] = {}

        for pii_type, pattern in self.patterns.items():
            matches = pattern.findall(text)
            if matches:
                # Flatten if findall returns tuples (from groups)
                if matches and isinstance(matches[0], tuple):
                    matches = [m[0] if m[0] else m[-1] for m in matches]
                found[pii_type] = matches

        return found

    def hash_pii(self, value: str, salt: str = "") -> str:
        """
        Hash PII value for pseudonymization.
        Allows correlation without storing actual PII.
        """
        salted = f"{salt}{value}".encode()
        return hashlib.sha256(salted).hexdigest()[:16]

    def get_statistics(self) -> dict[str, int]:
        """Get cumulative anonymization statistics."""
        return self._stats.copy()


# =============================================================================
# DATA RETENTION MANAGER
# =============================================================================

class DataRetentionManager:
    """
    Manages data retention and automatic cleanup.

    GDPR Art. 5(1)(e): Storage limitation
    """

    def __init__(self, config: GDPRConfig):
        self.config = config
        self._cleanup_log: list[dict] = []

    def cleanup_expired_data(self) -> dict[str, Any]:
        """
        Remove data older than retention period.

        Returns:
            Cleanup report with deleted files and stats
        """
        report = {
            "timestamp": datetime.now().isoformat(),
            "scan_data_deleted": 0,
            "log_files_deleted": 0,
            "bytes_freed": 0,
            "errors": [],
        }

        # Cleanup scan data
        scan_dirs = [
            self.config.data_root / "scans",
            self.config.data_root / "findings",
            Path.home() / ".phantom" / "pentest_logs",
        ]

        scan_cutoff = datetime.now() - timedelta(days=self.config.scan_data_retention_days)

        for scan_dir in scan_dirs:
            if scan_dir.exists():
                deleted, freed, errors = self._cleanup_directory(
                    scan_dir, scan_cutoff
                )
                report["scan_data_deleted"] += deleted
                report["bytes_freed"] += freed
                report["errors"].extend(errors)

        # Cleanup log files
        log_dirs = [
            self.config.data_root / "logs",
            Path("logs"),
        ]

        log_cutoff = datetime.now() - timedelta(days=self.config.log_retention_days)

        for log_dir in log_dirs:
            if log_dir.exists():
                deleted, freed, errors = self._cleanup_directory(
                    log_dir, log_cutoff
                )
                report["log_files_deleted"] += deleted
                report["bytes_freed"] += freed
                report["errors"].extend(errors)

        # Log cleanup
        self._cleanup_log.append(report)
        logger.info(
            f"GDPR cleanup completed: {report['scan_data_deleted']} scans, "
            f"{report['log_files_deleted']} logs, "
            f"{report['bytes_freed'] / 1024 / 1024:.2f} MB freed"
        )

        return report

    def _cleanup_directory(
        self,
        directory: Path,
        cutoff: datetime,
    ) -> tuple[int, int, list[str]]:
        """Clean up files older than cutoff in directory."""
        deleted = 0
        freed = 0
        errors = []

        try:
            for item in directory.rglob("*"):
                if not item.is_file():
                    continue

                try:
                    mtime = datetime.fromtimestamp(item.stat().st_mtime)
                    if mtime < cutoff:
                        size = item.stat().st_size
                        item.unlink()
                        deleted += 1
                        freed += size
                        logger.debug(f"Deleted expired file: {item}")
                except Exception as e:
                    errors.append(f"{item}: {e}")

        except Exception as e:
            errors.append(f"Directory {directory}: {e}")

        return deleted, freed, errors

    def get_data_inventory(self) -> dict[str, Any]:
        """
        Get inventory of all stored data.

        GDPR Art. 30 - Records of processing
        """
        inventory = {
            "timestamp": datetime.now().isoformat(),
            "categories": {},
        }

        # Check common data locations
        locations = {
            "scan_data": [
                self.config.data_root / "scans",
                Path.home() / ".phantom" / "pentest_logs",
            ],
            "logs": [
                self.config.data_root / "logs",
                Path("logs"),
            ],
            "reports": [
                self.config.data_root / "reports",
                Path("reports"),
            ],
            "gdpr_records": [
                self.config.data_root / "gdpr",
            ],
        }

        for category, paths in locations.items():
            files = []
            total_size = 0
            oldest = None
            newest = None

            for path in paths:
                if path.exists():
                    for item in path.rglob("*"):
                        if item.is_file():
                            stat = item.stat()
                            mtime = datetime.fromtimestamp(stat.st_mtime)
                            files.append({
                                "path": str(item),
                                "size": stat.st_size,
                                "modified": mtime.isoformat(),
                            })
                            total_size += stat.st_size

                            if oldest is None or mtime < oldest:
                                oldest = mtime
                            if newest is None or mtime > newest:
                                newest = mtime

            inventory["categories"][category] = {
                "file_count": len(files),
                "total_size_bytes": total_size,
                "total_size_mb": round(total_size / 1024 / 1024, 2),
                "oldest": oldest.isoformat() if oldest else None,
                "newest": newest.isoformat() if newest else None,
            }

        return inventory


# =============================================================================
# DATA SUBJECT RIGHTS HANDLER
# =============================================================================

class DataSubjectRightsHandler:
    """
    Handles data subject requests (GDPR Art. 15, 17, 20).

    - Right of access (Art. 15)
    - Right to erasure (Art. 17)
    - Right to data portability (Art. 20)
    """

    def __init__(self, config: GDPRConfig):
        self.config = config
        self.anonymizer = PIIAnonymizer()
        self.retention_manager = DataRetentionManager(config)

        # Ensure GDPR directory exists
        config.subject_requests_file.parent.mkdir(parents=True, exist_ok=True)

    def handle_access_request(
        self,
        identifier: str,
        identifier_type: str = "email",
    ) -> dict[str, Any]:
        """
        GDPR Art. 15 - Right of access.

        Find and export all data related to the identifier.
        """
        request_id = self._generate_request_id()

        request = DataSubjectRequest(
            request_id=request_id,
            request_type="access",
            identifier=self.anonymizer.hash_pii(identifier),  # Don't log actual PII
            timestamp=datetime.now(),
            status="processing",
        )
        self._log_request(request)

        # Search for data containing this identifier
        found_data = self._search_for_identifier(identifier, identifier_type)

        # Complete request
        request.status = "completed"
        request.completed_at = datetime.now()
        request.notes = f"Found {len(found_data['files'])} files with data"
        self._log_request(request)

        return {
            "request_id": request_id,
            "identifier_hash": self.anonymizer.hash_pii(identifier),
            "data_found": found_data,
            "export_format": "json",
            "completed_at": datetime.now().isoformat(),
        }

    def handle_erasure_request(
        self,
        identifier: str,
        identifier_type: str = "email",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """
        GDPR Art. 17 - Right to erasure ("Right to be forgotten").

        Delete all data related to the identifier.
        """
        request_id = self._generate_request_id()

        request = DataSubjectRequest(
            request_id=request_id,
            request_type="erasure",
            identifier=self.anonymizer.hash_pii(identifier),
            timestamp=datetime.now(),
            status="processing",
        )
        self._log_request(request)

        # Find data to delete
        found_data = self._search_for_identifier(identifier, identifier_type)

        deleted_files = []
        errors = []

        if not dry_run:
            for file_info in found_data["files"]:
                try:
                    file_path = Path(file_info["path"])
                    if file_path.exists():
                        file_path.unlink()
                        deleted_files.append(file_info["path"])
                        logger.info(f"GDPR erasure: Deleted {file_path}")
                except Exception as e:
                    errors.append(f"{file_info['path']}: {e}")

        # Complete request
        request.status = "completed"
        request.completed_at = datetime.now()
        request.notes = f"{'DRY RUN - ' if dry_run else ''}Deleted {len(deleted_files)} files"
        self._log_request(request)

        return {
            "request_id": request_id,
            "identifier_hash": self.anonymizer.hash_pii(identifier),
            "dry_run": dry_run,
            "files_found": len(found_data["files"]),
            "files_deleted": len(deleted_files),
            "deleted_files": deleted_files,
            "errors": errors,
            "completed_at": datetime.now().isoformat(),
        }

    def handle_portability_request(
        self,
        identifier: str,
        identifier_type: str = "email",
        output_path: Optional[Path] = None,
    ) -> dict[str, Any]:
        """
        GDPR Art. 20 - Right to data portability.

        Export all data in a machine-readable format.
        """
        request_id = self._generate_request_id()

        request = DataSubjectRequest(
            request_id=request_id,
            request_type="portability",
            identifier=self.anonymizer.hash_pii(identifier),
            timestamp=datetime.now(),
            status="processing",
        )
        self._log_request(request)

        # Find and collect all data
        found_data = self._search_for_identifier(identifier, identifier_type)

        # Create export package
        export_data = {
            "export_info": {
                "request_id": request_id,
                "identifier_type": identifier_type,
                "exported_at": datetime.now().isoformat(),
                "format": "json",
                "gdpr_article": "Art. 20 - Right to data portability",
            },
            "data": found_data,
        }

        # Save export
        if output_path is None:
            output_path = self.config.data_root / "gdpr" / "exports" / f"{request_id}.json"

        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            json.dump(export_data, f, indent=2, default=str)

        # Complete request
        request.status = "completed"
        request.completed_at = datetime.now()
        request.notes = f"Exported to {output_path}"
        self._log_request(request)

        return {
            "request_id": request_id,
            "export_path": str(output_path),
            "file_count": len(found_data["files"]),
            "completed_at": datetime.now().isoformat(),
        }

    def _search_for_identifier(
        self,
        identifier: str,
        identifier_type: str,
    ) -> dict[str, Any]:
        """Search all data stores for identifier."""
        found = {
            "files": [],
            "matches": [],
        }

        # Escape for regex
        escaped = re.escape(identifier)
        pattern = re.compile(escaped, re.IGNORECASE)

        # Search locations
        search_paths = [
            self.config.data_root,
            Path.home() / ".phantom" / "pentest_logs",
            Path("logs"),
            Path("reports"),
        ]

        for search_path in search_paths:
            if not search_path.exists():
                continue

            for item in search_path.rglob("*"):
                if not item.is_file():
                    continue

                # Skip binary files
                if item.suffix.lower() in [".pdf", ".png", ".jpg", ".zip"]:
                    continue

                try:
                    content = item.read_text(errors="ignore")
                    matches = pattern.findall(content)

                    if matches:
                        found["files"].append({
                            "path": str(item),
                            "match_count": len(matches),
                            "size": item.stat().st_size,
                            "modified": datetime.fromtimestamp(
                                item.stat().st_mtime
                            ).isoformat(),
                        })
                        found["matches"].extend(matches[:5])  # Limit matches

                except Exception:
                    continue

        return found

    def _generate_request_id(self) -> str:
        """Generate unique request ID."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        random_part = hashlib.sha256(os.urandom(8)).hexdigest()[:8]
        return f"DSR_{timestamp}_{random_part}"

    def _log_request(self, request: DataSubjectRequest) -> None:
        """Log data subject request for audit trail."""
        try:
            with open(self.config.subject_requests_file, "a") as f:
                f.write(json.dumps(request.to_dict()) + "\n")
        except Exception as e:
            logger.error(f"Failed to log GDPR request: {e}")


# =============================================================================
# PROCESSING RECORDS MANAGER (Art. 30)
# =============================================================================

class ProcessingRecordsManager:
    """
    Maintains records of processing activities.

    GDPR Art. 30 - Records of processing activities
    """

    def __init__(self, config: GDPRConfig):
        self.config = config
        config.processing_records_file.parent.mkdir(parents=True, exist_ok=True)

    def record_scan_activity(
        self,
        scan_id: str,
        target: str,
        purpose: str = "Security vulnerability assessment",
        legal_basis: str = "Legitimate interest / Authorized testing",
    ) -> ProcessingRecord:
        """Record a scan activity for GDPR compliance."""
        record = ProcessingRecord(
            record_id=f"PROC_{scan_id}",
            timestamp=datetime.now(),
            purpose=purpose,
            data_categories=[
                "IP addresses",
                "URLs",
                "HTTP headers",
                "HTTP responses",
                "Potential vulnerabilities",
            ],
            data_subjects=f"Target system: {target}",
            recipients=["Security analyst", "System owner"],
            retention_period_days=self.config.scan_data_retention_days,
            legal_basis=legal_basis,
        )

        self._save_record(record)
        return record

    def get_all_records(self) -> list[ProcessingRecord]:
        """Get all processing records."""
        records = []

        if self.config.processing_records_file.exists():
            with open(self.config.processing_records_file) as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        records.append(ProcessingRecord(
                            record_id=data["record_id"],
                            timestamp=datetime.fromisoformat(data["timestamp"]),
                            purpose=data["purpose"],
                            data_categories=data["data_categories"],
                            data_subjects=data["data_subjects"],
                            recipients=data["recipients"],
                            retention_period_days=data["retention_period_days"],
                            legal_basis=data["legal_basis"],
                            controller=data.get("controller", "PHANTOM AI User"),
                            processor=data.get("processor", "PHANTOM AI"),
                        ))
                    except Exception:
                        continue

        return records

    def generate_art30_report(self) -> dict[str, Any]:
        """Generate GDPR Art. 30 compliant report."""
        records = self.get_all_records()

        return {
            "report_type": "GDPR Article 30 - Records of Processing Activities",
            "generated_at": datetime.now().isoformat(),
            "controller": "PHANTOM AI User",
            "processor": "PHANTOM AI Security Scanner",
            "record_count": len(records),
            "records": [r.to_dict() for r in records],
            "data_categories_processed": list(set(
                cat for r in records for cat in r.data_categories
            )),
            "legal_bases_used": list(set(r.legal_basis for r in records)),
        }

    def _save_record(self, record: ProcessingRecord) -> None:
        """Save processing record."""
        try:
            with open(self.config.processing_records_file, "a") as f:
                f.write(json.dumps(record.to_dict()) + "\n")
        except Exception as e:
            logger.error(f"Failed to save processing record: {e}")


# =============================================================================
# MAIN GDPR COMPLIANCE ENGINE
# =============================================================================

class GDPRComplianceEngine:
    """
    Main GDPR compliance engine.

    Coordinates all GDPR features:
    - PII anonymization
    - Data retention
    - Data subject rights
    - Processing records
    """

    VERSION = "1.0.0"

    def __init__(self, config: Optional[GDPRConfig] = None):
        self.config = config or GDPRConfig()

        # Initialize components
        self.anonymizer = PIIAnonymizer()
        self.retention_manager = DataRetentionManager(self.config)
        self.rights_handler = DataSubjectRightsHandler(self.config)
        self.records_manager = ProcessingRecordsManager(self.config)

        # Run startup cleanup if enabled
        if self.config.auto_cleanup_enabled and self.config.cleanup_on_startup:
            self._startup_cleanup()

        logger.info(f"GDPRComplianceEngine v{self.VERSION} initialized")

    def _startup_cleanup(self) -> None:
        """Run cleanup on startup."""
        try:
            report = self.retention_manager.cleanup_expired_data()
            if report["scan_data_deleted"] > 0 or report["log_files_deleted"] > 0:
                logger.info(
                    f"Startup GDPR cleanup: {report['scan_data_deleted']} scans, "
                    f"{report['log_files_deleted']} logs deleted"
                )
        except Exception as e:
            logger.warning(f"Startup cleanup failed: {e}")

    # -------------------------------------------------------------------------
    # PII Protection
    # -------------------------------------------------------------------------

    def anonymize_text(
        self,
        text: str,
        preserve_types: Optional[list[str]] = None,
    ) -> str:
        """Anonymize PII in text."""
        if not self.config.anonymize_pii_in_logs:
            return text

        result, _ = self.anonymizer.anonymize(text, preserve_types)
        return result

    def anonymize_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Anonymize PII in a finding."""
        if not self.config.anonymize_pii_in_logs:
            return finding

        # Fields that may contain PII
        pii_fields = ["evidence", "response", "request", "payload", "parameter"]

        anonymized = finding.copy()
        for field in pii_fields:
            if field in anonymized and anonymized[field]:
                anonymized[field], _ = self.anonymizer.anonymize(str(anonymized[field]))

        return anonymized

    def detect_pii(self, text: str) -> dict[str, list[str]]:
        """Detect PII in text."""
        return self.anonymizer.detect_pii(text)

    # -------------------------------------------------------------------------
    # Data Subject Rights
    # -------------------------------------------------------------------------

    def process_access_request(
        self,
        identifier: str,
        identifier_type: str = "email",
    ) -> dict[str, Any]:
        """Process GDPR Art. 15 access request."""
        return self.rights_handler.handle_access_request(identifier, identifier_type)

    def process_erasure_request(
        self,
        identifier: str,
        identifier_type: str = "email",
        dry_run: bool = True,
    ) -> dict[str, Any]:
        """Process GDPR Art. 17 erasure request."""
        return self.rights_handler.handle_erasure_request(
            identifier, identifier_type, dry_run
        )

    def process_portability_request(
        self,
        identifier: str,
        identifier_type: str = "email",
        output_path: Optional[Path] = None,
    ) -> dict[str, Any]:
        """Process GDPR Art. 20 portability request."""
        return self.rights_handler.handle_portability_request(
            identifier, identifier_type, output_path
        )

    # -------------------------------------------------------------------------
    # Data Retention
    # -------------------------------------------------------------------------

    def run_cleanup(self) -> dict[str, Any]:
        """Run data retention cleanup."""
        return self.retention_manager.cleanup_expired_data()

    def get_data_inventory(self) -> dict[str, Any]:
        """Get inventory of all stored data."""
        return self.retention_manager.get_data_inventory()

    # -------------------------------------------------------------------------
    # Processing Records
    # -------------------------------------------------------------------------

    def record_scan(
        self,
        scan_id: str,
        target: str,
        purpose: str = "Security vulnerability assessment",
        legal_basis: str = "Legitimate interest / Authorized testing",
    ) -> ProcessingRecord:
        """Record a scan activity."""
        return self.records_manager.record_scan_activity(
            scan_id, target, purpose, legal_basis
        )

    def get_art30_report(self) -> dict[str, Any]:
        """Generate GDPR Art. 30 report."""
        return self.records_manager.generate_art30_report()

    # -------------------------------------------------------------------------
    # Compliance Report
    # -------------------------------------------------------------------------

    def generate_compliance_report(self) -> dict[str, Any]:
        """Generate full GDPR compliance status report."""
        inventory = self.get_data_inventory()

        return {
            "report_title": "PHANTOM AI - GDPR Compliance Status Report",
            "generated_at": datetime.now().isoformat(),
            "gdpr_engine_version": self.VERSION,

            "configuration": {
                "pii_anonymization": self.config.anonymize_pii_in_logs,
                "auto_cleanup": self.config.auto_cleanup_enabled,
                "scan_retention_days": self.config.scan_data_retention_days,
                "log_retention_days": self.config.log_retention_days,
            },

            "data_inventory": inventory,

            "anonymization_stats": self.anonymizer.get_statistics(),

            "compliance_status": {
                "art_5_data_minimization": "Configured" if self.config.store_full_responses is False else "Review needed",
                "art_15_access_rights": "Implemented",
                "art_17_erasure_rights": "Implemented",
                "art_20_portability": "Implemented",
                "art_25_privacy_by_design": "Implemented",
                "art_30_processing_records": "Implemented",
                "art_32_security": "Implemented (PII anonymization)",
            },
        }


# =============================================================================
# SINGLETON INSTANCE
# =============================================================================

_gdpr_engine: Optional[GDPRComplianceEngine] = None


def get_gdpr_engine(config: Optional[GDPRConfig] = None) -> GDPRComplianceEngine:
    """Get or create GDPR compliance engine singleton."""
    global _gdpr_engine

    if _gdpr_engine is None:
        _gdpr_engine = GDPRComplianceEngine(config)

    return _gdpr_engine


def anonymize_pii(text: str) -> str:
    """Quick function to anonymize PII in text."""
    return get_gdpr_engine().anonymize_text(text)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Main engine
    "GDPRComplianceEngine",
    "get_gdpr_engine",

    # Config
    "GDPRConfig",

    # Components
    "PIIAnonymizer",
    "DataRetentionManager",
    "DataSubjectRightsHandler",
    "ProcessingRecordsManager",

    # Data classes
    "ProcessingRecord",
    "DataSubjectRequest",

    # Utilities
    "anonymize_pii",
    "PII_PATTERNS",
]
