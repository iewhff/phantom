"""
State Manager for scan persistence and recovery.
Handles checkpointing, state recovery, and scan history.

SECURITY: Uses JSON serialization instead of pickle to prevent
arbitrary code execution vulnerabilities (CWE-502).
"""

from __future__ import annotations

import json
import hmac
import hashlib
import os
import secrets
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings
    from core.orchestrator import ScanContext, ScanPhase

logger = get_logger(__name__)


def _get_checkpoint_secret() -> str:
    """
    Get checkpoint secret from environment or generate secure default.

    SECURITY: Never hardcode secrets. Load from:
    1. Environment variable PETNTESTER_CHECKPOINT_SECRET
    2. Config file .secrets/checkpoint.key
    3. Generate new secure secret (first run only)

    CWE-798: Use of Hard-coded Credentials - FIXED
    """
    # Try environment variable first
    secret = os.environ.get("PETNTESTER_CHECKPOINT_SECRET")
    if secret:
        return secret

    # Try secret file
    secret_file = Path(".secrets/checkpoint.key")
    if secret_file.exists():
        try:
            return secret_file.read_text().strip()
        except (IOError, OSError) as e:
            logger.warning(f"Failed to read checkpoint secret file: {e}")

    # Generate new secret and save it
    secret = secrets.token_hex(32)  # 256-bit secret
    try:
        secret_file.parent.mkdir(parents=True, exist_ok=True)
        secret_file.write_text(secret)
        secret_file.chmod(0o600)  # Owner read/write only
        logger.info("Generated new checkpoint secret")
    except (IOError, OSError) as e:
        logger.warning(f"Failed to save checkpoint secret: {e}")

    return secret


# Load secret securely
_CHECKPOINT_SECRET = _get_checkpoint_secret()


class ScanStatus(str, Enum):
    """Scan execution status."""
    
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StateManager:
    """
    Manages scan state persistence and recovery.
    
    Features:
    - Checkpoint saving/loading
    - Scan history tracking
    - State recovery after crashes
    - Progress persistence
    """
    
    def __init__(self, settings: Settings) -> None:
        """
        Initialize StateManager.
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        self.state_dir = Path("data/scans")
        self.state_dir.mkdir(parents=True, exist_ok=True)
    
    def _serialize_context(self, context: ScanContext) -> dict[str, Any]:
        """
        Serialize ScanContext to JSON-safe dict.

        SECURITY: Avoids pickle to prevent code execution vulnerabilities.
        """
        # Convert dataclass/object to dict safely
        if hasattr(context, '__dict__'):
            data = {}
            for key, value in context.__dict__.items():
                try:
                    # Test if value is JSON serializable
                    json.dumps(value, default=str)
                    data[key] = value
                except (TypeError, ValueError):
                    # Convert complex objects to string representation
                    data[key] = str(value)
            return data
        return {"_raw": str(context)}

    def _deserialize_context(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Deserialize context data back to dict.

        Returns dict that can be used to reconstruct ScanContext.
        """
        return data

    def _compute_signature(self, data: str) -> str:
        """Compute HMAC signature for data integrity."""
        return hmac.new(
            _CHECKPOINT_SECRET.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()

    def _verify_signature(self, data: str, signature: str) -> bool:
        """Verify HMAC signature."""
        expected = self._compute_signature(data)
        return hmac.compare_digest(expected, signature)

    def save_checkpoint(
        self,
        scan_id: str,
        phase: ScanPhase,
        context: ScanContext,
        metadata: dict[str, Any] | None = None,
    ) -> Path:
        """
        Save a scan checkpoint using secure JSON serialization.

        Args:
            scan_id: Unique scan identifier
            phase: Current scan phase
            context: Scan context to save
            metadata: Optional additional metadata

        Returns:
            Path to checkpoint file

        SECURITY: Uses JSON instead of pickle to prevent CWE-502
        (Deserialization of Untrusted Data).
        """
        checkpoint_dir = self.state_dir / scan_id
        checkpoint_dir.mkdir(parents=True, exist_ok=True)

        checkpoint_data = {
            "scan_id": scan_id,
            "phase": phase.name if hasattr(phase, 'name') else str(phase),
            "timestamp": datetime.now().isoformat(),
            "metadata": metadata or {},
        }

        # Save metadata as JSON
        metadata_path = checkpoint_dir / f"checkpoint_{phase.value if hasattr(phase, 'value') else phase}.json"
        with open(metadata_path, 'w') as f:
            json.dump(checkpoint_data, f, indent=2, default=str)

        # Save context as signed JSON (SECURE - no pickle!)
        context_data = self._serialize_context(context)
        context_json = json.dumps(context_data, indent=2, default=str)
        signature = self._compute_signature(context_json)

        signed_data = {
            "version": "2.0",
            "signature": signature,
            "context": context_data,
        }

        context_path = checkpoint_dir / f"context_{phase.value if hasattr(phase, 'value') else phase}.json"
        with open(context_path, 'w') as f:
            json.dump(signed_data, f, indent=2, default=str)

        # Update scan status
        self._update_scan_status(scan_id, ScanStatus.RUNNING, phase)

        logger.info(f"Saved checkpoint for scan {scan_id} at phase {phase}")
        return context_path
    
    def load_checkpoint(
        self,
        scan_id: str,
        phase: ScanPhase | None = None,
    ) -> tuple[dict[str, Any] | None, ScanPhase | None]:
        """
        Load a scan checkpoint using secure JSON deserialization.

        Args:
            scan_id: Scan identifier
            phase: Specific phase to load (None for latest)

        Returns:
            Tuple of (context_dict, phase) or (None, None) if not found

        SECURITY: Uses signed JSON with HMAC verification to prevent
        tampering and code execution vulnerabilities.
        """
        checkpoint_dir = self.state_dir / scan_id

        if not checkpoint_dir.exists():
            logger.warning(f"No checkpoint found for scan {scan_id}")
            return None, None

        if phase is None:
            # Find latest checkpoint
            phase = self._find_latest_phase(checkpoint_dir)
            if phase is None:
                return None, None

        # Try new JSON format first
        context_path = checkpoint_dir / f"context_{phase.value if hasattr(phase, 'value') else phase}.json"

        # Fallback to old format detection (but don't load pickle!)
        old_pkl_path = checkpoint_dir / f"context_{phase.value if hasattr(phase, 'value') else phase}.pkl"
        if not context_path.exists() and old_pkl_path.exists():
            logger.error(
                f"Found old pickle checkpoint at {old_pkl_path}. "
                "Pickle loading is disabled for security. "
                "Please re-run the scan to create a new checkpoint."
            )
            return None, None

        if not context_path.exists():
            logger.warning(f"Context file not found: {context_path}")
            return None, None

        try:
            with open(context_path, 'r') as f:
                signed_data = json.load(f)

            # Verify signature for v2.0+ checkpoints
            if signed_data.get("version") == "2.0":
                context_data = signed_data.get("context", {})
                stored_signature = signed_data.get("signature", "")
                context_json = json.dumps(context_data, indent=2, default=str)

                if not self._verify_signature(context_json, stored_signature):
                    logger.error(f"Checkpoint signature verification failed for scan {scan_id}")
                    return None, None

                context = self._deserialize_context(context_data)
            else:
                # Legacy JSON format (unsigned)
                context = signed_data

            logger.info(f"Loaded checkpoint for scan {scan_id} at phase {phase}")
            return context, phase

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in checkpoint: {e}")
            return None, None
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}")
            return None, None
    
    def _find_latest_phase(self, checkpoint_dir: Path) -> ScanPhase | None:
        """Find the latest phase checkpoint."""
        from core.orchestrator import ScanPhase
        
        latest_phase = None
        latest_time = None
        
        for meta_file in checkpoint_dir.glob("checkpoint_*.json"):
            try:
                with open(meta_file) as f:
                    data = json.load(f)
                
                timestamp = datetime.fromisoformat(data["timestamp"])
                
                if latest_time is None or timestamp > latest_time:
                    latest_time = timestamp
                    phase_name = data["phase"]
                    latest_phase = ScanPhase[phase_name] if phase_name in ScanPhase.__members__ else None
                    
            except Exception:
                continue
        
        return latest_phase
    
    def _update_scan_status(
        self,
        scan_id: str,
        status: ScanStatus,
        phase: ScanPhase | None = None,
    ) -> None:
        """Update scan status in index."""
        index_path = self.state_dir / "scans_index.json"
        
        # Load existing index
        if index_path.exists():
            with open(index_path) as f:
                index = json.load(f)
        else:
            index = {"scans": {}}
        
        # Update scan entry
        if scan_id not in index["scans"]:
            index["scans"][scan_id] = {
                "created_at": datetime.now().isoformat(),
            }
        
        index["scans"][scan_id].update({
            "status": status.value,
            "current_phase": phase.name if phase and hasattr(phase, 'name') else str(phase),
            "updated_at": datetime.now().isoformat(),
        })
        
        # Save index
        with open(index_path, 'w') as f:
            json.dump(index, f, indent=2)
    
    def get_scan_info(self, scan_id: str) -> dict[str, Any] | None:
        """
        Get information about a scan.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Scan information dict or None
        """
        index_path = self.state_dir / "scans_index.json"
        
        if not index_path.exists():
            return None
        
        with open(index_path) as f:
            index = json.load(f)
        
        scan_data = index.get("scans", {}).get(scan_id)
        
        if scan_data:
            # Add findings count from latest checkpoint
            checkpoint_dir = self.state_dir / scan_id
            if checkpoint_dir.exists():
                context, _ = self.load_checkpoint(scan_id)
                if context:
                    scan_data["findings_count"] = len(getattr(context, 'findings', []))
                    scan_data["target"] = getattr(context, 'target', 'Unknown')
        
        return scan_data
    
    def list_scans(
        self,
        status: ScanStatus | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        List all scans.
        
        Args:
            status: Filter by status
            limit: Maximum number of results
            
        Returns:
            List of scan info dicts
        """
        index_path = self.state_dir / "scans_index.json"
        
        if not index_path.exists():
            return []
        
        with open(index_path) as f:
            index = json.load(f)
        
        scans = []
        for scan_id, data in index.get("scans", {}).items():
            if status and data.get("status") != status.value:
                continue
            
            scans.append({
                "id": scan_id,
                **data,
            })
        
        # Sort by updated_at descending
        scans.sort(
            key=lambda x: x.get("updated_at", ""),
            reverse=True,
        )
        
        return scans[:limit]
    
    def mark_completed(
        self,
        scan_id: str,
        context: ScanContext,
    ) -> None:
        """
        Mark a scan as completed.
        
        Args:
            scan_id: Scan identifier
            context: Final scan context
        """
        from core.orchestrator import ScanPhase
        
        # Save final state
        self.save_checkpoint(
            scan_id,
            ScanPhase.REPORTING,
            context,
            {"completed": True},
        )
        
        self._update_scan_status(scan_id, ScanStatus.COMPLETED)
        logger.info(f"Scan {scan_id} marked as completed")
    
    def mark_failed(
        self,
        scan_id: str,
        error: str,
        phase: ScanPhase | None = None,
    ) -> None:
        """
        Mark a scan as failed.
        
        Args:
            scan_id: Scan identifier
            error: Error message
            phase: Phase where failure occurred
        """
        self._update_scan_status(scan_id, ScanStatus.FAILED, phase)
        
        # Save error info
        error_path = self.state_dir / scan_id / "error.json"
        error_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(error_path, 'w') as f:
            json.dump({
                "error": error,
                "phase": phase.name if phase and hasattr(phase, 'name') else str(phase),
                "timestamp": datetime.now().isoformat(),
            }, f, indent=2)
        
        logger.error(f"Scan {scan_id} marked as failed: {error}")
    
    def can_resume(self, scan_id: str) -> bool:
        """
        Check if a scan can be resumed.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            True if scan can be resumed
        """
        info = self.get_scan_info(scan_id)
        
        if not info:
            return False
        
        resumable_statuses = {ScanStatus.PAUSED.value, ScanStatus.FAILED.value}
        return info.get("status") in resumable_statuses
    
    def cleanup_old_scans(self, days: int | None = None) -> int:
        """
        Clean up old scan data.
        
        Args:
            days: Delete scans older than this (uses config default if None)
            
        Returns:
            Number of scans cleaned up
        """
        if days is None:
            days = self.settings.storage.auto_cleanup_days
        
        cutoff = datetime.now().timestamp() - (days * 24 * 60 * 60)
        cleaned = 0
        
        for scan_dir in self.state_dir.iterdir():
            if not scan_dir.is_dir() or scan_dir.name == "scans_index.json":
                continue

            # Check modification time
            if scan_dir.stat().st_mtime < cutoff:
                import shutil
                shutil.rmtree(scan_dir)
                cleaned += 1
                logger.info(f"Cleaned up old scan: {scan_dir.name}")

        return cleaned

    # =========================================================================
    # PHANTOM AI ENHANCEMENTS
    # =========================================================================

    def save_incremental(
        self,
        scan_id: str,
        delta: dict[str, Any],
        event_type: str = "STATE_UPDATE",
    ) -> bool:
        """
        Save incremental state changes.

        Instead of saving the full context, this saves only the changes
        as a delta. More efficient for frequent updates during scanning.

        Args:
            scan_id: Scan identifier
            delta: Dictionary of changes to save
            event_type: Type of event for timeline

        Returns:
            bool: True if saved successfully

        Example:
            # Save a new finding incrementally
            state_manager.save_incremental(
                scan_id="abc123",
                delta={
                    "new_finding": {
                        "type": "sqli",
                        "endpoint": "/api/users",
                        "confidence": 0.95
                    }
                },
                event_type="FINDING_ADDED"
            )
        """
        try:
            checkpoint_dir = self.state_dir / scan_id
            checkpoint_dir.mkdir(parents=True, exist_ok=True)

            # Create incremental file with timestamp
            timestamp = datetime.now()
            incremental_id = timestamp.strftime("%Y%m%d_%H%M%S_%f")
            incremental_path = checkpoint_dir / f"incremental_{incremental_id}.json"

            # Prepare incremental data
            incremental_data = {
                "version": "2.0",
                "scan_id": scan_id,
                "timestamp": timestamp.isoformat(),
                "event_type": event_type,
                "delta": delta,
            }

            # Sign the data
            data_json = json.dumps(incremental_data["delta"], indent=2, default=str)
            signature = self._compute_signature(data_json)
            incremental_data["signature"] = signature

            # Save
            with open(incremental_path, 'w') as f:
                json.dump(incremental_data, f, indent=2, default=str)

            # Also log to timeline
            self._append_to_timeline(scan_id, event_type, delta)

            logger.debug(f"Saved incremental state for scan {scan_id}: {event_type}")
            return True

        except Exception as e:
            logger.error(f"Failed to save incremental state: {e}")
            return False

    def _append_to_timeline(
        self,
        scan_id: str,
        event_type: str,
        data: dict[str, Any],
    ) -> None:
        """
        Append an event to the scan timeline.

        The timeline is a chronological log of all events during a scan.
        Used for auditing, debugging, and report generation.

        Args:
            scan_id: Scan identifier
            event_type: Type of event
            data: Event data
        """
        try:
            checkpoint_dir = self.state_dir / scan_id
            checkpoint_dir.mkdir(parents=True, exist_ok=True)
            timeline_path = checkpoint_dir / "timeline.jsonl"

            event = {
                "timestamp": datetime.now().isoformat(),
                "event_type": event_type,
                "data": data,
            }

            with open(timeline_path, 'a') as f:
                f.write(json.dumps(event, default=str) + "\n")

        except Exception as e:
            logger.warning(f"Failed to append to timeline: {e}")

    def get_scan_timeline(
        self,
        scan_id: str,
        event_types: list[str] | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """
        Get the timeline of events for a scan.

        Returns a chronological list of all events that occurred
        during the scan. Useful for auditing and debugging.

        Args:
            scan_id: Scan identifier
            event_types: Filter by event types (None for all)
            start_time: Filter events after this time
            end_time: Filter events before this time
            limit: Maximum number of events to return

        Returns:
            List of event dictionaries, newest first

        Example:
            # Get all findings added during scan
            timeline = state_manager.get_scan_timeline(
                scan_id="abc123",
                event_types=["FINDING_ADDED", "FINDING_VALIDATED"]
            )
        """
        timeline_path = self.state_dir / scan_id / "timeline.jsonl"

        if not timeline_path.exists():
            return []

        events = []
        try:
            with open(timeline_path, 'r') as f:
                for line in f:
                    if not line.strip():
                        continue

                    try:
                        event = json.loads(line)

                        # Apply filters
                        if event_types and event.get("event_type") not in event_types:
                            continue

                        event_time = datetime.fromisoformat(event["timestamp"])

                        if start_time and event_time < start_time:
                            continue

                        if end_time and event_time > end_time:
                            continue

                        events.append(event)

                    except (json.JSONDecodeError, KeyError):
                        continue

        except Exception as e:
            logger.error(f"Failed to read timeline: {e}")
            return []

        # Sort by timestamp descending (newest first)
        events.sort(key=lambda e: e.get("timestamp", ""), reverse=True)

        return events[:limit]

    def export_for_resume(
        self,
        scan_id: str,
        output_path: str | Path | None = None,
    ) -> Path | None:
        """
        Export scan state in a format optimized for resume.

        Creates a single file containing all necessary state to
        resume the scan from where it left off.

        Args:
            scan_id: Scan identifier
            output_path: Custom output path (uses default if None)

        Returns:
            Path to export file, or None if failed

        Example:
            # Export for resume
            path = state_manager.export_for_resume("abc123")

            # Later, load and resume
            with open(path) as f:
                resume_data = json.load(f)
        """
        try:
            # Load latest checkpoint
            context, phase = self.load_checkpoint(scan_id)
            if context is None:
                logger.error(f"No checkpoint found for scan {scan_id}")
                return None

            # Load scan info
            scan_info = self.get_scan_info(scan_id)

            # Load timeline summary (last 100 events)
            timeline = self.get_scan_timeline(scan_id, limit=100)

            # Load incremental deltas
            deltas = self._load_incrementals(scan_id)

            # Compile resume package
            resume_data = {
                "version": "3.0",
                "export_timestamp": datetime.now().isoformat(),
                "scan_id": scan_id,
                "phase": phase.name if phase and hasattr(phase, 'name') else str(phase),
                "scan_info": scan_info,
                "context": context,
                "timeline_summary": timeline[:20],  # Last 20 events
                "incremental_count": len(deltas),
                "resume_instructions": {
                    "phase_to_resume": phase.name if phase and hasattr(phase, 'name') else str(phase),
                    "context_keys": list(context.keys()) if isinstance(context, dict) else [],
                },
            }

            # Sign the export
            export_json = json.dumps(resume_data, indent=2, default=str)
            signature = self._compute_signature(export_json)

            signed_export = {
                "version": "3.0",
                "signature": signature,
                "data": resume_data,
            }

            # Determine output path
            if output_path is None:
                export_dir = self.state_dir / "exports"
                export_dir.mkdir(parents=True, exist_ok=True)
                output_path = export_dir / f"{scan_id}_resume_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            else:
                output_path = Path(output_path)

            # Write export
            with open(output_path, 'w') as f:
                json.dump(signed_export, f, indent=2, default=str)

            logger.info(f"Exported scan {scan_id} for resume: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Failed to export for resume: {e}")
            return None

    def _load_incrementals(self, scan_id: str) -> list[dict[str, Any]]:
        """
        Load all incremental deltas for a scan.

        Args:
            scan_id: Scan identifier

        Returns:
            List of incremental data dictionaries
        """
        checkpoint_dir = self.state_dir / scan_id
        if not checkpoint_dir.exists():
            return []

        deltas = []
        for incremental_file in sorted(checkpoint_dir.glob("incremental_*.json")):
            try:
                with open(incremental_file, 'r') as f:
                    data = json.load(f)

                # Verify signature
                if data.get("version") == "2.0":
                    delta = data.get("delta", {})
                    stored_sig = data.get("signature", "")
                    delta_json = json.dumps(delta, indent=2, default=str)

                    if self._verify_signature(delta_json, stored_sig):
                        deltas.append(data)
                    else:
                        logger.warning(f"Invalid signature in {incremental_file}")
                else:
                    deltas.append(data)

            except Exception as e:
                logger.warning(f"Failed to load incremental {incremental_file}: {e}")

        return deltas

    def import_for_resume(
        self,
        import_path: str | Path,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """
        Import a resume package and prepare for resume.

        Args:
            import_path: Path to export file

        Returns:
            Tuple of (context, phase) or (None, None) if failed

        Example:
            context, phase = state_manager.import_for_resume("scan_resume.json")
            if context:
                orchestrator.resume(context, phase)
        """
        try:
            import_path = Path(import_path)

            with open(import_path, 'r') as f:
                signed_export = json.load(f)

            # Verify signature
            if signed_export.get("version") == "3.0":
                data = signed_export.get("data", {})
                stored_sig = signed_export.get("signature", "")
                data_json = json.dumps(data, indent=2, default=str)

                if not self._verify_signature(data_json, stored_sig):
                    logger.error("Invalid signature in resume file")
                    return None, None
            else:
                data = signed_export

            scan_id = data.get("scan_id")
            phase = data.get("phase")
            context = data.get("context")

            logger.info(f"Imported resume data for scan {scan_id}, phase {phase}")
            return context, phase

        except Exception as e:
            logger.error(f"Failed to import resume file: {e}")
            return None, None

    def get_scan_metrics(self, scan_id: str) -> dict[str, Any]:
        """
        Get metrics for a scan.

        Calculates various metrics from the timeline and state.

        Args:
            scan_id: Scan identifier

        Returns:
            Dictionary of metrics
        """
        timeline = self.get_scan_timeline(scan_id, limit=10000)
        scan_info = self.get_scan_info(scan_id)

        if not timeline:
            return {}

        # Calculate metrics
        event_counts: dict[str, int] = {}
        for event in timeline:
            event_type = event.get("event_type", "UNKNOWN")
            event_counts[event_type] = event_counts.get(event_type, 0) + 1

        # Get time range
        timestamps = [datetime.fromisoformat(e["timestamp"]) for e in timeline if "timestamp" in e]
        if timestamps:
            start_time = min(timestamps)
            end_time = max(timestamps)
            duration = (end_time - start_time).total_seconds()
        else:
            start_time = end_time = None
            duration = 0

        return {
            "scan_id": scan_id,
            "total_events": len(timeline),
            "event_counts": event_counts,
            "duration_seconds": duration,
            "start_time": start_time.isoformat() if start_time else None,
            "end_time": end_time.isoformat() if end_time else None,
            "status": scan_info.get("status") if scan_info else None,
            "findings_count": scan_info.get("findings_count", 0) if scan_info else 0,
        }

    def record_scan_event(
        self,
        scan_id: str,
        event_type: str,
        data: dict[str, Any] | None = None,
        severity: str = "info",
    ) -> None:
        """
        Record a scan event for timeline and audit.

        Convenience method for logging events during scanning.

        Args:
            scan_id: Scan identifier
            event_type: Type of event (e.g., "MODULE_STARTED", "FINDING_DETECTED")
            data: Optional event data
            severity: Event severity (info, warning, error, critical)

        Example:
            state_manager.record_scan_event(
                scan_id="abc123",
                event_type="MODULE_COMPLETED",
                data={"module": "sqli_scanner", "findings": 3},
                severity="info"
            )
        """
        event_data = {
            "severity": severity,
            **(data or {}),
        }

        self._append_to_timeline(scan_id, event_type, event_data)

        # Log based on severity
        log_msg = f"Scan {scan_id} - {event_type}"
        if severity == "critical":
            logger.critical(log_msg)
        elif severity == "error":
            logger.error(log_msg)
        elif severity == "warning":
            logger.warning(log_msg)
        else:
            logger.debug(log_msg)
