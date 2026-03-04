"""
Phase Tracker - Phase Timing and Progress Tracking.

Provides utilities for tracking scan phase execution:
- Phase timing (start, end, duration)
- Progress reporting
- Evidence engine integration
- Phase statistics

Extracted from full_scanner.py for centralized phase management.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol

from .phases import PhaseInfo, get_phase, ALL_PHASES, PhaseCategory

logger = logging.getLogger("phantom")


# ═══════════════════════════════════════════════════════════════════════════════
# Protocols
# ═══════════════════════════════════════════════════════════════════════════════


class EvidenceEngineProtocol(Protocol):
    """Protocol for evidence engine integration."""

    def add_timeline_event(
        self,
        event_type: str,
        description: str,
        url: str = "",
        details: Optional[dict] = None,
    ) -> None:
        """Add event to timeline."""
        ...


class ProgressCallbackProtocol(Protocol):
    """Protocol for progress callbacks."""

    def __call__(self, phase: str, progress: float, message: str) -> None:
        """Report progress."""
        ...


# ═══════════════════════════════════════════════════════════════════════════════
# Phase Execution Record
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class PhaseExecution:
    """Record of a single phase execution."""

    phase_id: str
    phase_info: Optional[PhaseInfo]
    start_time: float
    end_time: Optional[float] = None
    status: str = "running"  # running, completed, skipped, failed
    error: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    @property
    def duration(self) -> float:
        """Get duration in seconds."""
        if self.end_time is None:
            return time.time() - self.start_time
        return self.end_time - self.start_time

    @property
    def is_slow(self) -> bool:
        """Check if phase is running slow."""
        if self.phase_info is None:
            return False
        return self.duration > self.phase_info.max_duration

    def complete(self, status: str = "completed") -> None:
        """Mark phase as complete."""
        self.end_time = time.time()
        self.status = status


# ═══════════════════════════════════════════════════════════════════════════════
# Phase Tracker
# ═══════════════════════════════════════════════════════════════════════════════


class PhaseTracker:
    """Tracks phase execution timing and progress.

    Provides:
    - Phase start/end timing
    - Progress reporting
    - Evidence engine integration
    - Performance statistics
    """

    def __init__(
        self,
        target: str = "",
        evidence_engine: Optional[EvidenceEngineProtocol] = None,
        progress_callback: Optional[ProgressCallbackProtocol] = None,
    ):
        """Initialize phase tracker.

        Args:
            target: Target URL being scanned
            evidence_engine: Optional evidence engine for timeline events
            progress_callback: Optional callback for progress updates
        """
        self.target = target
        self.evidence_engine = evidence_engine
        self.progress_callback = progress_callback

        self._executions: dict[str, PhaseExecution] = {}
        self._current_phase: Optional[str] = None
        self._scan_start: Optional[float] = None
        self._scan_end: Optional[float] = None

    @property
    def current_phase(self) -> Optional[str]:
        """Get currently executing phase ID."""
        return self._current_phase

    @property
    def scan_duration(self) -> float:
        """Get total scan duration."""
        if self._scan_start is None:
            return 0.0
        end = self._scan_end or time.time()
        return end - self._scan_start

    def start_scan(self) -> None:
        """Mark scan start."""
        self._scan_start = time.time()
        self._executions.clear()
        self._current_phase = None

    def end_scan(self) -> None:
        """Mark scan end."""
        self._scan_end = time.time()
        self._current_phase = None

    def start_phase(
        self,
        phase_id: str,
        message: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> PhaseExecution:
        """Start tracking a phase.

        Args:
            phase_id: Phase identifier
            message: Optional custom log message
            metadata: Optional metadata to store

        Returns:
            PhaseExecution record
        """
        phase_info = get_phase(phase_id)

        # Create execution record
        execution = PhaseExecution(
            phase_id=phase_id,
            phase_info=phase_info,
            start_time=time.time(),
            metadata=metadata or {},
        )
        self._executions[phase_id] = execution
        self._current_phase = phase_id

        # Log phase start
        if phase_info:
            log_msg = message or phase_info.log_prefix
            logger.info(log_msg)
        else:
            logger.info(f"Phase {phase_id}: Starting...")

        # Add evidence timeline event
        if self.evidence_engine and phase_info:
            try:
                self.evidence_engine.add_timeline_event(
                    event_type="phase_start",
                    description=f"Phase {phase_id}: {phase_info.name} started",
                    url=self.target,
                    details={
                        "phase": phase_info.evidence_phase_id,
                        "category": phase_info.category.value,
                        **(metadata or {}),
                    },
                )
            except Exception as e:
                logger.debug(f"Evidence engine error: {e}")

        # Report progress
        if self.progress_callback:
            try:
                progress = self._calculate_progress()
                self.progress_callback(
                    phase_id,
                    progress,
                    message or (phase_info.name if phase_info else f"Phase {phase_id}"),
                )
            except Exception as e:
                logger.debug(f"Progress callback error: {e}")

        return execution

    def end_phase(
        self,
        phase_id: str,
        status: str = "completed",
        message: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> Optional[PhaseExecution]:
        """End tracking a phase.

        Args:
            phase_id: Phase identifier
            status: Completion status (completed, skipped, failed)
            message: Optional custom log message
            metadata: Optional metadata to add

        Returns:
            PhaseExecution record or None if not found
        """
        execution = self._executions.get(phase_id)
        if execution is None:
            logger.warning(f"Phase {phase_id} was not started")
            return None

        execution.complete(status)
        if metadata:
            execution.metadata.update(metadata)

        if self._current_phase == phase_id:
            self._current_phase = None

        phase_info = execution.phase_info

        # Log completion
        duration_str = f"{execution.duration:.1f}s"
        if phase_info:
            if status == "completed":
                logger.debug(f"Phase {phase_id}: {phase_info.name} completed in {duration_str}")
            elif status == "skipped":
                logger.debug(f"Phase {phase_id}: {phase_info.name} skipped")
            else:
                logger.warning(f"Phase {phase_id}: {phase_info.name} {status} after {duration_str}")

        # Add evidence timeline event
        if self.evidence_engine and phase_info:
            try:
                self.evidence_engine.add_timeline_event(
                    event_type="phase_complete",
                    description=message or f"Phase {phase_id}: {phase_info.name} {status}",
                    url=self.target,
                    details={
                        "phase": phase_info.evidence_phase_id,
                        "status": status,
                        "duration_seconds": execution.duration,
                        **(metadata or {}),
                    },
                )
            except Exception as e:
                logger.debug(f"Evidence engine error: {e}")

        # Warn if slow
        if execution.is_slow and status == "completed":
            logger.warning(
                f"Phase {phase_id} took {execution.duration:.1f}s "
                f"(expected max {phase_info.max_duration:.0f}s)"
            )

        return execution

    def skip_phase(
        self,
        phase_id: str,
        reason: str = "",
    ) -> PhaseExecution:
        """Record a skipped phase.

        Args:
            phase_id: Phase identifier
            reason: Reason for skipping

        Returns:
            PhaseExecution record
        """
        phase_info = get_phase(phase_id)

        execution = PhaseExecution(
            phase_id=phase_id,
            phase_info=phase_info,
            start_time=time.time(),
            end_time=time.time(),
            status="skipped",
            metadata={"skip_reason": reason},
        )
        self._executions[phase_id] = execution

        if phase_info:
            logger.debug(f"Phase {phase_id}: {phase_info.name} skipped - {reason}")
        else:
            logger.debug(f"Phase {phase_id} skipped - {reason}")

        return execution

    def fail_phase(
        self,
        phase_id: str,
        error: str,
    ) -> Optional[PhaseExecution]:
        """Record a failed phase.

        Args:
            phase_id: Phase identifier
            error: Error message

        Returns:
            PhaseExecution record or None
        """
        execution = self._executions.get(phase_id)
        if execution:
            execution.complete("failed")
            execution.error = error
        else:
            # Create failed execution record
            phase_info = get_phase(phase_id)
            execution = PhaseExecution(
                phase_id=phase_id,
                phase_info=phase_info,
                start_time=time.time(),
                end_time=time.time(),
                status="failed",
                error=error,
            )
            self._executions[phase_id] = execution

        logger.error(f"Phase {phase_id} failed: {error}")

        if self._current_phase == phase_id:
            self._current_phase = None

        return execution

    def get_execution(self, phase_id: str) -> Optional[PhaseExecution]:
        """Get execution record for a phase.

        Args:
            phase_id: Phase identifier

        Returns:
            PhaseExecution or None
        """
        return self._executions.get(phase_id)

    def get_all_executions(self) -> list[PhaseExecution]:
        """Get all execution records."""
        return list(self._executions.values())

    def _calculate_progress(self) -> float:
        """Calculate overall scan progress (0.0 to 1.0)."""
        if not self._executions:
            return 0.0

        total_phases = len(ALL_PHASES)
        completed = sum(
            1 for e in self._executions.values()
            if e.status in ("completed", "skipped")
        )
        return completed / total_phases

    def get_stats(self) -> dict[str, Any]:
        """Get phase execution statistics.

        Returns:
            Dictionary with stats
        """
        executions = list(self._executions.values())

        completed = [e for e in executions if e.status == "completed"]
        skipped = [e for e in executions if e.status == "skipped"]
        failed = [e for e in executions if e.status == "failed"]

        total_duration = sum(e.duration for e in completed)
        slow_phases = [e for e in completed if e.is_slow]

        # Duration by category
        duration_by_category: dict[str, float] = {}
        for e in completed:
            if e.phase_info:
                cat = e.phase_info.category.value
                duration_by_category[cat] = duration_by_category.get(cat, 0) + e.duration

        return {
            "total_phases": len(executions),
            "completed": len(completed),
            "skipped": len(skipped),
            "failed": len(failed),
            "total_duration": total_duration,
            "scan_duration": self.scan_duration,
            "slow_phases": [e.phase_id for e in slow_phases],
            "duration_by_category": duration_by_category,
            "failed_phases": [
                {"phase_id": e.phase_id, "error": e.error}
                for e in failed
            ],
        }

    def get_timeline(self) -> list[dict]:
        """Get phase execution timeline.

        Returns:
            List of phase execution records for reporting
        """
        timeline = []
        for e in sorted(self._executions.values(), key=lambda x: x.start_time):
            entry = {
                "phase_id": e.phase_id,
                "name": e.phase_info.name if e.phase_info else f"Phase {e.phase_id}",
                "status": e.status,
                "duration": e.duration,
                "start_time": e.start_time,
            }
            if e.error:
                entry["error"] = e.error
            if e.metadata:
                entry["metadata"] = e.metadata
            timeline.append(entry)
        return timeline


# ═══════════════════════════════════════════════════════════════════════════════
# Context Manager
# ═══════════════════════════════════════════════════════════════════════════════


class PhaseContext:
    """Context manager for phase execution.

    Usage:
        with phase_context(tracker, "4.2") as phase:
            # Do phase work
            phase.metadata["findings"] = 5
    """

    def __init__(
        self,
        tracker: PhaseTracker,
        phase_id: str,
        message: Optional[str] = None,
        metadata: Optional[dict] = None,
    ):
        self.tracker = tracker
        self.phase_id = phase_id
        self.message = message
        self.metadata = metadata or {}
        self.execution: Optional[PhaseExecution] = None

    def __enter__(self) -> PhaseExecution:
        self.execution = self.tracker.start_phase(
            self.phase_id,
            message=self.message,
            metadata=self.metadata,
        )
        return self.execution

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_type is not None:
            self.tracker.fail_phase(self.phase_id, str(exc_val))
            return False  # Re-raise exception

        self.tracker.end_phase(
            self.phase_id,
            status="completed",
            metadata=self.execution.metadata if self.execution else None,
        )
        return False


def phase_context(
    tracker: PhaseTracker,
    phase_id: str,
    message: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> PhaseContext:
    """Create a phase context manager.

    Args:
        tracker: Phase tracker instance
        phase_id: Phase identifier
        message: Optional log message
        metadata: Optional metadata

    Returns:
        PhaseContext for use with `with` statement
    """
    return PhaseContext(tracker, phase_id, message, metadata)
