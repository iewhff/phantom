"""
Pipeline Base Abstractions for PHANTOM AI Security Scanner.

This module provides the core pipeline infrastructure that replaces
the monolithic full_scanner.py with a composable, testable architecture.

Architecture:
    Pipeline
      └── Phase (abstract)
           ├── DiscoveryPhase
           ├── AuthAcquisitionPhase
           ├── TechIntelligencePhase
           ├── ModuleExecutionPhase
           ├── PostProcessingPhase
           ├── ValidationPhase
           └── ReportingPhase

Benefits:
- Each phase is independently testable
- Phases can be composed dynamically
- Easy to add/remove phases
- Clear separation of concerns
- Supports async execution

Usage:
    pipeline = (
        ScanPipeline()
        .add_phase(DiscoveryPhase())
        .add_phase(AuthAcquisitionPhase())
        .add_phase(TechIntelligencePhase())
        .add_phase(ModuleExecutionPhase(scanners))
        .add_phase(PostProcessingPhase())
        .add_phase(ValidationPhase())
        .add_phase(ReportingPhase())
    )

    result = await pipeline.execute(context)

Author: PHANTOM AI
Version: 2.0.0
Date: 2026-02-24
"""

from __future__ import annotations

import asyncio
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Callable, Optional, TypeVar
from uuid import uuid4

from utils.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# ENUMS
# =============================================================================

class PhaseStatus(Enum):
    """Status of a pipeline phase."""
    PENDING = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    SKIPPED = auto()
    CANCELLED = auto()


class PipelineStatus(Enum):
    """Status of the entire pipeline."""
    IDLE = auto()
    RUNNING = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()
    PAUSED = auto()


# =============================================================================
# CONTEXT
# =============================================================================

@dataclass
class ScanContext:
    """
    Context object passed through all pipeline phases.

    Contains all the state accumulated during the scan.
    Each phase reads from and writes to this context.
    """

    # ==========================================================================
    # IDENTITY
    # ==========================================================================
    scan_id: str = ""
    target_url: str = ""
    target_host: str = ""
    started_at: str = ""

    # ==========================================================================
    # CONFIGURATION
    # ==========================================================================
    config: dict[str, Any] = field(default_factory=dict)
    scan_mode: str = "full"  # full, quick, bounty, client

    # ==========================================================================
    # AUTHENTICATION
    # ==========================================================================
    auth_headers: dict[str, str] = field(default_factory=dict)
    auth_cookies: dict[str, str] = field(default_factory=dict)
    auth_tokens: dict[str, str] = field(default_factory=dict)
    is_authenticated: bool = False

    # ==========================================================================
    # DISCOVERY RESULTS
    # ==========================================================================
    endpoints: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    parameters: dict[str, list[str]] = field(default_factory=dict)
    subdomains: list[str] = field(default_factory=list)

    # ==========================================================================
    # TECH INTELLIGENCE
    # ==========================================================================
    tech_stack: dict[str, Any] = field(default_factory=dict)
    server: str = ""
    framework: str = ""
    language: str = ""
    database: str = ""
    waf_detected: bool = False
    waf_type: str = ""

    # ==========================================================================
    # FINDINGS
    # ==========================================================================
    findings: list[Any] = field(default_factory=list)  # List[Finding]
    raw_findings: list[Any] = field(default_factory=list)
    validated_findings: list[Any] = field(default_factory=list)

    # ==========================================================================
    # CHAINS
    # ==========================================================================
    attack_chains: list[dict] = field(default_factory=list)

    # ==========================================================================
    # METRICS
    # ==========================================================================
    requests_made: int = 0
    errors_count: int = 0
    coverage_data: dict[str, Any] = field(default_factory=dict)

    # ==========================================================================
    # PHASE TRACKING
    # ==========================================================================
    completed_phases: list[str] = field(default_factory=list)
    phase_results: dict[str, Any] = field(default_factory=dict)
    phase_timings: dict[str, float] = field(default_factory=dict)

    # ==========================================================================
    # CONTROL FLAGS
    # ==========================================================================
    should_stop: bool = False
    pause_requested: bool = False

    def __post_init__(self):
        """Initialize context with defaults."""
        if not self.scan_id:
            self.scan_id = f"SCAN-{uuid4().hex[:12]}"
        if not self.started_at:
            self.started_at = datetime.utcnow().isoformat()

    def mark_phase_complete(self, phase_name: str, result: Any = None, duration: float = 0.0) -> None:
        """Mark a phase as complete."""
        self.completed_phases.append(phase_name)
        if result is not None:
            self.phase_results[phase_name] = result
        self.phase_timings[phase_name] = duration

    def get_phase_result(self, phase_name: str) -> Any:
        """Get result from a completed phase."""
        return self.phase_results.get(phase_name)

    def add_finding(self, finding: Any) -> None:
        """Add a finding to the context."""
        self.findings.append(finding)

    def add_findings(self, findings: list[Any]) -> None:
        """Add multiple findings to the context."""
        self.findings.extend(findings)

    def add_endpoint(self, endpoint: str) -> None:
        """Add a discovered endpoint."""
        if endpoint not in self.endpoints:
            self.endpoints.append(endpoint)

    def add_endpoints(self, endpoints: list[str]) -> None:
        """Add multiple endpoints."""
        for ep in endpoints:
            self.add_endpoint(ep)

    def request(self) -> None:
        """Increment request counter."""
        self.requests_made += 1

    def error(self) -> None:
        """Increment error counter."""
        self.errors_count += 1

    def stop(self) -> None:
        """Request pipeline stop."""
        self.should_stop = True

    def pause(self) -> None:
        """Request pipeline pause."""
        self.pause_requested = True

    def resume(self) -> None:
        """Resume paused pipeline."""
        self.pause_requested = False

    def to_dict(self) -> dict[str, Any]:
        """Convert context to dictionary."""
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "target_host": self.target_host,
            "started_at": self.started_at,
            "scan_mode": self.scan_mode,
            "is_authenticated": self.is_authenticated,
            "endpoints_count": len(self.endpoints),
            "findings_count": len(self.findings),
            "requests_made": self.requests_made,
            "errors_count": self.errors_count,
            "completed_phases": self.completed_phases,
            "phase_timings": self.phase_timings,
            "tech_stack": self.tech_stack,
            "waf_detected": self.waf_detected,
        }


# =============================================================================
# PHASE RESULT
# =============================================================================

@dataclass
class PhaseResult:
    """Result of a pipeline phase execution."""

    phase_name: str
    status: PhaseStatus
    duration_seconds: float = 0.0
    findings_count: int = 0
    endpoints_discovered: int = 0
    error_message: str = ""
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        """Check if phase completed successfully."""
        return self.status == PhaseStatus.COMPLETED

    @property
    def failed(self) -> bool:
        """Check if phase failed."""
        return self.status == PhaseStatus.FAILED

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "phase_name": self.phase_name,
            "status": self.status.name,
            "duration_seconds": self.duration_seconds,
            "findings_count": self.findings_count,
            "endpoints_discovered": self.endpoints_discovered,
            "error_message": self.error_message,
            "data": self.data,
        }


# =============================================================================
# PHASE BASE CLASS
# =============================================================================

class Phase(ABC):
    """
    Abstract base class for pipeline phases.

    Each phase:
    - Receives a ScanContext
    - Performs its work
    - Returns a PhaseResult
    - May modify the context
    """

    def __init__(self, name: str = ""):
        self.name = name or self.__class__.__name__
        self.status = PhaseStatus.PENDING
        self._start_time: float = 0.0
        self._end_time: float = 0.0

    @abstractmethod
    async def execute(self, context: ScanContext) -> PhaseResult:
        """
        Execute the phase.

        Args:
            context: The scan context to read from and write to

        Returns:
            PhaseResult with status and metrics
        """
        pass

    async def run(self, context: ScanContext) -> PhaseResult:
        """
        Run the phase with timing and error handling.

        This is the public entry point that wraps execute().
        """
        self._start_time = time.time()
        self.status = PhaseStatus.RUNNING

        logger.info(f"[Pipeline] Starting phase: {self.name}")

        try:
            # Check if we should skip
            if context.should_stop:
                self.status = PhaseStatus.CANCELLED
                return PhaseResult(
                    phase_name=self.name,
                    status=PhaseStatus.CANCELLED,
                    error_message="Pipeline cancelled",
                )

            # Handle pause
            while context.pause_requested:
                await asyncio.sleep(1.0)

            # Execute the phase
            result = await self.execute(context)

            self._end_time = time.time()
            result.duration_seconds = self._end_time - self._start_time

            # Update status
            self.status = result.status

            # Mark phase complete in context
            context.mark_phase_complete(
                self.name,
                result=result.data,
                duration=result.duration_seconds,
            )

            logger.info(
                f"[Pipeline] Phase {self.name} completed in {result.duration_seconds:.2f}s "
                f"(status={result.status.name})"
            )

            return result

        except Exception as e:
            self._end_time = time.time()
            self.status = PhaseStatus.FAILED

            logger.error(f"[Pipeline] Phase {self.name} failed: {e}")

            return PhaseResult(
                phase_name=self.name,
                status=PhaseStatus.FAILED,
                duration_seconds=self._end_time - self._start_time,
                error_message=str(e),
            )

    @property
    def duration(self) -> float:
        """Get phase duration in seconds."""
        if self._end_time > 0:
            return self._end_time - self._start_time
        elif self._start_time > 0:
            return time.time() - self._start_time
        return 0.0

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name} status={self.status.name}>"


# =============================================================================
# PIPELINE
# =============================================================================

@dataclass
class PipelineResult:
    """Result of a complete pipeline execution."""

    scan_id: str
    status: PipelineStatus
    total_duration_seconds: float = 0.0
    phases_completed: int = 0
    phases_failed: int = 0
    total_findings: int = 0
    phase_results: list[PhaseResult] = field(default_factory=list)
    error_message: str = ""
    context: Optional[ScanContext] = None

    @property
    def success(self) -> bool:
        """Check if pipeline completed successfully."""
        return self.status == PipelineStatus.COMPLETED and self.phases_failed == 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "status": self.status.name,
            "total_duration_seconds": self.total_duration_seconds,
            "phases_completed": self.phases_completed,
            "phases_failed": self.phases_failed,
            "total_findings": self.total_findings,
            "phase_results": [pr.to_dict() for pr in self.phase_results],
            "error_message": self.error_message,
        }


class ScanPipeline:
    """
    Composable scan pipeline.

    Usage:
        pipeline = (
            ScanPipeline()
            .add_phase(DiscoveryPhase())
            .add_phase(AuthAcquisitionPhase())
            .add_phase(TechIntelligencePhase())
            .add_phase(ModuleExecutionPhase(scanners))
            .add_phase(PostProcessingPhase())
            .add_phase(ValidationPhase())
            .add_phase(ReportingPhase())
        )

        result = await pipeline.execute(context)
    """

    def __init__(self, name: str = "ScanPipeline"):
        self.name = name
        self.phases: list[Phase] = []
        self.status = PipelineStatus.IDLE
        self._start_time: float = 0.0
        self._end_time: float = 0.0
        self._on_phase_complete: Optional[Callable[[Phase, PhaseResult], None]] = None
        self._on_phase_error: Optional[Callable[[Phase, Exception], None]] = None

    def add_phase(self, phase: Phase) -> "ScanPipeline":
        """Add a phase to the pipeline."""
        self.phases.append(phase)
        return self

    def remove_phase(self, phase_name: str) -> "ScanPipeline":
        """Remove a phase by name."""
        self.phases = [p for p in self.phases if p.name != phase_name]
        return self

    def insert_phase(self, index: int, phase: Phase) -> "ScanPipeline":
        """Insert a phase at a specific index."""
        self.phases.insert(index, phase)
        return self

    def on_phase_complete(self, callback: Callable[[Phase, PhaseResult], None]) -> "ScanPipeline":
        """Set callback for phase completion."""
        self._on_phase_complete = callback
        return self

    def on_phase_error(self, callback: Callable[[Phase, Exception], None]) -> "ScanPipeline":
        """Set callback for phase errors."""
        self._on_phase_error = callback
        return self

    async def execute(self, context: ScanContext) -> PipelineResult:
        """
        Execute all phases in sequence.

        Args:
            context: The scan context

        Returns:
            PipelineResult with overall status and all phase results
        """
        self._start_time = time.time()
        self.status = PipelineStatus.RUNNING

        phase_results: list[PhaseResult] = []
        phases_completed = 0
        phases_failed = 0

        logger.info(f"[Pipeline] Starting {self.name} with {len(self.phases)} phases")

        try:
            for phase in self.phases:
                # Check for stop/cancel
                if context.should_stop:
                    self.status = PipelineStatus.CANCELLED
                    break

                # Run the phase
                result = await phase.run(context)
                phase_results.append(result)

                # Track results
                if result.success:
                    phases_completed += 1
                    if self._on_phase_complete:
                        self._on_phase_complete(phase, result)
                elif result.failed:
                    phases_failed += 1
                    if self._on_phase_error:
                        self._on_phase_error(phase, Exception(result.error_message))

                    # Optionally stop on failure
                    if context.config.get("stop_on_phase_failure", False):
                        context.stop()
                        break

            self._end_time = time.time()

            # Determine final status
            if context.should_stop:
                self.status = PipelineStatus.CANCELLED
            elif phases_failed > 0:
                self.status = PipelineStatus.FAILED
            else:
                self.status = PipelineStatus.COMPLETED

            logger.info(
                f"[Pipeline] {self.name} completed: "
                f"{phases_completed}/{len(self.phases)} phases, "
                f"{len(context.findings)} findings, "
                f"{self._end_time - self._start_time:.2f}s"
            )

            return PipelineResult(
                scan_id=context.scan_id,
                status=self.status,
                total_duration_seconds=self._end_time - self._start_time,
                phases_completed=phases_completed,
                phases_failed=phases_failed,
                total_findings=len(context.findings),
                phase_results=phase_results,
                context=context,
            )

        except Exception as e:
            self._end_time = time.time()
            self.status = PipelineStatus.FAILED

            logger.error(f"[Pipeline] {self.name} failed: {e}")

            return PipelineResult(
                scan_id=context.scan_id,
                status=PipelineStatus.FAILED,
                total_duration_seconds=self._end_time - self._start_time,
                phases_completed=phases_completed,
                phases_failed=phases_failed + 1,
                total_findings=len(context.findings),
                phase_results=phase_results,
                error_message=str(e),
                context=context,
            )

    @property
    def duration(self) -> float:
        """Get pipeline duration in seconds."""
        if self._end_time > 0:
            return self._end_time - self._start_time
        elif self._start_time > 0:
            return time.time() - self._start_time
        return 0.0

    def __repr__(self) -> str:
        return f"<ScanPipeline name={self.name} phases={len(self.phases)} status={self.status.name}>"


# =============================================================================
# PHASE UTILITIES
# =============================================================================

class ConditionalPhase(Phase):
    """
    Phase that only executes if a condition is met.

    Usage:
        phase = ConditionalPhase(
            inner_phase=AuthAcquisitionPhase(),
            condition=lambda ctx: ctx.config.get("auth_required", False)
        )
    """

    def __init__(
        self,
        inner_phase: Phase,
        condition: Callable[[ScanContext], bool],
        name: str = "",
    ):
        super().__init__(name or f"Conditional({inner_phase.name})")
        self.inner_phase = inner_phase
        self.condition = condition

    async def execute(self, context: ScanContext) -> PhaseResult:
        """Execute inner phase if condition is met."""
        if self.condition(context):
            return await self.inner_phase.execute(context)
        else:
            logger.info(f"[Pipeline] Skipping phase {self.inner_phase.name} (condition not met)")
            return PhaseResult(
                phase_name=self.name,
                status=PhaseStatus.SKIPPED,
            )


class ParallelPhase(Phase):
    """
    Phase that runs multiple phases in parallel.

    Usage:
        phase = ParallelPhase([
            Phase1(),
            Phase2(),
            Phase3(),
        ])
    """

    def __init__(self, phases: list[Phase], name: str = "ParallelPhase"):
        super().__init__(name)
        self.inner_phases = phases

    async def execute(self, context: ScanContext) -> PhaseResult:
        """Execute all inner phases in parallel."""
        tasks = [phase.run(context) for phase in self.inner_phases]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate results
        successful = 0
        failed = 0
        total_findings = 0

        for result in results:
            if isinstance(result, Exception):
                failed += 1
            elif isinstance(result, PhaseResult):
                if result.success:
                    successful += 1
                else:
                    failed += 1
                total_findings += result.findings_count

        status = PhaseStatus.COMPLETED if failed == 0 else PhaseStatus.FAILED

        return PhaseResult(
            phase_name=self.name,
            status=status,
            findings_count=total_findings,
            data={
                "successful": successful,
                "failed": failed,
                "total": len(self.inner_phases),
            },
        )


class RetryPhase(Phase):
    """
    Phase that retries on failure.

    Usage:
        phase = RetryPhase(
            inner_phase=FlakeyPhase(),
            max_retries=3,
            delay_seconds=5.0,
        )
    """

    def __init__(
        self,
        inner_phase: Phase,
        max_retries: int = 3,
        delay_seconds: float = 5.0,
        name: str = "",
    ):
        super().__init__(name or f"Retry({inner_phase.name})")
        self.inner_phase = inner_phase
        self.max_retries = max_retries
        self.delay_seconds = delay_seconds

    async def execute(self, context: ScanContext) -> PhaseResult:
        """Execute inner phase with retries."""
        last_result = None

        for attempt in range(self.max_retries + 1):
            result = await self.inner_phase.execute(context)
            last_result = result

            if result.success:
                return result

            if attempt < self.max_retries:
                logger.warning(
                    f"[Pipeline] Phase {self.inner_phase.name} failed, "
                    f"retrying in {self.delay_seconds}s ({attempt + 1}/{self.max_retries})"
                )
                await asyncio.sleep(self.delay_seconds)

        return last_result or PhaseResult(
            phase_name=self.name,
            status=PhaseStatus.FAILED,
            error_message=f"Failed after {self.max_retries} retries",
        )
