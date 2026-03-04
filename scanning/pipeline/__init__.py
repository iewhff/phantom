"""
PHANTOM AI Scan Pipeline Module.

This module provides a composable pipeline architecture for security scanning.

Components:
- ScanPipeline: Main pipeline orchestrator
- Phase: Abstract base class for pipeline phases
- ScanContext: Shared context passed between phases
- PhaseResult: Result of a phase execution
- PipelineResult: Result of the complete pipeline

Usage:
    from scanning.pipeline import ScanPipeline, ScanContext
    from scanning.pipeline.phases import (
        DiscoveryPhase,
        AuthAcquisitionPhase,
        TechIntelligencePhase,
        ModuleExecutionPhase,
        ValidationPhase,
        ReportingPhase,
    )

    # Create pipeline
    pipeline = (
        ScanPipeline()
        .add_phase(DiscoveryPhase())
        .add_phase(AuthAcquisitionPhase())
        .add_phase(TechIntelligencePhase())
        .add_phase(ModuleExecutionPhase(scanners))
        .add_phase(ValidationPhase())
        .add_phase(ReportingPhase())
    )

    # Create context
    context = ScanContext(
        target_url="https://example.com",
        scan_mode="full",
    )

    # Execute
    result = await pipeline.execute(context)

Author: PHANTOM AI
Version: 2.0.0
"""

from scanning.pipeline.base import (
    # Enums
    PhaseStatus,
    PipelineStatus,
    # Context
    ScanContext,
    # Results
    PhaseResult,
    PipelineResult,
    # Base classes
    Phase,
    ScanPipeline,
    # Utilities
    ConditionalPhase,
    ParallelPhase,
    RetryPhase,
)

__all__ = [
    # Enums
    "PhaseStatus",
    "PipelineStatus",
    # Context
    "ScanContext",
    # Results
    "PhaseResult",
    "PipelineResult",
    # Base classes
    "Phase",
    "ScanPipeline",
    # Utilities
    "ConditionalPhase",
    "ParallelPhase",
    "RetryPhase",
]
