"""
Pipeline Phases Module.

Contains implementations of all scan pipeline phases:
- DiscoveryPhase: Target discovery and endpoint enumeration (Phase 0-0.9)
- AuthAcquisitionPhase: Authentication and session management (Phase 2.5-2.9)
- ModuleExecutionPhase: Scanner module orchestration (Phase 3-3.5)
- PostProcessingPhase: Finding analysis and enhancement (Phase 4.x)
- ValidationPhase: False positive elimination (Phase 4.55-5.5)
- ReportingPhase: Metrics and report generation (Phase 6.x)

Author: PHANTOM AI
Version: 2.0.0
"""

from scanning.pipeline.phases.discovery import (
    DiscoveryPhase,
    DiscoveryConfig,
)
from scanning.pipeline.phases.auth import (
    AuthAcquisitionPhase,
    AuthConfig,
)
from scanning.pipeline.phases.execution import (
    ModuleExecutionPhase,
    ExecutionConfig,
)
from scanning.pipeline.phases.post_processing import (
    PostProcessingPhase,
    PostProcessingConfig,
)
from scanning.pipeline.phases.validation import (
    ValidationPhase,
    ValidationConfig,
)
from scanning.pipeline.phases.reporting import (
    ReportingPhase,
    ReportingConfig,
)

__all__ = [
    # Discovery
    "DiscoveryPhase",
    "DiscoveryConfig",
    # Auth
    "AuthAcquisitionPhase",
    "AuthConfig",
    # Execution
    "ModuleExecutionPhase",
    "ExecutionConfig",
    # Post-processing
    "PostProcessingPhase",
    "PostProcessingConfig",
    # Validation
    "ValidationPhase",
    "ValidationConfig",
    # Reporting
    "ReportingPhase",
    "ReportingConfig",
]
