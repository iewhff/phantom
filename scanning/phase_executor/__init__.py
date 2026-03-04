"""
Phase Executor Module - Scan Phase Management.

Provides components for managing scan phases:
- PhaseInfo: Phase metadata and configuration
- PhaseTracker: Phase timing and progress tracking
- Phase constants and utilities

Extracted from full_scanner.py for modularization.
"""

from .phases import (
    # Enums
    PhaseCategory,
    # Dataclass
    PhaseInfo,
    # Individual phases
    PHASE_0,
    PHASE_0_5,
    PHASE_0_6,
    PHASE_0_7,
    PHASE_0_75,
    PHASE_0_8,
    PHASE_0_9,
    PHASE_0_95,
    PHASE_1,
    PHASE_1_5,
    PHASE_2,
    PHASE_2_5_LINUX,
    PHASE_2_5_AUTH,
    PHASE_2_55,
    PHASE_2_56,
    PHASE_2_6,
    PHASE_2_7,
    PHASE_2_9,
    PHASE_3,
    PHASE_3_5,
    PHASE_4_1,
    PHASE_4_2,
    PHASE_4_3,
    PHASE_4_35,
    PHASE_4_45,
    PHASE_4_46,
    PHASE_4_47,
    PHASE_4_49,
    PHASE_4_5,
    PHASE_4_52,
    PHASE_4_53,
    PHASE_4_55,
    PHASE_4_56,
    PHASE_4_6,
    PHASE_4_65,
    PHASE_4_7,
    PHASE_5,
    PHASE_5_1,
    PHASE_5_2,
    PHASE_5_5,
    PHASE_6_5,
    # Collections
    ALL_PHASES,
    PHASES_BY_ID,
    PHASES_BY_CATEGORY,
    # Functions
    get_phase,
    get_phases_for_category,
    get_phase_count,
    get_typical_scan_duration,
)
from .tracker import (
    # Protocols
    EvidenceEngineProtocol,
    ProgressCallbackProtocol,
    # Classes
    PhaseExecution,
    PhaseTracker,
    PhaseContext,
    # Functions
    phase_context,
)

__all__ = [
    # Enums
    "PhaseCategory",
    # Dataclasses
    "PhaseInfo",
    "PhaseExecution",
    # Protocols
    "EvidenceEngineProtocol",
    "ProgressCallbackProtocol",
    # Classes
    "PhaseTracker",
    "PhaseContext",
    # Phase constants
    "PHASE_0",
    "PHASE_0_5",
    "PHASE_0_6",
    "PHASE_0_7",
    "PHASE_0_75",
    "PHASE_0_8",
    "PHASE_0_9",
    "PHASE_0_95",
    "PHASE_1",
    "PHASE_1_5",
    "PHASE_2",
    "PHASE_2_5_LINUX",
    "PHASE_2_5_AUTH",
    "PHASE_2_55",
    "PHASE_2_56",
    "PHASE_2_6",
    "PHASE_2_7",
    "PHASE_2_9",
    "PHASE_3",
    "PHASE_3_5",
    "PHASE_4_1",
    "PHASE_4_2",
    "PHASE_4_3",
    "PHASE_4_35",
    "PHASE_4_45",
    "PHASE_4_46",
    "PHASE_4_47",
    "PHASE_4_49",
    "PHASE_4_5",
    "PHASE_4_52",
    "PHASE_4_53",
    "PHASE_4_55",
    "PHASE_4_56",
    "PHASE_4_6",
    "PHASE_4_65",
    "PHASE_4_7",
    "PHASE_5",
    "PHASE_5_1",
    "PHASE_5_2",
    "PHASE_5_5",
    "PHASE_6_5",
    # Collections
    "ALL_PHASES",
    "PHASES_BY_ID",
    "PHASES_BY_CATEGORY",
    # Functions
    "get_phase",
    "get_phases_for_category",
    "get_phase_count",
    "get_typical_scan_duration",
    "phase_context",
]
