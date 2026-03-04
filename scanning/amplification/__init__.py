"""
Amplification System for PATHFINDER AI Scanner.

This module implements adaptive depth and cross-finding amplification:
- AmplificationAction: Actions triggered by findings
- AmplificationGuardrails: Safety limits for feedback loops
- AmplificationTracker: State tracking for guardrail enforcement
- ScanAmplifier: Core amplification engine

Philosophy: "When you find something, dig deeper."
"""

from .models import (
    AmplificationAction,
    GuardrailBlockReason,
    SuspensionLevel,
    ProgressMetrics,
    AmplificationGuardrails,
    ActionFingerprint,
)
from .tracker import AmplificationTracker
from .amplifier import ScanAmplifier

__all__ = [
    # Models
    "AmplificationAction",
    "GuardrailBlockReason",
    "SuspensionLevel",
    "ProgressMetrics",
    "AmplificationGuardrails",
    "ActionFingerprint",
    # Core classes
    "AmplificationTracker",
    "ScanAmplifier",
]
