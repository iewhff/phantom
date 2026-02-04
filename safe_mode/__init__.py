"""
Safe Mode Module - Legal and non-destructive penetration testing.

This module provides:
- Non-destructive payload generation
- Evidence-only proof of concepts  
- Safe scanning configurations
- Compliance-ready testing

Features:
- Non-destructive payloads (SELECT 1 instead of DROP TABLE)
- Evidence-only PoCs (prove vulnerability without exploitation)
- Zero operational risk
- Legal compliance ready
- Audit trail for all operations
- Configurable safety levels
"""

from safe_mode.safe_scanner import (
    SafetyLevel,
    SafePayload,
    SafeScanner,
)

from safe_mode.evidence_collector import (
    Evidence,
    EvidenceType,
    EvidenceStrength,
    EvidenceCollector,
)

from safe_mode.safe_payloads import (
    SafePayloadGenerator,
    PayloadCategory,
    PayloadPair,
)

__all__ = [
    # Safe Scanner
    "SafetyLevel",
    "SafePayload",
    "SafeScanner",
    
    # Evidence Collector
    "Evidence",
    "EvidenceType",
    "EvidenceStrength",
    "EvidenceCollector",
    
    # Payload Generator
    "SafePayloadGenerator",
    "PayloadCategory",
    "PayloadPair",
]
