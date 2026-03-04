"""
PHANTOM AI - 6-Stage Validation Pipeline (Refactored)

Split from phantom/validation_pipeline.py into:
- models.py: Enums, dataclasses, constants
- pipeline.py: ValidationPipeline orchestrator
- stages/: Individual validation stage implementations
- utils/: PatternMatcher, SafePayloadGenerator

All public symbols are re-exported here for backward compatibility.
"""

from phantom.validation.models import *  # noqa: F401,F403
from phantom.validation.pipeline import ValidationPipeline, create_raw_finding, validate_findings  # noqa: F401
from phantom.validation.stages import *  # noqa: F401,F403
from phantom.validation.utils import PatternMatcher, SafePayloadGenerator  # noqa: F401

# Full __all__ for backward compatibility with phantom.validation_pipeline
__all__ = [
    # Main classes
    "ValidationPipeline",
    "ValidationConfig",
    "RawFinding",
    "ValidatedFinding",
    "StageResult",
    # Enums
    "ValidationStage",
    "ValidationResult",
    "VulnerabilityType",
    "FindingConfidence",
    # Stage classes
    "DeduplicationStage",
    "PatternVerificationStage",
    "SafeReplayStage",
    "NegativeControlStage",
    "ContextValidationStage",
    "AIVerificationStage",
    # Utilities
    "PatternMatcher",
    "SafePayloadGenerator",
    "create_raw_finding",
    "validate_findings",
    "is_static_asset_url",
    # Confidence adjustment constants (M1 fix)
    "CONFIDENCE_BOOST_PATTERN_MATCH",
    "CONFIDENCE_BOOST_BLIND_VULN",
    "CONFIDENCE_BOOST_BEHAVIOR_EVIDENCE",
    "CONFIDENCE_BOOST_NEGATIVE_CONTROL",
    "CONFIDENCE_BOOST_SQL_ERROR",
    "CONFIDENCE_BOOST_CONTEXT_QUALITY",
    "CONFIDENCE_BOOST_IDOR_INDICATOR",
    "CONFIDENCE_BOOST_USER_DATA",
    "CONFIDENCE_BOOST_AUTHZ_DATA",
    "CONFIDENCE_BOOST_SAFE_REPLAY",
    "CONFIDENCE_PENALTY_MISSING_DATA",
    "CONFIDENCE_PENALTY_UNCERTAINTY",
    "CONFIDENCE_PENALTY_IDENTICAL_RESPONSE",
    "CONFIDENCE_PENALTY_SIMILAR_RESPONSE",
    "CONFIDENCE_PENALTY_IDENTICAL_BASELINE",
    # Threshold constants
    "TOKEN_OVERLAP_THRESHOLD",
    "SIGNIFICANT_NEW_TOKENS_PERCENT",
    "LENGTH_SIMILARITY_THRESHOLD",
    "SIGNIFICANT_NEW_TOKENS_MIN",
    "MAX_UNCERTAINTY_PENALTY",
    "DEFAULT_RAW_CONFIDENCE",
    "MAX_IDOR_BOOST",
    "MAX_BEHAVIOR_BOOST",
    # Context validation constants
    "CONTEXT_BOOST_QUALITY_EVIDENCE",
    "CONTEXT_BOOST_SQLI_EXFIL",
    "CONTEXT_BOOST_XSS_EXEC",
    "CONTEXT_BOOST_CMDI_EXEC",
    "CONTEXT_BOOST_SSRF_INTERNAL",
    "CONTEXT_BOOST_IDOR_STRONG",
    "CONTEXT_BOOST_IDOR_WEAK",
    "CONTEXT_BOOST_BIZLOGIC_STRONG",
    "CONTEXT_BOOST_BIZLOGIC_WEAK",
    "CONTEXT_BOOST_CREATIVE_EXPLOIT",
    "CONTEXT_BOOST_SESSION_ABUSE",
    "CONTEXT_BOOST_STATUS_EVIDENCE",
    "CONTEXT_PENALTY_NO_EVIDENCE",
    # Proof engine constants
    "PROOF_BOOST_CAN_REPEAT",
    "PROOF_BOOST_CAN_MUTATE",
    "PROOF_BOOST_CAN_ESCALATE",
    "PROOF_BOOST_CAN_CHAIN",
    "PROOF_BOOST_DATA_EXTRACTION",
    "PROOF_BOOST_STATE_CHANGE",
    "PROOF_BOOST_PRIVILEGE_ESCALATION",
    "PROOF_BOOST_DEMONSTRATED",
]
