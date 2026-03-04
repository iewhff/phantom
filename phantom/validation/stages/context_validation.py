"""
PHANTOM AI - Context Validation Stage
=======================================

Extracted from phantom/validation_pipeline.py (lines 2012-2174).

Stage 5: Context Validation
Validates finding in application context.
"""

import re
import logging
import time
from typing import Dict, List, Any, Tuple, Optional

from phantom.validation.models import (
    ValidationStage,
    ValidationResult,
    ValidationConfig,
    RawFinding,
    StageResult,
    VulnerabilityType,
    CONTEXT_BOOST_QUALITY_EVIDENCE,
    CONTEXT_BOOST_SQLI_EXFIL,
    CONTEXT_BOOST_XSS_EXEC,
    CONTEXT_BOOST_CMDI_EXEC,
    CONTEXT_BOOST_SSRF_INTERNAL,
    CONTEXT_BOOST_IDOR_STRONG,
    CONTEXT_BOOST_IDOR_WEAK,
    CONTEXT_BOOST_BIZLOGIC_STRONG,
    CONTEXT_BOOST_BIZLOGIC_WEAK,
    CONTEXT_BOOST_CREATIVE_EXPLOIT,
    CONTEXT_BOOST_SESSION_ABUSE,
    CONTEXT_BOOST_STATUS_EVIDENCE,
    CONTEXT_PENALTY_NO_EVIDENCE,
    CONFIDENCE_BOOST_USER_DATA,
    CONFIDENCE_BOOST_AUTHZ_DATA,
    CONFIDENCE_PENALTY_UNCERTAINTY,
    MAX_IDOR_BOOST,
    MAX_BEHAVIOR_BOOST,
    PROOF_BOOST_CAN_REPEAT,
    PROOF_BOOST_CAN_MUTATE,
    PROOF_BOOST_CAN_ESCALATE,
    PROOF_BOOST_CAN_CHAIN,
    PROOF_BOOST_DATA_EXTRACTION,
    PROOF_BOOST_STATE_CHANGE,
    PROOF_BOOST_PRIVILEGE_ESCALATION,
    PROOF_BOOST_DEMONSTRATED,
)
from phantom.validation.stages.safe_replay import _BEHAVIOR_BASED_MODULES

logger = logging.getLogger("phantom.validation.stages.context_validation")


class ContextValidationStage:
    """
    Stage 5: Context Validation
    Validates finding in application context.
    """

    def __init__(self, config: ValidationConfig) -> None:
        self.config = config

    def validate(self, finding: RawFinding) -> StageResult:
        """Validate in context."""
        start = time.time()

        confidence_boost = 0.0
        validations = []

        # Check evidence quality
        if finding.evidence and len(finding.evidence) > 20:
            confidence_boost += CONTEXT_BOOST_QUALITY_EVIDENCE
            validations.append("has_quality_evidence")

        # Check for specific exploitation indicators
        if finding.vulnerability_type == VulnerabilityType.SQLI:
            if any(x in (finding.evidence or "") for x in ["root:", "admin", "password"]):
                confidence_boost += CONTEXT_BOOST_SQLI_EXFIL
                validations.append("data_exfiltration_indicator")

        elif finding.vulnerability_type == VulnerabilityType.XSS:
            if "alert(" in (finding.response or ""):
                confidence_boost += CONTEXT_BOOST_XSS_EXEC
                validations.append("xss_execution_indicator")

        elif finding.vulnerability_type == VulnerabilityType.CMDI:
            if any(x in (finding.evidence or "") for x in ["uid=", "root:", "whoami"]):
                confidence_boost += CONTEXT_BOOST_CMDI_EXEC
                validations.append("command_execution_indicator")

        elif finding.vulnerability_type == VulnerabilityType.SSRF:
            if any(x in (finding.evidence or "") for x in ["169.254", "localhost", "127.0.0.1"]):
                confidence_boost += CONTEXT_BOOST_SSRF_INTERNAL
                validations.append("internal_access_indicator")

        # IDOR / Access Control validation
        # P1-5 FIX: Require MULTIPLE indicators from same category for boost
        elif finding.vulnerability_type in [VulnerabilityType.IDOR, VulnerabilityType.AUTHORIZATION]:
            evidence_text = finding.evidence or ""
            response_text = finding.response or ""
            combined_text = f"{evidence_text} {response_text}".lower()

            # Check for IDOR indicators - require at least 2 matches
            # FIX 2026-02-12: Expanded indicator patterns for better scanner coverage
            idor_indicators = [
                "different user", "other user", "unauthorized",
                "access to", "object id", "id manipulation",
                "modified id", "original id",
                # Additional patterns for better coverage
                "victim", "attacker", "target user", "accessed",
                "exposed", "data of", "record of", "user data",
                "profile of", "user_id=", "account_id=", "id=",
                "horizontal", "vertical", "privilege", "escalat",
            ]
            idor_matches = sum(1 for x in idor_indicators if x in combined_text)
            if idor_matches >= 2:  # Require 2+ indicators for boost
                confidence_boost += CONTEXT_BOOST_IDOR_STRONG
                validations.append(f"idor_access_indicator({idor_matches}_matches)")
            elif idor_matches == 1:
                confidence_boost += CONTEXT_BOOST_IDOR_WEAK
                validations.append("idor_weak_indicator")

            # Check for user data exposure - require 2+ matches
            user_data_indicators = [
                "email", "username", "user_id", "profile",
                "account", "address", "phone"
            ]
            user_matches = sum(1 for x in user_data_indicators if x in combined_text)
            if user_matches >= 2:  # Corroboration required
                confidence_boost += CONFIDENCE_BOOST_USER_DATA
                validations.append(f"user_data_exposure({user_matches}_matches)")

            # Check for role/permission exposure - require 2+ matches
            authz_indicators = [
                "admin", "role", "permission", "privilege",
                "can_delete", "can_edit", "access_level"
            ]
            authz_matches = sum(1 for x in authz_indicators if x in combined_text)
            if authz_matches >= 2:  # Corroboration required
                confidence_boost += CONFIDENCE_BOOST_AUTHZ_DATA
                validations.append(f"authorization_data_exposure({authz_matches}_matches)")

            # Cap total IDOR/authz boost to prevent over-stacking
            if confidence_boost > MAX_IDOR_BOOST:
                confidence_boost = MAX_IDOR_BOOST

        # Business logic / Creative exploiter / Session abuse validation
        # P1-5/P2-6 FIX: Require MULTIPLE indicators from same category
        elif finding.module_name in _BEHAVIOR_BASED_MODULES:
            evidence_text = finding.evidence or ""
            combined_text = f"{evidence_text} {finding.response or ''}".lower()

            # Business logic: check for mutation indicators - require 2+
            biz_indicators = [
                "quantity", "price", "total", "amount", "negative", "zero",
                "bypass", "immutab", "accepted", "tampered", "modified",
            ]
            biz_matches = sum(1 for x in biz_indicators if x in combined_text)
            if biz_matches >= 2:
                confidence_boost += CONTEXT_BOOST_BIZLOGIC_STRONG
                validations.append(f"business_logic_indicator({biz_matches}_matches)")
            elif biz_matches == 1:
                confidence_boost += CONTEXT_BOOST_BIZLOGIC_WEAK
                validations.append("business_logic_weak")

            # Creative exploiter: check for server-side processing - require 2+
            creative_indicators = [
                "length_change", "server_error", "status_bypass", "echo",
                "new_keys", "baseline", "mutated", "cross-context",
                "no auth", "admin endpoint", "unauth",
            ]
            creative_matches = sum(1 for x in creative_indicators if x in combined_text)
            if creative_matches >= 2:
                confidence_boost += CONTEXT_BOOST_CREATIVE_EXPLOIT
                validations.append(f"creative_exploit_indicator({creative_matches}_matches)")

            # Session abuse: check for token/session indicators - require 2+
            session_indicators = [
                "jwt", "token", "logout", "replay", "alg:none",
                "privilege", "escalat", "forged", "expired",
            ]
            session_matches = sum(1 for x in session_indicators if x in combined_text)
            if session_matches >= 2:
                confidence_boost += CONTEXT_BOOST_SESSION_ABUSE
                validations.append(f"session_abuse_indicator({session_matches}_matches)")

            # HTTP status only boosts if combined with other evidence
            has_status_evidence = any(x in combined_text for x in ["-> http 200", "-> http 201", "-> 200", "-> 201"])
            if has_status_evidence and (biz_matches + creative_matches + session_matches >= 1):
                confidence_boost += CONTEXT_BOOST_STATUS_EVIDENCE
                validations.append("server_accepted_mutation")

            # Cap behavior module boost
            if confidence_boost > MAX_BEHAVIOR_BOOST:
                confidence_boost = MAX_BEHAVIOR_BOOST

        if validations:
            return StageResult(
                stage=ValidationStage.CONTEXT_VALIDATION,
                result=ValidationResult.PASSED,
                confidence_delta=confidence_boost,
                message="Context validation passed",
                evidence=f"Validations: {', '.join(validations)}",
                duration_ms=(time.time() - start) * 1000,
            )
        else:
            # THEME-10 FIX: INCONCLUSIVE should penalize confidence
            return StageResult(
                stage=ValidationStage.CONTEXT_VALIDATION,
                result=ValidationResult.INCONCLUSIVE,
                confidence_delta=CONFIDENCE_PENALTY_UNCERTAINTY,
                message="No additional context validation (uncertainty penalty applied)",
                duration_ms=(time.time() - start) * 1000,
            )
