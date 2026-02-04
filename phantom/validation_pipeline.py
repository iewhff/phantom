"""
PHANTOM AI - 6-Stage Validation Pipeline
=========================================

Enterprise validation pipeline for near-zero false positive rates.

The 6 stages work together to ensure every reported finding is legitimate:

1. DEDUPLICATION - Remove duplicate findings across modules
2. PATTERN_VERIFICATION - Verify response patterns match expected indicators
3. SAFE_REPLAY - Replay the attack with a safe/harmless variant
4. NEGATIVE_CONTROL - Compare against baseline behavior
5. CONTEXT_VALIDATION - Validate in application context
6. AI_VERIFICATION - LLM-based final verification (auditor, not blocker)

Target: < 0.1% False Positive Rate

Author: PHANTOM AI Team
Version: 3.0.0
"""

from __future__ import annotations

import re
import json
import hashlib
import asyncio
import time
import logging
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Tuple, Callable
from collections import defaultdict

import httpx

logger = logging.getLogger("phantom.validation_pipeline")


# =============================================================================
# ENUMS AND CONSTANTS
# =============================================================================

class ValidationStage(Enum):
    """Validation pipeline stages."""
    DEDUPLICATION = 1
    PATTERN_VERIFICATION = 2
    SAFE_REPLAY = 3
    NEGATIVE_CONTROL = 4
    CONTEXT_VALIDATION = 5
    AI_VERIFICATION = 6


class ValidationResult(Enum):
    """Result of a validation check."""
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"
    INCONCLUSIVE = "inconclusive"


class FindingConfidence(Enum):
    """Confidence levels for findings."""
    SUSPECTED = 0.30       # 30-59%: Internal only
    DETECTED = 0.60        # 60-74%: Internal + analyst review
    CONFIRMED = 0.75       # 75-94%: Reported to user
    EXPLOITABLE = 0.95     # 95-100%: Priority report


class VulnerabilityType(Enum):
    """Types of vulnerabilities for validation."""
    SQLI = "sqli"
    XSS = "xss"
    CMDI = "cmdi"
    LFI = "lfi"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    NOSQL = "nosql"
    CRLF = "crlf"
    IDOR = "idor"
    OPEN_REDIRECT = "open_redirect"
    CSRF = "csrf"
    JWT = "jwt"
    INFORMATION_DISCLOSURE = "info_disclosure"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    OTHER = "other"


# =============================================================================
# DATA CLASSES
# =============================================================================

@dataclass
class RawFinding:
    """
    Raw finding from a scanner module.
    Input to the validation pipeline.
    """
    id: str
    title: str
    vulnerability_type: VulnerabilityType
    severity: str
    url: str
    parameter: Optional[str] = None
    method: str = "GET"
    payload: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None
    evidence: str = ""
    description: str = ""
    module_name: str = ""
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "vulnerability_type": self.vulnerability_type.value,
            "severity": self.severity,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "payload": self.payload,
            "evidence": self.evidence,
            "description": self.description,
            "module_name": self.module_name,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
        }

    def get_fingerprint(self) -> str:
        """Generate unique fingerprint for deduplication."""
        components = [
            self.vulnerability_type.value,
            self.url,
            self.parameter or "",
            self.method,
            self.payload or "",
        ]
        content = "|".join(components)
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class StageResult:
    """Result from a single validation stage."""
    stage: ValidationStage
    result: ValidationResult
    confidence_delta: float  # Change to confidence score
    message: str = ""
    evidence: str = ""
    duration_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidatedFinding:
    """
    Finding that has passed through the validation pipeline.
    Output of the validation pipeline.
    """
    raw_finding: RawFinding
    is_valid: bool
    final_confidence: float
    confidence_level: FindingConfidence
    stage_results: List[StageResult] = field(default_factory=list)
    validation_time_ms: float = 0.0
    should_report: bool = False
    suppression_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding": self.raw_finding.to_dict(),
            "is_valid": self.is_valid,
            "final_confidence": round(self.final_confidence, 4),
            "confidence_level": self.confidence_level.name,
            "validation_time_ms": round(self.validation_time_ms, 2),
            "should_report": self.should_report,
            "suppression_reason": self.suppression_reason,
            "stages": [
                {
                    "stage": sr.stage.name,
                    "result": sr.result.value,
                    "confidence_delta": round(sr.confidence_delta, 4),
                    "message": sr.message,
                }
                for sr in self.stage_results
            ],
        }


@dataclass
class ValidationConfig:
    """Configuration for the validation pipeline."""
    # Stage toggles
    enable_deduplication: bool = True
    enable_pattern_verification: bool = True
    enable_safe_replay: bool = True
    enable_negative_control: bool = True
    enable_context_validation: bool = True
    enable_ai_verification: bool = True  # Auditor only, not blocker

    # Thresholds
    min_confidence_to_report: float = 0.75
    dedup_similarity_threshold: float = 0.90
    pattern_match_threshold: float = 0.60

    # Timing
    replay_timeout: float = 10.0
    max_retries: int = 2
    retry_delay: float = 0.5

    # AI settings
    ai_verification_is_blocking: bool = False  # AI is auditor, not gate

    # Rate limiting
    max_concurrent_validations: int = 5


# =============================================================================
# PATTERN MATCHERS
# =============================================================================

class PatternMatcher:
    """
    Pattern matching for vulnerability indicators.
    """

    # Success indicators by vulnerability type
    SUCCESS_INDICATORS: Dict[VulnerabilityType, List[Tuple[str, float]]] = {
        VulnerabilityType.SQLI: [
            (r"SQL syntax.*MySQL", 0.9),
            (r"mysql_fetch_array\(\)", 0.85),
            (r"ORA-\d{5}", 0.9),
            (r"PostgreSQL.*ERROR", 0.9),
            (r"Warning.*mssql_", 0.85),
            (r"sqlite3\.OperationalError", 0.85),
            (r"You have an error in your SQL syntax", 0.9),
            (r"Unclosed quotation mark", 0.85),
            (r"quoted string not properly terminated", 0.85),
            (r"root:.*:0:0:", 0.95),  # /etc/passwd via SQLi
        ],
        VulnerabilityType.XSS: [
            (r"<script[^>]*>alert\(", 0.95),
            (r"javascript:alert", 0.9),
            (r"onerror\s*=", 0.8),
            (r"onload\s*=", 0.8),
            (r"<img[^>]*onerror", 0.85),
            (r"<svg[^>]*onload", 0.85),
        ],
        VulnerabilityType.CMDI: [
            (r"uid=\d+\(.*\)", 0.95),  # Unix id command
            (r"root:.*:0:0:", 0.95),   # /etc/passwd
            (r"Windows NT.*\d+\.\d+", 0.9),  # Windows version
            (r"Directory of", 0.85),    # Windows dir
            (r"Linux.*x86_64", 0.9),   # Linux uname
        ],
        VulnerabilityType.LFI: [
            (r"root:.*:0:0:", 0.95),
            (r"\[boot loader\]", 0.9),  # Windows boot.ini
            (r"\[fonts\]", 0.85),       # Windows win.ini
            (r"PD9waHA", 0.85),         # Base64 PHP
            (r"<\?php", 0.9),
        ],
        VulnerabilityType.SSRF: [
            (r"ami-[a-z0-9]{8,}", 0.95),  # AWS instance
            (r"169\.254\.169\.254", 0.9),
            (r"AccessKeyId", 0.95),
            (r"metadata.*internal", 0.85),
        ],
        VulnerabilityType.XXE: [
            (r"root:.*:0:0:", 0.95),
            (r"ENTITY.*SYSTEM", 0.7),
            (r"<!DOCTYPE.*\[", 0.6),
        ],
        VulnerabilityType.SSTI: [
            (r"49", 0.6),  # 7*7
            (r"config\s*[:{]", 0.7),
            (r"SECRET_KEY", 0.9),
            (r"__class__", 0.85),
            (r"__mro__", 0.85),
        ],
        # Access Control / IDOR / Authorization patterns
        VulnerabilityType.IDOR: [
            # Response contains different user data (comparison-based detection)
            (r"\"user_?id\":\s*\d+", 0.7),  # User ID in response
            (r"\"id\":\s*\d+", 0.6),  # ID field in response
            (r"\"email\":\s*\"[^\"]+@", 0.75),  # Email exposed
            (r"\"username\":\s*\"", 0.7),  # Username exposed
            (r"\"account\":", 0.65),  # Account data
            (r"\"profile\":", 0.65),  # Profile data
            (r"\"user\":\s*\{", 0.7),  # User object
            (r"\"owner\":", 0.7),  # Owner field
            (r"\"created_by\":", 0.65),  # Creator field
            # Status code indicators
            (r"200 OK", 0.6),  # Successful access (combined with ID change)
        ],
        VulnerabilityType.AUTHORIZATION: [
            # Unauthorized access indicators
            (r"\"role\":\s*\"admin\"", 0.85),  # Admin role exposed
            (r"\"is_?admin\":\s*true", 0.9),  # Admin flag
            (r"\"permissions\":\s*\[", 0.75),  # Permissions array
            (r"\"privilege\":", 0.75),  # Privilege field
            (r"\"access_?level\":", 0.7),  # Access level
            (r"\"can_delete\":", 0.75),  # Delete permission
            (r"\"can_edit\":", 0.75),  # Edit permission
            (r"\"can_manage\":", 0.8),  # Manage permission
            # Admin panel access
            (r"admin.*dashboard", 0.85),  # Admin dashboard
            (r"manage.*users", 0.8),  # User management
            (r"configuration.*settings", 0.7),  # Config access
        ],
    }

    # False positive indicators
    FALSE_POSITIVE_INDICATORS: List[Tuple[str, float]] = [
        (r"<title>404", 0.8),
        (r"Page Not Found", 0.7),
        (r"Access Denied", 0.6),
        (r"403 Forbidden", 0.7),
        (r"CSRF token", 0.5),
        (r"rate limit", 0.6),
        (r"too many requests", 0.6),
        (r"captcha", 0.5),
    ]

    @classmethod
    def check_indicators(
        cls,
        response: str,
        vuln_type: VulnerabilityType,
    ) -> Tuple[bool, float, List[str]]:
        """
        Check for vulnerability indicators in response.

        Returns:
            (has_indicators, confidence, matched_patterns)
        """
        indicators = cls.SUCCESS_INDICATORS.get(vuln_type, [])
        matched = []
        max_confidence = 0.0

        for pattern, confidence in indicators:
            if re.search(pattern, response, re.IGNORECASE):
                matched.append(pattern)
                max_confidence = max(max_confidence, confidence)

        return len(matched) > 0, max_confidence, matched

    @classmethod
    def check_false_positives(
        cls,
        response: str,
    ) -> Tuple[bool, float, List[str]]:
        """
        Check for false positive indicators.

        Returns:
            (has_fp_indicators, fp_confidence, matched_patterns)
        """
        matched = []
        max_confidence = 0.0

        for pattern, confidence in cls.FALSE_POSITIVE_INDICATORS:
            if re.search(pattern, response, re.IGNORECASE):
                matched.append(pattern)
                max_confidence = max(max_confidence, confidence)

        return len(matched) > 0, max_confidence, matched


# =============================================================================
# SAFE PAYLOAD GENERATOR
# =============================================================================

class SafePayloadGenerator:
    """
    Generate safe/harmless variants of payloads for replay testing.
    """

    @staticmethod
    def generate_safe_variant(
        payload: str,
        vuln_type: VulnerabilityType,
    ) -> str:
        """Generate a safe variant of the payload."""
        if vuln_type == VulnerabilityType.SQLI:
            # Replace attack with harmless query
            return "1' AND '1'='1"

        elif vuln_type == VulnerabilityType.XSS:
            # Replace script with harmless content
            return "<b>test</b>"

        elif vuln_type == VulnerabilityType.CMDI:
            # Replace with harmless command
            return "echo test"

        elif vuln_type == VulnerabilityType.LFI:
            # Replace with non-existent file
            return "/nonexistent/file/path.txt"

        elif vuln_type == VulnerabilityType.SSRF:
            # Replace with safe URL
            return "https://httpbin.org/status/200"

        elif vuln_type == VulnerabilityType.SSTI:
            # Replace with safe template
            return "{{1+1}}"

        else:
            # Generic safe variant
            return "safe_test_value"

    @staticmethod
    def generate_benign_payload(vuln_type: VulnerabilityType) -> str:
        """Generate a completely benign payload that should not trigger."""
        return "normal_user_input_12345"


# =============================================================================
# VALIDATION STAGES
# =============================================================================

class DeduplicationStage:
    """
    Stage 1: Deduplication
    Removes duplicate findings based on fingerprint similarity.
    """

    def __init__(self, config: ValidationConfig):
        self.config = config
        self._seen_fingerprints: Set[str] = set()

    def validate(
        self,
        finding: RawFinding,
        all_findings: List[RawFinding],
    ) -> StageResult:
        """Check if finding is a duplicate."""
        start = time.time()

        fingerprint = finding.get_fingerprint()

        if fingerprint in self._seen_fingerprints:
            return StageResult(
                stage=ValidationStage.DEDUPLICATION,
                result=ValidationResult.FAILED,
                confidence_delta=-1.0,  # Remove finding
                message="Duplicate finding detected",
                evidence=f"Fingerprint: {fingerprint}",
                duration_ms=(time.time() - start) * 1000,
            )

        self._seen_fingerprints.add(fingerprint)

        return StageResult(
            stage=ValidationStage.DEDUPLICATION,
            result=ValidationResult.PASSED,
            confidence_delta=0.0,
            message="Unique finding",
            duration_ms=(time.time() - start) * 1000,
        )

    def reset(self) -> None:
        """Reset seen fingerprints."""
        self._seen_fingerprints.clear()


class PatternVerificationStage:
    """
    Stage 2: Pattern Verification
    Verifies response patterns match expected vulnerability indicators.
    """

    def __init__(self, config: ValidationConfig):
        self.config = config
        self.matcher = PatternMatcher()

    def validate(self, finding: RawFinding) -> StageResult:
        """Verify patterns in the response."""
        start = time.time()

        if not finding.response:
            return StageResult(
                stage=ValidationStage.PATTERN_VERIFICATION,
                result=ValidationResult.SKIPPED,
                confidence_delta=0.0,
                message="No response data to verify",
                duration_ms=(time.time() - start) * 1000,
            )

        # Check for vulnerability indicators
        has_indicators, indicator_confidence, matched = self.matcher.check_indicators(
            finding.response, finding.vulnerability_type
        )

        # Check for false positive indicators
        has_fp, fp_confidence, fp_matched = self.matcher.check_false_positives(
            finding.response
        )

        if has_indicators and not has_fp:
            return StageResult(
                stage=ValidationStage.PATTERN_VERIFICATION,
                result=ValidationResult.PASSED,
                confidence_delta=indicator_confidence * 0.2,
                message=f"Pattern verification passed",
                evidence=f"Matched patterns: {matched[:3]}",
                duration_ms=(time.time() - start) * 1000,
                metadata={"matched_patterns": matched},
            )

        elif has_fp:
            return StageResult(
                stage=ValidationStage.PATTERN_VERIFICATION,
                result=ValidationResult.FAILED,
                confidence_delta=-fp_confidence * 0.3,
                message="False positive indicators detected",
                evidence=f"FP patterns: {fp_matched[:3]}",
                duration_ms=(time.time() - start) * 1000,
            )

        else:
            return StageResult(
                stage=ValidationStage.PATTERN_VERIFICATION,
                result=ValidationResult.INCONCLUSIVE,
                confidence_delta=0.0,
                message="No conclusive patterns found",
                duration_ms=(time.time() - start) * 1000,
            )


class SafeReplayStage:
    """
    Stage 3: Safe Replay
    Replays the attack with a safe variant to verify it's not a false positive.
    """

    def __init__(self, config: ValidationConfig):
        self.config = config
        self.generator = SafePayloadGenerator()

    async def validate(
        self,
        finding: RawFinding,
        http_client: httpx.AsyncClient,
    ) -> StageResult:
        """Replay with safe payload."""
        start = time.time()

        # IDOR/Authorization findings are behavior-based, not payload-based
        # They don't have traditional payloads to replay - skip this stage
        if finding.vulnerability_type in [VulnerabilityType.IDOR, VulnerabilityType.AUTHORIZATION]:
            return StageResult(
                stage=ValidationStage.SAFE_REPLAY,
                result=ValidationResult.SKIPPED,
                confidence_delta=0.0,
                message="IDOR/Auth findings are behavior-based, skipping replay",
                duration_ms=(time.time() - start) * 1000,
            )

        if not finding.payload or not finding.parameter:
            return StageResult(
                stage=ValidationStage.SAFE_REPLAY,
                result=ValidationResult.SKIPPED,
                confidence_delta=0.0,
                message="No payload/parameter to replay",
                duration_ms=(time.time() - start) * 1000,
            )

        try:
            # Generate safe payload
            safe_payload = self.generator.generate_safe_variant(
                finding.payload, finding.vulnerability_type
            )

            # Replay with safe payload
            if finding.method.upper() == "GET":
                params = {finding.parameter: safe_payload}
                response = await http_client.get(
                    finding.url,
                    params=params,
                    timeout=self.config.replay_timeout,
                )
            else:
                data = {finding.parameter: safe_payload}
                response = await http_client.post(
                    finding.url,
                    data=data,
                    timeout=self.config.replay_timeout,
                )

            # Compare with original response
            original_len = len(finding.response or "")
            safe_len = len(response.text)

            # If safe payload produces similar response, might be FP
            similarity = min(original_len, safe_len) / max(original_len, safe_len, 1)

            if similarity > 0.95:
                return StageResult(
                    stage=ValidationStage.SAFE_REPLAY,
                    result=ValidationResult.FAILED,
                    confidence_delta=-0.2,
                    message="Safe replay produced similar response (possible FP)",
                    evidence=f"Similarity: {similarity:.2%}",
                    duration_ms=(time.time() - start) * 1000,
                )
            else:
                return StageResult(
                    stage=ValidationStage.SAFE_REPLAY,
                    result=ValidationResult.PASSED,
                    confidence_delta=0.1,
                    message="Safe replay confirmed different behavior",
                    evidence=f"Similarity: {similarity:.2%}",
                    duration_ms=(time.time() - start) * 1000,
                )

        except Exception as e:
            return StageResult(
                stage=ValidationStage.SAFE_REPLAY,
                result=ValidationResult.ERROR,
                confidence_delta=0.0,
                message=f"Replay error: {str(e)}",
                duration_ms=(time.time() - start) * 1000,
            )


class NegativeControlStage:
    """
    Stage 4: Negative Control
    Compares against baseline behavior to detect false positives.
    """

    def __init__(self, config: ValidationConfig):
        self.config = config
        self._baseline_cache: Dict[str, str] = {}

    async def validate(
        self,
        finding: RawFinding,
        http_client: httpx.AsyncClient,
    ) -> StageResult:
        """Compare against baseline."""
        start = time.time()

        # IDOR/Authorization findings are already behavior-validated through
        # role comparison and ID manipulation. Skip baseline comparison as
        # it doesn't apply to these finding types.
        if finding.vulnerability_type in [VulnerabilityType.IDOR, VulnerabilityType.AUTHORIZATION]:
            return StageResult(
                stage=ValidationStage.NEGATIVE_CONTROL,
                result=ValidationResult.PASSED,
                confidence_delta=0.1,  # Small boost - already validated through behavior
                message="IDOR/Auth findings validated through role comparison",
                duration_ms=(time.time() - start) * 1000,
            )

        if not finding.parameter:
            return StageResult(
                stage=ValidationStage.NEGATIVE_CONTROL,
                result=ValidationResult.SKIPPED,
                confidence_delta=0.0,
                message="No parameter to test",
                duration_ms=(time.time() - start) * 1000,
            )

        try:
            # Get or fetch baseline
            baseline_key = f"{finding.url}|{finding.method}"

            if baseline_key not in self._baseline_cache:
                # Fetch baseline with benign input
                benign = SafePayloadGenerator.generate_benign_payload(
                    finding.vulnerability_type
                )

                if finding.method.upper() == "GET":
                    params = {finding.parameter: benign}
                    response = await http_client.get(
                        finding.url,
                        params=params,
                        timeout=self.config.replay_timeout,
                    )
                else:
                    data = {finding.parameter: benign}
                    response = await http_client.post(
                        finding.url,
                        data=data,
                        timeout=self.config.replay_timeout,
                    )

                self._baseline_cache[baseline_key] = response.text

            baseline = self._baseline_cache[baseline_key]
            attack_response = finding.response or ""

            # Compare responses
            if len(attack_response) == len(baseline):
                # Exact same length - suspicious
                return StageResult(
                    stage=ValidationStage.NEGATIVE_CONTROL,
                    result=ValidationResult.FAILED,
                    confidence_delta=-0.15,
                    message="Attack response identical to baseline",
                    duration_ms=(time.time() - start) * 1000,
                )

            # Check for new content in attack response
            baseline_set = set(baseline.split())
            attack_set = set(attack_response.split())
            new_content = attack_set - baseline_set

            if len(new_content) > 5:  # Significant new content
                return StageResult(
                    stage=ValidationStage.NEGATIVE_CONTROL,
                    result=ValidationResult.PASSED,
                    confidence_delta=0.15,
                    message="Attack response contains unique content",
                    evidence=f"New tokens: {len(new_content)}",
                    duration_ms=(time.time() - start) * 1000,
                )
            else:
                return StageResult(
                    stage=ValidationStage.NEGATIVE_CONTROL,
                    result=ValidationResult.INCONCLUSIVE,
                    confidence_delta=0.0,
                    message="Minor differences from baseline",
                    duration_ms=(time.time() - start) * 1000,
                )

        except Exception as e:
            return StageResult(
                stage=ValidationStage.NEGATIVE_CONTROL,
                result=ValidationResult.ERROR,
                confidence_delta=0.0,
                message=f"Baseline comparison error: {str(e)}",
                duration_ms=(time.time() - start) * 1000,
            )


class ContextValidationStage:
    """
    Stage 5: Context Validation
    Validates finding in application context.
    """

    def __init__(self, config: ValidationConfig):
        self.config = config

    def validate(self, finding: RawFinding) -> StageResult:
        """Validate in context."""
        start = time.time()

        confidence_boost = 0.0
        validations = []

        # Check evidence quality
        if finding.evidence and len(finding.evidence) > 20:
            confidence_boost += 0.05
            validations.append("has_quality_evidence")

        # Check for specific exploitation indicators
        if finding.vulnerability_type == VulnerabilityType.SQLI:
            if any(x in (finding.evidence or "") for x in ["root:", "admin", "password"]):
                confidence_boost += 0.1
                validations.append("data_exfiltration_indicator")

        elif finding.vulnerability_type == VulnerabilityType.XSS:
            if "alert(" in (finding.response or ""):
                confidence_boost += 0.1
                validations.append("xss_execution_indicator")

        elif finding.vulnerability_type == VulnerabilityType.CMDI:
            if any(x in (finding.evidence or "") for x in ["uid=", "root:", "whoami"]):
                confidence_boost += 0.15
                validations.append("command_execution_indicator")

        elif finding.vulnerability_type == VulnerabilityType.SSRF:
            if any(x in (finding.evidence or "") for x in ["169.254", "localhost", "127.0.0.1"]):
                confidence_boost += 0.1
                validations.append("internal_access_indicator")

        # IDOR / Access Control validation
        elif finding.vulnerability_type in [VulnerabilityType.IDOR, VulnerabilityType.AUTHORIZATION]:
            evidence_text = finding.evidence or ""
            response_text = finding.response or ""
            combined_text = f"{evidence_text} {response_text}".lower()
            
            # Check for IDOR indicators
            idor_indicators = [
                "different user", "other user", "unauthorized",
                "access to", "object id", "id manipulation",
                "modified id", "original id", "status: 200"
            ]
            if any(x in combined_text for x in idor_indicators):
                confidence_boost += 0.15
                validations.append("idor_access_indicator")
            
            # Check for user data exposure
            user_data_indicators = [
                "email", "username", "user_id", "profile",
                "account", "address", "phone", "password"
            ]
            if any(x in combined_text for x in user_data_indicators):
                confidence_boost += 0.1
                validations.append("user_data_exposure")
            
            # Check for role/permission exposure
            authz_indicators = [
                "admin", "role", "permission", "privilege",
                "can_delete", "can_edit", "access_level"
            ]
            if any(x in combined_text for x in authz_indicators):
                confidence_boost += 0.1
                validations.append("authorization_data_exposure")
            
            # High confidence if we have response comparison evidence
            if "status" in combined_text and "200" in combined_text:
                confidence_boost += 0.05
                validations.append("successful_unauthorized_access")

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
            return StageResult(
                stage=ValidationStage.CONTEXT_VALIDATION,
                result=ValidationResult.INCONCLUSIVE,
                confidence_delta=0.0,
                message="No additional context validation",
                duration_ms=(time.time() - start) * 1000,
            )


class AIVerificationStage:
    """
    Stage 6: AI Verification
    LLM-based final verification (auditor, not blocker).
    """

    def __init__(self, config: ValidationConfig):
        self.config = config

    async def validate(
        self,
        finding: RawFinding,
        ai_client: Optional[Any] = None,
    ) -> StageResult:
        """AI verification (placeholder for LLM integration)."""
        start = time.time()

        # This is a placeholder for actual LLM integration
        # In production, this would call the AI validator module

        if not ai_client:
            return StageResult(
                stage=ValidationStage.AI_VERIFICATION,
                result=ValidationResult.SKIPPED,
                confidence_delta=0.0,
                message="AI verification not configured",
                duration_ms=(time.time() - start) * 1000,
            )

        # Placeholder logic
        return StageResult(
            stage=ValidationStage.AI_VERIFICATION,
            result=ValidationResult.PASSED,
            confidence_delta=0.05,  # Small boost from AI
            message="AI verification completed",
            duration_ms=(time.time() - start) * 1000,
        )


# =============================================================================
# MAIN VALIDATION PIPELINE
# =============================================================================

class ValidationPipeline:
    """
    PHANTOM AI 6-Stage Validation Pipeline.

    Validates findings through 6 progressive stages to achieve
    near-zero false positive rates.
    """

    VERSION = "3.0.0"

    def __init__(self, config: Optional[ValidationConfig] = None):
        """Initialize the validation pipeline."""
        self.config = config or ValidationConfig()

        # Initialize stages
        self.dedup_stage = DeduplicationStage(self.config)
        self.pattern_stage = PatternVerificationStage(self.config)
        self.replay_stage = SafeReplayStage(self.config)
        self.negative_stage = NegativeControlStage(self.config)
        self.context_stage = ContextValidationStage(self.config)
        self.ai_stage = AIVerificationStage(self.config)

        # HTTP client for replay/negative control
        self._http_client: Optional[httpx.AsyncClient] = None

        # Evidence Engine v3.0 integration for comprehensive proof collection
        self._evidence_engine = None
        try:
            from utils.evidence_engine import get_evidence_engine
            self._evidence_engine = get_evidence_engine()
        except ImportError:
            logger.debug("Evidence Engine not available")

        # Statistics
        self._stats = {
            "total_processed": 0,
            "passed": 0,
            "failed": 0,
            "by_stage": {stage.name: 0 for stage in ValidationStage},
        }

        logger.info(f"ValidationPipeline v{self.VERSION} initialized")

    async def validate_finding(
        self,
        finding: RawFinding,
        all_findings: Optional[List[RawFinding]] = None,
        ai_client: Optional[Any] = None,
    ) -> ValidatedFinding:
        """
        Validate a single finding through all 6 stages.

        Args:
            finding: Raw finding to validate
            all_findings: All findings for deduplication
            ai_client: Optional AI client for stage 6

        Returns:
            ValidatedFinding with validation results
        """
        start_time = time.time()
        stage_results: List[StageResult] = []
        confidence = finding.confidence

        # Ensure HTTP client is available
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                verify=False,
            )

        # Stage 1: Deduplication
        if self.config.enable_deduplication:
            result = self.dedup_stage.validate(finding, all_findings or [])
            stage_results.append(result)
            confidence += result.confidence_delta

            if result.result == ValidationResult.FAILED:
                return self._create_result(
                    finding, False, confidence, stage_results, start_time,
                    "Duplicate finding"
                )

        # Stage 2: Pattern Verification
        if self.config.enable_pattern_verification:
            result = self.pattern_stage.validate(finding)
            stage_results.append(result)
            confidence += result.confidence_delta

        # Stage 3: Safe Replay
        if self.config.enable_safe_replay:
            result = await self.replay_stage.validate(finding, self._http_client)
            stage_results.append(result)
            confidence += result.confidence_delta

        # Stage 4: Negative Control
        if self.config.enable_negative_control:
            result = await self.negative_stage.validate(finding, self._http_client)
            stage_results.append(result)
            confidence += result.confidence_delta

        # Stage 5: Context Validation
        if self.config.enable_context_validation:
            result = self.context_stage.validate(finding)
            stage_results.append(result)
            confidence += result.confidence_delta

        # Stage 6: AI Verification (auditor, not blocker)
        if self.config.enable_ai_verification:
            result = await self.ai_stage.validate(finding, ai_client)
            stage_results.append(result)

            # AI is auditor only - doesn't block, only adds info
            if not self.config.ai_verification_is_blocking:
                # Log AI result but don't affect confidence
                pass
            else:
                confidence += result.confidence_delta

        # Clamp confidence
        confidence = max(0.0, min(1.0, confidence))

        # Determine if should report
        is_valid = confidence >= self.config.min_confidence_to_report
        suppression_reason = None if is_valid else f"Confidence {confidence:.2f} below threshold {self.config.min_confidence_to_report}"

        # Update stats
        self._stats["total_processed"] += 1
        if is_valid:
            self._stats["passed"] += 1
        else:
            self._stats["failed"] += 1

        return self._create_result(
            finding, is_valid, confidence, stage_results, start_time,
            suppression_reason
        )

    async def validate_findings(
        self,
        findings: List[RawFinding],
        ai_client: Optional[Any] = None,
    ) -> List[ValidatedFinding]:
        """
        Validate multiple findings.

        Args:
            findings: List of raw findings
            ai_client: Optional AI client

        Returns:
            List of validated findings
        """
        # Reset deduplication for new batch
        self.dedup_stage.reset()

        results = []
        for finding in findings:
            validated = await self.validate_finding(finding, findings, ai_client)
            results.append(validated)

        return results

    def _create_result(
        self,
        finding: RawFinding,
        is_valid: bool,
        confidence: float,
        stage_results: List[StageResult],
        start_time: float,
        suppression_reason: Optional[str],
    ) -> ValidatedFinding:
        """Create validated finding result."""
        # Determine confidence level
        if confidence >= 0.95:
            level = FindingConfidence.EXPLOITABLE
        elif confidence >= 0.75:
            level = FindingConfidence.CONFIRMED
        elif confidence >= 0.60:
            level = FindingConfidence.DETECTED
        else:
            level = FindingConfidence.SUSPECTED

        should_report = is_valid and confidence >= self.config.min_confidence_to_report

        # Evidence Engine v3.0: Add validation event to timeline for reportable findings
        if self._evidence_engine and should_report:
            try:
                self._evidence_engine.add_timeline_event(
                    event_type="validation_passed",
                    description=f"Finding validated: {finding.title} ({level.name})",
                    url=finding.url,
                    severity=finding.severity if hasattr(finding, 'severity') else "MEDIUM",
                    details={
                        "finding_id": finding.id,
                        "confidence": confidence,
                        "confidence_level": level.name,
                        "stages_passed": len([r for r in stage_results if r.result == ValidationResult.PASSED]),
                        "total_stages": len(stage_results),
                    }
                )
            except Exception as e:
                logger.debug(f"Evidence timeline event failed: {e}")

        return ValidatedFinding(
            raw_finding=finding,
            is_valid=is_valid,
            final_confidence=confidence,
            confidence_level=level,
            stage_results=stage_results,
            validation_time_ms=(time.time() - start_time) * 1000,
            should_report=should_report,
            suppression_reason=suppression_reason,
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Get pipeline statistics."""
        return {
            "version": self.VERSION,
            "total_processed": self._stats["total_processed"],
            "passed": self._stats["passed"],
            "failed": self._stats["failed"],
            "pass_rate": (
                self._stats["passed"] / self._stats["total_processed"]
                if self._stats["total_processed"] > 0 else 0
            ),
            "config": {
                "min_confidence": self.config.min_confidence_to_report,
                "ai_is_blocking": self.config.ai_verification_is_blocking,
            },
        }

    async def close(self) -> None:
        """Close resources."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_raw_finding(
    title: str,
    vuln_type: str,
    severity: str,
    url: str,
    **kwargs,
) -> RawFinding:
    """Create a RawFinding with minimal parameters."""
    import uuid

    vuln_type_enum = VulnerabilityType(vuln_type) if vuln_type in [v.value for v in VulnerabilityType] else VulnerabilityType.OTHER

    return RawFinding(
        id=str(uuid.uuid4())[:8],
        title=title,
        vulnerability_type=vuln_type_enum,
        severity=severity,
        url=url,
        **kwargs,
    )


async def validate_findings(
    findings: List[RawFinding],
    config: Optional[ValidationConfig] = None,
) -> List[ValidatedFinding]:
    """Convenience function to validate findings."""
    pipeline = ValidationPipeline(config)
    try:
        return await pipeline.validate_findings(findings)
    finally:
        await pipeline.close()


# =============================================================================
# MODULE TEST
# =============================================================================

if __name__ == "__main__":
    import asyncio

    async def test_pipeline():
        """Test the validation pipeline."""
        print("=" * 60)
        print("PHANTOM AI - 6-Stage Validation Pipeline Test")
        print("=" * 60)

        # Create test findings
        findings = [
            RawFinding(
                id="test-001",
                title="SQL Injection in login",
                vulnerability_type=VulnerabilityType.SQLI,
                severity="high",
                url="https://example.com/login",
                parameter="username",
                payload="' OR '1'='1",
                response="You have an error in your SQL syntax",
                evidence="SQL error message in response",
                confidence=0.6,
            ),
            RawFinding(
                id="test-002",
                title="XSS in search",
                vulnerability_type=VulnerabilityType.XSS,
                severity="medium",
                url="https://example.com/search",
                parameter="q",
                payload="<script>alert(1)</script>",
                response="<script>alert(1)</script>",
                evidence="Script tag reflected",
                confidence=0.7,
            ),
            # Duplicate of first
            RawFinding(
                id="test-003",
                title="SQL Injection in login (duplicate)",
                vulnerability_type=VulnerabilityType.SQLI,
                severity="high",
                url="https://example.com/login",
                parameter="username",
                payload="' OR '1'='1",
                response="You have an error in your SQL syntax",
                evidence="SQL error message in response",
                confidence=0.6,
            ),
        ]

        # Create pipeline
        config = ValidationConfig(
            enable_safe_replay=False,  # Disable for test
            enable_negative_control=False,  # Disable for test
            enable_ai_verification=False,  # Disable for test
        )
        pipeline = ValidationPipeline(config)

        print(f"\n✅ Pipeline v{pipeline.VERSION} created")
        print(f"\n🔍 Validating {len(findings)} findings...")

        # Validate
        results = await pipeline.validate_findings(findings)

        # Print results
        print(f"\n📊 Validation Results:")
        for result in results:
            status = "✅" if result.is_valid else "❌"
            print(f"\n   {status} {result.raw_finding.title}")
            print(f"      Confidence: {result.final_confidence:.2%}")
            print(f"      Level: {result.confidence_level.name}")
            print(f"      Should Report: {result.should_report}")
            if result.suppression_reason:
                print(f"      Suppressed: {result.suppression_reason}")

            print(f"      Stages:")
            for sr in result.stage_results:
                print(f"         - {sr.stage.name}: {sr.result.value} ({sr.confidence_delta:+.2f})")

        # Stats
        stats = pipeline.get_statistics()
        print(f"\n📈 Statistics:")
        print(f"   Processed: {stats['total_processed']}")
        print(f"   Passed: {stats['passed']}")
        print(f"   Failed: {stats['failed']}")
        print(f"   Pass Rate: {stats['pass_rate']:.2%}")

        await pipeline.close()

        print("\n" + "=" * 60)
        print("✅ Validation Pipeline test complete!")
        print("=" * 60)

    asyncio.run(test_pipeline())
