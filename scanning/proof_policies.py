"""
Proof Policies - Safe Evidence Collection
==========================================

P0.2 FIX: Defines policies for safe evidence collection during pentesting.

Problem:
- Provers can extract real data (emails, passwords, tokens)
- In production, extracting real client data is ILLEGAL without explicit consent
- Evidence in reports may contain PII that shouldn't be there

Solution:
- ProofPolicy enum defines extraction levels
- ProofConfig controls what data can be extracted
- Default is READ_ONLY - only proves vulnerability exists, no data extraction

Usage:
    config = ProofConfig(
        policy=ProofPolicy.SCHEMA_ONLY,
        explicit_consent=False,
        redact_pii=True,
    )
    result = await prover.prove(finding, config)

Author: PHANTOM AI
Date: 2026-02-13
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
import re

from utils.logger import get_logger

logger = get_logger(__name__)


class ProofPolicy(Enum):
    """
    Extraction policy levels for proof collection.

    READ_ONLY: Only prove vulnerability exists, extract NO data
    SCHEMA_ONLY: Extract schema/structure info, no actual data
    SAMPLE_REDACTED: Extract samples but auto-redact PII
    FULL_EXTRACTION: Extract all data (requires explicit consent)
    """

    READ_ONLY = "read_only"
    SCHEMA_ONLY = "schema_only"
    SAMPLE_REDACTED = "sample_redacted"
    FULL_EXTRACTION = "full_extraction"


class ConsentLevel(Enum):
    """Required consent level for data operations."""

    NONE = "none"  # No consent needed (read-only)
    IMPLICIT = "implicit"  # Implied by RoE (schema extraction)
    EXPLICIT = "explicit"  # Explicit written consent (data extraction)
    LEGAL_REVIEW = "legal_review"  # Requires legal review (sensitive data)


@dataclass
class ProofConfig:
    """
    Configuration for proof collection.

    Attributes:
        policy: The extraction policy level
        explicit_consent: Whether explicit consent was given for data extraction
        redact_pii: Whether to auto-redact PII in evidence
        max_rows: Maximum rows to extract (even with FULL_EXTRACTION)
        allowed_tables: Whitelist of tables that can be queried
        blocked_columns: Blacklist of columns that cannot be extracted
        environment: "staging" or "production" - affects defaults
    """

    policy: ProofPolicy = ProofPolicy.READ_ONLY
    explicit_consent: bool = False
    redact_pii: bool = True
    max_rows: int = 3
    allowed_tables: list[str] = field(default_factory=list)
    blocked_columns: list[str] = field(
        default_factory=lambda: [
            "password",
            "password_hash",
            "secret",
            "token",
            "api_key",
            "credit_card",
            "ssn",
            "social_security",
            "tax_id",
            "bank_account",
        ]
    )
    environment: str = "staging"

    def __post_init__(self):
        # Production defaults to stricter settings
        if self.environment == "production":
            if self.policy == ProofPolicy.FULL_EXTRACTION and not self.explicit_consent:
                logger.warning(
                    "[ProofConfig] FULL_EXTRACTION in production without explicit consent - downgrading to SAMPLE_REDACTED"
                )
                self.policy = ProofPolicy.SAMPLE_REDACTED
            self.redact_pii = True  # Always redact in production

    def get_required_consent(self) -> ConsentLevel:
        """Get the consent level required for this config."""
        if self.policy == ProofPolicy.READ_ONLY:
            return ConsentLevel.NONE
        elif self.policy == ProofPolicy.SCHEMA_ONLY:
            return ConsentLevel.IMPLICIT
        elif self.policy == ProofPolicy.SAMPLE_REDACTED:
            return ConsentLevel.EXPLICIT
        elif self.policy == ProofPolicy.FULL_EXTRACTION:
            if self.environment == "production":
                return ConsentLevel.LEGAL_REVIEW
            return ConsentLevel.EXPLICIT
        return ConsentLevel.NONE


class ProofPolicyViolation(Exception):
    """Raised when a proof operation violates the configured policy."""

    pass


class PIIRedactor:
    """
    Redacts Personally Identifiable Information from evidence.

    Patterns detected:
    - Email addresses
    - Phone numbers
    - Credit card numbers
    - Social security numbers
    - IP addresses
    - Password hashes
    - JWT tokens
    - API keys
    """

    PATTERNS = {
        "email": (
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "[EMAIL_REDACTED]",
        ),
        "phone": (
            r"\b(?:\+?1[-.]?)?\(?[0-9]{3}\)?[-.]?[0-9]{3}[-.]?[0-9]{4}\b",
            "[PHONE_REDACTED]",
        ),
        "credit_card": (
            r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            "[CC_REDACTED]",
        ),
        "ssn": (
            r"\b\d{3}[-]?\d{2}[-]?\d{4}\b",
            "[SSN_REDACTED]",
        ),
        "ip_address": (
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "[IP_REDACTED]",
        ),
        "password_hash": (
            r"\b[a-f0-9]{32,64}\b",
            "[HASH_REDACTED]",
        ),
        "jwt": (
            r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
            "[JWT_REDACTED]",
        ),
        "api_key": (
            r"\b(?:api[_-]?key|token|secret)[\"']?\s*[:=]\s*[\"']?([a-zA-Z0-9_-]{20,})",
            "[API_KEY_REDACTED]",
        ),
        "uuid": (
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            "[UUID_REDACTED]",
        ),
    }

    def __init__(self, preserve_format: bool = False):
        """
        Initialize redactor.

        Args:
            preserve_format: If True, redacted values keep similar format
                           (e.g., "john@example.com" -> "xxxx@xxxxxxx.xxx")
        """
        self.preserve_format = preserve_format
        self._compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, (pattern, _) in self.PATTERNS.items()
        }

    def redact(self, text: str) -> tuple[str, dict[str, int]]:
        """
        Redact PII from text.

        Args:
            text: The text to redact

        Returns:
            Tuple of (redacted text, counts by type)
        """
        counts: dict[str, int] = {}
        result = text

        for name, (_, replacement) in self.PATTERNS.items():
            pattern = self._compiled_patterns[name]
            matches = pattern.findall(result)
            if matches:
                counts[name] = len(matches)
                result = pattern.sub(replacement, result)

        return result, counts

    def redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Redact PII from dictionary values recursively.

        Args:
            data: Dictionary to redact

        Returns:
            Redacted dictionary
        """
        result = {}
        for key, value in data.items():
            if isinstance(value, str):
                redacted, _ = self.redact(value)
                result[key] = redacted
            elif isinstance(value, dict):
                result[key] = self.redact_dict(value)
            elif isinstance(value, list):
                result[key] = [
                    self.redact_dict(item) if isinstance(item, dict)
                    else self.redact(item)[0] if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                result[key] = value
        return result


class ProofPolicyEnforcer:
    """
    Enforces proof policies during evidence collection.

    Usage:
        enforcer = ProofPolicyEnforcer(config)

        # Before extracting data
        if enforcer.can_extract_data():
            data = await extract_data()
            data = enforcer.process_evidence(data)

        # For specific columns
        if enforcer.can_extract_column("email"):
            ...
    """

    def __init__(self, config: ProofConfig):
        self.config = config
        self.redactor = PIIRedactor()
        self._extraction_count = 0
        self._blocked_operations: list[str] = []

    def can_extract_data(self) -> bool:
        """Check if data extraction is allowed under current policy."""
        return self.config.policy in [
            ProofPolicy.SAMPLE_REDACTED,
            ProofPolicy.FULL_EXTRACTION,
        ]

    def can_extract_schema(self) -> bool:
        """Check if schema extraction is allowed."""
        return self.config.policy in [
            ProofPolicy.SCHEMA_ONLY,
            ProofPolicy.SAMPLE_REDACTED,
            ProofPolicy.FULL_EXTRACTION,
        ]

    def can_extract_column(self, column_name: str) -> bool:
        """Check if a specific column can be extracted."""
        column_lower = column_name.lower()

        # Check blocked columns
        for blocked in self.config.blocked_columns:
            if blocked in column_lower:
                return False

        return self.can_extract_data()

    def can_query_table(self, table_name: str) -> bool:
        """Check if a specific table can be queried."""
        if not self.config.allowed_tables:
            return True  # No whitelist = all allowed
        return table_name.lower() in [t.lower() for t in self.config.allowed_tables]

    def validate_extraction(self, operation: str, target: str) -> None:
        """
        Validate an extraction operation. Raises ProofPolicyViolation if not allowed.

        Args:
            operation: Type of operation (e.g., "extract_column", "query_table")
            target: Target of operation (e.g., column name, table name)
        """
        if operation == "extract_column" and not self.can_extract_column(target):
            raise ProofPolicyViolation(
                f"Extraction of column '{target}' blocked by policy"
            )

        if operation == "query_table" and not self.can_query_table(target):
            raise ProofPolicyViolation(
                f"Query of table '{target}' not in allowed tables"
            )

        if operation == "extract_data" and not self.can_extract_data():
            raise ProofPolicyViolation(
                f"Data extraction not allowed with policy {self.config.policy.value}"
            )

    def process_evidence(
        self, evidence: str | dict | list
    ) -> str | dict | list:
        """
        Process evidence according to policy (redact if needed).

        Args:
            evidence: Raw evidence data

        Returns:
            Processed (potentially redacted) evidence
        """
        if not self.config.redact_pii:
            return evidence

        if isinstance(evidence, str):
            redacted, counts = self.redactor.redact(evidence)
            if counts:
                logger.info(f"[ProofPolicy] Redacted PII: {counts}")
            return redacted

        elif isinstance(evidence, dict):
            return self.redactor.redact_dict(evidence)

        elif isinstance(evidence, list):
            return [self.process_evidence(item) for item in evidence]

        return evidence

    def create_safe_result(
        self,
        vulnerable: bool,
        evidence_type: str,
        raw_evidence: Any = None,
    ) -> dict[str, Any]:
        """
        Create a policy-compliant proof result.

        Args:
            vulnerable: Whether vulnerability was proven
            evidence_type: Type of evidence (e.g., "sqli_extraction", "xss_reflection")
            raw_evidence: Raw evidence data (will be processed according to policy)

        Returns:
            Safe result dictionary
        """
        result = {
            "vulnerable": vulnerable,
            "evidence_type": evidence_type,
            "policy_applied": self.config.policy.value,
            "environment": self.config.environment,
        }

        if self.config.policy == ProofPolicy.READ_ONLY:
            result["evidence"] = "[EVIDENCE_NOT_EXTRACTED_PER_POLICY]"
            result["extraction_possible"] = vulnerable

        elif self.config.policy == ProofPolicy.SCHEMA_ONLY:
            if isinstance(raw_evidence, dict) and "schema" in raw_evidence:
                result["schema"] = raw_evidence["schema"]
            result["data"] = "[DATA_NOT_EXTRACTED_SCHEMA_ONLY]"

        else:
            if raw_evidence:
                result["evidence"] = self.process_evidence(raw_evidence)
            if self.config.redact_pii:
                result["pii_redacted"] = True

        return result

    def get_audit_log(self) -> dict[str, Any]:
        """Get audit log of policy enforcement."""
        return {
            "policy": self.config.policy.value,
            "environment": self.config.environment,
            "extractions_performed": self._extraction_count,
            "operations_blocked": self._blocked_operations,
            "pii_redaction_enabled": self.config.redact_pii,
            "explicit_consent": self.config.explicit_consent,
        }


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================


def create_staging_config(
    policy: ProofPolicy = ProofPolicy.SAMPLE_REDACTED,
) -> ProofConfig:
    """Create a proof config suitable for staging environments."""
    return ProofConfig(
        policy=policy,
        explicit_consent=False,
        redact_pii=True,
        max_rows=10,
        environment="staging",
    )


def create_production_config(
    explicit_consent: bool = False,
) -> ProofConfig:
    """
    Create a proof config suitable for production environments.

    Always defaults to safe settings.
    """
    policy = ProofPolicy.READ_ONLY
    if explicit_consent:
        policy = ProofPolicy.SAMPLE_REDACTED

    return ProofConfig(
        policy=policy,
        explicit_consent=explicit_consent,
        redact_pii=True,  # Always redact in production
        max_rows=3,
        environment="production",
    )


def get_default_config(environment: str = "staging") -> ProofConfig:
    """Get the default config for an environment."""
    if environment == "production":
        return create_production_config()
    return create_staging_config()


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Enums
    "ProofPolicy",
    "ConsentLevel",
    # Config
    "ProofConfig",
    # Classes
    "ProofPolicyEnforcer",
    "PIIRedactor",
    # Exceptions
    "ProofPolicyViolation",
    # Factory functions
    "create_staging_config",
    "create_production_config",
    "get_default_config",
]
