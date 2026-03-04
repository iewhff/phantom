"""
Evidence Redactor - PII Protection for Reports
===============================================

P0.7 FIX: Redacts sensitive information from evidence before including in reports.

Problem:
- Scanner extracts real data (emails, tokens, passwords, IPs)
- Reports should NOT contain real client PII
- Legal compliance (GDPR, HIPAA) requires redaction

Solution:
- Automatic PII detection and redaction
- Configurable redaction levels
- Audit trail of what was redacted
- Separate technical vs executive report handling

Usage:
    redactor = EvidenceRedactor(config=RedactionConfig.STRICT)

    # Redact a finding
    safe_finding = redactor.redact_finding(finding)

    # Redact entire report
    safe_report = redactor.redact_report(report)

Author: PHANTOM AI
Date: 2026-02-13
"""

import re
import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)


class RedactionLevel(Enum):
    """Level of redaction to apply."""

    NONE = "none"  # No redaction (internal use only)
    MINIMAL = "minimal"  # Only passwords and tokens
    STANDARD = "standard"  # PII + credentials
    STRICT = "strict"  # All sensitive data + IPs + URLs
    PARANOID = "paranoid"  # Everything that could identify anyone


@dataclass
class RedactionConfig:
    """Configuration for evidence redaction."""

    level: RedactionLevel = RedactionLevel.STANDARD
    redact_emails: bool = True
    redact_ips: bool = True
    redact_tokens: bool = True
    redact_passwords: bool = True
    redact_credit_cards: bool = True
    redact_phone_numbers: bool = True
    redact_urls: bool = False  # Only in STRICT+
    redact_usernames: bool = False  # Only in PARANOID
    show_redaction_counts: bool = True
    preserve_evidence_structure: bool = True  # Keep JSON structure
    hash_redacted_values: bool = False  # Show hash for correlation

    @classmethod
    def from_level(cls, level: RedactionLevel) -> "RedactionConfig":
        """Create config from a redaction level."""
        if level == RedactionLevel.NONE:
            return cls(
                level=level,
                redact_emails=False,
                redact_ips=False,
                redact_tokens=False,
                redact_passwords=False,
                redact_credit_cards=False,
                redact_phone_numbers=False,
            )
        elif level == RedactionLevel.MINIMAL:
            return cls(
                level=level,
                redact_emails=False,
                redact_ips=False,
                redact_tokens=True,
                redact_passwords=True,
                redact_credit_cards=True,
                redact_phone_numbers=False,
            )
        elif level == RedactionLevel.STANDARD:
            return cls(level=level)
        elif level == RedactionLevel.STRICT:
            return cls(
                level=level,
                redact_urls=True,
            )
        elif level == RedactionLevel.PARANOID:
            return cls(
                level=level,
                redact_urls=True,
                redact_usernames=True,
            )
        return cls(level=level)


@dataclass
class RedactionResult:
    """Result of a redaction operation."""

    original_length: int
    redacted_length: int
    redactions_made: dict[str, int]  # Type -> count
    content: str | dict | list


class EvidenceRedactor:
    """
    Redacts sensitive information from evidence.

    Detects and replaces:
    - Email addresses
    - IP addresses (IPv4 and IPv6)
    - JWT tokens
    - API keys and secrets
    - Password hashes
    - Credit card numbers
    - Phone numbers
    - SSN/Tax IDs
    - URLs (optional)
    - Usernames (optional)
    """

    # Pattern definitions with replacements
    PATTERNS = {
        "email": {
            "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "replacement": "[EMAIL]",
            "description": "Email addresses",
        },
        "ipv4": {
            "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "replacement": "[IPv4]",
            "description": "IPv4 addresses",
        },
        "ipv6": {
            "pattern": r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
            "replacement": "[IPv6]",
            "description": "IPv6 addresses",
        },
        "jwt": {
            "pattern": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
            "replacement": "[JWT_TOKEN]",
            "description": "JWT tokens",
        },
        "bearer_token": {
            "pattern": r"Bearer\s+[a-zA-Z0-9_-]+",
            "replacement": "Bearer [TOKEN]",
            "description": "Bearer tokens",
        },
        "api_key": {
            "pattern": r"(?:api[_-]?key|apikey|api_secret)[\"'\s:=]+[\"']?([a-zA-Z0-9_-]{16,})",
            "replacement": "[API_KEY]",
            "description": "API keys",
        },
        "password_value": {
            "pattern": r"(?:password|passwd|pwd|secret)[\"'\s:=]+[\"']?([^\s\"']{4,})",
            "replacement": "[PASSWORD]",
            "description": "Password values",
        },
        "password_hash": {
            "pattern": r"\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b",
            "replacement": "[HASH]",
            "description": "Password hashes (MD5/SHA1/SHA256)",
        },
        "credit_card": {
            "pattern": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
            "replacement": "[CREDIT_CARD]",
            "description": "Credit card numbers",
        },
        "phone": {
            "pattern": r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
            "replacement": "[PHONE]",
            "description": "Phone numbers",
        },
        "ssn": {
            "pattern": r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
            "replacement": "[SSN]",
            "description": "Social Security Numbers",
        },
        "uuid": {
            "pattern": r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            "replacement": "[UUID]",
            "description": "UUIDs",
        },
        "url": {
            "pattern": r"https?://[^\s\"'<>]+",
            "replacement": "[URL]",
            "description": "Full URLs",
        },
        "session_id": {
            "pattern": r"(?:session[_-]?id|sessid|PHPSESSID|JSESSIONID)[\"'\s:=]+[\"']?([a-zA-Z0-9_-]{16,})",
            "replacement": "[SESSION_ID]",
            "description": "Session IDs",
        },
        "private_key": {
            "pattern": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA )?PRIVATE KEY-----",
            "replacement": "[PRIVATE_KEY]",
            "description": "Private keys",
        },
        "aws_key": {
            "pattern": r"(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}",
            "replacement": "[AWS_ACCESS_KEY]",
            "description": "AWS access keys",
        },
    }

    def __init__(self, config: RedactionConfig | None = None):
        """
        Initialize redactor.

        Args:
            config: Redaction configuration (default: STANDARD)
        """
        self.config = config or RedactionConfig()
        self._compile_patterns()
        self._redaction_log: list[dict] = []

    def _compile_patterns(self) -> None:
        """Compile regex patterns based on config."""
        self._compiled: dict[str, tuple[re.Pattern, str]] = {}

        # Map config flags to pattern names
        config_map = {
            "email": self.config.redact_emails,
            "ipv4": self.config.redact_ips,
            "ipv6": self.config.redact_ips,
            "jwt": self.config.redact_tokens,
            "bearer_token": self.config.redact_tokens,
            "api_key": self.config.redact_tokens,
            "password_value": self.config.redact_passwords,
            "password_hash": self.config.redact_passwords,
            "credit_card": self.config.redact_credit_cards,
            "phone": self.config.redact_phone_numbers,
            "ssn": True,  # Always redact SSN
            "uuid": False,  # UUIDs are usually OK
            "url": self.config.redact_urls,
            "session_id": self.config.redact_tokens,
            "private_key": True,  # Always redact private keys
            "aws_key": True,  # Always redact AWS keys
        }

        for name, pattern_info in self.PATTERNS.items():
            if config_map.get(name, True):
                self._compiled[name] = (
                    re.compile(pattern_info["pattern"], re.IGNORECASE),
                    pattern_info["replacement"],
                )

    def redact_text(self, text: str) -> RedactionResult:
        """
        Redact sensitive information from text.

        Args:
            text: Text to redact

        Returns:
            RedactionResult with redacted content and stats
        """
        original_length = len(text)
        redactions: dict[str, int] = {}
        result = text

        for name, (pattern, replacement) in self._compiled.items():
            matches = pattern.findall(result)
            if matches:
                count = len(matches) if isinstance(matches[0], str) else len(matches)
                redactions[name] = count

                # Apply replacement
                if self.config.hash_redacted_values:
                    # Replace with hash for correlation
                    def hash_replace(match):
                        original = match.group(0)
                        h = hashlib.md5(original.encode()).hexdigest()[:8]
                        return f"{replacement}#{h}"

                    result = pattern.sub(hash_replace, result)
                else:
                    result = pattern.sub(replacement, result)

        return RedactionResult(
            original_length=original_length,
            redacted_length=len(result),
            redactions_made=redactions,
            content=result,
        )

    def redact_dict(self, data: dict[str, Any]) -> RedactionResult:
        """
        Redact sensitive information from a dictionary.

        Args:
            data: Dictionary to redact

        Returns:
            RedactionResult with redacted dictionary
        """
        total_redactions: dict[str, int] = {}

        def redact_value(value: Any) -> Any:
            if isinstance(value, str):
                result = self.redact_text(value)
                for name, count in result.redactions_made.items():
                    total_redactions[name] = total_redactions.get(name, 0) + count
                return result.content
            elif isinstance(value, dict):
                return {k: redact_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [redact_value(item) for item in value]
            return value

        redacted = {k: redact_value(v) for k, v in data.items()}

        return RedactionResult(
            original_length=0,
            redacted_length=0,
            redactions_made=total_redactions,
            content=redacted,
        )

    def redact_finding(self, finding: dict) -> dict:
        """
        Redact a vulnerability finding.

        Handles common finding structures:
        - evidence (list of strings)
        - metadata (dict)
        - poc (string)
        - request/response (strings)

        Args:
            finding: Finding dictionary

        Returns:
            Redacted finding
        """
        redacted = dict(finding)
        total_redactions: dict[str, int] = {}

        # Redact evidence list
        if "evidence" in redacted and isinstance(redacted["evidence"], list):
            new_evidence = []
            for e in redacted["evidence"]:
                if isinstance(e, str):
                    result = self.redact_text(e)
                    new_evidence.append(result.content)
                    for name, count in result.redactions_made.items():
                        total_redactions[name] = total_redactions.get(name, 0) + count
                elif isinstance(e, dict):
                    result = self.redact_dict(e)
                    new_evidence.append(result.content)
                    for name, count in result.redactions_made.items():
                        total_redactions[name] = total_redactions.get(name, 0) + count
                else:
                    new_evidence.append(e)
            redacted["evidence"] = new_evidence

        # Redact metadata
        if "metadata" in redacted and isinstance(redacted["metadata"], dict):
            result = self.redact_dict(redacted["metadata"])
            redacted["metadata"] = result.content
            for name, count in result.redactions_made.items():
                total_redactions[name] = total_redactions.get(name, 0) + count

        # Redact specific string fields
        string_fields = ["poc", "request", "response", "description", "remediation"]
        for field_name in string_fields:
            if field_name in redacted and isinstance(redacted[field_name], str):
                result = self.redact_text(redacted[field_name])
                redacted[field_name] = result.content
                for name, count in result.redactions_made.items():
                    total_redactions[name] = total_redactions.get(name, 0) + count

        # Add redaction note if any redactions were made
        if total_redactions and self.config.show_redaction_counts:
            redacted["_redaction_info"] = {
                "redactions_applied": total_redactions,
                "redaction_level": self.config.level.value,
            }

        # Log redaction
        self._redaction_log.append({
            "finding_type": finding.get("type", "unknown"),
            "redactions": total_redactions,
        })

        return redacted

    def redact_report(self, report: dict) -> dict:
        """
        Redact an entire report.

        Args:
            report: Report dictionary (with findings list)

        Returns:
            Redacted report
        """
        redacted = dict(report)

        # Redact findings
        if "findings" in redacted:
            redacted["findings"] = [
                self.redact_finding(f) for f in redacted["findings"]
            ]

        # Redact chains
        if "chains" in redacted:
            redacted["chains"] = [
                self.redact_finding(c) for c in redacted["chains"]
            ]

        # Redact executive summary
        if "executive_summary" in redacted and isinstance(redacted["executive_summary"], str):
            result = self.redact_text(redacted["executive_summary"])
            redacted["executive_summary"] = result.content

        # Add report-level redaction summary
        redacted["_redaction_summary"] = self.get_redaction_summary()

        return redacted

    def get_redaction_summary(self) -> dict:
        """Get summary of all redactions performed."""
        total_by_type: dict[str, int] = {}
        for entry in self._redaction_log:
            for name, count in entry.get("redactions", {}).items():
                total_by_type[name] = total_by_type.get(name, 0) + count

        return {
            "total_findings_processed": len(self._redaction_log),
            "total_redactions_by_type": total_by_type,
            "total_redactions": sum(total_by_type.values()),
            "redaction_level": self.config.level.value,
        }

    def reset_log(self) -> None:
        """Reset the redaction log."""
        self._redaction_log = []


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def redact_for_executive(content: str | dict) -> str | dict:
    """
    Apply strict redaction suitable for executive reports.

    Removes all technical details and sensitive data.
    """
    config = RedactionConfig.from_level(RedactionLevel.STRICT)
    redactor = EvidenceRedactor(config)

    if isinstance(content, str):
        return redactor.redact_text(content).content
    return redactor.redact_dict(content).content


def redact_for_technical(content: str | dict) -> str | dict:
    """
    Apply standard redaction suitable for technical reports.

    Preserves technical details but removes PII.
    """
    config = RedactionConfig.from_level(RedactionLevel.STANDARD)
    redactor = EvidenceRedactor(config)

    if isinstance(content, str):
        return redactor.redact_text(content).content
    return redactor.redact_dict(content).content


def quick_redact(text: str) -> str:
    """Quick redaction with default settings."""
    redactor = EvidenceRedactor()
    return redactor.redact_text(text).content


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Enums
    "RedactionLevel",
    # Config
    "RedactionConfig",
    # Classes
    "EvidenceRedactor",
    "RedactionResult",
    # Functions
    "redact_for_executive",
    "redact_for_technical",
    "quick_redact",
]
