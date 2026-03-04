"""
Destructive Controls - Payload Safety Validation
=================================================

P0.3 FIX: Prevents destructive operations in non-aggressive modes.

Problem:
- Scanner can execute stacked queries (DELETE, UPDATE, INSERT)
- In production, modifying client data is ILLEGAL and DANGEROUS
- Even in staging, uncontrolled writes can corrupt test data

Solution:
- Categorize payloads by destructiveness
- Block destructive payloads by default
- Require explicit approval for write operations
- Log all blocked operations for audit

Safety Levels:
- SAFE: No requests that modify state (read-only scanning)
- CAUTIOUS: Read + limited write probes (no actual modification)
- STANDARD: Read + safe write probes (reversible only)
- AGGRESSIVE: All operations allowed (requires RoE + production approval)

Author: PHANTOM AI
Date: 2026-02-13
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from utils.logger import get_logger

logger = get_logger(__name__)


class DestructiveLevel(Enum):
    """Classification of payload destructiveness."""

    SAFE = "safe"  # No state change possible
    PROBE = "probe"  # Detects vulnerability, no real change
    REVERSIBLE = "reversible"  # Can be undone (e.g., add then delete)
    DESTRUCTIVE = "destructive"  # Permanent state change
    CATASTROPHIC = "catastrophic"  # System-wide impact (DROP DB, rm -rf)


# =============================================================================
# FIX 2026-02-13: Numeric ranking for proper comparison
# Bug: String comparison "destructive" > "safe" returns False (lexicographic)
# Fix: Use numeric ranks for semantic comparison
# =============================================================================
LEVEL_RANK: dict[DestructiveLevel, int] = {
    DestructiveLevel.SAFE: 0,
    DestructiveLevel.PROBE: 1,
    DestructiveLevel.REVERSIBLE: 2,
    DestructiveLevel.DESTRUCTIVE: 3,
    DestructiveLevel.CATASTROPHIC: 4,
}


class PayloadCategory(Enum):
    """Categories of security payloads."""

    SQLI = "sqli"
    XSS = "xss"
    CMDI = "cmdi"
    SSRF = "ssrf"
    XXE = "xxe"
    SSTI = "ssti"
    LFI = "lfi"
    RFI = "rfi"
    DESERIALIZATION = "deserialization"
    JWT = "jwt"
    OTHER = "other"


@dataclass
class PayloadAnalysis:
    """Result of payload safety analysis."""

    payload: str
    category: PayloadCategory
    level: DestructiveLevel
    blocked: bool
    reason: str
    alternative: str | None = None  # Safe alternative if available


# =============================================================================
# DESTRUCTIVE PATTERNS
# =============================================================================

# SQL Injection - Destructive patterns
SQLI_DESTRUCTIVE = [
    # Stacked queries that modify data
    (r";\s*DELETE\s+FROM", DestructiveLevel.DESTRUCTIVE, "DELETE statement"),
    (r";\s*DROP\s+(TABLE|DATABASE|INDEX)", DestructiveLevel.CATASTROPHIC, "DROP statement"),
    (r";\s*TRUNCATE\s+", DestructiveLevel.CATASTROPHIC, "TRUNCATE statement"),
    (r";\s*UPDATE\s+.*\s+SET\s+", DestructiveLevel.DESTRUCTIVE, "UPDATE statement"),
    (r";\s*INSERT\s+INTO", DestructiveLevel.DESTRUCTIVE, "INSERT statement"),
    (r";\s*ALTER\s+(TABLE|DATABASE)", DestructiveLevel.DESTRUCTIVE, "ALTER statement"),
    (r";\s*CREATE\s+(TABLE|DATABASE|USER)", DestructiveLevel.REVERSIBLE, "CREATE statement"),
    (r";\s*GRANT\s+", DestructiveLevel.DESTRUCTIVE, "GRANT statement"),
    (r";\s*REVOKE\s+", DestructiveLevel.DESTRUCTIVE, "REVOKE statement"),
    # Dangerous functions
    (r"xp_cmdshell", DestructiveLevel.CATASTROPHIC, "xp_cmdshell (RCE)"),
    (r"LOAD_FILE", DestructiveLevel.DESTRUCTIVE, "LOAD_FILE (file read)"),
    (r"INTO\s+OUTFILE", DestructiveLevel.DESTRUCTIVE, "INTO OUTFILE (file write)"),
    (r"INTO\s+DUMPFILE", DestructiveLevel.DESTRUCTIVE, "INTO DUMPFILE (file write)"),
    (r"BENCHMARK\s*\(", DestructiveLevel.REVERSIBLE, "BENCHMARK (DoS potential)"),
    (r"SLEEP\s*\(\s*\d{2,}", DestructiveLevel.REVERSIBLE, "Long SLEEP (DoS)"),  # >10s
    (r"pg_sleep\s*\(\s*\d{2,}", DestructiveLevel.REVERSIBLE, "Long pg_sleep (DoS)"),
    # Privilege escalation
    (r";\s*CREATE\s+USER", DestructiveLevel.DESTRUCTIVE, "CREATE USER"),
    (r";\s*SET\s+PASSWORD", DestructiveLevel.DESTRUCTIVE, "SET PASSWORD"),
]

# Command Injection - Destructive patterns
CMDI_DESTRUCTIVE = [
    # File system destruction
    (r"rm\s+-rf\s+/", DestructiveLevel.CATASTROPHIC, "rm -rf / (system destruction)"),
    (r"rm\s+-rf\s+\*", DestructiveLevel.CATASTROPHIC, "rm -rf * (directory wipe)"),
    (r"mkfs\.", DestructiveLevel.CATASTROPHIC, "mkfs (disk format)"),
    (r"dd\s+if=.*of=/dev/", DestructiveLevel.CATASTROPHIC, "dd to device (disk wipe)"),
    # System modification
    (r"chmod\s+-R\s+777", DestructiveLevel.DESTRUCTIVE, "chmod 777 recursively"),
    (r"chown\s+-R", DestructiveLevel.DESTRUCTIVE, "chown recursively"),
    (r"useradd|adduser", DestructiveLevel.DESTRUCTIVE, "user creation"),
    (r"passwd", DestructiveLevel.DESTRUCTIVE, "password change"),
    # Network attacks
    (r"iptables\s+-F", DestructiveLevel.DESTRUCTIVE, "firewall flush"),
    (r"service\s+.*\s+stop", DestructiveLevel.DESTRUCTIVE, "service stop"),
    (r"systemctl\s+stop", DestructiveLevel.DESTRUCTIVE, "systemctl stop"),
    (r"shutdown|reboot|halt|poweroff", DestructiveLevel.CATASTROPHIC, "system shutdown"),
    # Data exfiltration at scale
    (r"tar\s+.*\s+/", DestructiveLevel.DESTRUCTIVE, "tar of root"),
    (r"zip\s+-r\s+.*\s+/", DestructiveLevel.DESTRUCTIVE, "zip of root"),
]

# SSRF - Destructive patterns
SSRF_DESTRUCTIVE = [
    # Cloud metadata attacks
    (r"169\.254\.169\.254", DestructiveLevel.DESTRUCTIVE, "AWS metadata service"),
    (r"metadata\.google\.internal", DestructiveLevel.DESTRUCTIVE, "GCP metadata service"),
    # Internal service attacks
    (r"redis://.*FLUSHALL", DestructiveLevel.CATASTROPHIC, "Redis FLUSHALL"),
    (r"memcached://.*flush_all", DestructiveLevel.CATASTROPHIC, "Memcached flush"),
    # File access
    (r"file:///etc/shadow", DestructiveLevel.DESTRUCTIVE, "shadow file access"),
    (r"file:///etc/passwd", DestructiveLevel.PROBE, "passwd file access"),  # Read-only
]

# XXE - Destructive patterns
XXE_DESTRUCTIVE = [
    (r"<!ENTITY.*SYSTEM.*file:///etc/shadow", DestructiveLevel.DESTRUCTIVE, "shadow file"),
    (r"<!ENTITY.*SYSTEM.*file:///etc/passwd", DestructiveLevel.PROBE, "passwd file"),
    (r"<!ENTITY.*SYSTEM.*expect://", DestructiveLevel.DESTRUCTIVE, "expect (RCE)"),
    (r"<!ENTITY.*SYSTEM.*php://", DestructiveLevel.REVERSIBLE, "PHP wrapper"),
]

# JWT - Destructive patterns
JWT_DESTRUCTIVE = [
    # Creating admin tokens in production
    (r'"role"\s*:\s*"admin"', DestructiveLevel.DESTRUCTIVE, "admin role assignment"),
    (r'"admin"\s*:\s*true', DestructiveLevel.DESTRUCTIVE, "admin flag"),
    (r'"is_admin"\s*:\s*true', DestructiveLevel.DESTRUCTIVE, "is_admin flag"),
]


# =============================================================================
# SAFETY LEVEL DEFINITIONS
# =============================================================================

SAFETY_LEVELS = {
    "safe": {
        "allowed_levels": [DestructiveLevel.SAFE],
        "description": "Read-only scanning, no state modification",
    },
    "cautious": {
        "allowed_levels": [DestructiveLevel.SAFE, DestructiveLevel.PROBE],
        "description": "Detection probes only, no actual modification",
    },
    "standard": {
        "allowed_levels": [
            DestructiveLevel.SAFE,
            DestructiveLevel.PROBE,
            DestructiveLevel.REVERSIBLE,
        ],
        "description": "Reversible operations allowed",
    },
    "aggressive": {
        "allowed_levels": [
            DestructiveLevel.SAFE,
            DestructiveLevel.PROBE,
            DestructiveLevel.REVERSIBLE,
            DestructiveLevel.DESTRUCTIVE,
            DestructiveLevel.CATASTROPHIC,
        ],
        "description": "All operations allowed (requires RoE)",
    },
}


# =============================================================================
# PAYLOAD ANALYZER
# =============================================================================


class PayloadSafetyAnalyzer:
    """
    Analyzes payloads for destructive potential.

    Usage:
        analyzer = PayloadSafetyAnalyzer(safety_level="standard")

        # Check single payload
        result = analyzer.analyze(payload, category=PayloadCategory.SQLI)
        if result.blocked:
            logger.warning(f"Blocked: {result.reason}")

        # Validate before sending
        is_safe, reason = analyzer.validate(payload, category)
        if not is_safe:
            continue  # Skip this payload
    """

    def __init__(self, safety_level: str = "standard"):
        """
        Initialize analyzer.

        Args:
            safety_level: One of "safe", "cautious", "standard", "aggressive"
        """
        self.safety_level = safety_level
        self.allowed_levels = SAFETY_LEVELS.get(safety_level, SAFETY_LEVELS["standard"])[
            "allowed_levels"
        ]

        # Compile patterns for performance
        self._patterns: dict[PayloadCategory, list[tuple[re.Pattern, DestructiveLevel, str]]] = {
            PayloadCategory.SQLI: [
                (re.compile(p, re.IGNORECASE), level, desc)
                for p, level, desc in SQLI_DESTRUCTIVE
            ],
            PayloadCategory.CMDI: [
                (re.compile(p, re.IGNORECASE), level, desc)
                for p, level, desc in CMDI_DESTRUCTIVE
            ],
            PayloadCategory.SSRF: [
                (re.compile(p, re.IGNORECASE), level, desc)
                for p, level, desc in SSRF_DESTRUCTIVE
            ],
            PayloadCategory.XXE: [
                (re.compile(p, re.IGNORECASE), level, desc)
                for p, level, desc in XXE_DESTRUCTIVE
            ],
            PayloadCategory.JWT: [
                (re.compile(p, re.IGNORECASE), level, desc)
                for p, level, desc in JWT_DESTRUCTIVE
            ],
        }

        # Track blocked payloads for audit
        self._blocked_log: list[PayloadAnalysis] = []

    def analyze(
        self,
        payload: str,
        category: PayloadCategory = PayloadCategory.OTHER,
    ) -> PayloadAnalysis:
        """
        Analyze a payload for destructive potential.

        Args:
            payload: The payload to analyze
            category: Category of the payload

        Returns:
            PayloadAnalysis with classification and blocking decision
        """
        # Check against patterns for this category
        patterns = self._patterns.get(category, [])

        max_level = DestructiveLevel.SAFE
        matched_reason = ""

        for pattern, level, description in patterns:
            if pattern.search(payload):
                # FIX 2026-02-13: Use numeric rank for proper comparison
                # Bug was: level.value > max_level.value (string comparison)
                if LEVEL_RANK[level] > LEVEL_RANK[max_level]:
                    max_level = level
                    matched_reason = description

        # Determine if blocked
        blocked = max_level not in self.allowed_levels

        # Create analysis result
        result = PayloadAnalysis(
            payload=payload[:100] + "..." if len(payload) > 100 else payload,
            category=category,
            level=max_level,
            blocked=blocked,
            reason=matched_reason if blocked else "",
            alternative=self._get_safe_alternative(payload, category) if blocked else None,
        )

        # Log blocked payloads
        if blocked:
            self._blocked_log.append(result)
            logger.warning(
                f"[DestructiveControl] BLOCKED payload in {self.safety_level} mode: "
                f"{result.reason} ({result.level.value})"
            )

            # ═══════════════════════════════════════════════════════════════════════
            # AUDIT-LOG FIX 2026-02-13: Log safety blocks to audit trail
            # ═══════════════════════════════════════════════════════════════════════
            try:
                from utils.audit_logger import get_audit_logger
                audit = get_audit_logger()
                if audit:
                    audit.log_safety_block(
                        url=f"[{category.value}] {max_level.value}",
                        reason=result.reason,
                        payload=result.payload,
                    )
            except Exception:
                pass  # Audit logging is best-effort
            # ═══════════════════════════════════════════════════════════════════════

        return result

    def validate(
        self,
        payload: str,
        category: PayloadCategory = PayloadCategory.OTHER,
    ) -> tuple[bool, str]:
        """
        Simple validation - returns (is_safe, reason).

        Args:
            payload: The payload to validate
            category: Category of the payload

        Returns:
            Tuple of (is_safe, reason_if_blocked)
        """
        result = self.analyze(payload, category)
        return not result.blocked, result.reason

    def filter_payloads(
        self,
        payloads: list[str],
        category: PayloadCategory,
    ) -> list[str]:
        """
        Filter a list of payloads, returning only safe ones.

        Args:
            payloads: List of payloads to filter
            category: Category of payloads

        Returns:
            List of safe payloads
        """
        return [p for p in payloads if not self.analyze(p, category).blocked]

    def _get_safe_alternative(
        self,
        payload: str,
        category: PayloadCategory,
    ) -> str | None:
        """
        Suggest a safe alternative for a blocked payload.

        Args:
            payload: The blocked payload
            category: Category of payload

        Returns:
            Safe alternative or None
        """
        alternatives = {
            PayloadCategory.SQLI: {
                "DELETE": "Use SELECT COUNT(*) to prove access instead of DELETE",
                "DROP": "Use SHOW TABLES to prove access instead of DROP",
                "UPDATE": "Use SELECT to prove access instead of UPDATE",
                "INSERT": "Use SELECT to prove access instead of INSERT",
                "xp_cmdshell": "Use @@version to prove SQLi without RCE",
            },
            PayloadCategory.CMDI: {
                "rm -rf": "Use 'ls' or 'id' to prove RCE safely",
                "shutdown": "Use 'whoami' to prove RCE safely",
                "chmod": "Use 'ls -la' to prove access",
            },
        }

        for trigger, alternative in alternatives.get(category, {}).items():
            if trigger.lower() in payload.lower():
                return alternative

        return None

    def get_blocked_log(self) -> list[PayloadAnalysis]:
        """Get log of all blocked payloads."""
        return self._blocked_log.copy()

    def get_stats(self) -> dict:
        """Get blocking statistics."""
        by_level = {}
        by_category = {}

        for analysis in self._blocked_log:
            level_name = analysis.level.value
            cat_name = analysis.category.value

            by_level[level_name] = by_level.get(level_name, 0) + 1
            by_category[cat_name] = by_category.get(cat_name, 0) + 1

        return {
            "safety_level": self.safety_level,
            "total_blocked": len(self._blocked_log),
            "by_level": by_level,
            "by_category": by_category,
        }


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def is_destructive_payload(payload: str, category: str = "other") -> bool:
    """
    Quick check if a payload is destructive.

    Args:
        payload: The payload to check
        category: Category name (sqli, cmdi, etc.)

    Returns:
        True if payload is destructive
    """
    analyzer = PayloadSafetyAnalyzer(safety_level="standard")
    cat = PayloadCategory(category.lower()) if category.lower() in [
        c.value for c in PayloadCategory
    ] else PayloadCategory.OTHER
    result = analyzer.analyze(payload, cat)
    return result.level in [DestructiveLevel.DESTRUCTIVE, DestructiveLevel.CATASTROPHIC]


def validate_payload_safety(
    payload: str,
    safety_level: str,
    category: str = "other",
) -> tuple[bool, str]:
    """
    Validate a payload against a safety level.

    Args:
        payload: The payload to validate
        safety_level: Safety level to check against
        category: Category name

    Returns:
        Tuple of (is_safe, reason_if_blocked)
    """
    analyzer = PayloadSafetyAnalyzer(safety_level=safety_level)
    cat = PayloadCategory(category.lower()) if category.lower() in [
        c.value for c in PayloadCategory
    ] else PayloadCategory.OTHER
    return analyzer.validate(payload, cat)


def get_safe_sqli_payloads(safety_level: str = "standard") -> list[str]:
    """
    Get a list of safe SQL injection payloads for the given safety level.

    These payloads detect SQLi without modifying data.

    Args:
        safety_level: Safety level

    Returns:
        List of safe payloads
    """
    # All these payloads only READ data, never modify
    safe_payloads = [
        # Error-based (read-only)
        "' OR '1'='1",
        "' OR '1'='1'--",
        "1' ORDER BY 1--",
        "1' ORDER BY 10--",
        # Union-based (read-only)
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT @@version--",
        "' UNION SELECT user()--",
        "' UNION SELECT database()--",
        # Boolean-based (read-only)
        "' AND '1'='1",
        "' AND '1'='2",
        "1 AND 1=1",
        "1 AND 1=2",
        # Time-based (read-only, short delays)
        "' AND SLEEP(2)--",
        "'; WAITFOR DELAY '0:0:2'--",
        "' AND pg_sleep(2)--",
    ]

    analyzer = PayloadSafetyAnalyzer(safety_level=safety_level)
    return analyzer.filter_payloads(safe_payloads, PayloadCategory.SQLI)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Enums
    "DestructiveLevel",
    "PayloadCategory",
    # Classes
    "PayloadAnalysis",
    "PayloadSafetyAnalyzer",
    # Functions
    "is_destructive_payload",
    "validate_payload_safety",
    "get_safe_sqli_payloads",
    # Constants
    "SAFETY_LEVELS",
]
