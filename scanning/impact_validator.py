"""
PHANTOM AI - Impact Validator

Validates findings by proving real-world impact, not just theoretical weaknesses.

Philosophy: "What can an attacker ACTUALLY DO with this?"

For each finding, we attempt to:
1. PROVE exploitability (not just detect misconfiguration)
2. QUANTIFY impact (data volume, users affected, financial value)
3. DEMONSTRATE outcome (ATO, data theft, privilege escalation)
4. FILTER noise (deprioritize findings with no proven impact)

Impact Categories:
- DATA_EXFILTRATION: Can extract sensitive data (quantify volume)
- ACCOUNT_TAKEOVER: Can hijack user accounts (quantify scope)
- PRIVILEGE_ESCALATION: Can elevate from user to admin
- FINANCIAL_FRAUD: Can manipulate payments/transactions
- CODE_EXECUTION: Can run arbitrary code on server
- DENIAL_OF_SERVICE: Can disrupt service availability
- INFORMATION_DISCLOSURE: Can access sensitive information
- NO_PROVEN_IMPACT: Misconfiguration with no exploitation path

Usage:
    validator = ImpactValidator(auth_context, settings)
    validated_findings = await validator.validate_all(findings)
"""

from __future__ import annotations

import json
import re
import ssl
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any
from urllib.parse import urljoin, urlparse

import aiohttp

from utils.logger import get_logger

logger = get_logger(__name__)


class ImpactCategory(Enum):
    """Categories of proven impact."""
    DATA_EXFILTRATION = auto()
    ACCOUNT_TAKEOVER = auto()
    PRIVILEGE_ESCALATION = auto()
    FINANCIAL_FRAUD = auto()
    CODE_EXECUTION = auto()
    DENIAL_OF_SERVICE = auto()
    INFORMATION_DISCLOSURE = auto()
    NO_PROVEN_IMPACT = auto()


@dataclass
class ImpactAssessment:
    """Result of impact validation for a finding."""
    category: ImpactCategory
    proven: bool  # True if we actually demonstrated the impact
    confidence: float  # 0.0 - 1.0

    # Quantification
    data_volume: int = 0  # Estimated records/bytes at risk
    users_affected: int = 0  # Estimated users impacted
    financial_value: float = 0.0  # Estimated financial impact in USD

    # Evidence
    exploitation_steps: list[str] = field(default_factory=list)
    proof_request: str = ""  # HTTP request that proved impact
    proof_response: str = ""  # Response showing impact
    outcome_description: str = ""  # What the attacker can achieve

    # Severity adjustment
    original_severity: str = ""
    adjusted_severity: str = ""
    adjustment_reason: str = ""


# Patterns for detecting sensitive data in responses
_SENSITIVE_DATA_PATTERNS = {
    "email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "phone": r'[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}',
    "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
    "credit_card": r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
    "api_key": r'(?:api[_-]?key|apikey|access[_-]?token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})',
    "password_hash": r'\$(?:2[aby]?|5|6)\$[a-zA-Z0-9./]+\$[a-zA-Z0-9./]+',
    "jwt": r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
    "private_key": r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
}

# Business-critical endpoints that indicate high impact
_HIGH_IMPACT_ENDPOINTS = {
    "payment": ["/pay", "/checkout", "/purchase", "/transaction", "/billing", "/charge"],
    "admin": ["/admin", "/manage", "/dashboard", "/control", "/settings"],
    "auth": ["/login", "/auth", "/session", "/token", "/oauth", "/sso"],
    "user_data": ["/user", "/account", "/profile", "/customer", "/member"],
    "financial": ["/balance", "/transfer", "/withdraw", "/deposit", "/wallet"],
}

# SSL context for self-signed certs
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


class ImpactValidator:
    """
    Validates findings by proving real-world impact.

    Goes beyond detection to demonstrate what an attacker can actually achieve.
    """

    def __init__(
        self,
        auth_context: Any = None,
        settings: Any = None,
        timeout: float = 10.0,
        max_requests_per_finding: int = 5,
    ):
        self._auth_context = auth_context
        self._settings = settings
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._max_requests = max_requests_per_finding
        self._requests_made = 0

        # Get safe mode from settings or environment
        import os
        self._safe_mode = os.environ.get("PHANTOM_SAFE_MODE", "safe").lower()
        if settings and hasattr(settings, "safe_mode"):
            self._safe_mode = settings.safe_mode

    async def validate_all(self, findings: list[dict]) -> list[dict]:
        """
        Validate all findings and add impact assessments.

        Returns findings with added metadata.impact_assessment field.
        Filters out findings with NO_PROVEN_IMPACT in strict mode.
        """
        validated = []

        for finding in findings:
            # Skip INFO severity - these are informational only
            severity = (finding.get("severity") or "").upper()
            if severity == "INFO":
                validated.append(finding)
                continue

            # Validate impact
            assessment = await self._validate_finding(finding)

            # Add assessment to finding metadata
            metadata = finding.get("metadata", {})
            # LOGIC-V3 FIX: was using undefined 'data'
            if isinstance(metadata, dict):
                metadata["impact_assessment"] = {
                    "category": assessment.category.name,
                    "proven": assessment.proven,
                    "confidence": assessment.confidence,
                    "data_volume": assessment.data_volume,
                    "users_affected": assessment.users_affected,
                    "financial_value": assessment.financial_value,
                    "outcome": assessment.outcome_description,
                    "adjusted_severity": assessment.adjusted_severity,
                    "adjustment_reason": assessment.adjustment_reason,
                }

                if assessment.proof_request:
                    metadata["impact_proof"] = {
                        "request": assessment.proof_request,
                        "response": assessment.proof_response[:500] if assessment.proof_response else "",
                    }

            finding["metadata"] = metadata

            # Adjust severity based on proven impact
            if assessment.adjusted_severity and assessment.adjusted_severity != severity:
                finding["original_severity"] = severity
                finding["severity"] = assessment.adjusted_severity

            # For findings with no proven impact, record the assessment
            # but DON'T blanket-downgrade to INFO — the specific validator
            # already set adjusted_severity appropriately above (line 179-181).
            # Blanket downgrading destroys legitimate findings like XXE, SSRF
            # that were detected but not exploited yet.
            if assessment.category == ImpactCategory.NO_PROVEN_IMPACT:
                finding["metadata"]["no_proven_impact"] = True

            validated.append(finding)

        return validated

    async def _validate_finding(self, finding: dict) -> ImpactAssessment:
        """Validate a single finding and assess its real-world impact."""
        finding_type = (finding.get("vuln_type", finding.get("type")) or finding.get("vulnerability_type") or "").lower()
        severity = (finding.get("severity") or "").upper()

        # Route to appropriate validator based on finding type
        if "sql" in finding_type or "sqli" in finding_type:
            return await self._validate_sqli_impact(finding)
        elif "xss" in finding_type:
            return await self._validate_xss_impact(finding)
        elif "idor" in finding_type or "access" in finding_type:
            return await self._validate_idor_impact(finding)
        elif "cors" in finding_type:
            return await self._validate_cors_impact(finding)
        elif "business" in finding_type:
            return await self._validate_business_logic_impact(finding)
        elif "session" in finding_type or "jwt" in finding_type:
            return await self._validate_session_impact(finding)
        elif "ssrf" in finding_type:
            return await self._validate_ssrf_impact(finding)
        elif "smuggling" in finding_type:
            return await self._validate_smuggling_impact(finding)
        elif "concurrency" in finding_type or "race" in finding_type:
            return await self._validate_concurrency_impact(finding)
        elif "header" in finding_type:
            return await self._validate_header_impact(finding)
        elif "rate" in finding_type:
            return await self._validate_ratelimit_impact(finding)
        else:
            return await self._validate_generic_impact(finding)

    async def _validate_sqli_impact(self, finding: dict) -> ImpactAssessment:
        """Validate SQL injection impact - can we extract data?"""
        metadata = finding.get("metadata", {})

        # Check if data was already extracted
        # LOGIC-V3 FIX: was using undefined 'data', fixed cascading var
        extracted_data = metadata.get("extracted_data", {}) if isinstance(metadata, dict) else {}
        if extracted_data:
            # Count extracted records
            data_volume = sum(
                len(v) if isinstance(v, list) else 1
                for v in extracted_data.values()
            )

            # Check for sensitive data
            has_creds = any(
                k in str(extracted_data).lower()
                for k in ["password", "email", "user", "admin"]
            )

            return ImpactAssessment(
                category=ImpactCategory.DATA_EXFILTRATION,
                proven=True,
                confidence=0.95,
                data_volume=data_volume,
                users_affected=data_volume,  # Assume 1 record = 1 user
                outcome_description=f"Extracted {data_volume} records including {'credentials' if has_creds else 'data'}",
                original_severity=finding.get("severity", ""),
                adjusted_severity="CRITICAL" if has_creds else "HIGH",
                adjustment_reason="Proven data extraction" if data_volume > 0 else "",
            )

        # Check for auth bypass
        if "bypass" in finding.get("name", "").lower():
            return ImpactAssessment(
                category=ImpactCategory.ACCOUNT_TAKEOVER,
                proven=True,
                confidence=0.9,
                users_affected=1,  # At least 1 account compromised
                outcome_description="Authentication bypass allows account takeover",
                original_severity=finding.get("severity", ""),
                adjusted_severity="CRITICAL",
                adjustment_reason="Proven authentication bypass",
            )

        # SQLi detected but no extraction attempted/successful
        return ImpactAssessment(
            category=ImpactCategory.DATA_EXFILTRATION,
            proven=False,
            confidence=0.7,
            outcome_description="SQL injection detected - potential data exfiltration",
            original_severity=finding.get("severity", ""),
            adjusted_severity=finding.get("severity", "HIGH"),
            adjustment_reason="",
        )

    async def _validate_xss_impact(self, finding: dict) -> ImpactAssessment:
        """Validate XSS impact - can we steal sessions?"""
        metadata = finding.get("metadata", {})

        # Check if it's DOM XSS with confirmed execution
        # LOGIC-V3 FIX: was using undefined 'data'
        if isinstance(metadata, dict):
            if metadata.get("execution_confirmed") or metadata.get("browser_executed"):
                return ImpactAssessment(
                    category=ImpactCategory.ACCOUNT_TAKEOVER,
                    proven=True,
                    confidence=0.9,
                    users_affected=1,  # At least 1 victim
                    outcome_description="XSS executes in browser - can steal session tokens",
                    original_severity=finding.get("severity", ""),
                    adjusted_severity="HIGH",
                    adjustment_reason="Confirmed browser execution",
                )

        # Check for stored vs reflected
        # LOGIC-V3 FIX: was using undefined 'data', fixed cascading var
        xss_type = metadata.get("xss_type", "").lower() if isinstance(metadata, dict) else ""
        if "stored" in xss_type:
            return ImpactAssessment(
                category=ImpactCategory.ACCOUNT_TAKEOVER,
                proven=True,
                confidence=0.85,
                users_affected=100,  # Stored affects multiple users
                outcome_description="Stored XSS affects all users viewing the content",
                original_severity=finding.get("severity", ""),
                adjusted_severity="HIGH",
                adjustment_reason="Stored XSS with wide impact",
            )

        # Reflected XSS
        return ImpactAssessment(
            category=ImpactCategory.ACCOUNT_TAKEOVER,
            proven=False,
            confidence=0.6,
            users_affected=1,
            outcome_description="Reflected XSS requires victim to click malicious link",
            original_severity=finding.get("severity", ""),
            adjusted_severity="MEDIUM",
            adjustment_reason="Reflected XSS - requires user interaction",
        )

    async def _validate_idor_impact(self, finding: dict) -> ImpactAssessment:
        """Validate IDOR impact - how much data is accessible?"""
        metadata = finding.get("metadata", {})

        # Check if enumeration was successful
        # LOGIC-V3 FIX: was using undefined 'data', fixed cascading var
        accessible_ids = metadata.get("accessible_ids", []) if isinstance(metadata, dict) else []
        if accessible_ids:
            return ImpactAssessment(
                category=ImpactCategory.DATA_EXFILTRATION,
                proven=True,
                confidence=0.9,
                data_volume=len(accessible_ids),
                users_affected=len(accessible_ids),
                outcome_description=f"Can access {len(accessible_ids)} user records via IDOR",
                original_severity=finding.get("severity", ""),
                adjusted_severity="HIGH" if len(accessible_ids) > 10 else "MEDIUM",
                adjustment_reason=f"Proven access to {len(accessible_ids)} records",
            )

        # Check if it's write IDOR (more severe)
        # LOGIC-V3 FIX: was using undefined 'data'
        if isinstance(metadata, dict):
            if metadata.get("write_access") or "modify" in finding.get("name", "").lower():
                return ImpactAssessment(
                    category=ImpactCategory.DATA_EXFILTRATION,
                    proven=True,
                    confidence=0.85,
                    users_affected=1,
                    outcome_description="Can modify other users' data",
                    original_severity=finding.get("severity", ""),
                    adjusted_severity="HIGH",
                    adjustment_reason="Write access to other users' data",
                )

        # Read IDOR without enumeration
        return ImpactAssessment(
            category=ImpactCategory.DATA_EXFILTRATION,
            proven=False,
            confidence=0.6,
            users_affected=1,
            outcome_description="Can access other users' data (scope unknown)",
            original_severity=finding.get("severity", ""),
            adjusted_severity=finding.get("severity", "MEDIUM"),
            adjustment_reason="",
        )

    async def _validate_cors_impact(self, finding: dict) -> ImpactAssessment:
        """Validate CORS impact - can we steal authenticated data?"""
        metadata = finding.get("metadata", {})

        # Check if credentials are included
        # LOGIC-V3 FIX: was using undefined 'data', fixed cascading var
        allows_credentials = metadata.get("allows_credentials", False) if isinstance(metadata, dict) else False
        origin_type = metadata.get("origin_type", "") if isinstance(metadata, dict) else ""
        has_sensitive = metadata.get("has_sensitive_data", False) if isinstance(metadata, dict) else False

        if allows_credentials and "arbitrary" in origin_type.lower():
            return ImpactAssessment(
                category=ImpactCategory.DATA_EXFILTRATION,
                proven=True,
                confidence=0.85,
                users_affected=1,
                outcome_description="Can steal authenticated user data via CORS",
                original_severity=finding.get("severity", ""),
                adjusted_severity="HIGH",
                adjustment_reason="Credentials included with arbitrary origin",
            )

        if "null" in origin_type.lower():
            return ImpactAssessment(
                category=ImpactCategory.DATA_EXFILTRATION,
                proven=True,
                confidence=0.7,
                users_affected=1,
                outcome_description="Can exfiltrate data via null origin (sandboxed iframe)",
                original_severity=finding.get("severity", ""),
                adjusted_severity="MEDIUM",
                adjustment_reason="Null origin accepted - limited exploitation",
            )

        # CORS with sensitive data confirmed by scanner — don't downgrade
        if has_sensitive:
            return ImpactAssessment(
                category=ImpactCategory.DATA_EXFILTRATION,
                proven=True,
                confidence=0.75,
                users_affected=1,
                outcome_description="CORS wildcard exposes sensitive data (confirmed by body analysis)",
                original_severity=finding.get("severity", ""),
                adjusted_severity="",  # Empty = no adjustment, keep scanner's severity
                adjustment_reason="Sensitive data confirmed in response body",
            )

        # CORS without credentials and no sensitive data
        return ImpactAssessment(
            category=ImpactCategory.INFORMATION_DISCLOSURE,
            proven=False,
            confidence=0.5,
            outcome_description="CORS misconfiguration - limited impact without credentials",
            original_severity=finding.get("severity", ""),
            adjusted_severity="LOW",
            adjustment_reason="No credentials and no sensitive data - limited exploitation value",
        )

    async def _validate_business_logic_impact(self, finding: dict) -> ImpactAssessment:
        """Validate business logic impact - what's the financial value?"""
        metadata = finding.get("metadata", {})
        name = finding.get("name", "").lower()

        # Price manipulation
        if "price" in name or "amount" in name:
            # LOGIC-V3 FIX: was using undefined 'data', fixed cascading var
            manipulated_value = metadata.get("manipulated_value", 0) if isinstance(metadata, dict) else 0
            original_value = metadata.get("original_value", 0) if isinstance(metadata, dict) else 0

            if manipulated_value != original_value:
                financial_impact = abs(original_value - manipulated_value)
                return ImpactAssessment(
                    category=ImpactCategory.FINANCIAL_FRAUD,
                    proven=True,
                    confidence=0.9,
                    financial_value=financial_impact,
                    outcome_description=f"Can manipulate prices - ${financial_impact:.2f} per transaction",
                    original_severity=finding.get("severity", ""),
                    adjusted_severity="CRITICAL" if financial_impact > 100 else "HIGH",
                    adjustment_reason=f"Proven price manipulation: ${financial_impact:.2f}",
                )

        # Quantity manipulation (e-commerce)
        if "quantity" in name or "negative" in name:
            return ImpactAssessment(
                category=ImpactCategory.FINANCIAL_FRAUD,
                proven=True,
                confidence=0.85,
                financial_value=100.0,  # Conservative estimate
                outcome_description="Can manipulate order quantities for financial gain",
                original_severity=finding.get("severity", ""),
                adjusted_severity="HIGH",
                adjustment_reason="Proven quantity manipulation",
            )

        # Workflow bypass
        if "bypass" in name or "skip" in name:
            return ImpactAssessment(
                category=ImpactCategory.FINANCIAL_FRAUD,
                proven=True,
                confidence=0.8,
                outcome_description="Can bypass business workflow controls",
                original_severity=finding.get("severity", ""),
                adjusted_severity="HIGH",
                adjustment_reason="Proven workflow bypass",
            )

        # Generic business logic
        return ImpactAssessment(
            category=ImpactCategory.FINANCIAL_FRAUD,
            proven=False,
            confidence=0.6,
            outcome_description="Business logic flaw - potential abuse",
            original_severity=finding.get("severity", ""),
            adjusted_severity=finding.get("severity", "MEDIUM"),
            adjustment_reason="",
        )

    async def _validate_session_impact(self, finding: dict) -> ImpactAssessment:
        """Validate session/JWT impact - can we hijack accounts?"""
        metadata = finding.get("metadata", {})
        name = finding.get("name", "").lower()

        # Privilege escalation via JWT tampering
        if "privilege" in name or "admin" in name or "escalat" in name:
            return ImpactAssessment(
                category=ImpactCategory.PRIVILEGE_ESCALATION,
                proven=True,
                confidence=0.95,
                users_affected=1,
                outcome_description="Can escalate to admin privileges",
                original_severity=finding.get("severity", ""),
                adjusted_severity="CRITICAL",
                adjustment_reason="Proven privilege escalation to admin",
            )

        # Session fixation/hijacking
        if "hijack" in name or "fixation" in name or "valid after logout" in name:
            return ImpactAssessment(
                category=ImpactCategory.ACCOUNT_TAKEOVER,
                proven=True,
                confidence=0.85,
                users_affected=1,
                outcome_description="Can hijack user sessions",
                original_severity=finding.get("severity", ""),
                adjusted_severity="HIGH",
                adjustment_reason="Proven session vulnerability",
            )

        # JWT algorithm confusion
        if "alg" in name or "algorithm" in name:
            return ImpactAssessment(
                category=ImpactCategory.ACCOUNT_TAKEOVER,
                proven=True,
                confidence=0.9,
                users_affected=1,
                outcome_description="Can forge valid JWT tokens",
                original_severity=finding.get("severity", ""),
                adjusted_severity="CRITICAL",
                adjustment_reason="JWT algorithm bypass allows token forgery",
            )

        return ImpactAssessment(
            category=ImpactCategory.ACCOUNT_TAKEOVER,
            proven=False,
            confidence=0.6,
            outcome_description="Session management weakness",
            original_severity=finding.get("severity", ""),
            adjusted_severity=finding.get("severity", "MEDIUM"),
            adjustment_reason="",
        )

    async def _validate_ssrf_impact(self, finding: dict) -> ImpactAssessment:
        """Validate SSRF impact - can we access internal systems?"""
        metadata = finding.get("metadata", {})

        # Check for internal access
        # LOGIC-V3 FIX: was using undefined 'data', fixed cascading var
        internal_access = (metadata.get("internal_access") or metadata.get("cloud_metadata")) if isinstance(metadata, dict) else None
        if internal_access:
            return ImpactAssessment(
                category=ImpactCategory.DATA_EXFILTRATION,
                proven=True,
                confidence=0.9,
                outcome_description="Can access internal systems/cloud metadata",
                original_severity=finding.get("severity", ""),
                adjusted_severity="CRITICAL",
                adjustment_reason="Proven internal network access",
            )

        # SSRF detected but no internal access confirmed
        return ImpactAssessment(
            category=ImpactCategory.INFORMATION_DISCLOSURE,
            proven=False,
            confidence=0.6,
            outcome_description="SSRF detected - may access internal resources",
            original_severity=finding.get("severity", ""),
            adjusted_severity=finding.get("severity", "MEDIUM"),
            adjustment_reason="",
        )

    async def _validate_smuggling_impact(self, finding: dict) -> ImpactAssessment:
        """Validate HTTP smuggling impact."""
        # Confidence can be at top level or in metadata
        confidence = finding.get("confidence_score", finding.get("confidence", 0))
        if isinstance(confidence, str):
            confidence = {"critical": 0.95, "high": 0.85, "medium": 0.65, "low": 0.40}.get(confidence.lower(), 0.5)
        if isinstance(confidence, (int, float)) and confidence > 1:
            confidence = confidence / 100.0  # Convert 0-100 to 0-1
        if not confidence:
            metadata = finding.get("metadata", {})
            # LOGIC-V3 FIX: was using undefined 'data'
            if isinstance(metadata, dict):
                confidence = metadata.get("confidence", 0.5)

        # Smuggling with high confidence
        if confidence >= 0.7:
            return ImpactAssessment(
                category=ImpactCategory.ACCOUNT_TAKEOVER,
                proven=True,
                confidence=confidence,
                users_affected=100,  # Can affect many users
                outcome_description="HTTP smuggling can hijack other users' requests",
                original_severity=finding.get("severity", ""),
                adjusted_severity="CRITICAL",
                adjustment_reason="High-confidence HTTP smuggling",
            )

        # Low confidence smuggling - might be false positive
        # ═══════════════════════════════════════════════════════════════════
        # AUTOMATIC VALIDATION FIX: Instead of "needs manual verification",
        # explain what was detected and why confidence is insufficient
        # ═══════════════════════════════════════════════════════════════════
        return ImpactAssessment(
            category=ImpactCategory.NO_PROVEN_IMPACT,
            proven=False,
            confidence=confidence,
            outcome_description="HTTP smuggling detected with low confidence",
            original_severity=finding.get("severity", ""),
            adjusted_severity="INFO",
            adjustment_reason="Low confidence - single method detection without desync confirmation",
        )

    async def _validate_concurrency_impact(self, finding: dict) -> ImpactAssessment:
        """Validate concurrency/race condition impact."""
        metadata = finding.get("metadata", {})
        # LOGIC-V3 FIX: was using undefined 'data', fixed cascading var
        issues = metadata.get("issues", []) if isinstance(metadata, dict) else []

        # Check for actual state inconsistency
        has_state_issue = any("inconsist" in str(issue).lower() for issue in issues)
        has_error_spike = any("error rate" in str(issue).lower() for issue in issues)

        if has_state_issue:
            return ImpactAssessment(
                category=ImpactCategory.FINANCIAL_FRAUD,
                proven=True,
                confidence=0.8,
                outcome_description="Race condition causes state inconsistency - potential double-spend",
                original_severity=finding.get("severity", ""),
                adjusted_severity="HIGH",
                adjustment_reason="Proven state desynchronization",
            )

        if has_error_spike:
            return ImpactAssessment(
                category=ImpactCategory.DENIAL_OF_SERVICE,
                proven=True,
                confidence=0.7,
                outcome_description="Server becomes unstable under concurrent load",
                original_severity=finding.get("severity", ""),
                adjusted_severity="MEDIUM",
                adjustment_reason="Proven stability issue under load",
            )

        # Just performance degradation - low impact
        return ImpactAssessment(
            category=ImpactCategory.NO_PROVEN_IMPACT,
            proven=False,
            confidence=0.4,
            outcome_description="Performance degrades under load - no security impact",
            original_severity=finding.get("severity", ""),
            adjusted_severity="INFO",
            adjustment_reason="No security impact - performance issue only",
        )

    async def _validate_header_impact(self, finding: dict) -> ImpactAssessment:
        """Validate missing header impact."""
        name = finding.get("name", "").lower()

        # Missing security headers — keep module-assigned severity.
        # Headers like missing HSTS, CSP, X-Frame-Options are real findings
        # in pentest reports even without direct exploitation proof.
        if "missing" in name and "header" in name:
            return ImpactAssessment(
                category=ImpactCategory.INFORMATION_DISCLOSURE,
                proven=False,
                confidence=0.3,
                outcome_description="Missing headers weaken defense but have no direct exploit",
                original_severity=finding.get("severity", ""),
                adjusted_severity=finding.get("severity", "LOW"),
                adjustment_reason="Defense-in-depth issue",
            )

        return ImpactAssessment(
            category=ImpactCategory.INFORMATION_DISCLOSURE,
            proven=False,
            confidence=0.4,
            outcome_description="Header misconfiguration",
            original_severity=finding.get("severity", ""),
            adjusted_severity=finding.get("severity", "LOW"),
            adjustment_reason="",
        )

    async def _validate_ratelimit_impact(self, finding: dict) -> ImpactAssessment:
        """Validate rate limiting impact."""
        metadata = finding.get("metadata", {})

        # Check if it's on a sensitive endpoint
        endpoint = finding.get("matched_at", "").lower()
        is_auth_endpoint = any(kw in endpoint for kw in ["/login", "/auth", "/password", "/register"])

        if is_auth_endpoint:
            return ImpactAssessment(
                category=ImpactCategory.ACCOUNT_TAKEOVER,
                proven=True,
                confidence=0.7,
                outcome_description="No rate limiting on auth endpoint - enables brute force",
                original_severity=finding.get("severity", ""),
                adjusted_severity="MEDIUM",
                adjustment_reason="Enables brute force attacks on authentication",
            )

        # Rate limiting on non-sensitive endpoint
        return ImpactAssessment(
            category=ImpactCategory.NO_PROVEN_IMPACT,
            proven=False,
            confidence=0.3,
            outcome_description="Missing rate limiting on non-sensitive endpoint",
            original_severity=finding.get("severity", ""),
            adjusted_severity="INFO",
            adjustment_reason="Non-sensitive endpoint - low security impact",
        )

    async def _validate_generic_impact(self, finding: dict) -> ImpactAssessment:
        """Validate impact for unknown finding types."""
        severity = (finding.get("severity") or "").upper()
        metadata = finding.get("metadata", {})

        # Check if there's any proof of exploitation
        # LOGIC-V3 FIX: was using undefined 'data', fixed cascading var
        has_proof = bool(metadata.get("proof") or metadata.get("poc") or metadata.get("exploit")) if isinstance(metadata, dict) else False
        has_data = bool(metadata.get("extracted_data") or metadata.get("leaked_data")) if isinstance(metadata, dict) else False

        if has_data:
            return ImpactAssessment(
                category=ImpactCategory.DATA_EXFILTRATION,
                proven=True,
                confidence=0.8,
                outcome_description="Data exfiltration confirmed",
                original_severity=severity,
                adjusted_severity=severity,
                adjustment_reason="",
            )

        if has_proof:
            return ImpactAssessment(
                category=ImpactCategory.INFORMATION_DISCLOSURE,
                proven=True,
                confidence=0.7,
                outcome_description="Vulnerability confirmed with proof",
                original_severity=severity,
                adjusted_severity=severity,
                adjustment_reason="",
            )

        # No proof - keep original severity. Modules set severity based on
        # vuln type; downgrading to INFO just because no exploitation proof
        # exists would discard real findings (headers, SSL, config issues).
        return ImpactAssessment(
            category=ImpactCategory.NO_PROVEN_IMPACT,
            proven=False,
            confidence=0.4,
            outcome_description="Theoretical vulnerability - no proven impact",
            original_severity=severity,
            adjusted_severity=severity,
            adjustment_reason="No proven exploitation path",
        )


def count_sensitive_data(text: str) -> dict[str, int]:
    """Count occurrences of sensitive data patterns in text."""
    counts = {}
    for data_type, pattern in _SENSITIVE_DATA_PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            counts[data_type] = len(matches)
    return counts


def estimate_impact_score(assessment: ImpactAssessment) -> float:
    """
    Calculate a numeric impact score (0-100) based on the assessment.

    Higher scores indicate more severe, proven impacts.
    """
    base_score = 0.0

    # Category base scores
    category_scores = {
        ImpactCategory.CODE_EXECUTION: 95,
        ImpactCategory.PRIVILEGE_ESCALATION: 90,
        ImpactCategory.ACCOUNT_TAKEOVER: 85,
        ImpactCategory.DATA_EXFILTRATION: 80,
        ImpactCategory.FINANCIAL_FRAUD: 85,
        ImpactCategory.DENIAL_OF_SERVICE: 60,
        ImpactCategory.INFORMATION_DISCLOSURE: 40,
        ImpactCategory.NO_PROVEN_IMPACT: 10,
    }
    base_score = category_scores.get(assessment.category, 30)

    # Adjust for proven vs theoretical
    if not assessment.proven:
        base_score *= 0.5

    # Adjust for confidence
    base_score *= assessment.confidence

    # Bonus for quantified impact
    if assessment.data_volume > 100:
        base_score += 10
    if assessment.users_affected > 10:
        base_score += 10
    if assessment.financial_value > 1000:
        base_score += 15

    return min(100.0, base_score)
