"""
Unified Finding System for PHANTOM AI Security Scanner.

This module provides a single, comprehensive Finding class that replaces
all the various Finding classes scattered across the codebase.

Benefits:
- Consistent serialization/deserialization
- Unified validation pipeline
- Easier aggregation and deduplication
- Simplified reporting
- Type safety with enums

Migration:
- Replace AuthzFinding, DisclosureFinding, CMDiFinding, etc. with Finding
- Use VulnType enum instead of string types
- Use VulnCategory for grouping

Author: PHANTOM AI
Version: 2.0.0
Date: 2026-02-24
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Iterator, Optional
from uuid import uuid4


# =============================================================================
# ENUMS
# =============================================================================

class VulnCategory(Enum):
    """High-level vulnerability categories for grouping."""

    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DISCLOSURE = "disclosure"
    CONFIGURATION = "configuration"
    CRYPTOGRAPHY = "cryptography"
    SESSION = "session"
    BUSINESS_LOGIC = "business_logic"
    CLIENT_SIDE = "client_side"
    SERVER_SIDE = "server_side"
    API = "api"
    INFRASTRUCTURE = "infrastructure"
    UNKNOWN = "unknown"


class VulnType(Enum):
    """Specific vulnerability types."""

    # Injection
    SQLI = "sqli"
    SQLI_BLIND = "sqli_blind"
    SQLI_TIME_BASED = "sqli_time_based"
    SQLI_ERROR_BASED = "sqli_error_based"
    SQLI_UNION = "sqli_union"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    CMDI = "cmdi"
    CMDI_BLIND = "cmdi_blind"
    SSTI = "ssti"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    XXE = "xxe"
    XXE_BLIND = "xxe_blind"
    NOSQL_INJECTION = "nosql_injection"
    CRLF = "crlf"

    # Authentication
    AUTH_BYPASS = "auth_bypass"
    WEAK_PASSWORD = "weak_password"
    DEFAULT_CREDENTIALS = "default_credentials"
    BRUTE_FORCE = "brute_force"
    MFA_BYPASS = "mfa_bypass"
    JWT_VULNERABILITY = "jwt_vulnerability"
    OAUTH_MISCONFIGURATION = "oauth_misconfiguration"
    SAML_VULNERABILITY = "saml_vulnerability"

    # Authorization
    IDOR = "idor"
    BOLA = "bola"
    BFLA = "bfla"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    HORIZONTAL_PRIVESC = "horizontal_privesc"
    VERTICAL_PRIVESC = "vertical_privesc"
    MASS_ASSIGNMENT = "mass_assignment"

    # Disclosure
    INFO_DISCLOSURE = "info_disclosure"
    EXCESSIVE_DATA_EXPOSURE = "excessive_data_exposure"
    DEBUG_ENDPOINT = "debug_endpoint"
    SOURCE_CODE_DISCLOSURE = "source_code_disclosure"
    BACKUP_FILE = "backup_file"
    DIRECTORY_LISTING = "directory_listing"
    ERROR_DISCLOSURE = "error_disclosure"
    STACK_TRACE = "stack_trace"
    API_DOCS_EXPOSED = "api_docs_exposed"

    # Configuration
    CORS_MISCONFIGURATION = "cors_misconfiguration"
    SECURITY_HEADERS_MISSING = "security_headers_missing"
    SSL_TLS_ISSUE = "ssl_tls_issue"
    CLICKJACKING = "clickjacking"
    COOKIE_SECURITY = "cookie_security"
    HOST_HEADER_INJECTION = "host_header_injection"

    # Server-side
    SSRF = "ssrf"
    SSRF_BLIND = "ssrf_blind"
    LFI = "lfi"
    RFI = "rfi"
    PATH_TRAVERSAL = "path_traversal"
    FILE_UPLOAD = "file_upload"
    DESERIALIZATION = "deserialization"
    HTTP_SMUGGLING = "http_smuggling"
    CACHE_POISONING = "cache_poisoning"
    CACHE_DECEPTION = "cache_deception"

    # Client-side
    CSRF = "csrf"
    OPEN_REDIRECT = "open_redirect"
    DOM_CLOBBERING = "dom_clobbering"
    PROTOTYPE_POLLUTION = "prototype_pollution"

    # Business Logic
    RACE_CONDITION = "race_condition"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    LOGIC_FLAW = "logic_flaw"
    WORKFLOW_BYPASS = "workflow_bypass"

    # Session
    SESSION_FIXATION = "session_fixation"
    SESSION_HIJACKING = "session_hijacking"
    INSECURE_SESSION = "insecure_session"

    # API
    GRAPHQL_INTROSPECTION = "graphql_introspection"
    GRAPHQL_INJECTION = "graphql_injection"
    WEBSOCKET_VULNERABILITY = "websocket_vulnerability"
    GRPC_VULNERABILITY = "grpc_vulnerability"

    # Infrastructure
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    DNS_REBINDING = "dns_rebinding"
    CLOUD_MISCONFIGURATION = "cloud_misconfiguration"
    KUBERNETES_VULNERABILITY = "kubernetes_vulnerability"

    # Other
    OTHER = "other"
    UNKNOWN = "unknown"


class Severity(Enum):
    """Severity levels with CVSS score ranges."""

    CRITICAL = "CRITICAL"  # CVSS 9.0-10.0
    HIGH = "HIGH"          # CVSS 7.0-8.9
    MEDIUM = "MEDIUM"      # CVSS 4.0-6.9
    LOW = "LOW"            # CVSS 0.1-3.9
    INFO = "INFO"          # CVSS 0.0

    @property
    def cvss_range(self) -> tuple[float, float]:
        """Return CVSS score range for this severity."""
        ranges = {
            Severity.CRITICAL: (9.0, 10.0),
            Severity.HIGH: (7.0, 8.9),
            Severity.MEDIUM: (4.0, 6.9),
            Severity.LOW: (0.1, 3.9),
            Severity.INFO: (0.0, 0.0),
        }
        return ranges[self]

    @property
    def default_cvss(self) -> float:
        """Return default CVSS score for this severity."""
        defaults = {
            Severity.CRITICAL: 9.5,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.5,
            Severity.LOW: 2.5,
            Severity.INFO: 0.0,
        }
        return defaults[self]

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Determine severity from CVSS score."""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0.0:
            return cls.LOW
        return cls.INFO


class Confidence(Enum):
    """Confidence levels for findings."""

    CONFIRMED = "confirmed"    # 90-100% - Exploited/validated
    HIGH = "high"              # 75-89% - Strong indicators
    MEDIUM = "medium"          # 50-74% - Likely but not confirmed
    LOW = "low"                # 25-49% - Possible
    TENTATIVE = "tentative"    # 0-24% - Needs investigation

    @property
    def score_range(self) -> tuple[float, float]:
        """Return confidence score range."""
        ranges = {
            Confidence.CONFIRMED: (90.0, 100.0),
            Confidence.HIGH: (75.0, 89.9),
            Confidence.MEDIUM: (50.0, 74.9),
            Confidence.LOW: (25.0, 49.9),
            Confidence.TENTATIVE: (0.0, 24.9),
        }
        return ranges[self]

    @classmethod
    def from_score(cls, score: float) -> "Confidence":
        """Determine confidence level from score."""
        if score >= 90.0:
            return cls.CONFIRMED
        elif score >= 75.0:
            return cls.HIGH
        elif score >= 50.0:
            return cls.MEDIUM
        elif score >= 25.0:
            return cls.LOW
        return cls.TENTATIVE


# =============================================================================
# EVIDENCE STRUCTURES
# =============================================================================

@dataclass
class HttpEvidence:
    """HTTP request/response evidence."""

    request_method: str = ""
    request_url: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    response_status: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_time_ms: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    def summary(self, max_body_length: int = 500) -> str:
        """Return a summary string for reports."""
        lines = [
            f"{self.request_method} {self.request_url}",
            f"Status: {self.response_status}",
        ]
        if self.request_body:
            body = self.request_body[:max_body_length]
            if len(self.request_body) > max_body_length:
                body += "..."
            lines.append(f"Request Body: {body}")
        if self.response_body:
            body = self.response_body[:max_body_length]
            if len(self.response_body) > max_body_length:
                body += "..."
            lines.append(f"Response Body: {body}")
        return "\n".join(lines)


@dataclass
class ProofOfConcept:
    """Proof of concept for a vulnerability."""

    title: str = ""
    description: str = ""
    steps: list[str] = field(default_factory=list)
    payload: str = ""
    curl_command: str = ""
    script: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# =============================================================================
# MAIN FINDING CLASS
# =============================================================================

@dataclass
class Finding:
    """
    Unified finding class for all vulnerability types.

    This replaces all the various Finding classes (AuthzFinding, DisclosureFinding, etc.)
    across the codebase with a single, comprehensive structure.

    Usage:
        finding = Finding(
            vuln_type=VulnType.SQLI,
            severity=Severity.CRITICAL,
            endpoint="/api/users",
            parameter="id",
            description="SQL injection in user ID parameter",
        )
    """

    # ==========================================================================
    # IDENTITY
    # ==========================================================================
    id: str = ""
    vuln_type: VulnType = VulnType.UNKNOWN
    category: VulnCategory = VulnCategory.UNKNOWN

    # ==========================================================================
    # LOCATION
    # ==========================================================================
    host: str = ""
    endpoint: str = ""
    parameter: str = ""
    method: str = "GET"

    # ==========================================================================
    # SEVERITY & CONFIDENCE
    # ==========================================================================
    severity: Severity = Severity.INFO
    confidence_score: float = 50.0
    cvss_score: float = 0.0
    cvss_vector: str = ""

    # ==========================================================================
    # DESCRIPTION
    # ==========================================================================
    name: str = ""
    title: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""

    # ==========================================================================
    # EVIDENCE
    # ==========================================================================
    evidence: list[str] = field(default_factory=list)
    http_evidence: Optional[HttpEvidence] = None
    proof_of_concept: Optional[ProofOfConcept] = None
    screenshots: list[str] = field(default_factory=list)

    # ==========================================================================
    # STANDARDS MAPPING
    # ==========================================================================
    cwe_id: str = ""
    cwe_name: str = ""
    owasp_category: str = ""
    owasp_2021: str = ""
    references: list[str] = field(default_factory=list)

    # ==========================================================================
    # METADATA
    # ==========================================================================
    scanner: str = ""
    scan_id: str = ""
    timestamp: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    # ==========================================================================
    # VALIDATION STATE
    # ==========================================================================
    validated: bool = False
    validation_method: str = ""
    false_positive: bool = False
    fp_reason: str = ""
    duplicate_of: str = ""

    # ==========================================================================
    # CHAIN INFORMATION
    # ==========================================================================
    chain_id: str = ""
    chain_position: int = 0
    enables_findings: list[str] = field(default_factory=list)
    requires_findings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Initialize and validate finding."""
        # Coerce string vuln_type to VulnType enum
        if isinstance(self.vuln_type, str):
            try:
                self.vuln_type = VulnType(self.vuln_type)
            except ValueError:
                self.vuln_type = VulnType.OTHER

        # Coerce string severity to Severity enum
        if isinstance(self.severity, str):
            try:
                self.severity = Severity(self.severity.upper())
            except ValueError:
                self.severity = Severity.MEDIUM

        # Coerce string category to VulnCategory enum
        if isinstance(self.category, str):
            try:
                self.category = VulnCategory(self.category)
            except ValueError:
                self.category = VulnCategory.UNKNOWN

        # Generate ID if not provided
        if not self.id:
            self.id = self._generate_id()

        # Set timestamp if not provided
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat()

        # Infer category from vuln_type if not set
        if self.category == VulnCategory.UNKNOWN and self.vuln_type != VulnType.UNKNOWN:
            self.category = self._infer_category()

        # Calculate CVSS from severity if not provided
        if self.cvss_score == 0.0 and self.severity != Severity.INFO:
            self.cvss_score = self.severity.default_cvss

        # Generate name/title if not provided
        if not self.name:
            self.name = self.vuln_type.value.replace("_", " ").title()
        if not self.title:
            self.title = self.name

        # Normalize confidence score
        self.confidence_score = max(0.0, min(100.0, self.confidence_score))

    def _generate_id(self) -> str:
        """Generate a unique finding ID."""
        content = f"{self.vuln_type.value}:{self.host}:{self.endpoint}:{self.parameter}"
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:12]
        return f"FIND-{content_hash}-{uuid4().hex[:8]}"

    def _infer_category(self) -> VulnCategory:
        """Infer category from vulnerability type."""
        type_to_category = {
            # Injection
            VulnType.SQLI: VulnCategory.INJECTION,
            VulnType.SQLI_BLIND: VulnCategory.INJECTION,
            VulnType.SQLI_TIME_BASED: VulnCategory.INJECTION,
            VulnType.SQLI_ERROR_BASED: VulnCategory.INJECTION,
            VulnType.SQLI_UNION: VulnCategory.INJECTION,
            VulnType.XSS_REFLECTED: VulnCategory.INJECTION,
            VulnType.XSS_STORED: VulnCategory.INJECTION,
            VulnType.XSS_DOM: VulnCategory.CLIENT_SIDE,
            VulnType.CMDI: VulnCategory.INJECTION,
            VulnType.CMDI_BLIND: VulnCategory.INJECTION,
            VulnType.SSTI: VulnCategory.INJECTION,
            VulnType.XXE: VulnCategory.INJECTION,
            VulnType.XXE_BLIND: VulnCategory.INJECTION,
            VulnType.NOSQL_INJECTION: VulnCategory.INJECTION,
            VulnType.CRLF: VulnCategory.INJECTION,
            VulnType.LDAP_INJECTION: VulnCategory.INJECTION,
            VulnType.XPATH_INJECTION: VulnCategory.INJECTION,

            # Auth
            VulnType.AUTH_BYPASS: VulnCategory.AUTHENTICATION,
            VulnType.WEAK_PASSWORD: VulnCategory.AUTHENTICATION,
            VulnType.DEFAULT_CREDENTIALS: VulnCategory.AUTHENTICATION,
            VulnType.BRUTE_FORCE: VulnCategory.AUTHENTICATION,
            VulnType.MFA_BYPASS: VulnCategory.AUTHENTICATION,
            VulnType.JWT_VULNERABILITY: VulnCategory.AUTHENTICATION,
            VulnType.OAUTH_MISCONFIGURATION: VulnCategory.AUTHENTICATION,
            VulnType.SAML_VULNERABILITY: VulnCategory.AUTHENTICATION,

            # Authz
            VulnType.IDOR: VulnCategory.AUTHORIZATION,
            VulnType.BOLA: VulnCategory.AUTHORIZATION,
            VulnType.BFLA: VulnCategory.AUTHORIZATION,
            VulnType.PRIVILEGE_ESCALATION: VulnCategory.AUTHORIZATION,
            VulnType.HORIZONTAL_PRIVESC: VulnCategory.AUTHORIZATION,
            VulnType.VERTICAL_PRIVESC: VulnCategory.AUTHORIZATION,
            VulnType.MASS_ASSIGNMENT: VulnCategory.AUTHORIZATION,

            # Disclosure
            VulnType.INFO_DISCLOSURE: VulnCategory.DISCLOSURE,
            VulnType.DEBUG_ENDPOINT: VulnCategory.DISCLOSURE,
            VulnType.SOURCE_CODE_DISCLOSURE: VulnCategory.DISCLOSURE,
            VulnType.BACKUP_FILE: VulnCategory.DISCLOSURE,
            VulnType.DIRECTORY_LISTING: VulnCategory.DISCLOSURE,
            VulnType.ERROR_DISCLOSURE: VulnCategory.DISCLOSURE,
            VulnType.STACK_TRACE: VulnCategory.DISCLOSURE,
            VulnType.API_DOCS_EXPOSED: VulnCategory.DISCLOSURE,

            # Config
            VulnType.CORS_MISCONFIGURATION: VulnCategory.CONFIGURATION,
            VulnType.SECURITY_HEADERS_MISSING: VulnCategory.CONFIGURATION,
            VulnType.SSL_TLS_ISSUE: VulnCategory.CONFIGURATION,
            VulnType.CLICKJACKING: VulnCategory.CONFIGURATION,
            VulnType.COOKIE_SECURITY: VulnCategory.CONFIGURATION,
            VulnType.HOST_HEADER_INJECTION: VulnCategory.CONFIGURATION,

            # Server-side
            VulnType.SSRF: VulnCategory.SERVER_SIDE,
            VulnType.SSRF_BLIND: VulnCategory.SERVER_SIDE,
            VulnType.LFI: VulnCategory.SERVER_SIDE,
            VulnType.RFI: VulnCategory.SERVER_SIDE,
            VulnType.PATH_TRAVERSAL: VulnCategory.SERVER_SIDE,
            VulnType.FILE_UPLOAD: VulnCategory.SERVER_SIDE,
            VulnType.DESERIALIZATION: VulnCategory.SERVER_SIDE,
            VulnType.HTTP_SMUGGLING: VulnCategory.SERVER_SIDE,
            VulnType.CACHE_POISONING: VulnCategory.SERVER_SIDE,
            VulnType.CACHE_DECEPTION: VulnCategory.SERVER_SIDE,

            # Client-side
            VulnType.CSRF: VulnCategory.CLIENT_SIDE,
            VulnType.OPEN_REDIRECT: VulnCategory.CLIENT_SIDE,
            VulnType.DOM_CLOBBERING: VulnCategory.CLIENT_SIDE,
            VulnType.PROTOTYPE_POLLUTION: VulnCategory.CLIENT_SIDE,

            # Business logic
            VulnType.RACE_CONDITION: VulnCategory.BUSINESS_LOGIC,
            VulnType.RATE_LIMIT_BYPASS: VulnCategory.BUSINESS_LOGIC,
            VulnType.LOGIC_FLAW: VulnCategory.BUSINESS_LOGIC,
            VulnType.WORKFLOW_BYPASS: VulnCategory.BUSINESS_LOGIC,

            # Session
            VulnType.SESSION_FIXATION: VulnCategory.SESSION,
            VulnType.SESSION_HIJACKING: VulnCategory.SESSION,
            VulnType.INSECURE_SESSION: VulnCategory.SESSION,

            # API
            VulnType.GRAPHQL_INTROSPECTION: VulnCategory.API,
            VulnType.GRAPHQL_INJECTION: VulnCategory.API,
            VulnType.WEBSOCKET_VULNERABILITY: VulnCategory.API,
            VulnType.GRPC_VULNERABILITY: VulnCategory.API,

            # Infrastructure
            VulnType.SUBDOMAIN_TAKEOVER: VulnCategory.INFRASTRUCTURE,
            VulnType.DNS_REBINDING: VulnCategory.INFRASTRUCTURE,
            VulnType.CLOUD_MISCONFIGURATION: VulnCategory.INFRASTRUCTURE,
            VulnType.KUBERNETES_VULNERABILITY: VulnCategory.INFRASTRUCTURE,
        }
        return type_to_category.get(self.vuln_type, VulnCategory.UNKNOWN)

    # ==========================================================================
    # PROPERTIES
    # ==========================================================================

    @property
    def confidence(self) -> Confidence:
        """Return confidence level enum from score."""
        return Confidence.from_score(self.confidence_score)

    @property
    def is_critical(self) -> bool:
        """Check if finding is critical severity."""
        return self.severity == Severity.CRITICAL

    @property
    def is_high_confidence(self) -> bool:
        """Check if finding has high confidence."""
        return self.confidence_score >= 75.0

    @property
    def is_actionable(self) -> bool:
        """Check if finding is actionable (high severity + confidence)."""
        return (
            self.severity in (Severity.CRITICAL, Severity.HIGH) and
            self.confidence_score >= 50.0 and
            not self.false_positive
        )

    @property
    def full_url(self) -> str:
        """Return full URL of finding."""
        if self.endpoint.startswith("http"):
            return self.endpoint
        return f"{self.host.rstrip('/')}/{self.endpoint.lstrip('/')}"

    # ==========================================================================
    # SERIALIZATION
    # ==========================================================================

    def to_dict(self) -> dict[str, Any]:
        """Convert finding to dictionary for serialization."""
        data = {
            "id": self.id,
            "vuln_type": self.vuln_type.value,
            "category": self.category.value,
            "host": self.host,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "method": self.method,
            "severity": self.severity.value,
            "confidence_score": self.confidence_score,
            "confidence": self.confidence.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "impact": self.impact,
            "remediation": self.remediation,
            "evidence": self.evidence,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "owasp_category": self.owasp_category,
            "owasp_2021": self.owasp_2021,
            "references": self.references,
            "scanner": self.scanner,
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
            "tags": self.tags,
            "validated": self.validated,
            "validation_method": self.validation_method,
            "false_positive": self.false_positive,
            "fp_reason": self.fp_reason,
            "duplicate_of": self.duplicate_of,
            "chain_id": self.chain_id,
            "chain_position": self.chain_position,
            "enables_findings": self.enables_findings,
            "requires_findings": self.requires_findings,
            # Legacy compatibility: many consumers read "matched_at"
            "matched_at": self.endpoint or self.host,
        }

        # Add evidence objects
        if self.http_evidence:
            data["http_evidence"] = self.http_evidence.to_dict()
        if self.proof_of_concept:
            data["proof_of_concept"] = self.proof_of_concept.to_dict()
        if self.screenshots:
            data["screenshots"] = self.screenshots

        return data

    def to_json(self, indent: int = 2) -> str:
        """Convert finding to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Finding":
        """Create finding from dictionary."""
        # Convert string enums back to enum types
        if "vuln_type" in data and isinstance(data["vuln_type"], str):
            try:
                data["vuln_type"] = VulnType(data["vuln_type"])
            except ValueError:
                data["vuln_type"] = VulnType.UNKNOWN

        if "category" in data and isinstance(data["category"], str):
            try:
                data["category"] = VulnCategory(data["category"])
            except ValueError:
                data["category"] = VulnCategory.UNKNOWN

        if "severity" in data and isinstance(data["severity"], str):
            try:
                data["severity"] = Severity(data["severity"])
            except ValueError:
                data["severity"] = Severity.INFO

        # Handle nested objects
        if "http_evidence" in data and isinstance(data["http_evidence"], dict):
            data["http_evidence"] = HttpEvidence(**data["http_evidence"])

        if "proof_of_concept" in data and isinstance(data["proof_of_concept"], dict):
            data["proof_of_concept"] = ProofOfConcept(**data["proof_of_concept"])

        # Remove unknown fields
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered_data = {k: v for k, v in data.items() if k in known_fields}

        return cls(**filtered_data)

    @classmethod
    def from_json(cls, json_str: str) -> "Finding":
        """Create finding from JSON string."""
        return cls.from_dict(json.loads(json_str))

    # ==========================================================================
    # LEGACY COMPATIBILITY
    # ==========================================================================

    @classmethod
    def from_legacy(cls, legacy_finding: Any) -> "Finding":
        """
        Convert legacy finding objects to unified Finding.

        Supports: AuthzFinding, DisclosureFinding, CMDiFinding, etc.
        """
        # Get attributes from legacy object
        data = {}

        # Common fields
        data["id"] = getattr(legacy_finding, "id", "")
        data["endpoint"] = getattr(legacy_finding, "endpoint", "") or getattr(legacy_finding, "matched_at", "")
        data["description"] = getattr(legacy_finding, "description", "")
        data["evidence"] = getattr(legacy_finding, "evidence", [])
        data["remediation"] = getattr(legacy_finding, "remediation", "")
        data["confidence_score"] = float(getattr(legacy_finding, "confidence", 50.0))

        # Severity handling
        severity_val = getattr(legacy_finding, "severity", "INFO")
        if isinstance(severity_val, str):
            try:
                data["severity"] = Severity(severity_val.upper())
            except ValueError:
                data["severity"] = Severity.INFO

        # Type handling
        type_val = getattr(legacy_finding, "type", "") or getattr(legacy_finding, "vuln_type", "")
        if isinstance(type_val, str):
            try:
                data["vuln_type"] = VulnType(type_val.lower())
            except ValueError:
                data["vuln_type"] = VulnType.UNKNOWN
        elif hasattr(type_val, "value"):
            try:
                data["vuln_type"] = VulnType(type_val.value.lower())
            except ValueError:
                data["vuln_type"] = VulnType.UNKNOWN

        # Name
        data["name"] = getattr(legacy_finding, "name", "") or getattr(legacy_finding, "title", "")

        # CWE
        cwe = getattr(legacy_finding, "cwe", "") or getattr(legacy_finding, "cwe_id", "")
        if isinstance(cwe, int):
            data["cwe_id"] = f"CWE-{cwe}"
        else:
            data["cwe_id"] = str(cwe)

        # CVSS
        data["cvss_score"] = float(getattr(legacy_finding, "cvss_score", 0.0))

        # Impact
        data["impact"] = getattr(legacy_finding, "impact", "")

        return cls(**data)

    # ==========================================================================
    # COMPARISON
    # ==========================================================================

    def __hash__(self) -> int:
        """Hash finding for deduplication."""
        return hash((self.vuln_type, self.host, self.endpoint, self.parameter))

    def __eq__(self, other: object) -> bool:
        """Check equality for deduplication."""
        if not isinstance(other, Finding):
            return False
        return (
            self.vuln_type == other.vuln_type and
            self.host == other.host and
            self.endpoint == other.endpoint and
            self.parameter == other.parameter
        )

    def is_duplicate_of(self, other: "Finding") -> bool:
        """Check if this finding is a duplicate of another."""
        # Same vulnerability at same location
        if self == other:
            return True

        # Same type at similar endpoint (path prefix match)
        if (
            self.vuln_type == other.vuln_type and
            self.host == other.host and
            (
                self.endpoint.startswith(other.endpoint) or
                other.endpoint.startswith(self.endpoint)
            )
        ):
            return True

        return False


# =============================================================================
# FINDING COLLECTION
# =============================================================================

@dataclass
class FindingCollection:
    """Collection of findings with utility methods."""

    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        """Add a finding to the collection."""
        self.findings.append(finding)

    def add_many(self, findings: list[Finding]) -> None:
        """Add multiple findings."""
        self.findings.extend(findings)

    def deduplicate(self) -> "FindingCollection":
        """Return deduplicated collection."""
        seen = set()
        unique = []
        for finding in self.findings:
            key = (finding.vuln_type, finding.host, finding.endpoint, finding.parameter)
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return FindingCollection(findings=unique)

    def filter_by_severity(self, *severities: Severity) -> "FindingCollection":
        """Filter findings by severity."""
        return FindingCollection(
            findings=[f for f in self.findings if f.severity in severities]
        )

    def filter_by_category(self, *categories: VulnCategory) -> "FindingCollection":
        """Filter findings by category."""
        return FindingCollection(
            findings=[f for f in self.findings if f.category in categories]
        )

    def filter_by_confidence(self, min_score: float) -> "FindingCollection":
        """Filter findings by minimum confidence score."""
        return FindingCollection(
            findings=[f for f in self.findings if f.confidence_score >= min_score]
        )

    def filter_validated(self) -> "FindingCollection":
        """Return only validated findings."""
        return FindingCollection(
            findings=[f for f in self.findings if f.validated and not f.false_positive]
        )

    def sort_by_severity(self, descending: bool = True) -> "FindingCollection":
        """Sort findings by severity."""
        severity_order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        sorted_findings = sorted(
            self.findings,
            key=lambda f: severity_order.get(f.severity, 0),
            reverse=descending,
        )
        return FindingCollection(findings=sorted_findings)

    def group_by_category(self) -> dict[VulnCategory, list[Finding]]:
        """Group findings by category."""
        groups: dict[VulnCategory, list[Finding]] = {}
        for finding in self.findings:
            if finding.category not in groups:
                groups[finding.category] = []
            groups[finding.category].append(finding)
        return groups

    def group_by_host(self) -> dict[str, list[Finding]]:
        """Group findings by host."""
        groups: dict[str, list[Finding]] = {}
        for finding in self.findings:
            if finding.host not in groups:
                groups[finding.host] = []
            groups[finding.host].append(finding)
        return groups

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    def summary(self) -> dict[str, int]:
        """Return summary statistics."""
        return {
            "total": len(self.findings),
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "info": self.info_count,
            "validated": sum(1 for f in self.findings if f.validated),
            "false_positives": sum(1 for f in self.findings if f.false_positive),
        }

    def to_dict(self) -> list[dict]:
        """Convert all findings to dictionaries."""
        return [f.to_dict() for f in self.findings]

    def to_json(self, indent: int = 2) -> str:
        """Convert all findings to JSON."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def __len__(self) -> int:
        return len(self.findings)

    def __iter__(self) -> Iterator[Finding]:
        return iter(self.findings)

    def __getitem__(self, index: int) -> Finding:
        return self.findings[index]


# =============================================================================
# FACTORY FUNCTIONS
# =============================================================================

def create_sqli_finding(
    endpoint: str,
    parameter: str,
    payload: str,
    evidence: list[str],
    severity: Severity = Severity.CRITICAL,
    confidence: float = 85.0,
    **kwargs: Any
) -> Finding:
    """Factory for SQL injection findings."""
    return Finding(
        vuln_type=VulnType.SQLI,
        category=VulnCategory.INJECTION,
        severity=severity,
        confidence_score=confidence,
        endpoint=endpoint,
        parameter=parameter,
        name="SQL Injection",
        description=f"SQL injection vulnerability in parameter '{parameter}'",
        impact="Attackers can read, modify, or delete database contents. May lead to full system compromise.",
        remediation="Use parameterized queries or prepared statements. Never concatenate user input into SQL.",
        evidence=evidence,
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        owasp_2021="A03:2021-Injection",
        metadata={"payload": payload},
        **kwargs
    )


def create_xss_finding(
    endpoint: str,
    parameter: str,
    payload: str,
    xss_type: str = "reflected",
    evidence: list[str] = None,
    severity: Severity = Severity.HIGH,
    confidence: float = 80.0,
    **kwargs: Any
) -> Finding:
    """Factory for XSS findings."""
    vuln_type = {
        "reflected": VulnType.XSS_REFLECTED,
        "stored": VulnType.XSS_STORED,
        "dom": VulnType.XSS_DOM,
    }.get(xss_type.lower(), VulnType.XSS_REFLECTED)

    return Finding(
        vuln_type=vuln_type,
        category=VulnCategory.INJECTION if xss_type != "dom" else VulnCategory.CLIENT_SIDE,
        severity=severity,
        confidence_score=confidence,
        endpoint=endpoint,
        parameter=parameter,
        name=f"Cross-Site Scripting ({xss_type.upper()})",
        description=f"{xss_type.title()} XSS vulnerability in parameter '{parameter}'",
        impact="Attackers can execute malicious scripts in victims' browsers, steal session tokens, or perform actions on behalf of users.",
        remediation="Encode all user input before rendering. Use Content-Security-Policy headers. Implement input validation.",
        evidence=evidence or [],
        cwe_id="CWE-79",
        cwe_name="Cross-site Scripting (XSS)",
        owasp_2021="A03:2021-Injection",
        metadata={"payload": payload, "xss_type": xss_type},
        **kwargs
    )


def create_idor_finding(
    endpoint: str,
    parameter: str,
    original_value: str,
    accessed_value: str,
    evidence: list[str] = None,
    severity: Severity = Severity.HIGH,
    confidence: float = 85.0,
    **kwargs: Any
) -> Finding:
    """Factory for IDOR findings."""
    return Finding(
        vuln_type=VulnType.IDOR,
        category=VulnCategory.AUTHORIZATION,
        severity=severity,
        confidence_score=confidence,
        endpoint=endpoint,
        parameter=parameter,
        name="Insecure Direct Object Reference (IDOR)",
        description=f"IDOR vulnerability allows access to unauthorized resources by manipulating '{parameter}'",
        impact="Attackers can access or modify other users' data, including sensitive information.",
        remediation="Implement proper authorization checks. Verify that the authenticated user has permission to access the requested resource.",
        evidence=evidence or [],
        cwe_id="CWE-639",
        cwe_name="Authorization Bypass Through User-Controlled Key",
        owasp_2021="A01:2021-Broken Access Control",
        metadata={"original_value": original_value, "accessed_value": accessed_value},
        **kwargs
    )
