"""
PHANTOM AI - Compliance Mapper Module

Maps vulnerabilities to compliance frameworks and security standards.
Supports CWE, OWASP Top 10, PCI DSS, NIST, GDPR, ISO 27001, and more.

Version: 3.0.0
Date: 2026-01-30

Features:
- CWE mapping with full hierarchy
- OWASP Top 10 2021 mapping
- PCI DSS 4.0 requirements
- NIST SP 800-53 controls
- GDPR articles
- ISO 27001 controls
- HIPAA safeguards
- SOC 2 criteria
- Custom framework support
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS
# =============================================================================


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""

    CWE = "cwe"
    OWASP_TOP_10 = "owasp_top_10"
    OWASP_ASVS = "owasp_asvs"
    PCI_DSS = "pci_dss"
    NIST_800_53 = "nist_800_53"
    NIST_CSF = "nist_csf"
    GDPR = "gdpr"
    ISO_27001 = "iso_27001"
    HIPAA = "hipaa"
    SOC_2 = "soc_2"
    SANS_TOP_25 = "sans_top_25"
    MITRE_ATTACK = "mitre_attack"


class OWASPCategory(Enum):
    """OWASP Top 10 2021 categories."""

    A01_BROKEN_ACCESS_CONTROL = "A01:2021"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021"
    A03_INJECTION = "A03:2021"
    A04_INSECURE_DESIGN = "A04:2021"
    A05_SECURITY_MISCONFIGURATION = "A05:2021"
    A06_VULNERABLE_COMPONENTS = "A06:2021"
    A07_AUTH_FAILURES = "A07:2021"
    A08_SOFTWARE_DATA_INTEGRITY = "A08:2021"
    A09_LOGGING_MONITORING = "A09:2021"
    A10_SSRF = "A10:2021"


class PCIDSSRequirement(Enum):
    """PCI DSS 4.0 requirements."""

    REQ_1 = "1"   # Network Security Controls
    REQ_2 = "2"   # Secure Configurations
    REQ_3 = "3"   # Protect Account Data
    REQ_4 = "4"   # Protect Cardholder Data
    REQ_5 = "5"   # Protect Against Malware
    REQ_6 = "6"   # Develop Secure Systems
    REQ_7 = "7"   # Restrict Access
    REQ_8 = "8"   # Identity and Access
    REQ_9 = "9"   # Restrict Physical Access
    REQ_10 = "10"  # Log and Monitor
    REQ_11 = "11"  # Test Security Regularly
    REQ_12 = "12"  # Information Security Policy


class NISTControlFamily(Enum):
    """NIST SP 800-53 control families."""

    AC = "AC"   # Access Control
    AT = "AT"   # Awareness and Training
    AU = "AU"   # Audit and Accountability
    CA = "CA"   # Assessment, Authorization
    CM = "CM"   # Configuration Management
    CP = "CP"   # Contingency Planning
    IA = "IA"   # Identification and Authentication
    IR = "IR"   # Incident Response
    MA = "MA"   # Maintenance
    MP = "MP"   # Media Protection
    PE = "PE"   # Physical Protection
    PL = "PL"   # Planning
    PM = "PM"   # Program Management
    PS = "PS"   # Personnel Security
    PT = "PT"   # PII Processing
    RA = "RA"   # Risk Assessment
    SA = "SA"   # System Acquisition
    SC = "SC"   # System Communications Protection
    SI = "SI"   # System Information Integrity
    SR = "SR"   # Supply Chain Risk


# =============================================================================
# MAPPING DATA
# =============================================================================


# Vulnerability type to CWE mapping
VULNERABILITY_TO_CWE: Dict[str, List[int]] = {
    # Injection
    "sqli": [89, 564],
    "nosql": [943],
    "cmdi": [77, 78],
    "xss": [79],
    "stored_xss": [79],
    "dom_xss": [79],
    "xxe": [611],
    "ssti": [94, 1336],
    "ldap": [90],
    "xpath": [91],
    "crlf": [93],
    "lfi": [22, 98],
    "rfi": [98],
    "path_traversal": [22, 23],

    # Authentication
    "auth_bypass": [287, 306],
    "broken_auth": [287],
    "session_fixation": [384],
    "session_hijacking": [384, 613],
    "jwt_vuln": [347, 327],
    "oauth_vuln": [287, 346],
    "saml_vuln": [287],
    "mfa_bypass": [287, 308],
    "weak_password": [521],
    "credential_stuffing": [307],
    "brute_force": [307],

    # Authorization
    "idor": [639],
    "privilege_escalation": [269, 266],
    "horizontal_priv_esc": [639],
    "vertical_priv_esc": [269],
    "mass_assignment": [915],

    # Server-Side
    "ssrf": [918],
    "rce": [94],
    "insecure_deserialization": [502],
    "file_upload": [434],

    # Client-Side
    "csrf": [352],
    "clickjacking": [1021],
    "cors": [942, 346],
    "open_redirect": [601],

    # Information Disclosure
    "info_disclosure": [200],
    "path_disclosure": [548],
    "stack_trace": [209],
    "sensitive_data_exposure": [311, 312],
    "pii_exposure": [359],

    # Cryptography
    "weak_crypto": [327],
    "insecure_random": [330],
    "hardcoded_secrets": [798],
    "cleartext_storage": [312],
    "cleartext_transmission": [319],

    # Infrastructure
    "ssl_tls": [295, 326],
    "misconfiguration": [16],
    "security_headers": [16, 693],
    "subdomain_takeover": [404],

    # API
    "api_vuln": [200, 285],
    "graphql_vuln": [200, 400],
    "rate_limiting": [799],
    "race_condition": [362],

    # Business Logic
    "business_logic": [840],
}


# CWE to OWASP Top 10 2021 mapping
CWE_TO_OWASP: Dict[int, OWASPCategory] = {
    # A01 - Broken Access Control
    22: OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    23: OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    266: OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    269: OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    284: OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    285: OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    352: OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    359: OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    425: OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    548: OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    639: OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    915: OWASPCategory.A01_BROKEN_ACCESS_CONTROL,

    # A02 - Cryptographic Failures
    295: OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    311: OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    312: OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    319: OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    326: OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    327: OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    330: OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    798: OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,

    # A03 - Injection
    77: OWASPCategory.A03_INJECTION,
    78: OWASPCategory.A03_INJECTION,
    79: OWASPCategory.A03_INJECTION,
    89: OWASPCategory.A03_INJECTION,
    90: OWASPCategory.A03_INJECTION,
    91: OWASPCategory.A03_INJECTION,
    93: OWASPCategory.A03_INJECTION,
    94: OWASPCategory.A03_INJECTION,
    98: OWASPCategory.A03_INJECTION,
    564: OWASPCategory.A03_INJECTION,
    611: OWASPCategory.A03_INJECTION,
    943: OWASPCategory.A03_INJECTION,
    1336: OWASPCategory.A03_INJECTION,

    # A04 - Insecure Design
    209: OWASPCategory.A04_INSECURE_DESIGN,
    256: OWASPCategory.A04_INSECURE_DESIGN,
    501: OWASPCategory.A04_INSECURE_DESIGN,
    521: OWASPCategory.A04_INSECURE_DESIGN,
    522: OWASPCategory.A04_INSECURE_DESIGN,
    840: OWASPCategory.A04_INSECURE_DESIGN,

    # A05 - Security Misconfiguration
    16: OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    200: OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    693: OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    942: OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    1021: OWASPCategory.A05_SECURITY_MISCONFIGURATION,

    # A06 - Vulnerable Components
    937: OWASPCategory.A06_VULNERABLE_COMPONENTS,
    1035: OWASPCategory.A06_VULNERABLE_COMPONENTS,
    1104: OWASPCategory.A06_VULNERABLE_COMPONENTS,

    # A07 - Identification and Authentication Failures
    287: OWASPCategory.A07_AUTH_FAILURES,
    306: OWASPCategory.A07_AUTH_FAILURES,
    307: OWASPCategory.A07_AUTH_FAILURES,
    308: OWASPCategory.A07_AUTH_FAILURES,
    346: OWASPCategory.A07_AUTH_FAILURES,
    347: OWASPCategory.A07_AUTH_FAILURES,
    384: OWASPCategory.A07_AUTH_FAILURES,
    613: OWASPCategory.A07_AUTH_FAILURES,

    # A08 - Software and Data Integrity Failures
    345: OWASPCategory.A08_SOFTWARE_DATA_INTEGRITY,
    353: OWASPCategory.A08_SOFTWARE_DATA_INTEGRITY,
    426: OWASPCategory.A08_SOFTWARE_DATA_INTEGRITY,
    434: OWASPCategory.A08_SOFTWARE_DATA_INTEGRITY,
    502: OWASPCategory.A08_SOFTWARE_DATA_INTEGRITY,
    565: OWASPCategory.A08_SOFTWARE_DATA_INTEGRITY,
    829: OWASPCategory.A08_SOFTWARE_DATA_INTEGRITY,

    # A09 - Security Logging and Monitoring Failures
    117: OWASPCategory.A09_LOGGING_MONITORING,
    223: OWASPCategory.A09_LOGGING_MONITORING,
    778: OWASPCategory.A09_LOGGING_MONITORING,

    # A10 - Server-Side Request Forgery
    918: OWASPCategory.A10_SSRF,
}


# OWASP to PCI DSS mapping
OWASP_TO_PCI_DSS: Dict[OWASPCategory, List[str]] = {
    OWASPCategory.A01_BROKEN_ACCESS_CONTROL: ["6.4.1", "6.4.2", "7.2", "8.3"],
    OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES: ["3.4", "3.5", "4.1", "4.2.1"],
    OWASPCategory.A03_INJECTION: ["6.2.4", "6.4.1", "6.4.2", "11.3.1"],
    OWASPCategory.A04_INSECURE_DESIGN: ["6.2.1", "6.2.2", "6.2.3"],
    OWASPCategory.A05_SECURITY_MISCONFIGURATION: ["2.2", "2.2.1", "6.4.1"],
    OWASPCategory.A06_VULNERABLE_COMPONENTS: ["6.2.4", "6.3.1", "11.3.1"],
    OWASPCategory.A07_AUTH_FAILURES: ["8.2", "8.3", "8.4", "8.5"],
    OWASPCategory.A08_SOFTWARE_DATA_INTEGRITY: ["6.2.4", "10.1", "11.5.2"],
    OWASPCategory.A09_LOGGING_MONITORING: ["10.1", "10.2", "10.3", "10.4"],
    OWASPCategory.A10_SSRF: ["6.2.4", "6.4.1", "6.4.2"],
}


# OWASP to NIST 800-53 mapping
OWASP_TO_NIST: Dict[OWASPCategory, List[str]] = {
    OWASPCategory.A01_BROKEN_ACCESS_CONTROL: ["AC-3", "AC-4", "AC-5", "AC-6", "AC-24"],
    OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES: ["SC-8", "SC-12", "SC-13", "SC-28"],
    OWASPCategory.A03_INJECTION: ["SI-10", "SI-11", "SI-16", "SA-11"],
    OWASPCategory.A04_INSECURE_DESIGN: ["SA-8", "SA-11", "SA-15", "SA-17"],
    OWASPCategory.A05_SECURITY_MISCONFIGURATION: ["CM-2", "CM-6", "CM-7", "SA-22"],
    OWASPCategory.A06_VULNERABLE_COMPONENTS: ["RA-5", "SA-11", "SI-2", "CM-8"],
    OWASPCategory.A07_AUTH_FAILURES: ["IA-2", "IA-4", "IA-5", "IA-8"],
    OWASPCategory.A08_SOFTWARE_DATA_INTEGRITY: ["SI-7", "SA-11", "SA-15", "CM-14"],
    OWASPCategory.A09_LOGGING_MONITORING: ["AU-2", "AU-3", "AU-6", "SI-4"],
    OWASPCategory.A10_SSRF: ["AC-3", "AC-4", "SC-7", "SA-11"],
}


# OWASP to ISO 27001 mapping
OWASP_TO_ISO27001: Dict[OWASPCategory, List[str]] = {
    OWASPCategory.A01_BROKEN_ACCESS_CONTROL: ["A.9.1", "A.9.2", "A.9.4", "A.13.1"],
    OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES: ["A.10.1", "A.14.1", "A.18.1.5"],
    OWASPCategory.A03_INJECTION: ["A.14.2", "A.14.2.5"],
    OWASPCategory.A04_INSECURE_DESIGN: ["A.14.1", "A.14.2"],
    OWASPCategory.A05_SECURITY_MISCONFIGURATION: ["A.12.5", "A.12.6", "A.14.2.4"],
    OWASPCategory.A06_VULNERABLE_COMPONENTS: ["A.12.5", "A.12.6.1", "A.14.2.1"],
    OWASPCategory.A07_AUTH_FAILURES: ["A.9.2", "A.9.3", "A.9.4"],
    OWASPCategory.A08_SOFTWARE_DATA_INTEGRITY: ["A.14.2", "A.14.2.6", "A.14.2.9"],
    OWASPCategory.A09_LOGGING_MONITORING: ["A.12.4", "A.16.1"],
    OWASPCategory.A10_SSRF: ["A.13.1", "A.14.2"],
}


# GDPR relevant articles for security
SECURITY_GDPR_ARTICLES: Dict[str, str] = {
    "Art. 5": "Principles relating to processing of personal data",
    "Art. 25": "Data protection by design and by default",
    "Art. 32": "Security of processing",
    "Art. 33": "Notification of a personal data breach",
    "Art. 34": "Communication of a personal data breach",
    "Art. 35": "Data protection impact assessment",
}


# HIPAA safeguards
HIPAA_SAFEGUARDS: Dict[str, str] = {
    "164.308(a)(1)": "Security Management Process",
    "164.308(a)(3)": "Workforce Security",
    "164.308(a)(4)": "Information Access Management",
    "164.308(a)(5)": "Security Awareness and Training",
    "164.308(a)(6)": "Security Incident Procedures",
    "164.310(a)(1)": "Facility Access Controls",
    "164.310(d)(1)": "Device and Media Controls",
    "164.312(a)(1)": "Access Control",
    "164.312(b)": "Audit Controls",
    "164.312(c)(1)": "Integrity",
    "164.312(d)": "Person or Entity Authentication",
    "164.312(e)(1)": "Transmission Security",
}


# SOC 2 Trust Service Criteria
SOC2_CRITERIA: Dict[str, str] = {
    "CC1": "Control Environment",
    "CC2": "Communication and Information",
    "CC3": "Risk Assessment",
    "CC4": "Monitoring Activities",
    "CC5": "Control Activities",
    "CC6": "Logical and Physical Access",
    "CC7": "System Operations",
    "CC8": "Change Management",
    "CC9": "Risk Mitigation",
}


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class CWEMapping:
    """CWE mapping result."""

    cwe_id: int
    name: str
    description: str
    url: str
    abstraction: str  # Pillar, Class, Base, Variant
    related_cwes: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "cwe_id": self.cwe_id,
            "name": self.name,
            "description": self.description,
            "url": self.url,
            "abstraction": self.abstraction,
            "related_cwes": self.related_cwes,
        }


@dataclass
class ComplianceMapping:
    """Compliance mapping for a vulnerability."""

    vulnerability_id: str
    vulnerability_type: str
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Mappings
    cwe_ids: List[int] = field(default_factory=list)
    owasp_categories: List[str] = field(default_factory=list)
    pci_dss_requirements: List[str] = field(default_factory=list)
    nist_controls: List[str] = field(default_factory=list)
    iso27001_controls: List[str] = field(default_factory=list)
    gdpr_articles: List[str] = field(default_factory=list)
    hipaa_safeguards: List[str] = field(default_factory=list)
    soc2_criteria: List[str] = field(default_factory=list)

    # Additional info
    mitre_techniques: List[str] = field(default_factory=list)
    remediation_guidance: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "vulnerability_id": self.vulnerability_id,
            "vulnerability_type": self.vulnerability_type,
            "timestamp": self.timestamp.isoformat(),
            "mappings": {
                "cwe": [f"CWE-{cwe}" for cwe in self.cwe_ids],
                "owasp_top_10": self.owasp_categories,
                "pci_dss": self.pci_dss_requirements,
                "nist_800_53": self.nist_controls,
                "iso_27001": self.iso27001_controls,
                "gdpr": self.gdpr_articles,
                "hipaa": self.hipaa_safeguards,
                "soc_2": self.soc2_criteria,
                "mitre_attack": self.mitre_techniques,
            },
            "remediation_guidance": self.remediation_guidance,
        }

    def get_all_frameworks(self) -> Dict[str, List[str]]:
        """Get all frameworks with mappings."""
        frameworks = {}

        if self.cwe_ids:
            frameworks["CWE"] = [f"CWE-{cwe}" for cwe in self.cwe_ids]
        if self.owasp_categories:
            frameworks["OWASP Top 10"] = self.owasp_categories
        if self.pci_dss_requirements:
            frameworks["PCI DSS 4.0"] = self.pci_dss_requirements
        if self.nist_controls:
            frameworks["NIST 800-53"] = self.nist_controls
        if self.iso27001_controls:
            frameworks["ISO 27001"] = self.iso27001_controls
        if self.gdpr_articles:
            frameworks["GDPR"] = self.gdpr_articles
        if self.hipaa_safeguards:
            frameworks["HIPAA"] = self.hipaa_safeguards
        if self.soc2_criteria:
            frameworks["SOC 2"] = self.soc2_criteria

        return frameworks


@dataclass
class ComplianceReport:
    """Full compliance report for scan results."""

    scan_id: str
    target: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    mappings: List[ComplianceMapping] = field(default_factory=list)

    # Aggregated statistics
    frameworks_covered: List[str] = field(default_factory=list)
    total_findings: int = 0
    owasp_coverage: Dict[str, int] = field(default_factory=dict)
    pci_dss_coverage: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "summary": {
                "total_findings": self.total_findings,
                "frameworks_covered": self.frameworks_covered,
                "owasp_coverage": self.owasp_coverage,
                "pci_dss_coverage": self.pci_dss_coverage,
            },
            "findings": [m.to_dict() for m in self.mappings],
        }


# =============================================================================
# CWE DATABASE (Subset of common CWEs)
# =============================================================================


CWE_DATABASE: Dict[int, Dict[str, str]] = {
    16: {"name": "Configuration", "desc": "Improper configuration or maintenance of the software."},
    22: {"name": "Path Traversal", "desc": "Improper limitation of a pathname to a restricted directory."},
    23: {"name": "Relative Path Traversal", "desc": "Relative path traversal vulnerability."},
    77: {"name": "Command Injection", "desc": "Improper neutralization of special elements used in a command."},
    78: {"name": "OS Command Injection", "desc": "Improper neutralization of special elements used in an OS command."},
    79: {"name": "Cross-site Scripting (XSS)", "desc": "Improper neutralization of input during web page generation."},
    89: {"name": "SQL Injection", "desc": "Improper neutralization of special elements used in an SQL command."},
    90: {"name": "LDAP Injection", "desc": "Improper neutralization of special elements used in an LDAP query."},
    91: {"name": "XPath Injection", "desc": "Improper neutralization of special elements in XPath expression."},
    93: {"name": "CRLF Injection", "desc": "Improper neutralization of CRLF sequences in HTTP headers."},
    94: {"name": "Code Injection", "desc": "Improper control of generation of code."},
    98: {"name": "Improper Control of Filename", "desc": "Improper control of filename for include/require statement."},
    200: {"name": "Information Exposure", "desc": "Exposure of sensitive information to an unauthorized actor."},
    209: {"name": "Error Message Information Exposure", "desc": "Information exposure through an error message."},
    266: {"name": "Incorrect Privilege Assignment", "desc": "A privilege is not correctly assigned to an actor."},
    269: {"name": "Improper Privilege Management", "desc": "The software does not properly manage privileges."},
    287: {"name": "Improper Authentication", "desc": "Authentication is not properly verified."},
    295: {"name": "Improper Certificate Validation", "desc": "The software does not validate certificates correctly."},
    306: {"name": "Missing Authentication", "desc": "Missing authentication for critical function."},
    307: {"name": "Improper Restriction of Authentication", "desc": "Excessive authentication attempts not properly restricted."},
    308: {"name": "Single-factor Authentication", "desc": "Use of single-factor authentication."},
    311: {"name": "Missing Encryption", "desc": "Missing encryption of sensitive data."},
    312: {"name": "Cleartext Storage", "desc": "Cleartext storage of sensitive information."},
    319: {"name": "Cleartext Transmission", "desc": "Cleartext transmission of sensitive information."},
    326: {"name": "Inadequate Encryption Strength", "desc": "The software uses an algorithm that is weak."},
    327: {"name": "Broken Crypto Algorithm", "desc": "Use of a broken or risky cryptographic algorithm."},
    330: {"name": "Insufficient Randomness", "desc": "Use of insufficiently random values."},
    346: {"name": "Origin Validation Error", "desc": "The software does not properly verify origin."},
    347: {"name": "Improper Verification of Signature", "desc": "The software does not verify cryptographic signature."},
    352: {"name": "Cross-Site Request Forgery (CSRF)", "desc": "CSRF vulnerability."},
    362: {"name": "Race Condition", "desc": "Concurrent execution using shared resource."},
    384: {"name": "Session Fixation", "desc": "The application authenticates without invalidating session."},
    434: {"name": "Unrestricted File Upload", "desc": "Unrestricted upload of file with dangerous type."},
    502: {"name": "Deserialization of Untrusted Data", "desc": "The application deserializes untrusted data."},
    521: {"name": "Weak Password Requirements", "desc": "The software does not require strong passwords."},
    548: {"name": "Information Exposure Through Directory Listing", "desc": "Directory listing enabled."},
    564: {"name": "SQL Injection: Hibernate", "desc": "SQL injection vulnerability in Hibernate."},
    601: {"name": "URL Redirection", "desc": "URL redirection to untrusted site."},
    611: {"name": "XXE", "desc": "Improper restriction of XML external entity reference."},
    613: {"name": "Insufficient Session Expiration", "desc": "Session does not expire properly."},
    639: {"name": "IDOR", "desc": "Authorization bypass through user-controlled key."},
    693: {"name": "Protection Mechanism Failure", "desc": "The software does not use protection mechanism."},
    798: {"name": "Hardcoded Credentials", "desc": "Use of hard-coded credentials."},
    799: {"name": "Improper Control of Interaction Frequency", "desc": "Missing rate limiting."},
    840: {"name": "Business Logic Errors", "desc": "Business logic error in the application."},
    915: {"name": "Improperly Controlled Modification", "desc": "Mass assignment vulnerability."},
    918: {"name": "SSRF", "desc": "Server-side request forgery vulnerability."},
    942: {"name": "CORS Misconfiguration", "desc": "Permissive cross-domain policy with untrusted domains."},
    943: {"name": "NoSQL Injection", "desc": "Improper neutralization for NoSQL query."},
    1021: {"name": "Improper Restriction of Rendered UI", "desc": "Clickjacking vulnerability."},
    1336: {"name": "SSTI", "desc": "Improper neutralization in template engine."},
}


# =============================================================================
# COMPLIANCE MAPPER ENGINE
# =============================================================================


class ComplianceMapper:
    """
    PHANTOM AI Compliance Mapper.

    Maps vulnerabilities to compliance frameworks and security standards.
    """

    VERSION = "3.0.0"

    def __init__(
        self,
        frameworks: Optional[List[ComplianceFramework]] = None,
        include_pii_frameworks: bool = True,
    ) -> None:
        """
        Initialize compliance mapper.

        Args:
            frameworks: Optional list of frameworks to include
            include_pii_frameworks: Whether to include PII-related frameworks
        """
        self.frameworks = frameworks or list(ComplianceFramework)
        self.include_pii_frameworks = include_pii_frameworks
        self._mappings: List[ComplianceMapping] = []

        logger.info(f"ComplianceMapper v{self.VERSION} initialized")

    def map_vulnerability(
        self,
        vulnerability_id: str,
        vulnerability_type: str,
        affects_pii: bool = False,
        affects_financial_data: bool = False,
        affects_health_data: bool = False,
    ) -> ComplianceMapping:
        """
        Map a vulnerability to compliance frameworks.

        Args:
            vulnerability_id: Unique identifier
            vulnerability_type: Type of vulnerability
            affects_pii: Whether vulnerability affects PII
            affects_financial_data: Whether vulnerability affects financial data
            affects_health_data: Whether vulnerability affects health data

        Returns:
            ComplianceMapping with all applicable mappings
        """
        vuln_type_lower = vulnerability_type.lower()

        # Get CWE mappings
        cwe_ids = VULNERABILITY_TO_CWE.get(vuln_type_lower, [])

        # Get OWASP mappings from CWE
        owasp_categories: Set[str] = set()
        for cwe_id in cwe_ids:
            owasp = CWE_TO_OWASP.get(cwe_id)
            if owasp:
                owasp_categories.add(owasp.value)

        # Get PCI DSS mappings from OWASP
        pci_dss_requirements: Set[str] = set()
        for owasp_value in owasp_categories:
            try:
                owasp_cat = OWASPCategory(owasp_value)
                pci_reqs = OWASP_TO_PCI_DSS.get(owasp_cat, [])
                pci_dss_requirements.update(pci_reqs)
            except ValueError:
                pass

        # Get NIST mappings from OWASP
        nist_controls: Set[str] = set()
        for owasp_value in owasp_categories:
            try:
                owasp_cat = OWASPCategory(owasp_value)
                nist = OWASP_TO_NIST.get(owasp_cat, [])
                nist_controls.update(nist)
            except ValueError:
                pass

        # Get ISO 27001 mappings from OWASP
        iso27001_controls: Set[str] = set()
        for owasp_value in owasp_categories:
            try:
                owasp_cat = OWASPCategory(owasp_value)
                iso = OWASP_TO_ISO27001.get(owasp_cat, [])
                iso27001_controls.update(iso)
            except ValueError:
                pass

        # Get GDPR articles if affects PII
        gdpr_articles = []
        if affects_pii and self.include_pii_frameworks:
            gdpr_articles = ["Art. 32", "Art. 33"]
            if vuln_type_lower in ["info_disclosure", "sensitive_data_exposure", "pii_exposure"]:
                gdpr_articles.extend(["Art. 5", "Art. 34"])

        # Get HIPAA safeguards if affects health data
        hipaa_safeguards = []
        if affects_health_data and self.include_pii_frameworks:
            hipaa_safeguards = [
                "164.312(a)(1)",  # Access Control
                "164.312(b)",     # Audit Controls
                "164.312(c)(1)",  # Integrity
            ]
            if vuln_type_lower in ["cleartext_transmission", "ssl_tls"]:
                hipaa_safeguards.append("164.312(e)(1)")  # Transmission Security

        # Get SOC 2 criteria
        soc2_criteria = ["CC6", "CC7"]  # Default security controls
        if vuln_type_lower in ["auth_bypass", "broken_auth", "jwt_vuln"]:
            soc2_criteria.extend(["CC6.1", "CC6.2"])
        if vuln_type_lower in ["info_disclosure", "misconfiguration"]:
            soc2_criteria.append("CC8")

        # Generate remediation guidance
        remediation = self._generate_remediation(vuln_type_lower)

        mapping = ComplianceMapping(
            vulnerability_id=vulnerability_id,
            vulnerability_type=vulnerability_type,
            cwe_ids=cwe_ids,
            owasp_categories=list(owasp_categories),
            pci_dss_requirements=list(pci_dss_requirements),
            nist_controls=list(nist_controls),
            iso27001_controls=list(iso27001_controls),
            gdpr_articles=gdpr_articles,
            hipaa_safeguards=hipaa_safeguards,
            soc2_criteria=soc2_criteria,
            remediation_guidance=remediation,
        )

        self._mappings.append(mapping)
        return mapping

    def map_findings(
        self,
        findings: List[Dict[str, Any]],
        affects_pii: bool = False,
        affects_financial_data: bool = False,
        affects_health_data: bool = False,
    ) -> List[ComplianceMapping]:
        """
        Map multiple findings to compliance frameworks.

        Args:
            findings: List of finding dictionaries
            affects_pii: Whether findings affect PII
            affects_financial_data: Whether findings affect financial data
            affects_health_data: Whether findings affect health data

        Returns:
            List of compliance mappings
        """
        mappings = []
        for finding in findings:
            mapping = self.map_vulnerability(
                vulnerability_id=finding.get("id", ""),
                vulnerability_type=finding.get("type", "unknown"),
                affects_pii=affects_pii,
                affects_financial_data=affects_financial_data,
                affects_health_data=affects_health_data,
            )
            mappings.append(mapping)
        return mappings

    def generate_report(
        self,
        scan_id: str,
        target: str,
    ) -> ComplianceReport:
        """
        Generate a compliance report from collected mappings.

        Args:
            scan_id: Scan identifier
            target: Target URL/identifier

        Returns:
            ComplianceReport with aggregated statistics
        """
        # Collect statistics
        frameworks_covered: Set[str] = set()
        owasp_coverage: Dict[str, int] = {}
        pci_dss_coverage: Dict[str, int] = {}

        for mapping in self._mappings:
            frameworks = mapping.get_all_frameworks()
            frameworks_covered.update(frameworks.keys())

            # Count OWASP categories
            for cat in mapping.owasp_categories:
                owasp_coverage[cat] = owasp_coverage.get(cat, 0) + 1

            # Count PCI DSS requirements
            for req in mapping.pci_dss_requirements:
                pci_dss_coverage[req] = pci_dss_coverage.get(req, 0) + 1

        report = ComplianceReport(
            scan_id=scan_id,
            target=target,
            mappings=self._mappings.copy(),
            frameworks_covered=list(frameworks_covered),
            total_findings=len(self._mappings),
            owasp_coverage=owasp_coverage,
            pci_dss_coverage=pci_dss_coverage,
        )

        return report

    def get_cwe_info(self, cwe_id: int) -> Optional[CWEMapping]:
        """
        Get detailed CWE information.

        Args:
            cwe_id: CWE identifier

        Returns:
            CWEMapping with details or None if not found
        """
        cwe_data = CWE_DATABASE.get(cwe_id)
        if not cwe_data:
            return None

        return CWEMapping(
            cwe_id=cwe_id,
            name=cwe_data["name"],
            description=cwe_data["desc"],
            url=f"https://cwe.mitre.org/data/definitions/{cwe_id}.html",
            abstraction="Base",  # Simplified
        )

    def _generate_remediation(self, vulnerability_type: str) -> str:
        """Generate remediation guidance for vulnerability type."""
        remediation_map = {
            "sqli": "Use parameterized queries and prepared statements. Implement input validation.",
            "xss": "Implement context-aware output encoding. Use Content Security Policy.",
            "cmdi": "Avoid system commands. Use safe APIs and strict input validation.",
            "ssrf": "Implement URL allowlisting. Block private IP ranges.",
            "xxe": "Disable external entities in XML parsers. Use JSON instead.",
            "idor": "Implement proper authorization checks. Use indirect references.",
            "auth_bypass": "Strengthen authentication mechanisms. Implement MFA.",
            "csrf": "Implement CSRF tokens. Use SameSite cookie attribute.",
            "jwt_vuln": "Use strong algorithms (RS256). Validate all claims.",
            "cors": "Implement strict origin allowlisting. Avoid wildcards.",
            "info_disclosure": "Remove debug information. Implement proper error handling.",
            "ssl_tls": "Use TLS 1.2+. Enable HSTS. Use strong cipher suites.",
            "insecure_deserialization": "Avoid native deserialization. Implement integrity checks.",
        }

        return remediation_map.get(
            vulnerability_type,
            "Review security controls and implement defense-in-depth measures."
        )

    def get_framework_summary(self) -> Dict[str, int]:
        """Get summary of findings per framework."""
        summary: Dict[str, int] = {}

        for mapping in self._mappings:
            frameworks = mapping.get_all_frameworks()
            for framework in frameworks:
                summary[framework] = summary.get(framework, 0) + 1

        return summary

    def clear_mappings(self) -> None:
        """Clear stored mappings."""
        self._mappings.clear()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def map_to_compliance(
    vulnerability_type: str,
    affects_pii: bool = False,
) -> ComplianceMapping:
    """
    Quick compliance mapping.

    Args:
        vulnerability_type: Type of vulnerability
        affects_pii: Whether vulnerability affects PII

    Returns:
        ComplianceMapping
    """
    mapper = ComplianceMapper()
    return mapper.map_vulnerability(
        vulnerability_id="quick-map",
        vulnerability_type=vulnerability_type,
        affects_pii=affects_pii,
    )


def get_cwe_mapping(vulnerability_type: str) -> List[int]:
    """
    Get CWE IDs for vulnerability type.

    Args:
        vulnerability_type: Type of vulnerability

    Returns:
        List of CWE IDs
    """
    return VULNERABILITY_TO_CWE.get(vulnerability_type.lower(), [])


def get_owasp_category(cwe_id: int) -> Optional[str]:
    """
    Get OWASP Top 10 category for CWE.

    Args:
        cwe_id: CWE identifier

    Returns:
        OWASP category string or None
    """
    owasp = CWE_TO_OWASP.get(cwe_id)
    return owasp.value if owasp else None


# =============================================================================
# EXPORTS
# =============================================================================


__all__ = [
    # Main class
    "ComplianceMapper",

    # Data classes
    "CWEMapping",
    "ComplianceMapping",
    "ComplianceReport",

    # Enums
    "ComplianceFramework",
    "OWASPCategory",
    "PCIDSSRequirement",
    "NISTControlFamily",

    # Constants
    "VULNERABILITY_TO_CWE",
    "CWE_TO_OWASP",
    "OWASP_TO_PCI_DSS",
    "OWASP_TO_NIST",
    "OWASP_TO_ISO27001",
    "SECURITY_GDPR_ARTICLES",
    "HIPAA_SAFEGUARDS",
    "SOC2_CRITERIA",
    "CWE_DATABASE",

    # Convenience functions
    "map_to_compliance",
    "get_cwe_mapping",
    "get_owasp_category",
]
