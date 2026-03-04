"""
PHANTOM AI - SARIF Generator Module

Generates SARIF 2.1.0 compliant output for DevSecOps integration.
Supports GitHub Security, Azure DevOps, and other SARIF-compatible tools.

Version: 3.0.0
Date: 2026-01-30

SARIF Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Features:
- SARIF 2.1.0 specification compliance
- GitHub Code Scanning integration
- Azure DevOps integration
- Detailed vulnerability reporting
- CWE, CVE, and OWASP mapping
- Request/response artifacts
- Fix suggestions
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# =============================================================================
# SARIF CONSTANTS
# =============================================================================


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

PHANTOM_TOOL_NAME = "PHANTOM AI"
PHANTOM_TOOL_VERSION = "3.0.0"
PHANTOM_TOOL_SEMANTIC_VERSION = "3.0.0"
PHANTOM_TOOL_ORGANIZATION = "PHANTOM AI Security"
PHANTOM_TOOL_INFORMATION_URI = "https://github.com/phantom-ai/phantom"


# =============================================================================
# ENUMS
# =============================================================================


class SARIFLevel(Enum):
    """SARIF result levels."""

    NONE = "none"
    NOTE = "note"
    WARNING = "warning"
    ERROR = "error"


class SARIFKind(Enum):
    """SARIF result kinds."""

    NOT_APPLICABLE = "notApplicable"
    PASS = "pass"
    FAIL = "fail"
    REVIEW = "review"
    OPEN = "open"
    INFORMATIONAL = "informational"


class SeverityToLevel:
    """Map vulnerability severity to SARIF level."""

    MAPPING = {
        "critical": SARIFLevel.ERROR,
        "high": SARIFLevel.ERROR,
        "medium": SARIFLevel.WARNING,
        "low": SARIFLevel.NOTE,
        "info": SARIFLevel.NOTE,
        "informational": SARIFLevel.NONE,
    }

    @classmethod
    def get(cls, severity: str) -> SARIFLevel:
        """Get SARIF level for severity."""
        return cls.MAPPING.get(severity.lower(), SARIFLevel.WARNING)


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class SARIFLocation:
    """SARIF physical location."""

    uri: str
    start_line: int = 1
    start_column: int = 1
    end_line: Optional[int] = None
    end_column: Optional[int] = None
    snippet: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to SARIF location object."""
        region: Dict[str, Any] = {
            "startLine": self.start_line,
            "startColumn": self.start_column,
        }

        if self.end_line:
            region["endLine"] = self.end_line
        if self.end_column:
            region["endColumn"] = self.end_column
        if self.snippet:
            region["snippet"] = {"text": self.snippet}

        return {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": self.uri,
                    "uriBaseId": "%SRCROOT%",
                },
                "region": region,
            }
        }


@dataclass
class SARIFWebLocation:
    """SARIF web-based location for dynamic analysis."""

    uri: str
    method: str = "GET"
    parameter: Optional[str] = None
    request_headers: Optional[Dict[str, str]] = None
    response_status: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to SARIF location with properties."""
        location: Dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": self.uri,
                }
            },
            "properties": {
                "requestMethod": self.method,
            }
        }

        if self.parameter:
            location["properties"]["vulnerableParameter"] = self.parameter
        if self.request_headers:
            location["properties"]["requestHeaders"] = self.request_headers
        if self.response_status:
            location["properties"]["responseStatus"] = self.response_status

        return location


@dataclass
class SARIFFix:
    """SARIF fix suggestion."""

    description: str
    artifact_changes: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to SARIF fix object."""
        return {
            "description": {
                "text": self.description,
            },
            "artifactChanges": self.artifact_changes,
        }


@dataclass
class SARIFRule:
    """SARIF reporting rule."""

    id: str
    name: str
    short_description: str
    full_description: str
    help_uri: Optional[str] = None
    help_text: Optional[str] = None
    default_level: SARIFLevel = SARIFLevel.WARNING
    tags: List[str] = field(default_factory=list)
    cwe_ids: List[int] = field(default_factory=list)
    owasp_ids: List[str] = field(default_factory=list)
    relationships: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to SARIF rule object."""
        rule: Dict[str, Any] = {
            "id": self.id,
            "name": self.name,
            "shortDescription": {
                "text": self.short_description,
            },
            "fullDescription": {
                "text": self.full_description,
            },
            "defaultConfiguration": {
                "level": self.default_level.value,
            },
            "properties": {
                "tags": self.tags,
                "precision": "high",
                "security-severity": self._get_security_severity(),
            },
        }

        if self.help_uri:
            rule["helpUri"] = self.help_uri

        if self.help_text:
            rule["help"] = {
                "text": self.help_text,
                "markdown": self.help_text,
            }

        # Add CWE relationships
        if self.cwe_ids:
            rule["properties"]["cwe"] = [f"CWE-{cwe}" for cwe in self.cwe_ids]
            rule["relationships"] = [
                {
                    "target": {
                        "id": f"CWE-{cwe}",
                        "guid": self._cwe_guid(cwe),
                        "toolComponent": {
                            "name": "CWE",
                            "guid": "a3e4e7c4-4b0c-4e8d-9c6a-8e7f5b6c4d3e",
                        },
                    },
                    "kinds": ["superset"],
                }
                for cwe in self.cwe_ids
            ]

        if self.owasp_ids:
            rule["properties"]["owasp"] = self.owasp_ids

        return rule

    def _get_security_severity(self) -> str:
        """Get security severity score (0-10)."""
        level_scores = {
            SARIFLevel.ERROR: "9.0",
            SARIFLevel.WARNING: "6.0",
            SARIFLevel.NOTE: "3.0",
            SARIFLevel.NONE: "0.0",
        }
        return level_scores.get(self.default_level, "5.0")

    def _cwe_guid(self, cwe_id: int) -> str:
        """Generate GUID for CWE reference."""
        return hashlib.md5(f"CWE-{cwe_id}".encode()).hexdigest()


@dataclass
class SARIFResult:
    """SARIF result (finding)."""

    rule_id: str
    message: str
    level: SARIFLevel = SARIFLevel.WARNING
    kind: SARIFKind = SARIFKind.FAIL
    locations: List[Union[SARIFLocation, SARIFWebLocation]] = field(default_factory=list)
    related_locations: List[Union[SARIFLocation, SARIFWebLocation]] = field(default_factory=list)
    fixes: List[SARIFFix] = field(default_factory=list)
    fingerprints: Dict[str, str] = field(default_factory=dict)
    partial_fingerprints: Dict[str, str] = field(default_factory=dict)
    code_flows: List[Dict[str, Any]] = field(default_factory=list)
    stacks: List[Dict[str, Any]] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)

    # PHANTOM-specific
    vulnerability_id: Optional[str] = None
    cvss_score: Optional[float] = None
    confidence: Optional[float] = None
    evidence: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to SARIF result object."""
        result: Dict[str, Any] = {
            "ruleId": self.rule_id,
            "level": self.level.value,
            "kind": self.kind.value,
            "message": {
                "text": self.message,
            },
        }

        if self.locations:
            result["locations"] = [loc.to_dict() for loc in self.locations]

        if self.related_locations:
            result["relatedLocations"] = [
                loc.to_dict() for loc in self.related_locations
            ]

        if self.fixes:
            result["fixes"] = [fix.to_dict() for fix in self.fixes]

        if self.fingerprints:
            result["fingerprints"] = self.fingerprints

        if self.partial_fingerprints:
            result["partialFingerprints"] = self.partial_fingerprints

        if self.code_flows:
            result["codeFlows"] = self.code_flows

        if self.stacks:
            result["stacks"] = self.stacks

        # Properties
        props: Dict[str, Any] = dict(self.properties)

        if self.vulnerability_id:
            props["vulnerabilityId"] = self.vulnerability_id
        if self.cvss_score is not None:
            props["cvssScore"] = self.cvss_score
        if self.confidence is not None:
            props["confidence"] = self.confidence
        if self.evidence:
            props["evidence"] = self.evidence
        if self.request:
            props["httpRequest"] = self.request
        if self.response:
            props["httpResponse"] = self.response[:5000] if self.response else None

        if props:
            result["properties"] = props

        return result


@dataclass
class SARIFInvocation:
    """SARIF invocation (scan execution)."""

    execution_successful: bool = True
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    working_directory: Optional[str] = None
    command_line: Optional[str] = None
    exit_code: int = 0
    tool_execution_notifications: List[Dict[str, Any]] = field(default_factory=list)
    tool_configuration_notifications: List[Dict[str, Any]] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to SARIF invocation object."""
        invocation: Dict[str, Any] = {
            "executionSuccessful": self.execution_successful,
            "exitCode": self.exit_code,
        }

        if self.start_time:
            invocation["startTimeUtc"] = self.start_time.astimezone(timezone.utc).isoformat()
        if self.end_time:
            invocation["endTimeUtc"] = self.end_time.astimezone(timezone.utc).isoformat()
        if self.working_directory:
            invocation["workingDirectory"] = {
                "uri": self.working_directory,
            }
        if self.command_line:
            invocation["commandLine"] = self.command_line

        if self.tool_execution_notifications:
            invocation["toolExecutionNotifications"] = self.tool_execution_notifications
        if self.tool_configuration_notifications:
            invocation["toolConfigurationNotifications"] = self.tool_configuration_notifications

        if self.properties:
            invocation["properties"] = self.properties

        return invocation


@dataclass
class SARIFArtifact:
    """SARIF artifact (scanned resource)."""

    uri: str
    mime_type: Optional[str] = None
    length: Optional[int] = None
    contents: Optional[str] = None
    hashes: Optional[Dict[str, str]] = None
    roles: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to SARIF artifact object."""
        artifact: Dict[str, Any] = {
            "location": {
                "uri": self.uri,
            },
        }

        if self.mime_type:
            artifact["mimeType"] = self.mime_type
        if self.length:
            artifact["length"] = self.length
        if self.contents:
            artifact["contents"] = {
                "text": self.contents[:10000],  # Limit size
            }
        if self.hashes:
            artifact["hashes"] = self.hashes
        if self.roles:
            artifact["roles"] = self.roles

        return artifact


# =============================================================================
# VULNERABILITY RULES DATABASE
# =============================================================================


VULNERABILITY_RULES: Dict[str, SARIFRule] = {
    "sqli": SARIFRule(
        id="PHANTOM-SQL-001",
        name="SQL Injection",
        short_description="SQL Injection vulnerability detected",
        full_description=(
            "SQL Injection occurs when untrusted data is sent to an interpreter "
            "as part of a command or query. The attacker's hostile data can trick "
            "the interpreter into executing unintended commands or accessing data "
            "without proper authorization."
        ),
        help_uri="https://owasp.org/www-community/attacks/SQL_Injection",
        help_text=(
            "## Remediation\n\n"
            "1. Use parameterized queries (prepared statements)\n"
            "2. Use stored procedures\n"
            "3. Validate and sanitize all user input\n"
            "4. Apply the principle of least privilege to database accounts\n"
            "5. Use ORM frameworks that handle escaping automatically"
        ),
        default_level=SARIFLevel.ERROR,
        tags=["security", "injection", "sql", "database", "owasp-top-10"],
        cwe_ids=[89],
        owasp_ids=["A03:2021"],
    ),
    "xss": SARIFRule(
        id="PHANTOM-XSS-001",
        name="Cross-Site Scripting (XSS)",
        short_description="Cross-Site Scripting vulnerability detected",
        full_description=(
            "XSS flaws occur when an application includes untrusted data in a new "
            "web page without proper validation or escaping. XSS allows attackers "
            "to execute scripts in the victim's browser which can hijack user sessions, "
            "deface websites, or redirect users to malicious sites."
        ),
        help_uri="https://owasp.org/www-community/attacks/xss/",
        help_text=(
            "## Remediation\n\n"
            "1. Use context-aware output encoding\n"
            "2. Implement Content Security Policy (CSP)\n"
            "3. Use HttpOnly and Secure flags for cookies\n"
            "4. Validate and sanitize user input\n"
            "5. Use frameworks that automatically escape XSS by design"
        ),
        default_level=SARIFLevel.WARNING,
        tags=["security", "xss", "injection", "client-side", "owasp-top-10"],
        cwe_ids=[79],
        owasp_ids=["A03:2021"],
    ),
    "cmdi": SARIFRule(
        id="PHANTOM-CMD-001",
        name="Command Injection",
        short_description="OS Command Injection vulnerability detected",
        full_description=(
            "OS command injection allows an attacker to execute arbitrary system "
            "commands on the server. This can result in complete system compromise, "
            "data theft, or use of the compromised system to attack other systems."
        ),
        help_uri="https://owasp.org/www-community/attacks/Command_Injection",
        help_text=(
            "## Remediation\n\n"
            "1. Avoid system calls and shell commands where possible\n"
            "2. Use safe APIs that don't invoke shell interpreters\n"
            "3. Implement strict input validation with allowlists\n"
            "4. Run with minimal privileges\n"
            "5. Use containerization to limit impact"
        ),
        default_level=SARIFLevel.ERROR,
        tags=["security", "injection", "rce", "command", "owasp-top-10"],
        cwe_ids=[78, 77],
        owasp_ids=["A03:2021"],
    ),
    "ssrf": SARIFRule(
        id="PHANTOM-SSRF-001",
        name="Server-Side Request Forgery (SSRF)",
        short_description="SSRF vulnerability detected",
        full_description=(
            "SSRF occurs when a web application fetches a remote resource without "
            "validating the user-supplied URL. This allows attackers to coerce the "
            "application to send requests to unexpected destinations, potentially "
            "accessing internal services, cloud metadata, or sensitive resources."
        ),
        help_uri="https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
        help_text=(
            "## Remediation\n\n"
            "1. Implement URL allowlisting\n"
            "2. Block requests to private IP ranges\n"
            "3. Disable unnecessary URL schemes\n"
            "4. Use network segmentation\n"
            "5. Implement request timeouts"
        ),
        default_level=SARIFLevel.ERROR,
        tags=["security", "ssrf", "network", "cloud", "owasp-top-10"],
        cwe_ids=[918],
        owasp_ids=["A10:2021"],
    ),
    "xxe": SARIFRule(
        id="PHANTOM-XXE-001",
        name="XML External Entity (XXE)",
        short_description="XXE vulnerability detected",
        full_description=(
            "XXE attacks exploit vulnerable XML parsers that process external entity "
            "references. Attackers can use XXE to read local files, perform SSRF, "
            "execute remote code, or cause denial of service."
        ),
        help_uri="https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
        help_text=(
            "## Remediation\n\n"
            "1. Disable external entity processing in XML parsers\n"
            "2. Use JSON instead of XML where possible\n"
            "3. Upgrade XML libraries to latest versions\n"
            "4. Implement server-side input validation\n"
            "5. Use SAST tools to detect XXE vulnerabilities"
        ),
        default_level=SARIFLevel.ERROR,
        tags=["security", "xxe", "xml", "injection", "owasp-top-10"],
        cwe_ids=[611],
        owasp_ids=["A05:2021"],
    ),
    "idor": SARIFRule(
        id="PHANTOM-IDOR-001",
        name="Insecure Direct Object Reference (IDOR)",
        short_description="IDOR vulnerability detected",
        full_description=(
            "IDOR occurs when an application exposes a reference to an internal "
            "implementation object, such as a database key, without proper access "
            "control. Attackers can manipulate these references to access unauthorized data."
        ),
        help_uri="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References",
        help_text=(
            "## Remediation\n\n"
            "1. Implement proper authorization checks\n"
            "2. Use indirect object references\n"
            "3. Validate user permissions for every request\n"
            "4. Use session-based access control\n"
            "5. Log and monitor access patterns"
        ),
        default_level=SARIFLevel.ERROR,
        tags=["security", "idor", "authorization", "access-control", "owasp-top-10"],
        cwe_ids=[639],
        owasp_ids=["A01:2021"],
    ),
    "auth_bypass": SARIFRule(
        id="PHANTOM-AUTH-001",
        name="Authentication Bypass",
        short_description="Authentication bypass vulnerability detected",
        full_description=(
            "Authentication bypass vulnerabilities allow attackers to gain access "
            "to protected resources without providing valid credentials. This can "
            "lead to unauthorized access to sensitive data and functionality."
        ),
        help_uri="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/",
        help_text=(
            "## Remediation\n\n"
            "1. Implement multi-factor authentication\n"
            "2. Use strong session management\n"
            "3. Enforce password policies\n"
            "4. Implement account lockout mechanisms\n"
            "5. Use proven authentication frameworks"
        ),
        default_level=SARIFLevel.ERROR,
        tags=["security", "authentication", "bypass", "access-control", "owasp-top-10"],
        cwe_ids=[287, 306],
        owasp_ids=["A07:2021"],
    ),
    "jwt_vuln": SARIFRule(
        id="PHANTOM-JWT-001",
        name="JWT Vulnerability",
        short_description="JWT security vulnerability detected",
        full_description=(
            "JWT vulnerabilities include algorithm confusion attacks, weak secrets, "
            "missing signature validation, and other issues that can lead to "
            "authentication bypass and privilege escalation."
        ),
        help_uri="https://portswigger.net/web-security/jwt",
        help_text=(
            "## Remediation\n\n"
            "1. Use strong algorithms (RS256, ES256)\n"
            "2. Validate all JWT claims\n"
            "3. Use strong, unique secrets\n"
            "4. Implement proper token expiration\n"
            "5. Never trust user-supplied algorithm headers"
        ),
        default_level=SARIFLevel.ERROR,
        tags=["security", "jwt", "authentication", "token", "crypto"],
        cwe_ids=[347, 327],
        owasp_ids=["A07:2021"],
    ),
    "csrf": SARIFRule(
        id="PHANTOM-CSRF-001",
        name="Cross-Site Request Forgery (CSRF)",
        short_description="CSRF vulnerability detected",
        full_description=(
            "CSRF forces an authenticated user to execute unwanted actions on a "
            "web application. With social engineering, an attacker may trick users "
            "into executing actions of the attacker's choosing."
        ),
        help_uri="https://owasp.org/www-community/attacks/csrf",
        help_text=(
            "## Remediation\n\n"
            "1. Implement CSRF tokens\n"
            "2. Use SameSite cookie attribute\n"
            "3. Verify Origin/Referer headers\n"
            "4. Require re-authentication for sensitive actions\n"
            "5. Use custom request headers for AJAX"
        ),
        default_level=SARIFLevel.WARNING,
        tags=["security", "csrf", "session", "state-changing"],
        cwe_ids=[352],
        owasp_ids=["A01:2021"],
    ),
    "cors": SARIFRule(
        id="PHANTOM-CORS-001",
        name="CORS Misconfiguration",
        short_description="CORS misconfiguration detected",
        full_description=(
            "Misconfigured CORS policies can allow unauthorized websites to access "
            "sensitive data from your application. This can lead to data theft "
            "and unauthorized actions on behalf of users."
        ),
        help_uri="https://portswigger.net/web-security/cors",
        help_text=(
            "## Remediation\n\n"
            "1. Implement strict origin allowlists\n"
            "2. Avoid using wildcards (*) in CORS headers\n"
            "3. Never reflect the Origin header without validation\n"
            "4. Use credentials: 'same-origin' where possible\n"
            "5. Implement proper preflight request handling"
        ),
        default_level=SARIFLevel.WARNING,
        tags=["security", "cors", "configuration", "browser"],
        cwe_ids=[942, 346],
        owasp_ids=["A05:2021"],
    ),
    "info_disclosure": SARIFRule(
        id="PHANTOM-INFO-001",
        name="Information Disclosure",
        short_description="Information disclosure vulnerability detected",
        full_description=(
            "Information disclosure vulnerabilities expose sensitive data such as "
            "configuration details, internal paths, stack traces, or user information "
            "that can aid attackers in further exploitation."
        ),
        help_uri="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/",
        help_text=(
            "## Remediation\n\n"
            "1. Implement proper error handling\n"
            "2. Remove debug information in production\n"
            "3. Configure secure HTTP headers\n"
            "4. Review and sanitize API responses\n"
            "5. Implement proper access controls"
        ),
        default_level=SARIFLevel.NOTE,
        tags=["security", "information-disclosure", "configuration"],
        cwe_ids=[200],
        owasp_ids=["A05:2021"],
    ),
    "ssti": SARIFRule(
        id="PHANTOM-SSTI-001",
        name="Server-Side Template Injection (SSTI)",
        short_description="SSTI vulnerability detected",
        full_description=(
            "SSTI occurs when user input is embedded in a template in an unsafe "
            "manner. Attackers can use template syntax to execute arbitrary code "
            "on the server, leading to complete system compromise."
        ),
        help_uri="https://portswigger.net/web-security/server-side-template-injection",
        help_text=(
            "## Remediation\n\n"
            "1. Never pass user input directly to templates\n"
            "2. Use logic-less templates where possible\n"
            "3. Implement strict input validation\n"
            "4. Use sandboxed template environments\n"
            "5. Keep template engines updated"
        ),
        default_level=SARIFLevel.ERROR,
        tags=["security", "ssti", "injection", "rce", "template"],
        cwe_ids=[94, 1336],
        owasp_ids=["A03:2021"],
    ),
    "lfi": SARIFRule(
        id="PHANTOM-LFI-001",
        name="Local File Inclusion (LFI)",
        short_description="LFI vulnerability detected",
        full_description=(
            "LFI vulnerabilities allow attackers to include local files from the "
            "server, potentially exposing sensitive configuration files, source code, "
            "or enabling remote code execution through log poisoning."
        ),
        help_uri="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
        help_text=(
            "## Remediation\n\n"
            "1. Implement strict input validation with allowlists\n"
            "2. Use absolute paths and avoid user-controlled paths\n"
            "3. Implement proper file permission controls\n"
            "4. Use chroot jails or containers\n"
            "5. Disable dangerous PHP functions if applicable"
        ),
        default_level=SARIFLevel.ERROR,
        tags=["security", "lfi", "file-inclusion", "path-traversal"],
        cwe_ids=[98, 22],
        owasp_ids=["A03:2021"],
    ),
    "insecure_deserialization": SARIFRule(
        id="PHANTOM-DESER-001",
        name="Insecure Deserialization",
        short_description="Insecure deserialization vulnerability detected",
        full_description=(
            "Insecure deserialization often leads to remote code execution. Even if "
            "deserialization flaws do not result in RCE, they can be used to perform "
            "attacks including replay attacks, injection attacks, and privilege escalation."
        ),
        help_uri="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Incoming_Requests",
        help_text=(
            "## Remediation\n\n"
            "1. Avoid native deserialization formats\n"
            "2. Implement integrity checks (digital signatures)\n"
            "3. Enforce strict type constraints\n"
            "4. Isolate deserialization code\n"
            "5. Log and monitor deserialization exceptions"
        ),
        default_level=SARIFLevel.ERROR,
        tags=["security", "deserialization", "rce", "owasp-top-10"],
        cwe_ids=[502],
        owasp_ids=["A08:2021"],
    ),
}


# =============================================================================
# SARIF GENERATOR
# =============================================================================


class SARIFGenerator:
    """
    PHANTOM AI SARIF Generator.

    Generates SARIF 2.1.0 compliant output for integration with
    GitHub Security, Azure DevOps, and other DevSecOps tools.
    """

    VERSION = "3.0.0"

    def __init__(
        self,
        tool_name: str = PHANTOM_TOOL_NAME,
        tool_version: str = PHANTOM_TOOL_VERSION,
    ) -> None:
        """
        Initialize SARIF generator.

        Args:
            tool_name: Name of the scanning tool
            tool_version: Version of the scanning tool
        """
        self.tool_name = tool_name
        self.tool_version = tool_version

        # Collect rules that are used
        self._used_rules: Dict[str, SARIFRule] = {}
        self._results: List[SARIFResult] = []
        self._artifacts: List[SARIFArtifact] = []
        self._invocation: Optional[SARIFInvocation] = None

        logger.info(f"SARIFGenerator v{self.VERSION} initialized")

    def set_invocation(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        working_directory: Optional[str] = None,
        command_line: Optional[str] = None,
        execution_successful: bool = True,
        **properties,
    ) -> None:
        """
        Set scan invocation details.

        Args:
            start_time: Scan start time
            end_time: Scan end time
            working_directory: Working directory
            command_line: Command line used
            execution_successful: Whether scan completed successfully
            **properties: Additional properties
        """
        self._invocation = SARIFInvocation(
            execution_successful=execution_successful,
            start_time=start_time,
            end_time=end_time,
            working_directory=working_directory,
            command_line=command_line,
            properties=properties,
        )

    def add_finding(
        self,
        vulnerability_type: str,
        url: str,
        message: str,
        severity: str = "medium",
        parameter: Optional[str] = None,
        evidence: Optional[str] = None,
        request: Optional[str] = None,
        response: Optional[str] = None,
        vulnerability_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        confidence: Optional[float] = None,
        method: str = "GET",
        fix_suggestion: Optional[str] = None,
        **properties,
    ) -> SARIFResult:
        """
        Add a finding to the SARIF report.

        Args:
            vulnerability_type: Type of vulnerability (e.g., "sqli", "xss")
            url: URL where vulnerability was found
            message: Description of the finding
            severity: Severity level (critical, high, medium, low, info)
            parameter: Vulnerable parameter name
            evidence: Evidence of vulnerability
            request: HTTP request
            response: HTTP response
            vulnerability_id: Unique identifier
            cvss_score: CVSS score
            confidence: Confidence level (0.0-1.0)
            method: HTTP method
            fix_suggestion: Suggested fix
            **properties: Additional properties

        Returns:
            Created SARIF result
        """
        # Get or create rule
        rule = self._get_or_create_rule(vulnerability_type, severity)
        self._used_rules[rule.id] = rule

        # Create location
        location = SARIFWebLocation(
            uri=url,
            method=method,
            parameter=parameter,
        )

        # Generate fingerprint
        fingerprint_data = f"{rule.id}:{url}:{parameter or ''}"
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]

        # Create result
        result = SARIFResult(
            rule_id=rule.id,
            message=message,
            level=SeverityToLevel.get(severity),
            kind=SARIFKind.FAIL,
            locations=[location],
            fingerprints={"primaryLocationLineHash": fingerprint},
            vulnerability_id=vulnerability_id,
            cvss_score=cvss_score,
            confidence=confidence,
            evidence=evidence,
            request=request,
            response=response,
            properties=properties,
        )

        # Add fix if provided
        if fix_suggestion:
            result.fixes.append(SARIFFix(description=fix_suggestion))

        self._results.append(result)

        # Add artifact
        parsed_url = urlparse(url)
        artifact = SARIFArtifact(
            uri=url,
            mime_type="text/html",
            roles=["analysisTarget"],
        )
        if not any(a.uri == url for a in self._artifacts):
            self._artifacts.append(artifact)

        return result

    def add_artifact(
        self,
        uri: str,
        mime_type: Optional[str] = None,
        contents: Optional[str] = None,
        roles: Optional[List[str]] = None,
    ) -> SARIFArtifact:
        """
        Add an artifact to the SARIF report.

        Args:
            uri: Artifact URI
            mime_type: MIME type
            contents: Artifact contents
            roles: Artifact roles

        Returns:
            Created SARIF artifact
        """
        artifact = SARIFArtifact(
            uri=uri,
            mime_type=mime_type,
            contents=contents,
            roles=roles or ["analysisTarget"],
        )
        self._artifacts.append(artifact)
        return artifact

    def add_vulnerability_chain(
        self,
        chain: Dict[str, Any],
        severity: str = "critical",
    ) -> List[SARIFResult]:
        """
        Add a vulnerability chain as related findings.

        Args:
            chain: Chain data from ChainActionsEngine
            severity: Chain severity

        Returns:
            List of created SARIF results
        """
        results = []
        vulnerabilities = chain.get("vulnerabilities", [])

        for idx, vuln in enumerate(vulnerabilities):
            result = self.add_finding(
                vulnerability_type=vuln.get("type", "unknown"),
                url=vuln.get("url", ""),
                message=f"Chain Step {idx + 1}: {vuln.get('description', 'Part of vulnerability chain')}",
                severity=vuln.get("severity", severity),
                parameter=vuln.get("parameter"),
                vulnerability_id=vuln.get("id"),
                cvss_score=vuln.get("cvss_score"),
                chain_id=chain.get("chain_id"),
                chain_position=idx,
                chain_size=len(vulnerabilities),
            )
            results.append(result)

        return results

    def _get_or_create_rule(
        self,
        vulnerability_type: str,
        severity: str,
    ) -> SARIFRule:
        """Get existing rule or create a generic one."""
        vuln_type_lower = vulnerability_type.lower()

        if vuln_type_lower in VULNERABILITY_RULES:
            return VULNERABILITY_RULES[vuln_type_lower]

        # Create generic rule for unknown type
        rule_id = f"PHANTOM-{vuln_type_lower.upper()}-001"

        if rule_id in self._used_rules:
            return self._used_rules[rule_id]

        return SARIFRule(
            id=rule_id,
            name=vulnerability_type.replace("_", " ").title(),
            short_description=f"{vulnerability_type.replace('_', ' ').title()} vulnerability detected",
            full_description=f"A {vulnerability_type.replace('_', ' ')} vulnerability was detected during security scanning.",
            default_level=SeverityToLevel.get(severity),
            tags=["security", vulnerability_type.lower()],
        )

    def generate(self) -> Dict[str, Any]:
        """
        Generate SARIF document.

        Returns:
            Complete SARIF document as dictionary
        """
        # Build tool component
        tool: Dict[str, Any] = {
            "driver": {
                "name": self.tool_name,
                "version": self.tool_version,
                "semanticVersion": PHANTOM_TOOL_SEMANTIC_VERSION,
                "organization": PHANTOM_TOOL_ORGANIZATION,
                "informationUri": PHANTOM_TOOL_INFORMATION_URI,
                "rules": [rule.to_dict() for rule in self._used_rules.values()],
                "properties": {
                    "tags": ["security", "dast", "penetration-testing"],
                },
            },
        }

        # Build run
        run: Dict[str, Any] = {
            "tool": tool,
            "results": [result.to_dict() for result in self._results],
        }

        if self._artifacts:
            run["artifacts"] = [artifact.to_dict() for artifact in self._artifacts]

        if self._invocation:
            run["invocations"] = [self._invocation.to_dict()]

        # Add taxonomy reference for CWE
        run["taxonomies"] = [
            {
                "name": "CWE",
                "version": "4.13",
                "organization": "MITRE",
                "shortDescription": {
                    "text": "Common Weakness Enumeration",
                },
                "informationUri": "https://cwe.mitre.org/",
                "guid": "a3e4e7c4-4b0c-4e8d-9c6a-8e7f5b6c4d3e",
            }
        ]

        # Build complete SARIF document
        sarif: Dict[str, Any] = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [run],
        }

        return sarif

    def generate_json(self, pretty: bool = True) -> str:
        """
        Generate SARIF as JSON string.

        Args:
            pretty: Whether to pretty-print

        Returns:
            JSON string
        """
        sarif = self.generate()
        indent = 2 if pretty else None
        return json.dumps(sarif, indent=indent)

    def save(self, output_path: Union[str, Path], pretty: bool = True) -> None:
        """
        Save SARIF to file.

        Args:
            output_path: Output file path
            pretty: Whether to pretty-print
        """
        path = Path(output_path)
        sarif_json = self.generate_json(pretty=pretty)
        path.write_text(sarif_json)
        logger.info(f"SARIF saved to {path}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get generation statistics."""
        severity_counts = {
            "error": 0,
            "warning": 0,
            "note": 0,
            "none": 0,
        }

        for result in self._results:
            severity_counts[result.level.value] += 1

        return {
            "total_results": len(self._results),
            "total_rules": len(self._used_rules),
            "total_artifacts": len(self._artifacts),
            "severity_distribution": severity_counts,
            "rules_used": list(self._used_rules.keys()),
        }

    def reset(self) -> None:
        """Reset generator state."""
        self._used_rules.clear()
        self._results.clear()
        self._artifacts.clear()
        self._invocation = None


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def findings_to_sarif(
    findings: List[Dict[str, Any]],
    tool_name: str = PHANTOM_TOOL_NAME,
    output_path: Optional[str] = None,
) -> str:
    """
    Convert findings list to SARIF format.

    Args:
        findings: List of finding dictionaries
        tool_name: Tool name
        output_path: Optional path to save SARIF

    Returns:
        SARIF JSON string
    """
    generator = SARIFGenerator(tool_name=tool_name)

    for finding in findings:
        generator.add_finding(
            vulnerability_type=finding.get("type", "unknown"),
            url=finding.get("url", ""),
            message=finding.get("description", finding.get("message", "")),
            severity=finding.get("severity", "medium"),
            parameter=finding.get("parameter"),
            evidence=finding.get("evidence"),
            request=finding.get("request"),
            response=finding.get("response"),
            vulnerability_id=finding.get("id"),
            cvss_score=finding.get("cvss_score"),
            confidence=finding.get("confidence"),
        )

    sarif_json = generator.generate_json()

    if output_path:
        Path(output_path).write_text(sarif_json)

    return sarif_json


def create_sarif_generator(
    tool_name: str = PHANTOM_TOOL_NAME,
    tool_version: str = PHANTOM_TOOL_VERSION,
) -> SARIFGenerator:
    """
    Create a SARIF generator instance.

    Args:
        tool_name: Tool name
        tool_version: Tool version

    Returns:
        SARIFGenerator instance
    """
    return SARIFGenerator(tool_name=tool_name, tool_version=tool_version)


# =============================================================================
# EXPORTS
# =============================================================================


__all__ = [
    # Main class
    "SARIFGenerator",

    # Data classes
    "SARIFLocation",
    "SARIFWebLocation",
    "SARIFFix",
    "SARIFRule",
    "SARIFResult",
    "SARIFInvocation",
    "SARIFArtifact",

    # Enums
    "SARIFLevel",
    "SARIFKind",
    "SeverityToLevel",

    # Constants
    "SARIF_VERSION",
    "SARIF_SCHEMA",
    "VULNERABILITY_RULES",

    # Convenience functions
    "findings_to_sarif",
    "create_sarif_generator",
]
