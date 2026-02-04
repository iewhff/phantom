"""
Compliance Mapping Engine.
Maps findings to compliance frameworks (OWASP ASVS, ISO 27001, PCI DSS, GDPR).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from utils.logger import get_logger

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


@dataclass
class ComplianceControl:
    """Represents a compliance control."""
    id: str
    framework: str
    name: str
    description: str
    severity: str
    related_cwes: list[str] = field(default_factory=list)
    related_vulns: list[str] = field(default_factory=list)


@dataclass
class ComplianceViolation:
    """Represents a compliance violation."""
    control: ComplianceControl
    finding: dict[str, Any]
    gap_description: str
    remediation_priority: str


class ComplianceMapper:
    """
    Maps security findings to compliance frameworks.
    
    Supports:
    - OWASP ASVS 4.0
    - ISO 27001:2022
    - PCI DSS 4.0
    - GDPR
    - SOC 2
    - HIPAA
    """
    
    # OWASP ASVS 4.0 Controls
    OWASP_ASVS = {
        "V1.1": ComplianceControl(
            id="V1.1",
            framework="OWASP ASVS 4.0",
            name="Secure Software Development Lifecycle",
            description="Verify that a secure development lifecycle is in use",
            severity="HIGH",
            related_cwes=["CWE-693"],
            related_vulns=["security_misconfiguration"],
        ),
        "V2.1.1": ComplianceControl(
            id="V2.1.1",
            framework="OWASP ASVS 4.0",
            name="Password Length",
            description="Verify user passwords are at least 12 characters",
            severity="MEDIUM",
            related_cwes=["CWE-521"],
            related_vulns=["weak_password", "auth"],
        ),
        "V2.2.1": ComplianceControl(
            id="V2.2.1",
            framework="OWASP ASVS 4.0",
            name="Anti-Automation",
            description="Verify anti-automation controls for credential stuffing",
            severity="HIGH",
            related_cwes=["CWE-307"],
            related_vulns=["auth", "brute_force"],
        ),
        "V3.4.1": ComplianceControl(
            id="V3.4.1",
            framework="OWASP ASVS 4.0",
            name="Cookie Security",
            description="Verify cookie-based session tokens have Secure attribute",
            severity="MEDIUM",
            related_cwes=["CWE-614"],
            related_vulns=["session", "cookie"],
        ),
        "V5.1.1": ComplianceControl(
            id="V5.1.1",
            framework="OWASP ASVS 4.0",
            name="Input Validation",
            description="Verify input validation on trusted service layer",
            severity="HIGH",
            related_cwes=["CWE-20"],
            related_vulns=["sqli", "xss", "cmdi", "injection"],
        ),
        "V5.2.4": ComplianceControl(
            id="V5.2.4",
            framework="OWASP ASVS 4.0",
            name="SQL Injection Prevention",
            description="Verify protection against SQL injection",
            severity="CRITICAL",
            related_cwes=["CWE-89"],
            related_vulns=["sqli"],
        ),
        "V5.2.6": ComplianceControl(
            id="V5.2.6",
            framework="OWASP ASVS 4.0",
            name="OS Command Injection",
            description="Verify protection against OS command injection",
            severity="CRITICAL",
            related_cwes=["CWE-78"],
            related_vulns=["cmdi"],
        ),
        "V5.3.3": ComplianceControl(
            id="V5.3.3",
            framework="OWASP ASVS 4.0",
            name="XSS Prevention",
            description="Verify context-aware output encoding for XSS",
            severity="HIGH",
            related_cwes=["CWE-79"],
            related_vulns=["xss"],
        ),
        "V5.5.2": ComplianceControl(
            id="V5.5.2",
            framework="OWASP ASVS 4.0",
            name="XXE Prevention",
            description="Verify XML parsing is protected against XXE",
            severity="HIGH",
            related_cwes=["CWE-611"],
            related_vulns=["xxe"],
        ),
        "V7.1.1": ComplianceControl(
            id="V7.1.1",
            framework="OWASP ASVS 4.0",
            name="Error Handling",
            description="Verify application does not leak sensitive errors",
            severity="MEDIUM",
            related_cwes=["CWE-209"],
            related_vulns=["information_disclosure"],
        ),
        "V9.1.1": ComplianceControl(
            id="V9.1.1",
            framework="OWASP ASVS 4.0",
            name="TLS for Communications",
            description="Verify TLS for all client connectivity",
            severity="HIGH",
            related_cwes=["CWE-319"],
            related_vulns=["ssl", "tls"],
        ),
        "V10.3.2": ComplianceControl(
            id="V10.3.2",
            framework="OWASP ASVS 4.0",
            name="Dependency Security",
            description="Verify components are from trusted sources",
            severity="MEDIUM",
            related_cwes=["CWE-829"],
            related_vulns=["vulnerable_component"],
        ),
        "V12.3.1": ComplianceControl(
            id="V12.3.1",
            framework="OWASP ASVS 4.0",
            name="Path Traversal",
            description="Verify protection against path traversal",
            severity="HIGH",
            related_cwes=["CWE-22"],
            related_vulns=["lfi", "path_traversal"],
        ),
        "V13.1.3": ComplianceControl(
            id="V13.1.3",
            framework="OWASP ASVS 4.0",
            name="SSRF Prevention",
            description="Verify API URLs are not used as input",
            severity="HIGH",
            related_cwes=["CWE-918"],
            related_vulns=["ssrf"],
        ),
        "V14.2.1": ComplianceControl(
            id="V14.2.1",
            framework="OWASP ASVS 4.0",
            name="Security Headers",
            description="Verify security headers are set appropriately",
            severity="MEDIUM",
            related_cwes=["CWE-693"],
            related_vulns=["headers", "security_headers"],
        ),
    }
    
    # ISO 27001:2022 Controls
    ISO_27001 = {
        "A.5.1": ComplianceControl(
            id="A.5.1",
            framework="ISO 27001:2022",
            name="Information Security Policies",
            description="Policies for information security",
            severity="MEDIUM",
            related_vulns=["policy"],
        ),
        "A.8.2": ComplianceControl(
            id="A.8.2",
            framework="ISO 27001:2022",
            name="Privileged Access Rights",
            description="Restriction and control of privileged access",
            severity="HIGH",
            related_cwes=["CWE-269", "CWE-250"],
            related_vulns=["authorization", "privilege_escalation"],
        ),
        "A.8.3": ComplianceControl(
            id="A.8.3",
            framework="ISO 27001:2022",
            name="Information Access Restriction",
            description="Access to information restricted per access control policy",
            severity="HIGH",
            related_cwes=["CWE-862", "CWE-863"],
            related_vulns=["authorization", "idor", "access_control"],
        ),
        "A.8.7": ComplianceControl(
            id="A.8.7",
            framework="ISO 27001:2022",
            name="Protection Against Malware",
            description="Protection against malware implemented",
            severity="HIGH",
            related_vulns=["malware", "file_upload"],
        ),
        "A.8.9": ComplianceControl(
            id="A.8.9",
            framework="ISO 27001:2022",
            name="Configuration Management",
            description="Security configurations established and managed",
            severity="MEDIUM",
            related_cwes=["CWE-16"],
            related_vulns=["security_misconfiguration", "headers"],
        ),
        "A.8.12": ComplianceControl(
            id="A.8.12",
            framework="ISO 27001:2022",
            name="Data Leakage Prevention",
            description="Measures to prevent data leakage",
            severity="HIGH",
            related_cwes=["CWE-200"],
            related_vulns=["information_disclosure", "data_exposure"],
        ),
        "A.8.20": ComplianceControl(
            id="A.8.20",
            framework="ISO 27001:2022",
            name="Networks Security",
            description="Network controls to protect information",
            severity="HIGH",
            related_vulns=["network", "ssl", "tls"],
        ),
        "A.8.24": ComplianceControl(
            id="A.8.24",
            framework="ISO 27001:2022",
            name="Use of Cryptography",
            description="Cryptographic controls defined and implemented",
            severity="HIGH",
            related_cwes=["CWE-327", "CWE-328"],
            related_vulns=["crypto", "ssl", "tls", "weak_cipher"],
        ),
        "A.8.26": ComplianceControl(
            id="A.8.26",
            framework="ISO 27001:2022",
            name="Application Security Requirements",
            description="Security requirements for applications",
            severity="HIGH",
            related_vulns=["sqli", "xss", "injection"],
        ),
        "A.8.28": ComplianceControl(
            id="A.8.28",
            framework="ISO 27001:2022",
            name="Secure Coding",
            description="Secure coding principles applied",
            severity="HIGH",
            related_cwes=["CWE-20"],
            related_vulns=["injection", "sqli", "xss", "cmdi"],
        ),
    }
    
    # PCI DSS 4.0 Requirements
    PCI_DSS = {
        "2.2.1": ComplianceControl(
            id="2.2.1",
            framework="PCI DSS 4.0",
            name="Configuration Standards",
            description="Configuration standards for all system components",
            severity="HIGH",
            related_vulns=["security_misconfiguration"],
        ),
        "3.5.1": ComplianceControl(
            id="3.5.1",
            framework="PCI DSS 4.0",
            name="Cryptographic Architecture",
            description="Document and implement cryptographic architecture",
            severity="HIGH",
            related_cwes=["CWE-327"],
            related_vulns=["crypto", "ssl"],
        ),
        "4.2.1": ComplianceControl(
            id="4.2.1",
            framework="PCI DSS 4.0",
            name="Strong Cryptography",
            description="Strong cryptography for transmission of CHD",
            severity="CRITICAL",
            related_cwes=["CWE-319"],
            related_vulns=["ssl", "tls", "weak_cipher"],
        ),
        "6.2.4": ComplianceControl(
            id="6.2.4",
            framework="PCI DSS 4.0",
            name="Injection Attacks",
            description="Prevention of injection attacks",
            severity="CRITICAL",
            related_cwes=["CWE-89", "CWE-78", "CWE-79"],
            related_vulns=["sqli", "cmdi", "xss"],
        ),
        "6.3.1": ComplianceControl(
            id="6.3.1",
            framework="PCI DSS 4.0",
            name="Vulnerability Identification",
            description="Security vulnerabilities identified and addressed",
            severity="HIGH",
            related_vulns=["all"],
        ),
        "6.4.1": ComplianceControl(
            id="6.4.1",
            framework="PCI DSS 4.0",
            name="Web Application Attacks",
            description="Protection against web application attacks",
            severity="CRITICAL",
            related_vulns=["sqli", "xss", "xxe", "ssrf", "cmdi"],
        ),
        "7.2.2": ComplianceControl(
            id="7.2.2",
            framework="PCI DSS 4.0",
            name="Access Control",
            description="Access control based on job responsibilities",
            severity="HIGH",
            related_cwes=["CWE-862"],
            related_vulns=["authorization", "idor"],
        ),
        "8.3.1": ComplianceControl(
            id="8.3.1",
            framework="PCI DSS 4.0",
            name="Authentication",
            description="Strong authentication for all system components",
            severity="HIGH",
            related_cwes=["CWE-287"],
            related_vulns=["auth", "brute_force"],
        ),
        "11.3.1": ComplianceControl(
            id="11.3.1",
            framework="PCI DSS 4.0",
            name="Penetration Testing",
            description="External and internal penetration testing",
            severity="HIGH",
            related_vulns=["all"],
        ),
    }
    
    # GDPR Articles
    GDPR = {
        "Art.5.1.f": ComplianceControl(
            id="Art.5.1.f",
            framework="GDPR",
            name="Integrity and Confidentiality",
            description="Appropriate security for personal data",
            severity="CRITICAL",
            related_vulns=["sqli", "xss", "injection", "data_exposure"],
        ),
        "Art.25": ComplianceControl(
            id="Art.25",
            framework="GDPR",
            name="Data Protection by Design",
            description="Appropriate measures for data protection",
            severity="HIGH",
            related_vulns=["all"],
        ),
        "Art.32.1.a": ComplianceControl(
            id="Art.32.1.a",
            framework="GDPR",
            name="Encryption",
            description="Pseudonymisation and encryption of personal data",
            severity="HIGH",
            related_cwes=["CWE-311"],
            related_vulns=["ssl", "crypto", "data_exposure"],
        ),
        "Art.32.1.b": ComplianceControl(
            id="Art.32.1.b",
            framework="GDPR",
            name="Confidentiality",
            description="Ensure confidentiality of processing systems",
            severity="CRITICAL",
            related_cwes=["CWE-200"],
            related_vulns=["sqli", "idor", "data_exposure", "authorization"],
        ),
        "Art.32.2": ComplianceControl(
            id="Art.32.2",
            framework="GDPR",
            name="Risk Assessment",
            description="Assess risks to rights of data subjects",
            severity="HIGH",
            related_vulns=["all"],
        ),
        "Art.33": ComplianceControl(
            id="Art.33",
            framework="GDPR",
            name="Breach Notification",
            description="Notify supervisory authority of breaches",
            severity="CRITICAL",
            related_vulns=["sqli", "data_breach"],
        ),
    }
    
    def __init__(self):
        self.all_controls = {
            **self.OWASP_ASVS,
            **self.ISO_27001,
            **self.PCI_DSS,
            **self.GDPR,
        }
    
    def map_finding_to_compliance(
        self,
        finding: dict[str, Any],
    ) -> list[ComplianceViolation]:
        """Map a finding to applicable compliance controls."""
        violations = []
        
        vuln_type = finding.get("type", "").lower()
        cwe = finding.get("cwe", "")
        severity = finding.get("severity", "MEDIUM")
        
        for control_id, control in self.all_controls.items():
            # Check by vulnerability type
            if any(v in vuln_type for v in control.related_vulns) or "all" in control.related_vulns:
                violations.append(ComplianceViolation(
                    control=control,
                    finding=finding,
                    gap_description=f"Finding '{finding.get('name')}' violates {control.framework} {control.id}",
                    remediation_priority=self._calculate_priority(severity, control.severity),
                ))
                continue
            
            # Check by CWE
            if cwe and cwe in control.related_cwes:
                violations.append(ComplianceViolation(
                    control=control,
                    finding=finding,
                    gap_description=f"CWE {cwe} maps to {control.framework} {control.id}",
                    remediation_priority=self._calculate_priority(severity, control.severity),
                ))
        
        return violations
    
    def _calculate_priority(self, finding_severity: str, control_severity: str) -> str:
        """Calculate remediation priority based on severities."""
        severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        
        finding_score = severity_order.get(finding_severity, 2)
        control_score = severity_order.get(control_severity, 2)
        
        combined = (finding_score + control_score) / 2
        
        if combined >= 3.5:
            return "IMMEDIATE"
        elif combined >= 2.5:
            return "HIGH"
        elif combined >= 1.5:
            return "MEDIUM"
        return "LOW"
    
    def generate_compliance_report(
        self,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Generate full compliance report from findings."""
        all_violations: list[ComplianceViolation] = []
        
        for finding in findings:
            violations = self.map_finding_to_compliance(finding)
            all_violations.extend(violations)
        
        # Group by framework
        by_framework: dict[str, list[dict]] = {}
        
        for violation in all_violations:
            framework = violation.control.framework
            if framework not in by_framework:
                by_framework[framework] = []
            
            by_framework[framework].append({
                "control_id": violation.control.id,
                "control_name": violation.control.name,
                "finding": violation.finding.get("name"),
                "gap": violation.gap_description,
                "priority": violation.remediation_priority,
            })
        
        # Calculate compliance scores
        scores = {}
        for framework, violations in by_framework.items():
            total_controls = sum(
                1 for c in self.all_controls.values() 
                if c.framework == framework
            )
            violated_controls = len(set(v["control_id"] for v in violations))
            score = max(0, 100 - (violated_controls / total_controls * 100))
            scores[framework] = round(score, 1)
        
        return {
            "compliance_report": by_framework,
            "compliance_scores": scores,
            "total_violations": len(all_violations),
            "frameworks_assessed": list(by_framework.keys()),
            "immediate_actions": [
                v for v in all_violations 
                if v.remediation_priority == "IMMEDIATE"
            ][:10],
        }
    
    def get_framework_requirements(
        self,
        framework: str,
    ) -> list[ComplianceControl]:
        """Get all controls for a specific framework."""
        return [
            c for c in self.all_controls.values()
            if c.framework == framework
        ]
    
    def get_control_by_id(self, control_id: str) -> ComplianceControl | None:
        """Get a specific control by ID."""
        return self.all_controls.get(control_id)
