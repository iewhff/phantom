"""
HackerOne Bug Bounty Report Generator

Generates professional bug bounty reports in formats accepted by:
- HackerOne
- Bugcrowd
- Intigriti
- Other bug bounty platforms

Features:
- CVSS 3.1 scoring
- Proper severity classification
- Step-by-step reproduction
- Impact analysis
- Remediation recommendations
- JSON and Markdown export

Version: 1.0.0
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from utils.logger import get_logger

logger = get_logger(__name__)


class Severity(Enum):
    """Bug bounty severity levels."""
    CRITICAL = "critical"   # 9.0-10.0 CVSS
    HIGH = "high"           # 7.0-8.9 CVSS
    MEDIUM = "medium"       # 4.0-6.9 CVSS
    LOW = "low"             # 0.1-3.9 CVSS
    INFORMATIONAL = "informational"  # 0.0 CVSS


class VulnerabilityType(Enum):
    """Common vulnerability types for bug bounty."""
    XSS = "Cross-Site Scripting (XSS)"
    SQLI = "SQL Injection"
    SSRF = "Server-Side Request Forgery (SSRF)"
    IDOR = "Insecure Direct Object Reference (IDOR)"
    RCE = "Remote Code Execution (RCE)"
    AUTH_BYPASS = "Authentication Bypass"
    BROKEN_ACCESS = "Broken Access Control"
    SENSITIVE_DATA = "Sensitive Data Exposure"
    CSRF = "Cross-Site Request Forgery (CSRF)"
    XXE = "XML External Entity (XXE)"
    OPEN_REDIRECT = "Open Redirect"
    CORS = "CORS Misconfiguration"
    INFO_DISCLOSURE = "Information Disclosure"
    RATE_LIMITING = "Rate Limiting Bypass"
    BUSINESS_LOGIC = "Business Logic Flaw"
    OTHER = "Other"


@dataclass
class ReproductionStep:
    """A single step in reproducing the vulnerability."""
    step_number: int
    action: str
    expected_result: str
    actual_result: Optional[str] = None
    screenshot: Optional[str] = None
    request: Optional[str] = None
    response: Optional[str] = None


@dataclass
class ProofOfConcept:
    """Proof of concept details."""
    description: str
    request: Optional[str] = None
    response: Optional[str] = None
    screenshot_paths: list[str] = field(default_factory=list)
    video_path: Optional[str] = None
    code: Optional[str] = None


@dataclass
class CVSSVector:
    """CVSS 3.1 vector components."""
    # Base Metrics
    attack_vector: str = "N"      # N=Network, A=Adjacent, L=Local, P=Physical
    attack_complexity: str = "L"  # L=Low, H=High
    privileges_required: str = "N"  # N=None, L=Low, H=High
    user_interaction: str = "N"   # N=None, R=Required
    scope: str = "U"              # U=Unchanged, C=Changed
    confidentiality: str = "N"    # N=None, L=Low, H=High
    integrity: str = "N"          # N=None, L=Low, H=High
    availability: str = "N"       # N=None, L=Low, H=High

    def to_string(self) -> str:
        """Generate CVSS vector string."""
        return (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
            f"S:{self.scope}/C:{self.confidentiality}/I:{self.integrity}/"
            f"A:{self.availability}"
        )

    def calculate_score(self) -> float:
        """Calculate CVSS 3.1 base score."""
        # Value mappings
        av_values = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        ac_values = {"L": 0.77, "H": 0.44}
        pr_values_unchanged = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_values_changed = {"N": 0.85, "L": 0.68, "H": 0.50}
        ui_values = {"N": 0.85, "R": 0.62}
        cia_values = {"N": 0, "L": 0.22, "H": 0.56}

        # Get values
        av = av_values.get(self.attack_vector, 0.85)
        ac = ac_values.get(self.attack_complexity, 0.77)
        pr = (pr_values_changed if self.scope == "C" else pr_values_unchanged).get(
            self.privileges_required, 0.85
        )
        ui = ui_values.get(self.user_interaction, 0.85)

        c = cia_values.get(self.confidentiality, 0)
        i = cia_values.get(self.integrity, 0)
        a = cia_values.get(self.availability, 0)

        # Calculate ISS (Impact Sub-Score)
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))

        # Calculate Impact
        if self.scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss - 0.02, 15)

        # Calculate Exploitability
        exploitability = 8.22 * av * ac * pr * ui

        # Calculate Base Score
        if impact <= 0:
            return 0.0

        if self.scope == "U":
            score = min(impact + exploitability, 10)
        else:
            score = min(1.08 * (impact + exploitability), 10)

        return round(score * 10) / 10


@dataclass
class BugBountyReport:
    """Complete bug bounty report."""

    # Required fields
    title: str
    vulnerability_type: VulnerabilityType
    target: str
    endpoint: str
    description: str
    impact: str

    # Severity
    severity: Severity
    cvss: CVSSVector = field(default_factory=CVSSVector)

    # Reproduction
    steps_to_reproduce: list[ReproductionStep] = field(default_factory=list)

    # Evidence
    proof_of_concept: Optional[ProofOfConcept] = None

    # Additional info
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)

    # Metadata
    discovered_at: datetime = field(default_factory=datetime.now)
    reporter: str = "PetNTester AI"
    program_name: str = ""

    # Internal use
    confidence: float = 0.0  # 0-100
    false_positive_likelihood: float = 0.0

    def to_json(self) -> str:
        """Export report as JSON."""
        data = {
            "title": self.title,
            "vulnerability_type": self.vulnerability_type.value,
            "target": self.target,
            "endpoint": self.endpoint,
            "description": self.description,
            "impact": self.impact,
            "severity": self.severity.value,
            "cvss_score": self.cvss.calculate_score(),
            "cvss_vector": self.cvss.to_string(),
            "steps_to_reproduce": [asdict(s) for s in self.steps_to_reproduce],
            "proof_of_concept": asdict(self.proof_of_concept) if self.proof_of_concept else None,
            "remediation": self.remediation,
            "references": self.references,
            "cwe_ids": self.cwe_ids,
            "discovered_at": self.discovered_at.isoformat(),
            "reporter": self.reporter,
            "program_name": self.program_name,
            "confidence": self.confidence,
        }
        return json.dumps(data, indent=2)

    def to_markdown(self) -> str:
        """Export report as HackerOne-style Markdown."""
        cvss_score = self.cvss.calculate_score()

        md = f"""# {self.title}

## Summary

**Vulnerability Type:** {self.vulnerability_type.value}
**Severity:** {self.severity.value.upper()} (CVSS {cvss_score})
**Target:** {self.target}
**Endpoint:** `{self.endpoint}`
**CVSS Vector:** `{self.cvss.to_string()}`

---

## Description

{self.description}

---

## Impact

{self.impact}

---

## Steps to Reproduce

"""
        for step in self.steps_to_reproduce:
            md += f"""### Step {step.step_number}: {step.action}

**Expected:** {step.expected_result}
"""
            if step.actual_result:
                md += f"**Actual:** {step.actual_result}\n"

            if step.request:
                md += f"""
**Request:**
```http
{step.request}
```
"""
            if step.response:
                md += f"""
**Response:**
```http
{step.response}
```
"""
            md += "\n"

        if self.proof_of_concept:
            md += f"""---

## Proof of Concept

{self.proof_of_concept.description}

"""
            if self.proof_of_concept.code:
                md += f"""**PoC Code:**
```python
{self.proof_of_concept.code}
```

"""
            if self.proof_of_concept.request:
                md += f"""**PoC Request:**
```http
{self.proof_of_concept.request}
```

"""

        md += f"""---

## Remediation

{self.remediation}

"""

        if self.references:
            md += "---\n\n## References\n\n"
            for ref in self.references:
                md += f"- {ref}\n"
            md += "\n"

        if self.cwe_ids:
            md += "---\n\n## CWE IDs\n\n"
            for cwe in self.cwe_ids:
                md += f"- [{cwe}](https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html)\n"
            md += "\n"

        md += f"""---

**Discovered:** {self.discovered_at.strftime('%Y-%m-%d %H:%M UTC')}
**Reporter:** {self.reporter}
**Confidence:** {self.confidence:.0f}%

---

*Report generated by PetNTester AI - Bug Bounty Edition*
"""
        return md


class HackerOneReportGenerator:
    """
    Generate professional HackerOne-ready bug bounty reports.

    Features:
    - Automatic severity classification
    - CVSS score calculation
    - Impact assessment
    - Remediation suggestions
    - Export to JSON and Markdown
    """

    # Standard remediation templates
    REMEDIATION_TEMPLATES = {
        VulnerabilityType.XSS: """
1. Implement proper output encoding based on context (HTML, JavaScript, URL, CSS)
2. Use Content Security Policy (CSP) headers
3. Enable HTTPOnly and Secure flags on cookies
4. Use frameworks with built-in XSS protection (React, Angular, Vue)
5. Sanitize user input using allowlist validation
""",
        VulnerabilityType.SQLI: """
1. Use parameterized queries (prepared statements) for all database queries
2. Implement input validation with allowlist approach
3. Apply principle of least privilege for database accounts
4. Use stored procedures where appropriate
5. Enable Web Application Firewall (WAF) rules for SQL injection
6. Regularly update and patch database software
""",
        VulnerabilityType.SSRF: """
1. Implement strict allowlist for allowed domains and IPs
2. Block requests to internal IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)
3. Block requests to cloud metadata endpoints (169.254.169.254)
4. Disable unnecessary URL schemes (file://, gopher://, dict://)
5. Use a dedicated service for URL fetching with network isolation
6. Implement egress filtering at network level
""",
        VulnerabilityType.IDOR: """
1. Implement proper authorization checks for every request
2. Use indirect object references (random tokens) instead of direct IDs
3. Verify user has permission to access requested resource
4. Log and monitor access patterns for anomalies
5. Implement rate limiting to prevent enumeration
""",
        VulnerabilityType.RCE: """
1. CRITICAL: Remove or restrict the vulnerable functionality immediately
2. Never pass user input to system commands or eval functions
3. Use allowlist validation for any necessary command parameters
4. Implement sandboxing and containerization
5. Apply principle of least privilege for application processes
6. Enable application-level security monitoring
""",
        VulnerabilityType.AUTH_BYPASS: """
1. Review and strengthen authentication logic
2. Implement multi-factor authentication (MFA)
3. Use secure session management
4. Implement account lockout after failed attempts
5. Log and alert on authentication anomalies
6. Regular security audits of authentication code
""",
    }

    # CVSS templates by vulnerability type
    CVSS_TEMPLATES = {
        VulnerabilityType.XSS: CVSSVector(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="R", scope="C", confidentiality="L", integrity="L", availability="N"
        ),
        VulnerabilityType.SQLI: CVSSVector(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="U", confidentiality="H", integrity="H", availability="H"
        ),
        VulnerabilityType.SSRF: CVSSVector(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="C", confidentiality="H", integrity="L", availability="N"
        ),
        VulnerabilityType.IDOR: CVSSVector(
            attack_vector="N", attack_complexity="L", privileges_required="L",
            user_interaction="N", scope="U", confidentiality="H", integrity="N", availability="N"
        ),
        VulnerabilityType.RCE: CVSSVector(
            attack_vector="N", attack_complexity="L", privileges_required="N",
            user_interaction="N", scope="C", confidentiality="H", integrity="H", availability="H"
        ),
    }

    # CWE mappings
    CWE_MAPPINGS = {
        VulnerabilityType.XSS: ["CWE-79"],
        VulnerabilityType.SQLI: ["CWE-89"],
        VulnerabilityType.SSRF: ["CWE-918"],
        VulnerabilityType.IDOR: ["CWE-639"],
        VulnerabilityType.RCE: ["CWE-94", "CWE-78"],
        VulnerabilityType.AUTH_BYPASS: ["CWE-287"],
        VulnerabilityType.BROKEN_ACCESS: ["CWE-284"],
        VulnerabilityType.SENSITIVE_DATA: ["CWE-200"],
        VulnerabilityType.CSRF: ["CWE-352"],
        VulnerabilityType.XXE: ["CWE-611"],
        VulnerabilityType.OPEN_REDIRECT: ["CWE-601"],
        VulnerabilityType.CORS: ["CWE-942"],
    }

    def __init__(self, program_name: str = ""):
        self.program_name = program_name
        self.reports: list[BugBountyReport] = []

    def create_report(
        self,
        title: str,
        vulnerability_type: VulnerabilityType,
        target: str,
        endpoint: str,
        description: str,
        impact: str,
        steps: list[dict],
        poc_description: str = "",
        poc_request: str = "",
        poc_response: str = "",
        confidence: float = 80.0,
        custom_cvss: Optional[CVSSVector] = None,
        custom_remediation: str = "",
    ) -> BugBountyReport:
        """
        Create a complete bug bounty report.

        Args:
            title: Clear, descriptive title
            vulnerability_type: Type of vulnerability
            target: Target domain/application
            endpoint: Specific vulnerable endpoint
            description: Detailed description
            impact: Business/security impact
            steps: List of reproduction steps as dicts
            poc_description: Proof of concept description
            poc_request: HTTP request for PoC
            poc_response: HTTP response
            confidence: Confidence level (0-100)
            custom_cvss: Custom CVSS vector (or use template)
            custom_remediation: Custom remediation (or use template)

        Returns:
            Complete BugBountyReport
        """
        # Get CVSS from template or custom
        cvss = custom_cvss or self.CVSS_TEMPLATES.get(
            vulnerability_type,
            CVSSVector()  # Default
        )

        # Calculate severity from CVSS score
        cvss_score = cvss.calculate_score()
        if cvss_score >= 9.0:
            severity = Severity.CRITICAL
        elif cvss_score >= 7.0:
            severity = Severity.HIGH
        elif cvss_score >= 4.0:
            severity = Severity.MEDIUM
        elif cvss_score > 0:
            severity = Severity.LOW
        else:
            severity = Severity.INFORMATIONAL

        # Build reproduction steps
        reproduction_steps = [
            ReproductionStep(
                step_number=i + 1,
                action=step.get("action", ""),
                expected_result=step.get("expected", ""),
                actual_result=step.get("actual", ""),
                request=step.get("request", ""),
                response=step.get("response", ""),
            )
            for i, step in enumerate(steps)
        ]

        # Build PoC
        poc = None
        if poc_description:
            poc = ProofOfConcept(
                description=poc_description,
                request=poc_request,
                response=poc_response,
            )

        # Get remediation
        remediation = custom_remediation or self.REMEDIATION_TEMPLATES.get(
            vulnerability_type,
            "Consult security documentation for remediation guidance."
        )

        # Get CWE IDs
        cwe_ids = self.CWE_MAPPINGS.get(vulnerability_type, [])

        # Create report
        report = BugBountyReport(
            title=title,
            vulnerability_type=vulnerability_type,
            target=target,
            endpoint=endpoint,
            description=description,
            impact=impact,
            severity=severity,
            cvss=cvss,
            steps_to_reproduce=reproduction_steps,
            proof_of_concept=poc,
            remediation=remediation,
            cwe_ids=cwe_ids,
            confidence=confidence,
            program_name=self.program_name,
        )

        self.reports.append(report)
        return report

    def export_all_json(self, output_path: Path) -> None:
        """Export all reports as JSON."""
        output_path.parent.mkdir(parents=True, exist_ok=True)

        all_reports = [json.loads(r.to_json()) for r in self.reports]

        with open(output_path, "w") as f:
            json.dump({
                "program": self.program_name,
                "generated_at": datetime.now().isoformat(),
                "total_reports": len(self.reports),
                "reports": all_reports,
            }, f, indent=2)

        logger.info(f"Exported {len(self.reports)} reports to {output_path}")

    def export_all_markdown(self, output_dir: Path) -> None:
        """Export all reports as individual Markdown files."""
        output_dir.mkdir(parents=True, exist_ok=True)

        for i, report in enumerate(self.reports):
            # Create filename from title
            filename = f"{i+1:03d}_{report.severity.value}_{report.vulnerability_type.name.lower()}.md"
            filepath = output_dir / filename

            with open(filepath, "w") as f:
                f.write(report.to_markdown())

        logger.info(f"Exported {len(self.reports)} reports to {output_dir}")

    def get_summary(self) -> dict:
        """Get summary of all reports."""
        severity_counts = {s.value: 0 for s in Severity}
        type_counts = {}

        for report in self.reports:
            severity_counts[report.severity.value] += 1
            type_name = report.vulnerability_type.value
            type_counts[type_name] = type_counts.get(type_name, 0) + 1

        return {
            "total_reports": len(self.reports),
            "by_severity": severity_counts,
            "by_type": type_counts,
            "high_confidence": sum(1 for r in self.reports if r.confidence >= 80),
        }


def convert_finding_to_report(
    finding: dict,
    generator: HackerOneReportGenerator,
) -> Optional[BugBountyReport]:
    """
    Convert a scanner finding to a HackerOne report.

    Args:
        finding: Finding dict from scanner
        generator: Report generator instance

    Returns:
        BugBountyReport or None if conversion fails
    """
    try:
        # Map finding type to vulnerability type
        vuln_type_map = {
            "xss": VulnerabilityType.XSS,
            "sqli": VulnerabilityType.SQLI,
            "sql_injection": VulnerabilityType.SQLI,
            "ssrf": VulnerabilityType.SSRF,
            "idor": VulnerabilityType.IDOR,
            "rce": VulnerabilityType.RCE,
            "command_injection": VulnerabilityType.RCE,
            "auth_bypass": VulnerabilityType.AUTH_BYPASS,
            "csrf": VulnerabilityType.CSRF,
            "xxe": VulnerabilityType.XXE,
            "open_redirect": VulnerabilityType.OPEN_REDIRECT,
            "cors": VulnerabilityType.CORS,
            "info_disclosure": VulnerabilityType.INFO_DISCLOSURE,
        }

        finding_type = finding.get("type", "").lower()
        vuln_type = vuln_type_map.get(finding_type, VulnerabilityType.OTHER)

        # Extract details
        title = finding.get("title", f"{vuln_type.value} in {finding.get('url', 'Unknown')}")
        target = finding.get("target", "")
        endpoint = finding.get("url", finding.get("endpoint", ""))
        description = finding.get("description", "")
        impact = finding.get("impact", "Security impact pending assessment.")
        confidence = finding.get("confidence", 70.0)

        # Build steps from evidence
        steps = []
        if finding.get("request"):
            steps.append({
                "action": "Send the following HTTP request",
                "expected": "Normal response",
                "actual": "Vulnerability triggered",
                "request": finding.get("request"),
                "response": finding.get("response", ""),
            })

        if finding.get("payload"):
            steps.append({
                "action": f"Inject payload: {finding.get('payload')}",
                "expected": "Input sanitized",
                "actual": "Payload executed",
            })

        # Create report
        return generator.create_report(
            title=title,
            vulnerability_type=vuln_type,
            target=target,
            endpoint=endpoint,
            description=description,
            impact=impact,
            steps=steps,
            poc_description=finding.get("poc", ""),
            poc_request=finding.get("request", ""),
            poc_response=finding.get("response", ""),
            confidence=confidence,
        )

    except Exception as e:
        logger.error(f"Failed to convert finding to report: {e}")
        return None


# Example usage
if __name__ == "__main__":
    # Create generator
    generator = HackerOneReportGenerator(program_name="Example Bug Bounty Program")

    # Create a sample report
    report = generator.create_report(
        title="Stored XSS in User Profile Bio Field",
        vulnerability_type=VulnerabilityType.XSS,
        target="example.com",
        endpoint="/api/v1/users/profile",
        description="""
A stored cross-site scripting (XSS) vulnerability was discovered in the user profile bio field.
When a user saves a malicious script in their bio, it is stored in the database and executed
whenever another user views the profile. This allows attackers to steal session cookies,
redirect users to phishing sites, or perform actions on behalf of victims.
        """.strip(),
        impact="""
**Security Impact:**
- Session hijacking via cookie theft
- Account takeover
- Phishing attacks
- Malware distribution
- Reputation damage

**Business Impact:**
- User trust erosion
- Potential data breach
- Regulatory compliance issues (GDPR, etc.)
        """.strip(),
        steps=[
            {
                "action": "Login to the application with a valid account",
                "expected": "Successful login",
            },
            {
                "action": "Navigate to Profile Settings",
                "expected": "Profile page loads",
            },
            {
                "action": "Enter the following payload in the Bio field: `<script>alert(document.cookie)</script>`",
                "expected": "Input sanitized or rejected",
                "actual": "Payload accepted and stored",
            },
            {
                "action": "Save the profile and view it from another browser/incognito",
                "expected": "Bio displayed as text",
                "actual": "JavaScript executes, showing alert with cookies",
            },
        ],
        poc_description="The following request demonstrates the XSS vulnerability",
        poc_request="""POST /api/v1/users/profile HTTP/1.1
Host: example.com
Content-Type: application/json
Cookie: session=abc123

{
    "bio": "<script>alert(document.cookie)</script>"
}""",
        poc_response="""HTTP/1.1 200 OK
Content-Type: application/json

{"success": true, "message": "Profile updated"}""",
        confidence=95.0,
    )

    # Export
    print("=" * 60)
    print("SAMPLE HACKERONE REPORT")
    print("=" * 60)
    print(report.to_markdown())

    # Show summary
    print("\n" + "=" * 60)
    print("REPORT SUMMARY")
    print("=" * 60)
    print(f"CVSS Score: {report.cvss.calculate_score()}")
    print(f"Severity: {report.severity.value.upper()}")
    print(f"Vector: {report.cvss.to_string()}")
