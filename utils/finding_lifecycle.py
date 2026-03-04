"""
Finding Lifecycle Manager v1.0.0-ENTERPRISE
=============================================

Gestão profissional do ciclo de vida de findings!

Estados:
- DETECTED: Scanner encontrou algo (NÃO mostrar por defeito!)
- VALIDATED: Confirmado com negative control ou cross-validation
- EXPLOITABLE: Exploração real demonstrada
- DISCARDED: Falso positivo confirmado

Princípio: NUNCA mostrar finding sem evidência mínima obrigatória!

Evidência Mínima:
✅ Request completo
✅ Response relevante  
✅ Diferença visível (baseline vs attack)
✅ Explicação do porquê é vulnerável

Sem isto → finding é LIXO → DISCARDED
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any, Set
from uuid import uuid4


class FindingState(Enum):
    """
    Finding lifecycle states
    
    Flow: DETECTED → VALIDATED → EXPLOITABLE
                ↘ DISCARDED ↙
    """
    DETECTED = "detected"           # Initial detection (internal only!)
    VALIDATED = "validated"         # Confirmed via negative control/cross-validation
    EXPLOITABLE = "exploitable"     # Real exploitation demonstrated
    DISCARDED = "discarded"         # Confirmed false positive
    
    @property
    def is_reportable(self) -> bool:
        """Only VALIDATED and EXPLOITABLE should appear in reports"""
        return self in {FindingState.VALIDATED, FindingState.EXPLOITABLE}
    
    @property
    def display_name(self) -> str:
        names = {
            FindingState.DETECTED: "🔍 Detected (Unverified)",
            FindingState.VALIDATED: "✅ Validated",
            FindingState.EXPLOITABLE: "💥 Exploitable",
            FindingState.DISCARDED: "❌ Discarded (False Positive)"
        }
        return names.get(self, self.value)


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    
    @property
    def cvss_range(self) -> tuple:
        ranges = {
            Severity.CRITICAL: (9.0, 10.0),
            Severity.HIGH: (7.0, 8.9),
            Severity.MEDIUM: (4.0, 6.9),
            Severity.LOW: (0.1, 3.9),
            Severity.INFO: (0.0, 0.0)
        }
        return ranges.get(self, (0.0, 0.0))


class EvidenceType(Enum):
    """Types of evidence that can be collected"""
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    RESPONSE_DIFF = "response_diff"
    TIMING_DATA = "timing_data"
    ERROR_MESSAGE = "error_message"
    STACK_TRACE = "stack_trace"
    DATA_EXFILTRATION = "data_exfiltration"
    OOB_CALLBACK = "oob_callback"
    SCREENSHOT = "screenshot"
    CODE_SNIPPET = "code_snippet"
    EXPLANATION = "explanation"


@dataclass
class Evidence:
    """
    A piece of evidence supporting a finding
    """
    evidence_type: EvidenceType
    title: str
    content: str
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.evidence_type.value,
            "title": self.title,
            "content": self.content[:10000],  # Limit size
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }
    
    def to_markdown(self) -> str:
        """Format evidence for markdown report"""
        md = f"### {self.title}\n\n"
        
        if self.evidence_type == EvidenceType.HTTP_REQUEST:
            md += f"```http\n{self.content}\n```\n"
        elif self.evidence_type == EvidenceType.HTTP_RESPONSE:
            md += f"```http\n{self.content[:2000]}\n```\n"
        elif self.evidence_type == EvidenceType.RESPONSE_DIFF:
            md += f"```diff\n{self.content}\n```\n"
        elif self.evidence_type == EvidenceType.EXPLANATION:
            md += f"{self.content}\n"
        else:
            md += f"```\n{self.content}\n```\n"
        
        return md


@dataclass
class Finding:
    """
    A security finding with full lifecycle management
    
    Must have minimum evidence to be reportable!
    """
    # Identity
    id: str = field(default_factory=lambda: str(uuid4())[:8])
    
    # Classification
    vulnerability_type: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.INFO
    cvss_score: float = 0.0
    
    # Location
    url: str = ""
    parameter: str = ""
    method: str = "GET"
    endpoint: str = ""
    
    # State
    state: FindingState = FindingState.DETECTED
    
    # Evidence collection
    evidence: List[Evidence] = field(default_factory=list)
    
    # Validation
    validation_method: str = ""
    confidence_score: float = 0.0
    
    # Metadata
    scanner_module: str = ""
    detected_at: datetime = field(default_factory=datetime.now)
    validated_at: Optional[datetime] = None
    payload_used: str = ""
    
    # Tracking
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    # State history
    state_history: List[Dict[str, Any]] = field(default_factory=list)
    
    def __post_init__(self):
        """Record initial state"""
        self._record_state_change("Initial detection")
    
    def _record_state_change(self, reason: str):
        """Record state transition"""
        self.state_history.append({
            "state": self.state.value,
            "timestamp": datetime.now().isoformat(),
            "reason": reason
        })
    
    def add_evidence(self, evidence: Evidence):
        """Add evidence to the finding"""
        self.evidence.append(evidence)
    
    def add_request_evidence(self, request: str, title: str = "HTTP Request"):
        """Convenience method to add request evidence"""
        self.add_evidence(Evidence(
            evidence_type=EvidenceType.HTTP_REQUEST,
            title=title,
            content=request
        ))
    
    def add_response_evidence(self, response: str, title: str = "HTTP Response"):
        """Convenience method to add response evidence"""
        self.add_evidence(Evidence(
            evidence_type=EvidenceType.HTTP_RESPONSE,
            title=title,
            content=response
        ))
    
    def add_diff_evidence(self, baseline: str, attack: str, title: str = "Response Difference"):
        """Add diff evidence showing baseline vs attack response"""
        diff_content = self._generate_diff(baseline, attack)
        self.add_evidence(Evidence(
            evidence_type=EvidenceType.RESPONSE_DIFF,
            title=title,
            content=diff_content,
            metadata={"baseline_length": len(baseline), "attack_length": len(attack)}
        ))
    
    def add_explanation(self, explanation: str):
        """Add explanation of why this is vulnerable"""
        self.add_evidence(Evidence(
            evidence_type=EvidenceType.EXPLANATION,
            title="Why This Is Vulnerable",
            content=explanation
        ))
    
    def _generate_diff(self, baseline: str, attack: str) -> str:
        """Generate a simple diff between baseline and attack"""
        baseline_lines = baseline.split('\n')[:50]  # Limit lines
        attack_lines = attack.split('\n')[:50]
        
        diff_lines = []
        
        # Simple diff
        for i, (b, a) in enumerate(zip(baseline_lines, attack_lines)):
            if b != a:
                diff_lines.append(f"- {b[:100]}")
                diff_lines.append(f"+ {a[:100]}")
        
        # Extra lines in attack
        if len(attack_lines) > len(baseline_lines):
            for line in attack_lines[len(baseline_lines):]:
                diff_lines.append(f"+ {line[:100]}")
        
        return '\n'.join(diff_lines[:50]) if diff_lines else "No visible difference"
    
    def has_minimum_evidence(self) -> bool:
        """
        Check if finding has minimum required evidence
        
        Required:
        1. HTTP Request
        2. HTTP Response  
        3. Response Diff OR Error Message OR OOB Callback
        4. Explanation
        """
        evidence_types = {e.evidence_type for e in self.evidence}
        
        has_request = EvidenceType.HTTP_REQUEST in evidence_types
        has_response = EvidenceType.HTTP_RESPONSE in evidence_types
        has_diff = any(t in evidence_types for t in [
            EvidenceType.RESPONSE_DIFF,
            EvidenceType.ERROR_MESSAGE,
            EvidenceType.OOB_CALLBACK,
            EvidenceType.TIMING_DATA,
            EvidenceType.DATA_EXFILTRATION
        ])
        has_explanation = EvidenceType.EXPLANATION in evidence_types
        
        return has_request and has_response and has_diff and has_explanation
    
    def get_missing_evidence(self) -> List[str]:
        """Get list of missing required evidence"""
        evidence_types = {e.evidence_type for e in self.evidence}
        missing = []
        
        if EvidenceType.HTTP_REQUEST not in evidence_types:
            missing.append("HTTP Request (complete request with headers)")
        if EvidenceType.HTTP_RESPONSE not in evidence_types:
            missing.append("HTTP Response (relevant portion)")
        
        has_diff = any(t in evidence_types for t in [
            EvidenceType.RESPONSE_DIFF,
            EvidenceType.ERROR_MESSAGE,
            EvidenceType.OOB_CALLBACK,
            EvidenceType.TIMING_DATA,
            EvidenceType.DATA_EXFILTRATION
        ])
        if not has_diff:
            missing.append("Visible Difference (diff, error, timing, or OOB callback)")
        
        if EvidenceType.EXPLANATION not in evidence_types:
            missing.append("Explanation (why this is vulnerable)")
        
        return missing
    
    def validate(self, method: str, confidence: float) -> bool:
        """
        Attempt to validate the finding
        
        Returns True if finding can be validated
        """
        if not self.has_minimum_evidence():
            return False
        
        if confidence < 50.0:
            self.discard(f"Low confidence: {confidence}")
            return False
        
        self.state = FindingState.VALIDATED
        self.validation_method = method
        self.confidence_score = confidence
        self.validated_at = datetime.now()
        self._record_state_change(f"Validated via {method} (confidence: {confidence})")
        return True
    
    def mark_exploitable(self, exploit_evidence: str):
        """Mark finding as exploitable with proof"""
        if self.state not in {FindingState.VALIDATED, FindingState.DETECTED}:
            return
        
        self.add_evidence(Evidence(
            evidence_type=EvidenceType.DATA_EXFILTRATION,
            title="Exploitation Proof",
            content=exploit_evidence
        ))
        
        self.state = FindingState.EXPLOITABLE
        self._record_state_change("Exploitation demonstrated")
    
    def discard(self, reason: str):
        """Discard finding as false positive"""
        self.state = FindingState.DISCARDED
        self._record_state_change(f"Discarded: {reason}")
    
    @property
    def is_reportable(self) -> bool:
        """Check if finding should appear in reports"""
        return (
            self.state.is_reportable and 
            self.has_minimum_evidence()
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Export finding to dictionary"""
        return {
            "id": self.id,
            "vulnerability_type": self.vulnerability_type,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "url": self.url,
            "parameter": self.parameter,
            "method": self.method,
            "endpoint": self.endpoint,
            "state": self.state.value,
            "is_reportable": self.is_reportable,
            "evidence": [e.to_dict() for e in self.evidence],
            "validation_method": self.validation_method,
            "confidence_score": self.confidence_score,
            "scanner_module": self.scanner_module,
            "detected_at": self.detected_at.isoformat(),
            "validated_at": self.validated_at.isoformat() if self.validated_at else None,
            "payload_used": self.payload_used,
            "cwe_id": self.cwe_id,
            "owasp_category": self.owasp_category,
            "remediation": self.remediation,
            "references": self.references,
            "state_history": self.state_history,
            "has_minimum_evidence": self.has_minimum_evidence(),
            "missing_evidence": self.get_missing_evidence()
        }
    
    def to_markdown(self) -> str:
        """Generate markdown report for this finding"""
        if not self.is_reportable:
            return ""
        
        md = f"""
## {self.state.display_name} - {self.title}

**ID:** {self.id}  
**Severity:** {self.severity.value.upper()} (CVSS: {self.cvss_score})  
**Type:** {self.vulnerability_type}  
**Confidence:** {self.confidence_score}%

### Location
- **URL:** `{self.url}`
- **Method:** {self.method}
- **Parameter:** `{self.parameter}`

### Description
{self.description}

### Payload Used
```
{self.payload_used}
```

"""
        # Add all evidence
        md += "## Evidence\n\n"
        for evidence in self.evidence:
            md += evidence.to_markdown() + "\n"
        
        # Add remediation
        if self.remediation:
            md += f"""
### Remediation
{self.remediation}
"""
        
        # Add references
        if self.references:
            md += "\n### References\n"
            for ref in self.references:
                md += f"- {ref}\n"
        
        if self.cwe_id:
            md += f"\n**CWE:** {self.cwe_id}"
        if self.owasp_category:
            md += f"  \n**OWASP:** {self.owasp_category}"
        
        return md


class FindingManager:
    """
    Manages the lifecycle of all findings in a scan
    
    Key responsibilities:
    1. Track all findings by state
    2. Enforce minimum evidence requirements
    3. Filter reportable findings
    4. Generate professional reports
    """
    
    VERSION = "1.0.0-ENTERPRISE"
    
    def __init__(self):
        self.findings: Dict[str, Finding] = {}
        self._by_state: Dict[FindingState, Set[str]] = {
            state: set() for state in FindingState
        }
        self._by_url: Dict[str, Set[str]] = {}
        self._by_type: Dict[str, Set[str]] = {}
    
    def add_finding(self, finding: Finding) -> str:
        """Add a new finding"""
        self.findings[finding.id] = finding
        self._by_state[finding.state].add(finding.id)
        
        if finding.url not in self._by_url:
            self._by_url[finding.url] = set()
        self._by_url[finding.url].add(finding.id)
        
        if finding.vulnerability_type not in self._by_type:
            self._by_type[finding.vulnerability_type] = set()
        self._by_type[finding.vulnerability_type].add(finding.id)
        
        return finding.id
    
    def create_finding(
        self,
        vulnerability_type: str,
        title: str,
        url: str,
        parameter: str,
        severity: Severity,
        **kwargs
    ) -> Finding:
        """Create and register a new finding"""
        finding = Finding(
            vulnerability_type=vulnerability_type,
            title=title,
            url=url,
            parameter=parameter,
            severity=severity,
            **kwargs
        )
        self.add_finding(finding)
        return finding
    
    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Get finding by ID"""
        return self.findings.get(finding_id)
    
    def update_state(self, finding_id: str, new_state: FindingState, reason: str):
        """Update finding state"""
        finding = self.findings.get(finding_id)
        if not finding:
            return
        
        # Remove from old state set
        self._by_state[finding.state].discard(finding_id)
        
        # Update state
        finding.state = new_state
        finding._record_state_change(reason)
        
        # Add to new state set
        self._by_state[new_state].add(finding_id)
    
    def validate_finding(
        self,
        finding_id: str,
        method: str,
        confidence: float
    ) -> bool:
        """Validate a finding"""
        finding = self.findings.get(finding_id)
        if not finding:
            return False
        
        success = finding.validate(method, confidence)
        
        if success:
            self._by_state[FindingState.DETECTED].discard(finding_id)
            self._by_state[FindingState.VALIDATED].add(finding_id)
        
        return success
    
    def discard_finding(self, finding_id: str, reason: str):
        """Discard a finding as false positive"""
        finding = self.findings.get(finding_id)
        if not finding:
            return
        
        old_state = finding.state
        finding.discard(reason)
        
        self._by_state[old_state].discard(finding_id)
        self._by_state[FindingState.DISCARDED].add(finding_id)
    
    def get_reportable_findings(self) -> List[Finding]:
        """Get all findings that should appear in reports"""
        reportable = []
        for state in [FindingState.EXPLOITABLE, FindingState.VALIDATED]:
            for finding_id in self._by_state[state]:
                finding = self.findings[finding_id]
                if finding.is_reportable:
                    reportable.append(finding)
        
        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        reportable.sort(key=lambda f: severity_order.get(f.severity, 5))
        
        return reportable
    
    def get_incomplete_findings(self) -> List[Finding]:
        """Get findings missing required evidence"""
        incomplete = []
        for finding in self.findings.values():
            if finding.state == FindingState.DETECTED and not finding.has_minimum_evidence():
                incomplete.append(finding)
        return incomplete
    
    def get_discarded_findings(self) -> List[Finding]:
        """Get all discarded findings (for audit)"""
        return [
            self.findings[fid] 
            for fid in self._by_state[FindingState.DISCARDED]
        ]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get finding statistics"""
        reportable = self.get_reportable_findings()
        
        severity_counts = {}
        for finding in reportable:
            sev = finding.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            "total_detected": len(self._by_state[FindingState.DETECTED]),
            "total_validated": len(self._by_state[FindingState.VALIDATED]),
            "total_exploitable": len(self._by_state[FindingState.EXPLOITABLE]),
            "total_discarded": len(self._by_state[FindingState.DISCARDED]),
            "total_reportable": len(reportable),
            "by_severity": severity_counts,
            "incomplete_count": len(self.get_incomplete_findings()),
            "false_positive_rate": self._calculate_fp_rate()
        }
    
    def _calculate_fp_rate(self) -> float:
        """Calculate false positive rate"""
        total = len(self.findings)
        if total == 0:
            return 0.0
        discarded = len(self._by_state[FindingState.DISCARDED])
        return round((discarded / total) * 100, 2)
    
    def generate_report(self, include_discarded: bool = False) -> str:
        """Generate markdown report"""
        stats = self.get_statistics()
        reportable = self.get_reportable_findings()
        
        report = f"""# Security Assessment Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Finding Lifecycle Manager:** v{self.VERSION}

## Executive Summary

| Metric | Count |
|--------|-------|
| Total Reportable Findings | {stats['total_reportable']} |
| Critical | {stats['by_severity'].get('critical', 0)} |
| High | {stats['by_severity'].get('high', 0)} |
| Medium | {stats['by_severity'].get('medium', 0)} |
| Low | {stats['by_severity'].get('low', 0)} |
| Info | {stats['by_severity'].get('info', 0)} |

**Quality Metrics:**
- Findings Detected: {stats['total_detected']} (unverified, not shown)
- Findings Validated: {stats['total_validated']}
- Findings Exploitable: {stats['total_exploitable']}
- False Positives Discarded: {stats['total_discarded']}
- False Positive Rate: {stats['false_positive_rate']}%

---

# Findings

"""
        # Add reportable findings
        for finding in reportable:
            report += finding.to_markdown()
            report += "\n---\n"
        
        # Optionally add discarded for audit
        if include_discarded:
            discarded = self.get_discarded_findings()
            if discarded:
                report += "\n# Discarded Findings (False Positives)\n\n"
                report += "*These findings were detected but determined to be false positives.*\n\n"
                for finding in discarded:
                    report += f"- **{finding.title}** at `{finding.url}`: {finding.state_history[-1]['reason']}\n"
        
        return report
    
    def to_json(self) -> str:
        """Export all findings to JSON"""
        return json.dumps({
            "version": self.VERSION,
            "generated_at": datetime.now().isoformat(),
            "statistics": self.get_statistics(),
            "reportable_findings": [f.to_dict() for f in self.get_reportable_findings()],
            "all_findings": [f.to_dict() for f in self.findings.values()]
        }, indent=2)


# Convenience functions
def create_finding_with_evidence(
    manager: FindingManager,
    vulnerability_type: str,
    title: str,
    url: str,
    parameter: str,
    severity: Severity,
    request: str,
    response: str,
    baseline_response: str,
    explanation: str,
    payload: str,
    **kwargs
) -> Finding:
    """
    Create a finding with all required evidence in one call
    """
    finding = manager.create_finding(
        vulnerability_type=vulnerability_type,
        title=title,
        url=url,
        parameter=parameter,
        severity=severity,
        payload_used=payload,
        **kwargs
    )
    
    # Add all evidence
    finding.add_request_evidence(request)
    finding.add_response_evidence(response)
    finding.add_diff_evidence(baseline_response, response)
    finding.add_explanation(explanation)
    
    return finding


# Export
__all__ = [
    "FindingManager",
    "Finding",
    "FindingState",
    "Severity",
    "Evidence",
    "EvidenceType",
    "create_finding_with_evidence"
]
