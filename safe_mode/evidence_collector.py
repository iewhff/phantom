"""
Evidence Collector - Collect proof of vulnerabilities without exploitation.
Designed for legal compliance in critical infrastructure testing.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional
import httpx

from utils.logger import get_logger

logger = get_logger(__name__)


class EvidenceType(Enum):
    """Types of evidence that can be collected."""
    SCREENSHOT = "screenshot"
    RESPONSE_BODY = "response_body"
    RESPONSE_HEADERS = "response_headers"
    ERROR_MESSAGE = "error_message"
    TIMING_ANALYSIS = "timing_analysis"
    BEHAVIORAL_DIFF = "behavioral_diff"
    VERSION_DISCLOSURE = "version_disclosure"
    CONFIGURATION_LEAK = "configuration_leak"
    DEBUG_INFO = "debug_info"
    STACK_TRACE = "stack_trace"
    REFLECTION = "reflection"  # Input reflected in output
    STATUS_CODE_ANOMALY = "status_code_anomaly"
    REDIRECT_CHAIN = "redirect_chain"


class EvidenceStrength(Enum):
    """Strength of evidence for vulnerability confirmation."""
    DEFINITIVE = "definitive"      # 100% confirmed
    STRONG = "strong"              # 90%+ confident
    MODERATE = "moderate"          # 70-90% confident
    WEAK = "weak"                  # 50-70% confident
    INDICATIVE = "indicative"      # Suggests but doesn't prove


@dataclass
class Evidence:
    """Evidence of a vulnerability without actual exploitation."""
    id: str
    evidence_type: EvidenceType
    strength: EvidenceStrength
    vulnerability: str
    description: str
    raw_data: str
    indicators: list[str]
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    request_details: Optional[dict] = None
    response_details: Optional[dict] = None
    cvss_indicators: Optional[dict] = None
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "evidence_type": self.evidence_type.value,
            "strength": self.strength.value,
            "vulnerability": self.vulnerability,
            "description": self.description,
            "raw_data": self.raw_data[:5000],  # Limit size
            "indicators": self.indicators,
            "timestamp": self.timestamp,
            "request_details": self.request_details,
            "response_details": self.response_details,
            "cvss_indicators": self.cvss_indicators,
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class EvidenceCollector:
    """
    Collect evidence of vulnerabilities without exploitation.
    
    Proves exploitability through:
    - Error message analysis
    - Timing differences
    - Response behavior changes
    - Information disclosure
    - Reflected input detection
    
    Never performs actual exploitation.
    """
    
    # Patterns that indicate vulnerabilities
    ERROR_PATTERNS = {
        "sqli": [
            r"SQL syntax.*?MySQL",
            r"Warning.*?\Wmysqli?_",
            r"PostgreSQL.*?ERROR",
            r"Driver.*? SQL[\-\_\ ]*Server",
            r"ORA-[0-9][0-9][0-9][0-9]",
            r"Microsoft SQL Server",
            r"sqlite.*?error",
            r"SQLSTATE\[",
            r"mysql_fetch",
            r"Unclosed quotation mark",
            r"quoted string not properly terminated",
        ],
        "xss": [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on(error|load|click|mouse)\s*=",
            r"<img[^>]+onerror",
            r"<svg[^>]+onload",
        ],
        "lfi": [
            r"root:.*?:0:0:",
            r"\[boot loader\]",
            r"; for 16-bit app support",
            r"<b>Warning</b>:.*?include",
            r"Failed opening.*?for inclusion",
        ],
        "cmdi": [
            r"uid=\d+.*?gid=\d+",
            r"root:x:0:0",
            r"total \d+\s+drwx",
            r"Volume Serial Number",
            r"Directory of [A-Z]:\\",
        ],
        "xxe": [
            r"<!DOCTYPE",
            r"<!ENTITY",
            r"SYSTEM\s+['\"]file://",
            r"parser error.*?Entity",
            r"root:.*?:0:0:",  # /etc/passwd content
        ],
        "ssrf": [
            r"localhost",
            r"127\.0\.0\.1",
            r"192\.168\.\d+\.\d+",
            r"10\.\d+\.\d+\.\d+",
            r"172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+",
            r"Connection refused",
            r"No route to host",
        ],
        "path_traversal": [
            r"\.\./\.\./",
            r"root:x:0:",
            r"\[extensions\]",
            r"C:\\Windows",
        ],
        "idor": [
            r'"user_?id"\s*:\s*\d+',
            r'"account"\s*:\s*"[^"]+"',
            r'"email"\s*:\s*"[^@]+@',
        ],
    }
    
    # Information disclosure patterns
    INFO_DISCLOSURE_PATTERNS = {
        "version": [
            r"Apache/[\d\.]+",
            r"nginx/[\d\.]+",
            r"PHP/[\d\.]+",
            r"Python/[\d\.]+",
            r"Node\.js v[\d\.]+",
            r"Express [\d\.]+",
            r"Laravel v[\d\.]+",
            r"Django/[\d\.]+",
            r"ASP\.NET Version:[\d\.]+",
            r"X-Powered-By: (.+)",
            r"Server: (.+)",
        ],
        "debug": [
            r"DEBUG\s*=\s*True",
            r"Stack Trace:",
            r"at \w+\.\w+\(.*?:\d+\)",
            r"Traceback \(most recent call last\)",
            r"Exception in thread",
            r"SQLSTATE",
        ],
        "secrets": [
            r"api[_-]?key['\"]?\s*[:=]\s*['\"]?[\w-]{20,}",
            r"password['\"]?\s*[:=]\s*['\"]?[^\s'\"]+",
            r"secret['\"]?\s*[:=]\s*['\"]?[\w-]{10,}",
            r"token['\"]?\s*[:=]\s*['\"]?[\w-]{20,}",
            r"BEGIN (RSA |DSA |EC )?PRIVATE KEY",
            r"AWS[_A-Z]*\s*[:=]\s*['\"]?[A-Z0-9]{20,}",
        ],
        "internal": [
            r"internal[_-]?ip:\s*[\d\.]+",
            r"database[_-]?host:\s*[\w\.-]+",
            r"mysql://[\w:]+@[\w\.-]+",
            r"postgresql://[\w:]+@[\w\.-]+",
            r"mongodb://[\w:]+@[\w\.-]+",
        ],
    }
    
    def __init__(self):
        self.evidence_collection: list[Evidence] = []
        self.scan_id = hashlib.md5(
            datetime.now().isoformat().encode()
        ).hexdigest()[:8]
    
    def analyze_response(
        self,
        response: httpx.Response,
        test_type: str,
        payload_sent: str,
        original_request: Optional[dict] = None,
    ) -> list[Evidence]:
        """
        Analyze response for evidence of vulnerability.
        
        Args:
            response: HTTP response to analyze
            test_type: Type of test (sqli, xss, etc.)
            payload_sent: The payload that was sent
            original_request: Original request details
            
        Returns:
            List of Evidence objects found
        """
        found_evidence: list[Evidence] = []
        
        response_text = response.text
        response_headers = dict(response.headers)
        status_code = response.status_code
        
        # Check for error-based evidence
        error_evidence = self._check_error_patterns(
            response_text, test_type, payload_sent
        )
        found_evidence.extend(error_evidence)
        
        # Check for reflection (input echoed back)
        reflection_evidence = self._check_reflection(
            response_text, payload_sent, test_type
        )
        if reflection_evidence:
            found_evidence.append(reflection_evidence)
        
        # Check for information disclosure in headers
        header_evidence = self._check_header_disclosure(response_headers)
        found_evidence.extend(header_evidence)
        
        # Check for debug/stack trace information
        debug_evidence = self._check_debug_info(response_text)
        found_evidence.extend(debug_evidence)
        
        # Check status code anomalies
        if status_code == 500:
            found_evidence.append(self._create_evidence(
                EvidenceType.STATUS_CODE_ANOMALY,
                EvidenceStrength.MODERATE,
                test_type,
                f"Server error (500) triggered by payload",
                response_text[:500],
                [f"Status code: {status_code}", "Possible input validation issue"],
            ))
        
        # Add request/response details to all evidence
        for evidence in found_evidence:
            evidence.request_details = original_request or {
                "url": str(response.url),
                "method": response.request.method if response.request else "GET",
                "payload": payload_sent[:200],
            }
            evidence.response_details = {
                "status_code": status_code,
                "content_length": len(response_text),
                "content_type": response_headers.get("content-type", ""),
            }
        
        self.evidence_collection.extend(found_evidence)
        return found_evidence
    
    def _check_error_patterns(
        self,
        content: str,
        test_type: str,
        payload: str,
    ) -> list[Evidence]:
        """Check for error-based evidence patterns."""
        evidence_list = []
        
        patterns = self.ERROR_PATTERNS.get(test_type, [])
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                evidence_list.append(self._create_evidence(
                    EvidenceType.ERROR_MESSAGE,
                    EvidenceStrength.STRONG,
                    test_type,
                    f"Error pattern detected: {pattern}",
                    str(matches[:3]),
                    [f"Pattern: {pattern}", f"Matches: {len(matches)}"],
                ))
        
        return evidence_list
    
    def _check_reflection(
        self,
        content: str,
        payload: str,
        test_type: str,
    ) -> Optional[Evidence]:
        """Check if payload is reflected in response."""
        # Simplify payload for comparison
        simple_payload = payload.strip()[:50]
        
        if simple_payload in content:
            # Determine context of reflection
            context = self._get_reflection_context(content, simple_payload)
            
            strength = EvidenceStrength.MODERATE
            if test_type == "xss":
                # Check if reflected in dangerous context
                if any(c in context for c in ["<script", "onerror", "javascript:"]):
                    strength = EvidenceStrength.STRONG
            
            return self._create_evidence(
                EvidenceType.REFLECTION,
                strength,
                test_type,
                f"Input reflected in response",
                context,
                ["Input echoed back", f"Context: {context[:100]}"],
            )
        
        return None
    
    def _get_reflection_context(self, content: str, payload: str) -> str:
        """Get context around reflected payload."""
        idx = content.find(payload)
        if idx == -1:
            return ""
        
        start = max(0, idx - 50)
        end = min(len(content), idx + len(payload) + 50)
        return content[start:end]
    
    def _check_header_disclosure(
        self,
        headers: dict,
    ) -> list[Evidence]:
        """Check response headers for information disclosure."""
        evidence_list = []
        
        disclosure_headers = {
            "server": "Server version disclosure",
            "x-powered-by": "Technology stack disclosure",
            "x-aspnet-version": "ASP.NET version disclosure",
            "x-aspnetmvc-version": "ASP.NET MVC version disclosure",
        }
        
        for header, description in disclosure_headers.items():
            if header in headers:
                evidence_list.append(self._create_evidence(
                    EvidenceType.VERSION_DISCLOSURE,
                    EvidenceStrength.MODERATE,
                    "info_disclosure",
                    description,
                    f"{header}: {headers[header]}",
                    [f"Header: {header}", f"Value: {headers[header]}"],
                ))
        
        return evidence_list
    
    def _check_debug_info(self, content: str) -> list[Evidence]:
        """Check for debug information disclosure."""
        evidence_list = []
        
        for category, patterns in self.INFO_DISCLOSURE_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                if matches:
                    evidence_list.append(self._create_evidence(
                        EvidenceType.DEBUG_INFO,
                        EvidenceStrength.MODERATE,
                        f"info_disclosure_{category}",
                        f"{category.title()} information disclosure",
                        str(matches[:3]),
                        [f"Category: {category}", f"Pattern: {pattern}"],
                    ))
        
        return evidence_list
    
    def analyze_timing(
        self,
        baseline_time: float,
        test_time: float,
        test_type: str,
        threshold: float = 5.0,
    ) -> Optional[Evidence]:
        """
        Analyze timing differences for blind vulnerabilities.
        
        Args:
            baseline_time: Time for normal request
            test_time: Time for test payload request
            test_type: Type of test (sqli, cmdi, etc.)
            threshold: Time difference threshold in seconds
            
        Returns:
            Evidence if significant timing difference detected
        """
        time_diff = test_time - baseline_time
        
        if time_diff >= threshold:
            return self._create_evidence(
                EvidenceType.TIMING_ANALYSIS,
                EvidenceStrength.STRONG,
                test_type,
                f"Significant timing difference detected ({time_diff:.2f}s delay)",
                f"Baseline: {baseline_time:.2f}s, Test: {test_time:.2f}s",
                [
                    f"Time difference: {time_diff:.2f}s",
                    f"Threshold: {threshold}s",
                    "Suggests time-based blind vulnerability",
                ],
            )
        
        return None
    
    def analyze_behavioral_diff(
        self,
        baseline_response: str,
        test_response: str,
        test_type: str,
    ) -> Optional[Evidence]:
        """
        Analyze behavioral differences between responses.
        
        Args:
            baseline_response: Response to normal request
            test_response: Response to test payload
            test_type: Type of test
            
        Returns:
            Evidence if significant behavioral difference detected
        """
        # Calculate similarity
        baseline_len = len(baseline_response)
        test_len = len(test_response)
        
        len_diff = abs(baseline_len - test_len)
        len_ratio = len_diff / max(baseline_len, 1)
        
        # Significant length difference
        if len_ratio > 0.3:
            return self._create_evidence(
                EvidenceType.BEHAVIORAL_DIFF,
                EvidenceStrength.MODERATE,
                test_type,
                f"Response length changed significantly ({len_ratio*100:.1f}% difference)",
                f"Baseline: {baseline_len} bytes, Test: {test_len} bytes",
                [
                    f"Length difference: {len_diff} bytes",
                    f"Ratio: {len_ratio*100:.1f}%",
                    "Indicates different code path executed",
                ],
            )
        
        return None
    
    def _create_evidence(
        self,
        evidence_type: EvidenceType,
        strength: EvidenceStrength,
        vulnerability: str,
        description: str,
        raw_data: str,
        indicators: list[str],
    ) -> Evidence:
        """Create an Evidence object."""
        evidence_id = f"E-{self.scan_id}-{len(self.evidence_collection)+1:04d}"
        
        return Evidence(
            id=evidence_id,
            evidence_type=evidence_type,
            strength=strength,
            vulnerability=vulnerability,
            description=description,
            raw_data=raw_data,
            indicators=indicators,
        )
    
    def get_evidence_summary(self) -> dict[str, Any]:
        """Get summary of all collected evidence."""
        by_type: dict[str, int] = {}
        by_strength: dict[str, int] = {}
        by_vuln: dict[str, int] = {}
        
        for evidence in self.evidence_collection:
            by_type[evidence.evidence_type.value] = by_type.get(
                evidence.evidence_type.value, 0
            ) + 1
            by_strength[evidence.strength.value] = by_strength.get(
                evidence.strength.value, 0
            ) + 1
            by_vuln[evidence.vulnerability] = by_vuln.get(
                evidence.vulnerability, 0
            ) + 1
        
        return {
            "total_evidence": len(self.evidence_collection),
            "by_type": by_type,
            "by_strength": by_strength,
            "by_vulnerability": by_vuln,
            "scan_id": self.scan_id,
            "timestamp": datetime.now().isoformat(),
        }
    
    def export_evidence(self, output_path: Path) -> str:
        """Export evidence to JSON file."""
        export_data = {
            "scan_id": self.scan_id,
            "timestamp": datetime.now().isoformat(),
            "summary": self.get_evidence_summary(),
            "evidence": [e.to_dict() for e in self.evidence_collection],
        }
        
        output_file = output_path / f"evidence_{self.scan_id}.json"
        output_file.write_text(json.dumps(export_data, indent=2))
        
        return str(output_file)
    
    def generate_evidence_report_html(self) -> str:
        """Generate HTML report of collected evidence."""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Security Evidence Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .card { background: white; margin: 15px 0; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .evidence { border-left: 4px solid #3498db; padding-left: 15px; margin: 10px 0; }
        .definitive { border-color: #e74c3c; }
        .strong { border-color: #e67e22; }
        .moderate { border-color: #f1c40f; }
        .weak { border-color: #3498db; }
        .indicative { border-color: #95a5a6; }
        .tag { display: inline-block; padding: 2px 8px; margin: 2px; border-radius: 4px; font-size: 12px; }
        .tag-vuln { background: #e74c3c; color: white; }
        .tag-type { background: #3498db; color: white; }
        .raw-data { background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #34495e; color: white; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .summary-item { text-align: center; padding: 15px; background: #ecf0f1; border-radius: 8px; }
        .summary-number { font-size: 32px; font-weight: bold; color: #2c3e50; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Security Evidence Report</h1>
            <p>Scan ID: """ + self.scan_id + """ | Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
            <p><strong>Mode:</strong> Non-Destructive / Evidence-Only</p>
        </div>
        
        <div class="card">
            <h2>📊 Summary</h2>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-number">""" + str(len(self.evidence_collection)) + """</div>
                    <div>Total Evidence</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">""" + str(sum(1 for e in self.evidence_collection if e.strength == EvidenceStrength.DEFINITIVE)) + """</div>
                    <div>Definitive</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">""" + str(sum(1 for e in self.evidence_collection if e.strength == EvidenceStrength.STRONG)) + """</div>
                    <div>Strong</div>
                </div>
                <div class="summary-item">
                    <div class="summary-number">""" + str(len(set(e.vulnerability for e in self.evidence_collection))) + """</div>
                    <div>Vuln Types</div>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>🔍 Evidence Collection</h2>
"""
        
        for evidence in self.evidence_collection:
            html += f"""
            <div class="evidence {evidence.strength.value}">
                <h3>{evidence.id}: {evidence.description}</h3>
                <p>
                    <span class="tag tag-vuln">{evidence.vulnerability}</span>
                    <span class="tag tag-type">{evidence.evidence_type.value}</span>
                    <span class="tag" style="background: #27ae60; color: white;">Strength: {evidence.strength.value}</span>
                </p>
                <p><strong>Indicators:</strong></p>
                <ul>
                    {''.join(f"<li>{ind}</li>" for ind in evidence.indicators)}
                </ul>
                <p><strong>Raw Data:</strong></p>
                <div class="raw-data">{evidence.raw_data[:500]}</div>
            </div>
"""
        
        html += """
        </div>
        
        <div class="card">
            <h2>⚖️ Legal Notice</h2>
            <p>This report documents evidence of potential security vulnerabilities collected through 
            <strong>non-destructive testing methods only</strong>. No actual exploitation was performed. 
            All evidence is based on observable behaviors, error messages, and timing analysis.</p>
            <p>Testing was conducted in compliance with applicable laws and authorized scope.</p>
        </div>
    </div>
</body>
</html>"""
        
        return html
