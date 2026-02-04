"""
Abuse Case Generator - Generates abuse cases per endpoint.
Creates detailed attack scenarios for each identified endpoint.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from threat_modeling.stride_analyzer import (
    STRIDECategory,
    AbuseCaseSeverity,
    AbuseCase,
)
from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class EndpointAnalysis:
    """Complete analysis of a single endpoint."""
    endpoint: str
    method: str
    requires_auth: bool
    data_types: list[str]
    parameters: list[str]
    abuse_cases: list[AbuseCase]
    risk_score: float
    attack_surface: str  # HIGH, MEDIUM, LOW
    
    def to_dict(self) -> dict:
        return {
            "endpoint": self.endpoint,
            "method": self.method,
            "requires_auth": self.requires_auth,
            "data_types": self.data_types,
            "parameters": self.parameters,
            "abuse_cases": [ac.to_dict() for ac in self.abuse_cases],
            "risk_score": self.risk_score,
            "attack_surface": self.attack_surface,
        }


class AbuseCaseGenerator:
    """
    Generates detailed abuse cases for each endpoint.
    
    Thinks like an attacker by considering:
    - What can go wrong?
    - How can this be abused?
    - What's the business impact?
    """
    
    # Endpoint-specific abuse patterns
    ABUSE_PATTERNS = {
        # Authentication & Session
        "login": [
            {
                "name": "Credential Brute Force",
                "description": "Automated password guessing attack",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.SPOOFING],
                "preconditions": ["Know or enumerate valid usernames"],
                "steps": [
                    "Enumerate valid usernames via registration/password reset",
                    "Use wordlist of common passwords",
                    "Send rapid login attempts",
                    "Bypass rate limiting via IP rotation or header manipulation",
                ],
                "expected_result": "Access to victim account",
                "impact": "Account compromise, data breach",
                "test_payload": '{"username":"admin","password":"{{FUZZ}}"}',
            },
            {
                "name": "Credential Stuffing",
                "description": "Using leaked credentials from other breaches",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.SPOOFING],
                "preconditions": ["Access to leaked credential databases"],
                "steps": [
                    "Obtain leaked credential lists",
                    "Test credentials against target",
                    "Identify reused passwords",
                ],
                "expected_result": "Access to accounts with reused passwords",
                "impact": "Mass account compromise",
            },
        ],
        "password_reset": [
            {
                "name": "Account Takeover via Password Reset",
                "description": "Exploit password reset flow to take over accounts",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.SPOOFING, STRIDECategory.ELEVATION_OF_PRIVILEGE],
                "preconditions": ["Know victim's email"],
                "steps": [
                    "Request password reset for victim",
                    "Intercept or predict reset token",
                    "Use token before expiration",
                    "Set new password",
                ],
                "expected_result": "Full account takeover",
                "impact": "Complete account compromise",
            },
            {
                "name": "Token Prediction",
                "description": "Predict weak password reset tokens",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.SPOOFING],
                "preconditions": ["Multiple reset tokens for analysis"],
                "steps": [
                    "Request multiple reset tokens",
                    "Analyze token patterns",
                    "Predict victim's token",
                ],
                "expected_result": "Valid reset token for victim",
                "impact": "Account takeover without email access",
            },
        ],
        "token": [
            {
                "name": "JWT Algorithm Confusion",
                "description": "Exploit JWT algorithm vulnerabilities",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.SPOOFING, STRIDECategory.ELEVATION_OF_PRIVILEGE],
                "preconditions": ["Valid JWT token"],
                "steps": [
                    "Decode JWT header and payload",
                    "Change algorithm to 'none'",
                    "Remove signature",
                    "Submit modified token",
                ],
                "expected_result": "Authentication bypass",
                "impact": "Full authentication bypass",
                "test_payload": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.{{PAYLOAD}}.''",
            },
            {
                "name": "JWT Secret Brute Force",
                "description": "Crack weak JWT signing secret",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.SPOOFING],
                "preconditions": ["Sample JWT token"],
                "steps": [
                    "Capture valid JWT",
                    "Attempt signature verification with common secrets",
                    "Forge tokens with discovered secret",
                ],
                "expected_result": "Ability to forge valid JWTs",
                "impact": "Full authentication bypass, privilege escalation",
            },
        ],
        # Payment & Financial
        "payment": [
            {
                "name": "Price Manipulation",
                "description": "Modify prices in payment request",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.TAMPERING],
                "preconditions": ["Item in cart", "Ability to intercept requests"],
                "steps": [
                    "Add item to cart",
                    "Intercept checkout request",
                    "Modify price/amount field",
                    "Complete payment at reduced price",
                ],
                "expected_result": "Purchase at manipulated price",
                "impact": "Direct financial loss",
                "test_payload": '{"item_id":123,"price":0.01}',
            },
            {
                "name": "Race Condition Double Spend",
                "description": "Exploit race condition for multiple redemptions",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.TAMPERING, STRIDECategory.REPUDIATION],
                "preconditions": ["Valid voucher/credit", "Multiple request capability"],
                "steps": [
                    "Prepare multiple identical requests",
                    "Send all requests simultaneously",
                    "Exploit time-of-check to time-of-use gap",
                ],
                "expected_result": "Multiple redemptions of same voucher",
                "impact": "Financial fraud, voucher abuse",
            },
            {
                "name": "Currency Confusion",
                "description": "Exploit currency conversion logic",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.TAMPERING],
                "preconditions": ["Multi-currency support"],
                "steps": [
                    "Set account to high-value currency",
                    "Purchase in low-value currency",
                    "Request refund in high-value currency",
                ],
                "expected_result": "Profit from exchange rate abuse",
                "impact": "Financial loss",
            },
        ],
        "refund": [
            {
                "name": "Unauthorized Refund",
                "description": "Process refunds without authorization",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.ELEVATION_OF_PRIVILEGE, STRIDECategory.TAMPERING],
                "preconditions": ["Access to refund endpoint"],
                "steps": [
                    "Identify refund API endpoint",
                    "Modify order ID to target other orders",
                    "Process refund",
                ],
                "expected_result": "Refund processed for any order",
                "impact": "Financial loss, fraud",
            },
            {
                "name": "Refund After Chargeback",
                "description": "Double refund via refund + chargeback",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.REPUDIATION],
                "preconditions": ["Successful purchase"],
                "steps": [
                    "Complete purchase",
                    "Request official refund",
                    "Simultaneously file chargeback",
                ],
                "expected_result": "Double refund",
                "impact": "Financial fraud",
            },
        ],
        # User & Profile
        "user": [
            {
                "name": "IDOR Profile Access",
                "description": "Access other users' profiles via ID manipulation",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.INFORMATION_DISCLOSURE],
                "preconditions": ["Authenticated user"],
                "steps": [
                    "Capture own profile request",
                    "Note user ID parameter",
                    "Increment/decrement ID",
                    "Access other profiles",
                ],
                "expected_result": "Access to other users' data",
                "impact": "Privacy breach, PII exposure",
                "test_payload": "/api/users/{VICTIM_ID}",
            },
            {
                "name": "Mass Assignment Privilege",
                "description": "Elevate privileges via mass assignment",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.ELEVATION_OF_PRIVILEGE, STRIDECategory.TAMPERING],
                "preconditions": ["Profile update capability"],
                "steps": [
                    "Intercept profile update request",
                    "Add isAdmin/role field",
                    "Submit modified request",
                ],
                "expected_result": "Elevated privileges",
                "impact": "Full privilege escalation",
                "test_payload": '{"name":"Test","role":"admin","isAdmin":true}',
            },
        ],
        # File Operations
        "upload": [
            {
                "name": "Unrestricted File Upload",
                "description": "Upload malicious executable files",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE],
                "preconditions": ["File upload functionality"],
                "steps": [
                    "Prepare webshell",
                    "Bypass extension whitelist",
                    "Bypass content-type check",
                    "Upload to accessible location",
                    "Execute uploaded file",
                ],
                "expected_result": "Remote code execution",
                "impact": "Full server compromise",
            },
            {
                "name": "Path Traversal Upload",
                "description": "Upload files to arbitrary locations",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.TAMPERING],
                "preconditions": ["File upload functionality"],
                "steps": [
                    "Intercept upload request",
                    "Modify filename with ../ sequences",
                    "Overwrite critical files",
                ],
                "expected_result": "Arbitrary file write",
                "impact": "Configuration compromise, backdoor",
                "test_payload": "filename=../../../etc/cron.d/backdoor",
            },
        ],
        "download": [
            {
                "name": "Path Traversal Read",
                "description": "Read arbitrary files from server",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.INFORMATION_DISCLOSURE],
                "preconditions": ["File download functionality"],
                "steps": [
                    "Identify download parameter",
                    "Inject ../../../ sequences",
                    "Read /etc/passwd",
                    "Extract sensitive configurations",
                ],
                "expected_result": "Arbitrary file read",
                "impact": "Credential exposure, data breach",
                "test_payload": "/download?file=../../../etc/passwd",
            },
        ],
        # Admin Functions
        "admin": [
            {
                "name": "Broken Access Control",
                "description": "Access admin functions without authorization",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.ELEVATION_OF_PRIVILEGE],
                "preconditions": ["Knowledge of admin endpoints"],
                "steps": [
                    "Discover admin endpoints",
                    "Access with regular user token",
                    "Modify role in JWT/session",
                ],
                "expected_result": "Admin access",
                "impact": "Full system compromise",
            },
            {
                "name": "Privilege Escalation via API",
                "description": "Use API to grant self admin privileges",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.ELEVATION_OF_PRIVILEGE, STRIDECategory.TAMPERING],
                "preconditions": ["Authenticated user"],
                "steps": [
                    "Find user management API",
                    "Identify role modification endpoint",
                    "Modify own role to admin",
                ],
                "expected_result": "Self-granted admin access",
                "impact": "Complete privilege escalation",
            },
        ],
        # Search & Query
        "search": [
            {
                "name": "SQL Injection",
                "description": "Extract data via SQL injection",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.INFORMATION_DISCLOSURE, STRIDECategory.TAMPERING],
                "preconditions": ["Search functionality"],
                "steps": [
                    "Identify injectable parameter",
                    "Test for error-based SQLi",
                    "Extract database schema",
                    "Dump sensitive tables",
                ],
                "expected_result": "Database extraction",
                "impact": "Complete data breach",
                "test_payload": "' OR '1'='1' UNION SELECT username,password FROM users--",
            },
            {
                "name": "NoSQL Injection",
                "description": "Bypass authentication or extract data via NoSQL operators",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.SPOOFING, STRIDECategory.INFORMATION_DISCLOSURE],
                "preconditions": ["MongoDB or similar backend"],
                "steps": [
                    "Inject MongoDB operators",
                    "Use $gt/$ne for auth bypass",
                    "Extract data via $regex",
                ],
                "expected_result": "Auth bypass or data extraction",
                "impact": "Authentication bypass, data breach",
                "test_payload": '{"username":{"$gt":""},"password":{"$gt":""}}',
            },
        ],
    }
    
    # Parameter-based abuse patterns
    PARAM_ABUSE = {
        "id": {
            "name": "IDOR via ID Parameter",
            "description": "Access other resources by changing ID",
            "severity": AbuseCaseSeverity.HIGH,
            "stride": [STRIDECategory.INFORMATION_DISCLOSURE],
            "test": "Increment/decrement ID values",
        },
        "price": {
            "name": "Price Tampering",
            "description": "Modify price parameter",
            "severity": AbuseCaseSeverity.CRITICAL,
            "stride": [STRIDECategory.TAMPERING],
            "test": "Change to 0.01 or negative value",
        },
        "quantity": {
            "name": "Quantity Manipulation",
            "description": "Use negative or extreme quantities",
            "severity": AbuseCaseSeverity.HIGH,
            "stride": [STRIDECategory.TAMPERING],
            "test": "Use -1, 0, or MAX_INT",
        },
        "role": {
            "name": "Role Manipulation",
            "description": "Modify role parameter to escalate privileges",
            "severity": AbuseCaseSeverity.CRITICAL,
            "stride": [STRIDECategory.ELEVATION_OF_PRIVILEGE],
            "test": "Change to 'admin', 'root', 'superuser'",
        },
        "email": {
            "name": "Email Parameter Abuse",
            "description": "Inject or enumerate via email parameter",
            "severity": AbuseCaseSeverity.MEDIUM,
            "stride": [STRIDECategory.INFORMATION_DISCLOSURE, STRIDECategory.SPOOFING],
            "test": "Use victim email for account takeover",
        },
        "redirect": {
            "name": "Open Redirect",
            "description": "Redirect users to malicious sites",
            "severity": AbuseCaseSeverity.MEDIUM,
            "stride": [STRIDECategory.SPOOFING],
            "test": "Inject external URL",
        },
        "url": {
            "name": "SSRF via URL Parameter",
            "description": "Access internal resources via URL parameter",
            "severity": AbuseCaseSeverity.HIGH,
            "stride": [STRIDECategory.INFORMATION_DISCLOSURE],
            "test": "Use internal URLs like http://localhost, http://169.254.169.254",
        },
        "file": {
            "name": "Path Traversal",
            "description": "Read files outside intended directory",
            "severity": AbuseCaseSeverity.HIGH,
            "stride": [STRIDECategory.INFORMATION_DISCLOSURE],
            "test": "Use ../../etc/passwd",
        },
        "query": {
            "name": "Injection Attack",
            "description": "SQL/NoSQL/Command injection via query parameter",
            "severity": AbuseCaseSeverity.CRITICAL,
            "stride": [STRIDECategory.INFORMATION_DISCLOSURE, STRIDECategory.TAMPERING],
            "test": "Inject SQL, NoSQL operators, or shell commands",
        },
    }
    
    def __init__(self):
        self.analyses: list[EndpointAnalysis] = []
    
    def analyze_endpoint(
        self,
        endpoint: str,
        method: str = "GET",
        parameters: list[str] | None = None,
        requires_auth: bool = True,
        data_types: list[str] | None = None,
    ) -> EndpointAnalysis:
        """
        Generate comprehensive abuse cases for an endpoint.
        
        Args:
            endpoint: The API endpoint path
            method: HTTP method
            parameters: List of parameter names
            requires_auth: Whether endpoint requires authentication
            data_types: Types of data handled
            
        Returns:
            EndpointAnalysis with all abuse cases
        """
        parameters = parameters or []
        data_types = data_types or []
        
        abuse_cases = []
        
        # 1. Pattern-based abuse cases
        endpoint_lower = endpoint.lower()
        for pattern, cases in self.ABUSE_PATTERNS.items():
            if pattern in endpoint_lower:
                for case_template in cases:
                    case_id = hashlib.md5(
                        f"{endpoint}{case_template['name']}".encode()
                    ).hexdigest()[:8]
                    
                    abuse_cases.append(AbuseCase(
                        id=f"AC-{case_id}",
                        endpoint=endpoint,
                        method=method,
                        name=case_template["name"],
                        description=case_template["description"],
                        severity=case_template["severity"],
                        stride_categories=case_template["stride"],
                        preconditions=case_template["preconditions"],
                        attack_steps=case_template["steps"],
                        expected_result=case_template["expected_result"],
                        business_impact=case_template["impact"],
                        test_payload=case_template.get("test_payload"),
                    ))
        
        # 2. Parameter-based abuse cases
        for param in parameters:
            param_lower = param.lower()
            for param_pattern, abuse_info in self.PARAM_ABUSE.items():
                if param_pattern in param_lower:
                    case_id = hashlib.md5(
                        f"{endpoint}{param}{abuse_info['name']}".encode()
                    ).hexdigest()[:8]
                    
                    abuse_cases.append(AbuseCase(
                        id=f"AC-{case_id}",
                        endpoint=endpoint,
                        method=method,
                        name=f"{abuse_info['name']} ({param})",
                        description=abuse_info["description"],
                        severity=abuse_info["severity"],
                        stride_categories=abuse_info["stride"],
                        preconditions=["Parameter is user-controllable"],
                        attack_steps=[
                            f"Identify {param} parameter",
                            abuse_info["test"],
                            "Analyze response",
                        ],
                        expected_result="Successful exploitation",
                        business_impact="Depends on data accessed",
                    ))
        
        # 3. Authentication-related abuse if no auth required
        if not requires_auth:
            case_id = hashlib.md5(f"{endpoint}noauth".encode()).hexdigest()[:8]
            abuse_cases.append(AbuseCase(
                id=f"AC-{case_id}",
                endpoint=endpoint,
                method=method,
                name="Unauthenticated Access",
                description="Endpoint accessible without authentication",
                severity=AbuseCaseSeverity.HIGH,
                stride_categories=[STRIDECategory.SPOOFING, STRIDECategory.INFORMATION_DISCLOSURE],
                preconditions=["None - no authentication required"],
                attack_steps=[
                    "Access endpoint without credentials",
                    "Enumerate/extract available data",
                ],
                expected_result="Data access without authentication",
                business_impact="Data exposure, unauthorized access",
            ))
        
        # 4. Method-specific abuse
        if method in ["PUT", "PATCH", "DELETE"]:
            case_id = hashlib.md5(f"{endpoint}{method}abuse".encode()).hexdigest()[:8]
            abuse_cases.append(AbuseCase(
                id=f"AC-{case_id}",
                endpoint=endpoint,
                method=method,
                name=f"Unauthorized {method} Operation",
                description=f"Perform unauthorized {method} operations on resources",
                severity=AbuseCaseSeverity.HIGH,
                stride_categories=[STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE],
                preconditions=["Authenticated user"],
                attack_steps=[
                    f"Identify resource ID",
                    f"Send {method} request to other user's resource",
                    "Verify unauthorized modification/deletion",
                ],
                expected_result="Unauthorized resource modification",
                business_impact="Data integrity compromise",
            ))
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(abuse_cases, requires_auth)
        attack_surface = self._determine_attack_surface(abuse_cases, parameters, requires_auth)
        
        analysis = EndpointAnalysis(
            endpoint=endpoint,
            method=method,
            requires_auth=requires_auth,
            data_types=data_types,
            parameters=parameters,
            abuse_cases=abuse_cases,
            risk_score=risk_score,
            attack_surface=attack_surface,
        )
        
        self.analyses.append(analysis)
        
        return analysis
    
    def _calculate_risk_score(
        self,
        abuse_cases: list[AbuseCase],
        requires_auth: bool,
    ) -> float:
        """Calculate overall risk score for endpoint."""
        if not abuse_cases:
            return 0.0
        
        severity_scores = {
            AbuseCaseSeverity.CRITICAL: 10,
            AbuseCaseSeverity.HIGH: 7,
            AbuseCaseSeverity.MEDIUM: 4,
            AbuseCaseSeverity.LOW: 2,
            AbuseCaseSeverity.INFO: 1,
        }
        
        total = sum(severity_scores.get(ac.severity, 0) for ac in abuse_cases)
        avg = total / len(abuse_cases)
        
        # Increase score if no auth required
        if not requires_auth:
            avg *= 1.5
        
        return min(10.0, round(avg, 1))
    
    def _determine_attack_surface(
        self,
        abuse_cases: list[AbuseCase],
        parameters: list[str],
        requires_auth: bool,
    ) -> str:
        """Determine attack surface level."""
        critical_count = len([ac for ac in abuse_cases if ac.severity == AbuseCaseSeverity.CRITICAL])
        high_count = len([ac for ac in abuse_cases if ac.severity == AbuseCaseSeverity.HIGH])
        
        if critical_count >= 2 or (critical_count >= 1 and not requires_auth):
            return "HIGH"
        elif high_count >= 2 or critical_count >= 1:
            return "MEDIUM"
        else:
            return "LOW"
    
    def generate_test_cases(self) -> list[dict[str, Any]]:
        """Generate test cases from all analyses."""
        test_cases = []
        
        for analysis in self.analyses:
            for abuse_case in analysis.abuse_cases:
                test_cases.append({
                    "id": abuse_case.id,
                    "name": abuse_case.name,
                    "endpoint": abuse_case.endpoint,
                    "method": abuse_case.method,
                    "severity": abuse_case.severity.value,
                    "steps": abuse_case.attack_steps,
                    "payload": abuse_case.test_payload,
                    "expected": abuse_case.expected_result,
                })
        
        return test_cases
    
    def get_summary(self) -> dict[str, Any]:
        """Get summary of all analyses."""
        total_cases = sum(len(a.abuse_cases) for a in self.analyses)
        
        by_severity = {}
        for sev in AbuseCaseSeverity:
            count = sum(
                len([ac for ac in a.abuse_cases if ac.severity == sev])
                for a in self.analyses
            )
            by_severity[sev.value] = count
        
        high_risk_endpoints = [
            a.endpoint for a in self.analyses if a.attack_surface == "HIGH"
        ]
        
        return {
            "total_endpoints": len(self.analyses),
            "total_abuse_cases": total_cases,
            "by_severity": by_severity,
            "high_risk_endpoints": high_risk_endpoints,
            "avg_risk_score": sum(a.risk_score for a in self.analyses) / len(self.analyses) if self.analyses else 0,
        }
