"""
STRIDE Analyzer - Automatic threat mapping using STRIDE methodology.
Maps threats to endpoints based on functionality, data, and authentication.
"""

from __future__ import annotations

import re
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


class STRIDECategory(Enum):
    """STRIDE threat categories."""
    SPOOFING = "spoofing"                    # S - Identity spoofing
    TAMPERING = "tampering"                  # T - Data tampering
    REPUDIATION = "repudiation"              # R - Deny actions
    INFORMATION_DISCLOSURE = "info_disclosure"  # I - Data leakage
    DENIAL_OF_SERVICE = "dos"                # D - Service disruption
    ELEVATION_OF_PRIVILEGE = "elevation"     # E - Privilege escalation


class AbuseCaseSeverity(Enum):
    """Severity levels for abuse cases."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Threat:
    """A single STRIDE threat."""
    id: str
    category: STRIDECategory
    name: str
    description: str
    affected_component: str
    attack_vector: str
    likelihood: str  # HIGH, MEDIUM, LOW
    impact: str      # HIGH, MEDIUM, LOW
    mitigations: list[str]
    references: list[str] = field(default_factory=list)
    cwe: Optional[str] = None
    capec: Optional[str] = None
    
    @property
    def risk_score(self) -> int:
        """Calculate risk score based on likelihood and impact."""
        likelihood_scores = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        impact_scores = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return likelihood_scores.get(self.likelihood, 1) * impact_scores.get(self.impact, 1)
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "category": self.category.value,
            "name": self.name,
            "description": self.description,
            "affected_component": self.affected_component,
            "attack_vector": self.attack_vector,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "risk_score": self.risk_score,
            "mitigations": self.mitigations,
            "references": self.references,
            "cwe": self.cwe,
            "capec": self.capec,
        }


@dataclass
class AbuseCase:
    """An abuse case for an endpoint."""
    id: str
    endpoint: str
    method: str
    name: str
    description: str
    severity: AbuseCaseSeverity
    stride_categories: list[STRIDECategory]
    preconditions: list[str]
    attack_steps: list[str]
    expected_result: str
    business_impact: str
    test_payload: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "endpoint": self.endpoint,
            "method": self.method,
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "stride_categories": [c.value for c in self.stride_categories],
            "preconditions": self.preconditions,
            "attack_steps": self.attack_steps,
            "expected_result": self.expected_result,
            "business_impact": self.business_impact,
            "test_payload": self.test_payload,
        }


class STRIDEAnalyzer:
    """
    Analyzes endpoints and generates STRIDE threat mappings.
    
    Thinks like an attacker by analyzing:
    - Endpoints and their functionality
    - Authentication/authorization flows
    - Sensitive data exposure
    - Trust boundaries
    """
    
    # Patterns that indicate specific functionalities
    ENDPOINT_PATTERNS = {
        # Authentication endpoints
        "auth": {
            "patterns": [r"/auth", r"/login", r"/signin", r"/token", r"/oauth", r"/sso"],
            "stride": [STRIDECategory.SPOOFING, STRIDECategory.ELEVATION_OF_PRIVILEGE],
            "threats": ["credential_stuffing", "brute_force", "session_hijacking"],
        },
        # User management
        "user": {
            "patterns": [r"/user", r"/profile", r"/account", r"/me"],
            "stride": [STRIDECategory.SPOOFING, STRIDECategory.INFORMATION_DISCLOSURE, STRIDECategory.TAMPERING],
            "threats": ["idor", "mass_assignment", "pii_exposure"],
        },
        # Payment/Financial
        "payment": {
            "patterns": [r"/pay", r"/order", r"/cart", r"/checkout", r"/refund", r"/transaction"],
            "stride": [STRIDECategory.TAMPERING, STRIDECategory.REPUDIATION, STRIDECategory.ELEVATION_OF_PRIVILEGE],
            "threats": ["price_manipulation", "race_condition", "negative_balance"],
        },
        # Admin/Management
        "admin": {
            "patterns": [r"/admin", r"/manage", r"/dashboard", r"/config", r"/settings"],
            "stride": [STRIDECategory.ELEVATION_OF_PRIVILEGE, STRIDECategory.TAMPERING],
            "threats": ["privilege_escalation", "unauthorized_access", "config_tampering"],
        },
        # File operations
        "file": {
            "patterns": [r"/upload", r"/download", r"/file", r"/document", r"/export", r"/import"],
            "stride": [STRIDECategory.INFORMATION_DISCLOSURE, STRIDECategory.TAMPERING, STRIDECategory.DENIAL_OF_SERVICE],
            "threats": ["path_traversal", "malicious_upload", "xxe", "ssrf"],
        },
        # Search/Query
        "search": {
            "patterns": [r"/search", r"/query", r"/filter", r"/find"],
            "stride": [STRIDECategory.INFORMATION_DISCLOSURE, STRIDECategory.DENIAL_OF_SERVICE],
            "threats": ["sqli", "nosql_injection", "regex_dos"],
        },
        # API/Integration
        "api": {
            "patterns": [r"/api", r"/webhook", r"/callback", r"/integrate"],
            "stride": [STRIDECategory.SPOOFING, STRIDECategory.TAMPERING, STRIDECategory.REPUDIATION],
            "threats": ["api_key_leak", "webhook_spoofing", "replay_attack"],
        },
        # Password/Credentials
        "password": {
            "patterns": [r"/password", r"/reset", r"/forgot", r"/recover"],
            "stride": [STRIDECategory.SPOOFING, STRIDECategory.INFORMATION_DISCLOSURE],
            "threats": ["account_takeover", "token_prediction", "email_enumeration"],
        },
    }
    
    # STRIDE threat templates
    THREAT_TEMPLATES = {
        STRIDECategory.SPOOFING: {
            "jwt_bypass": {
                "name": "JWT Authentication Bypass",
                "description": "Attacker forges or manipulates JWT tokens to impersonate users",
                "attack_vector": "Modify JWT algorithm to 'none', use weak key, or exploit kid injection",
                "mitigations": ["Enforce algorithm whitelist", "Use strong secrets", "Validate all claims"],
                "cwe": "CWE-287",
                "capec": "CAPEC-194",
            },
            "session_hijacking": {
                "name": "Session Hijacking",
                "description": "Attacker steals or predicts session tokens",
                "attack_vector": "XSS to steal cookies, session fixation, predictable tokens",
                "mitigations": ["HttpOnly cookies", "Secure flag", "Token rotation", "Binding to IP"],
                "cwe": "CWE-384",
                "capec": "CAPEC-61",
            },
            "credential_stuffing": {
                "name": "Credential Stuffing",
                "description": "Using leaked credentials to access accounts",
                "attack_vector": "Automated login attempts with credential databases",
                "mitigations": ["Rate limiting", "MFA", "Breached password detection", "CAPTCHA"],
                "cwe": "CWE-307",
                "capec": "CAPEC-600",
            },
        },
        STRIDECategory.TAMPERING: {
            "price_manipulation": {
                "name": "Price/Amount Manipulation",
                "description": "Modifying prices, quantities, or amounts in requests",
                "attack_vector": "Intercept and modify price parameter in payment requests",
                "mitigations": ["Server-side price calculation", "Signed requests", "Integrity checks"],
                "cwe": "CWE-472",
                "capec": "CAPEC-162",
            },
            "mass_assignment": {
                "name": "Mass Assignment",
                "description": "Modifying restricted fields via API binding",
                "attack_vector": "Add extra fields (isAdmin=true) to API requests",
                "mitigations": ["Whitelist allowed fields", "DTOs", "Input validation"],
                "cwe": "CWE-915",
                "capec": "CAPEC-271",
            },
            "parameter_tampering": {
                "name": "Parameter Tampering",
                "description": "Modifying request parameters to bypass controls",
                "attack_vector": "Change user_id, role, or other parameters",
                "mitigations": ["Server-side validation", "Signed parameters", "Authorization checks"],
                "cwe": "CWE-639",
                "capec": "CAPEC-146",
            },
        },
        STRIDECategory.REPUDIATION: {
            "missing_audit": {
                "name": "Missing Audit Trail",
                "description": "Actions not logged, allowing denial of activities",
                "attack_vector": "Perform malicious actions that aren't logged",
                "mitigations": ["Comprehensive logging", "Immutable logs", "Log integrity checks"],
                "cwe": "CWE-778",
                "capec": "CAPEC-93",
            },
            "log_injection": {
                "name": "Log Injection/Forging",
                "description": "Manipulating logs to hide or forge evidence",
                "attack_vector": "Inject newlines and fake log entries",
                "mitigations": ["Log sanitization", "Structured logging", "Log separation"],
                "cwe": "CWE-117",
                "capec": "CAPEC-268",
            },
        },
        STRIDECategory.INFORMATION_DISCLOSURE: {
            "idor": {
                "name": "Insecure Direct Object Reference",
                "description": "Accessing other users' data via predictable references",
                "attack_vector": "Change user_id=123 to user_id=124 to access other user's data",
                "mitigations": ["Indirect references", "Authorization checks", "UUIDs"],
                "cwe": "CWE-639",
                "capec": "CAPEC-647",
            },
            "pii_exposure": {
                "name": "PII/Sensitive Data Exposure",
                "description": "Personal data leaked in responses",
                "attack_vector": "API returns more fields than necessary, verbose errors",
                "mitigations": ["Data minimization", "Response filtering", "Field-level access control"],
                "cwe": "CWE-200",
                "capec": "CAPEC-169",
            },
            "error_disclosure": {
                "name": "Verbose Error Messages",
                "description": "Detailed errors reveal system information",
                "attack_vector": "Trigger errors to extract stack traces, paths, versions",
                "mitigations": ["Custom error pages", "Error logging without exposure"],
                "cwe": "CWE-209",
                "capec": "CAPEC-54",
            },
        },
        STRIDECategory.DENIAL_OF_SERVICE: {
            "regex_dos": {
                "name": "ReDoS (Regular Expression DoS)",
                "description": "Malicious input causes exponential regex evaluation",
                "attack_vector": "Craft input that causes catastrophic backtracking",
                "mitigations": ["Regex timeout", "Input length limits", "Safer regex patterns"],
                "cwe": "CWE-1333",
                "capec": "CAPEC-492",
            },
            "resource_exhaustion": {
                "name": "Resource Exhaustion",
                "description": "Depleting server resources via malicious requests",
                "attack_vector": "Large file uploads, complex queries, infinite loops",
                "mitigations": ["Rate limiting", "Request size limits", "Query complexity limits"],
                "cwe": "CWE-400",
                "capec": "CAPEC-130",
            },
            "api_abuse": {
                "name": "API Rate Limit Bypass",
                "description": "Bypassing rate limits to abuse API",
                "attack_vector": "Header rotation, IP spoofing, distributed requests",
                "mitigations": ["Multiple rate limit keys", "Anomaly detection", "Account-level limits"],
                "cwe": "CWE-770",
                "capec": "CAPEC-469",
            },
        },
        STRIDECategory.ELEVATION_OF_PRIVILEGE: {
            "vertical_privesc": {
                "name": "Vertical Privilege Escalation",
                "description": "Regular user gains admin privileges",
                "attack_vector": "Access admin endpoints, modify role in JWT/session",
                "mitigations": ["RBAC enforcement", "Principle of least privilege", "Re-authentication"],
                "cwe": "CWE-269",
                "capec": "CAPEC-233",
            },
            "horizontal_privesc": {
                "name": "Horizontal Privilege Escalation",
                "description": "Access other users' resources at same privilege level",
                "attack_vector": "IDOR, parameter tampering to access other accounts",
                "mitigations": ["Authorization checks on every request", "Object-level access control"],
                "cwe": "CWE-639",
                "capec": "CAPEC-122",
            },
            "function_level_bypass": {
                "name": "Broken Function Level Authorization",
                "description": "Accessing restricted functions without proper authorization",
                "attack_vector": "Direct URL access, API endpoint guessing",
                "mitigations": ["Centralized authorization", "Deny by default", "Function-level access control"],
                "cwe": "CWE-285",
                "capec": "CAPEC-122",
            },
        },
    }
    
    # Abuse case templates by endpoint type
    ABUSE_TEMPLATES = {
        "payment": [
            {
                "name": "Price Manipulation",
                "description": "Alter product prices in payment request",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.TAMPERING],
                "steps": [
                    "Intercept payment request",
                    "Modify price/amount field",
                    "Forward modified request",
                    "Complete purchase at reduced price",
                ],
                "impact": "Direct financial loss, revenue fraud",
            },
            {
                "name": "Negative Balance Purchase",
                "description": "Purchase with negative quantity or price",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.TAMPERING],
                "steps": [
                    "Add item with negative quantity",
                    "Proceed to checkout",
                    "Observe credit added to account",
                ],
                "impact": "Financial loss, balance manipulation",
            },
            {
                "name": "Race Condition - Double Spend",
                "description": "Exploit race condition for multiple redemptions",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.TAMPERING, STRIDECategory.REPUDIATION],
                "steps": [
                    "Send multiple parallel requests",
                    "Redeem same voucher/credit multiple times",
                    "Verify multiple redemptions succeeded",
                ],
                "impact": "Voucher/credit fraud, financial loss",
            },
            {
                "name": "Refund Abuse",
                "description": "Process unauthorized refunds",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.ELEVATION_OF_PRIVILEGE, STRIDECategory.TAMPERING],
                "steps": [
                    "Access refund endpoint",
                    "Modify order/user ID",
                    "Process refund for other users",
                ],
                "impact": "Unauthorized refunds, financial loss",
            },
        ],
        "auth": [
            {
                "name": "Brute Force Login",
                "description": "Automated credential guessing",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.SPOOFING],
                "steps": [
                    "Enumerate valid usernames",
                    "Attempt common passwords",
                    "Bypass rate limiting if present",
                    "Gain unauthorized access",
                ],
                "impact": "Account compromise, data breach",
            },
            {
                "name": "Token Reuse/Replay",
                "description": "Reuse authentication tokens",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.SPOOFING, STRIDECategory.REPUDIATION],
                "steps": [
                    "Capture valid authentication token",
                    "Wait for user logout",
                    "Replay captured token",
                    "Access account without credentials",
                ],
                "impact": "Session hijacking, unauthorized access",
            },
            {
                "name": "MFA Bypass",
                "description": "Circumvent multi-factor authentication",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.SPOOFING, STRIDECategory.ELEVATION_OF_PRIVILEGE],
                "steps": [
                    "Complete first factor",
                    "Attempt direct access to post-MFA endpoints",
                    "Modify step parameter in flow",
                    "Access account without second factor",
                ],
                "impact": "Complete auth bypass, account takeover",
            },
        ],
        "user": [
            {
                "name": "IDOR - Access Other Profiles",
                "description": "View other users' private data",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.INFORMATION_DISCLOSURE],
                "steps": [
                    "Identify own user ID in requests",
                    "Enumerate or guess other user IDs",
                    "Access other users' profiles",
                    "Extract PII/sensitive data",
                ],
                "impact": "Privacy violation, data breach, GDPR violation",
            },
            {
                "name": "Mass Assignment - Privilege",
                "description": "Elevate privileges via hidden fields",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.ELEVATION_OF_PRIVILEGE, STRIDECategory.TAMPERING],
                "steps": [
                    "Capture profile update request",
                    "Add role/isAdmin field",
                    "Submit modified request",
                    "Verify elevated privileges",
                ],
                "impact": "Full account takeover, admin access",
            },
            {
                "name": "Account Enumeration",
                "description": "Identify valid accounts",
                "severity": AbuseCaseSeverity.MEDIUM,
                "stride": [STRIDECategory.INFORMATION_DISCLOSURE],
                "steps": [
                    "Submit registration with target email",
                    "Observe 'email exists' message",
                    "Enumerate valid accounts",
                ],
                "impact": "Privacy violation, enables targeted attacks",
            },
        ],
        "admin": [
            {
                "name": "Direct Admin Access",
                "description": "Access admin functions without authorization",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.ELEVATION_OF_PRIVILEGE],
                "steps": [
                    "Identify admin endpoints",
                    "Attempt access with regular user token",
                    "Modify role claims in JWT",
                    "Access admin functionality",
                ],
                "impact": "Complete system compromise",
            },
            {
                "name": "Configuration Tampering",
                "description": "Modify system configuration",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE],
                "steps": [
                    "Access configuration endpoints",
                    "Modify security settings",
                    "Disable logging/auditing",
                    "Enable backdoor access",
                ],
                "impact": "System compromise, persistent access",
            },
        ],
        "file": [
            {
                "name": "Malicious File Upload",
                "description": "Upload executable or malicious files",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.TAMPERING, STRIDECategory.ELEVATION_OF_PRIVILEGE],
                "steps": [
                    "Prepare webshell with image extension",
                    "Bypass content-type validation",
                    "Upload to accessible directory",
                    "Execute uploaded file",
                ],
                "impact": "Remote code execution, server compromise",
            },
            {
                "name": "Path Traversal Download",
                "description": "Read arbitrary files from server",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.INFORMATION_DISCLOSURE],
                "steps": [
                    "Identify download endpoint",
                    "Insert ../../../etc/passwd",
                    "Extract sensitive files",
                    "Read configuration/credentials",
                ],
                "impact": "Data breach, credential exposure",
            },
            {
                "name": "XXE via File Upload",
                "description": "XML External Entity injection via file parsing",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.INFORMATION_DISCLOSURE, STRIDECategory.TAMPERING],
                "steps": [
                    "Create malicious XML/SVG/DOCX",
                    "Include external entity definition",
                    "Upload file for processing",
                    "Exfiltrate internal files via XXE",
                ],
                "impact": "SSRF, file disclosure, DoS",
            },
        ],
        "search": [
            {
                "name": "SQL Injection",
                "description": "Extract or manipulate database via SQL",
                "severity": AbuseCaseSeverity.CRITICAL,
                "stride": [STRIDECategory.INFORMATION_DISCLOSURE, STRIDECategory.TAMPERING],
                "steps": [
                    "Identify injectable parameter",
                    "Determine database type",
                    "Extract schema information",
                    "Dump sensitive data",
                ],
                "impact": "Complete database compromise",
            },
            {
                "name": "NoSQL Injection",
                "description": "Bypass authentication or extract data",
                "severity": AbuseCaseSeverity.HIGH,
                "stride": [STRIDECategory.SPOOFING, STRIDECategory.INFORMATION_DISCLOSURE],
                "steps": [
                    "Inject MongoDB operators",
                    "Use $gt/$ne for auth bypass",
                    "Extract data via $regex",
                ],
                "impact": "Auth bypass, data extraction",
            },
        ],
    }
    
    def __init__(self):
        self.threats: list[Threat] = []
        self.abuse_cases: list[AbuseCase] = []
    
    def analyze_endpoint(
        self,
        endpoint: str,
        method: str = "GET",
        parameters: list[str] | None = None,
        requires_auth: bool = True,
        data_types: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Analyze a single endpoint for STRIDE threats.
        
        Args:
            endpoint: The API endpoint path
            method: HTTP method
            parameters: List of parameter names
            requires_auth: Whether endpoint requires authentication
            data_types: Types of data handled (pii, financial, etc.)
            
        Returns:
            Dictionary with threats and abuse cases
        """
        parameters = parameters or []
        data_types = data_types or []
        
        # Identify endpoint type
        endpoint_type = self._identify_endpoint_type(endpoint)
        
        # Generate threats based on endpoint type
        threats = self._generate_threats(endpoint, endpoint_type, method, parameters, requires_auth)
        
        # Generate abuse cases
        abuse_cases = self._generate_abuse_cases(endpoint, endpoint_type, method, parameters)
        
        # Add data-type specific threats
        if "pii" in data_types or "personal" in data_types:
            threats.extend(self._get_pii_threats(endpoint))
        
        if "financial" in data_types or "payment" in data_types:
            threats.extend(self._get_financial_threats(endpoint))
        
        self.threats.extend(threats)
        self.abuse_cases.extend(abuse_cases)
        
        return {
            "endpoint": endpoint,
            "method": method,
            "type": endpoint_type,
            "threats": [t.to_dict() for t in threats],
            "abuse_cases": [a.to_dict() for a in abuse_cases],
            "risk_summary": self._calculate_risk_summary(threats),
        }
    
    def _identify_endpoint_type(self, endpoint: str) -> str:
        """Identify the type/category of an endpoint."""
        endpoint_lower = endpoint.lower()
        
        for ep_type, config in self.ENDPOINT_PATTERNS.items():
            for pattern in config["patterns"]:
                if re.search(pattern, endpoint_lower):
                    return ep_type
        
        return "generic"
    
    def _generate_threats(
        self,
        endpoint: str,
        endpoint_type: str,
        method: str,
        parameters: list[str],
        requires_auth: bool,
    ) -> list[Threat]:
        """Generate STRIDE threats for an endpoint."""
        threats = []
        
        # Get STRIDE categories for this endpoint type
        if endpoint_type in self.ENDPOINT_PATTERNS:
            stride_categories = self.ENDPOINT_PATTERNS[endpoint_type]["stride"]
        else:
            # Generic endpoints - check all categories
            stride_categories = list(STRIDECategory)
        
        for category in stride_categories:
            if category in self.THREAT_TEMPLATES:
                for threat_key, template in self.THREAT_TEMPLATES[category].items():
                    # Check if threat is relevant
                    if self._is_threat_relevant(threat_key, endpoint, method, parameters, requires_auth):
                        threat_id = hashlib.md5(f"{endpoint}{threat_key}".encode()).hexdigest()[:8]
                        
                        threat = Threat(
                            id=f"T-{threat_id}",
                            category=category,
                            name=template["name"],
                            description=template["description"],
                            affected_component=endpoint,
                            attack_vector=template["attack_vector"],
                            likelihood=self._assess_likelihood(threat_key, endpoint_type, requires_auth),
                            impact=self._assess_impact(threat_key, endpoint_type),
                            mitigations=template["mitigations"],
                            cwe=template.get("cwe"),
                            capec=template.get("capec"),
                        )
                        threats.append(threat)
        
        return threats
    
    def _generate_abuse_cases(
        self,
        endpoint: str,
        endpoint_type: str,
        method: str,
        parameters: list[str],
    ) -> list[AbuseCase]:
        """Generate abuse cases for an endpoint."""
        abuse_cases = []
        
        if endpoint_type in self.ABUSE_TEMPLATES:
            for template in self.ABUSE_TEMPLATES[endpoint_type]:
                case_id = hashlib.md5(f"{endpoint}{template['name']}".encode()).hexdigest()[:8]
                
                abuse_case = AbuseCase(
                    id=f"AC-{case_id}",
                    endpoint=endpoint,
                    method=method,
                    name=template["name"],
                    description=template["description"],
                    severity=template["severity"],
                    stride_categories=template["stride"],
                    preconditions=self._get_preconditions(endpoint_type, method),
                    attack_steps=template["steps"],
                    expected_result=f"Successful {template['name'].lower()}",
                    business_impact=template["impact"],
                )
                abuse_cases.append(abuse_case)
        
        return abuse_cases
    
    def _is_threat_relevant(
        self,
        threat_key: str,
        endpoint: str,
        method: str,
        parameters: list[str],
        requires_auth: bool,
    ) -> bool:
        """Check if a threat is relevant to the endpoint."""
        # Auth-related threats only for auth endpoints or when no auth
        if threat_key in ["credential_stuffing", "brute_force", "session_hijacking"]:
            return "login" in endpoint.lower() or "auth" in endpoint.lower() or not requires_auth
        
        # IDOR relevant when there are ID parameters
        if threat_key == "idor":
            return any(p in str(parameters).lower() for p in ["id", "user", "account"])
        
        # Price manipulation for payment endpoints
        if threat_key == "price_manipulation":
            return any(p in endpoint.lower() for p in ["pay", "order", "cart", "price"])
        
        # Default: assume relevant
        return True
    
    def _assess_likelihood(self, threat_key: str, endpoint_type: str, requires_auth: bool) -> str:
        """Assess the likelihood of a threat."""
        high_likelihood = ["idor", "price_manipulation", "credential_stuffing", "pii_exposure"]
        medium_likelihood = ["session_hijacking", "mass_assignment", "parameter_tampering"]
        
        if threat_key in high_likelihood:
            return "HIGH"
        elif threat_key in medium_likelihood:
            return "MEDIUM"
        elif not requires_auth:
            return "HIGH"
        else:
            return "LOW"
    
    def _assess_impact(self, threat_key: str, endpoint_type: str) -> str:
        """Assess the impact of a threat."""
        critical_impact = ["vertical_privesc", "price_manipulation", "credential_stuffing"]
        high_impact = ["idor", "pii_exposure", "session_hijacking", "mass_assignment"]
        
        if threat_key in critical_impact or endpoint_type in ["payment", "admin"]:
            return "HIGH"
        elif threat_key in high_impact:
            return "HIGH"
        else:
            return "MEDIUM"
    
    def _get_preconditions(self, endpoint_type: str, method: str) -> list[str]:
        """Get preconditions for testing an endpoint type."""
        preconditions = ["Valid user account"]
        
        if endpoint_type == "payment":
            preconditions.extend(["Items in cart", "Valid payment method"])
        elif endpoint_type == "admin":
            preconditions.append("Knowledge of admin endpoints")
        elif endpoint_type == "file":
            preconditions.append("Ability to upload files")
        
        return preconditions
    
    def _get_pii_threats(self, endpoint: str) -> list[Threat]:
        """Get PII-specific threats."""
        return [
            Threat(
                id=f"T-PII-{hashlib.md5(endpoint.encode()).hexdigest()[:6]}",
                category=STRIDECategory.INFORMATION_DISCLOSURE,
                name="PII Data Exposure",
                description="Personal Identifiable Information may be exposed",
                affected_component=endpoint,
                attack_vector="Access API response containing unfiltered PII fields",
                likelihood="MEDIUM",
                impact="HIGH",
                mitigations=["Data masking", "Field-level access control", "Response filtering"],
                cwe="CWE-359",
            )
        ]
    
    def _get_financial_threats(self, endpoint: str) -> list[Threat]:
        """Get financial data specific threats."""
        return [
            Threat(
                id=f"T-FIN-{hashlib.md5(endpoint.encode()).hexdigest()[:6]}",
                category=STRIDECategory.TAMPERING,
                name="Financial Data Manipulation",
                description="Financial transactions may be manipulated",
                affected_component=endpoint,
                attack_vector="Modify transaction amounts, currencies, or destinations",
                likelihood="MEDIUM",
                impact="HIGH",
                mitigations=["Transaction signing", "Server-side validation", "Dual approval"],
                cwe="CWE-472",
            )
        ]
    
    def _calculate_risk_summary(self, threats: list[Threat]) -> dict[str, Any]:
        """Calculate risk summary for threats."""
        if not threats:
            return {"total_threats": 0, "risk_level": "LOW"}
        
        total_risk = sum(t.risk_score for t in threats)
        max_risk = max(t.risk_score for t in threats)
        
        by_category = {}
        for t in threats:
            cat = t.category.value
            by_category[cat] = by_category.get(cat, 0) + 1
        
        if max_risk >= 9:
            risk_level = "CRITICAL"
        elif max_risk >= 6:
            risk_level = "HIGH"
        elif max_risk >= 4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            "total_threats": len(threats),
            "total_risk_score": total_risk,
            "max_risk_score": max_risk,
            "risk_level": risk_level,
            "by_category": by_category,
        }
    
    def get_stride_summary(self) -> dict[str, Any]:
        """Get summary of all STRIDE threats analyzed."""
        summary = {
            "total_threats": len(self.threats),
            "total_abuse_cases": len(self.abuse_cases),
            "by_category": {},
            "by_severity": {},
            "high_risk_threats": [],
        }
        
        for cat in STRIDECategory:
            count = len([t for t in self.threats if t.category == cat])
            summary["by_category"][cat.value] = count
        
        for sev in AbuseCaseSeverity:
            count = len([a for a in self.abuse_cases if a.severity == sev])
            summary["by_severity"][sev.value] = count
        
        # High risk threats
        summary["high_risk_threats"] = [
            t.to_dict() for t in self.threats if t.risk_score >= 6
        ]
        
        return summary
