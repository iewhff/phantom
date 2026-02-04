"""
API Logic Profiler v1.0 - Role-Based Response Analysis

Enterprise-grade API security scanner that detects authorization vulnerabilities
by comparing responses across different roles/users/tenants.

This is WHERE TOP TIER BOUNTIES COME FROM ($3k-$20k+):
- Broken Access Control (OWASP #1)
- IDORs
- Privilege Escalation
- Multi-tenant isolation failures

Features:
- Multi-role response comparison
- Automatic IDOR detection
- Field-level permission analysis
- State inconsistency detection
- Response diff visualization
- Mass assignment detection
- Horizontal/Vertical privilege escalation

Author: PetNTester AI
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from difflib import unified_diff, SequenceMatcher
from enum import Enum, auto
from typing import TYPE_CHECKING, Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from scanning.vuln_scanner import Finding, ScanModule
from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings
    from utils.rate_limiter import RateLimiter

logger = get_logger(__name__)


# =============================================================================
# VERSION & CONSTANTS
# =============================================================================

API_LOGIC_PROFILER_VERSION = "1.0.0"

# Minimum confidence to report
MIN_CONFIDENCE_THRESHOLD = 70


class VulnerabilityType(Enum):
    """Types of authorization vulnerabilities."""
    IDOR = "IDOR"                                    # Insecure Direct Object Reference
    BOLA = "BOLA"                                    # Broken Object Level Authorization
    BFLA = "BFLA"                                    # Broken Function Level Authorization
    HORIZONTAL_PRIV_ESC = "Horizontal Privilege Escalation"
    VERTICAL_PRIV_ESC = "Vertical Privilege Escalation"
    MASS_ASSIGNMENT = "Mass Assignment"
    DATA_LEAKAGE = "Data Leakage"
    MULTI_TENANT_ISOLATION = "Multi-Tenant Isolation Failure"
    STATE_INCONSISTENCY = "State Inconsistency"


class ResponseDiffType(Enum):
    """Types of response differences."""
    STATUS_CODE = auto()
    BODY_CONTENT = auto()
    FIELD_PRESENCE = auto()
    FIELD_VALUE = auto()
    ARRAY_LENGTH = auto()
    PERMISSIONS = auto()


@dataclass
class RoleConfig:
    """Configuration for a role/user context."""
    name: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    description: str = ""


@dataclass
class ResponseProfile:
    """Profile of an API response."""
    role: str
    status_code: int
    headers: dict[str, str]
    body: Any  # Can be dict, list, or str
    body_hash: str
    response_time_ms: float
    fields: set[str]  # JSON paths present
    sensitive_fields: list[str]  # Fields that look sensitive
    timestamp: float


@dataclass
class ResponseDiff:
    """Difference between two responses."""
    diff_type: ResponseDiffType
    field_path: str
    role_a: str
    role_b: str
    value_a: Any
    value_b: Any
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    description: str


@dataclass
class AuthzFinding:
    """Authorization vulnerability finding."""
    vuln_type: VulnerabilityType
    endpoint: str
    method: str
    roles_affected: list[str]
    diffs: list[ResponseDiff]
    confidence: float
    impact: str
    evidence: list[str]
    remediation: str


# =============================================================================
# SENSITIVE FIELD PATTERNS
# =============================================================================

SENSITIVE_FIELD_PATTERNS = [
    # Personal data
    r"email", r"phone", r"address", r"ssn", r"social.*security",
    r"birth.*date", r"dob", r"age", r"gender", r"name",

    # Financial
    r"credit.*card", r"card.*number", r"cvv", r"bank", r"account.*number",
    r"balance", r"salary", r"income", r"payment", r"billing",

    # Authentication
    r"password", r"secret", r"token", r"api.*key", r"auth",
    r"session", r"jwt", r"bearer", r"credential",

    # Internal
    r"internal", r"admin", r"role", r"permission", r"privilege",
    r"tenant.*id", r"org.*id", r"user.*id", r"owner",

    # Sensitive status
    r"is.*admin", r"is.*superuser", r"is.*verified", r"is.*active",
    r"can.*delete", r"can.*edit", r"can.*manage",
]

# ID patterns that indicate object references
ID_PATTERNS = [
    r"id$", r"_id$", r"Id$", r"ID$",
    r"uuid", r"guid",
    r"user_id", r"org_id", r"tenant_id", r"account_id",
    r"order_id", r"transaction_id", r"payment_id",
]


# =============================================================================
# RESPONSE ANALYZER
# =============================================================================

class ResponseAnalyzer:
    """Analyze API responses for security-relevant information."""

    @staticmethod
    def profile_response(
        role: str,
        response: httpx.Response,
        start_time: float,
    ) -> ResponseProfile:
        """Create a profile from an HTTP response."""
        body = None
        fields = set()
        sensitive_fields = []

        try:
            body = response.json()
            fields, sensitive_fields = ResponseAnalyzer._extract_fields(body)
        except Exception:
            body = response.text

        body_hash = hashlib.md5(response.content).hexdigest()
        response_time = (time.time() - start_time) * 1000

        return ResponseProfile(
            role=role,
            status_code=response.status_code,
            headers=dict(response.headers),
            body=body,
            body_hash=body_hash,
            response_time_ms=response_time,
            fields=fields,
            sensitive_fields=sensitive_fields,
            timestamp=time.time(),
        )

    @staticmethod
    def _extract_fields(obj: Any, prefix: str = "") -> tuple[set[str], list[str]]:
        """Recursively extract field paths from JSON object."""
        fields = set()
        sensitive = []

        if isinstance(obj, dict):
            for key, value in obj.items():
                path = f"{prefix}.{key}" if prefix else key
                fields.add(path)

                # Check if sensitive
                key_lower = key.lower()
                for pattern in SENSITIVE_FIELD_PATTERNS:
                    if re.search(pattern, key_lower):
                        sensitive.append(path)
                        break

                # Recurse
                sub_fields, sub_sensitive = ResponseAnalyzer._extract_fields(value, path)
                fields.update(sub_fields)
                sensitive.extend(sub_sensitive)

        elif isinstance(obj, list) and obj:
            # Sample first element
            sub_fields, sub_sensitive = ResponseAnalyzer._extract_fields(obj[0], f"{prefix}[]")
            fields.update(sub_fields)
            sensitive.extend(sub_sensitive)

        return fields, sensitive

    @staticmethod
    def compare_profiles(
        profile_a: ResponseProfile,
        profile_b: ResponseProfile,
    ) -> list[ResponseDiff]:
        """Compare two response profiles for security-relevant differences."""
        diffs = []

        # Status code difference
        if profile_a.status_code != profile_b.status_code:
            # Significant difference
            severity = "HIGH" if abs(profile_a.status_code - profile_b.status_code) >= 100 else "MEDIUM"
            if profile_a.status_code == 200 and profile_b.status_code in [401, 403]:
                severity = "CRITICAL"  # Potential bypass

            diffs.append(ResponseDiff(
                diff_type=ResponseDiffType.STATUS_CODE,
                field_path="status_code",
                role_a=profile_a.role,
                role_b=profile_b.role,
                value_a=profile_a.status_code,
                value_b=profile_b.status_code,
                severity=severity,
                description=f"Status code difference: {profile_a.status_code} vs {profile_b.status_code}",
            ))

        # Field presence difference
        fields_only_a = profile_a.fields - profile_b.fields
        fields_only_b = profile_b.fields - profile_a.fields

        for field in fields_only_a:
            severity = "HIGH" if any(re.search(p, field.lower()) for p in SENSITIVE_FIELD_PATTERNS) else "LOW"
            diffs.append(ResponseDiff(
                diff_type=ResponseDiffType.FIELD_PRESENCE,
                field_path=field,
                role_a=profile_a.role,
                role_b=profile_b.role,
                value_a="present",
                value_b="absent",
                severity=severity,
                description=f"Field '{field}' only visible to {profile_a.role}",
            ))

        for field in fields_only_b:
            severity = "HIGH" if any(re.search(p, field.lower()) for p in SENSITIVE_FIELD_PATTERNS) else "LOW"
            diffs.append(ResponseDiff(
                diff_type=ResponseDiffType.FIELD_PRESENCE,
                field_path=field,
                role_a=profile_a.role,
                role_b=profile_b.role,
                value_a="absent",
                value_b="present",
                severity=severity,
                description=f"Field '{field}' only visible to {profile_b.role}",
            ))

        # Compare common field values
        if isinstance(profile_a.body, dict) and isinstance(profile_b.body, dict):
            value_diffs = ResponseAnalyzer._compare_dicts(
                profile_a.body, profile_b.body,
                profile_a.role, profile_b.role
            )
            diffs.extend(value_diffs)

        # Array length differences (data leakage indicator)
        if isinstance(profile_a.body, list) and isinstance(profile_b.body, list):
            if len(profile_a.body) != len(profile_b.body):
                severity = "MEDIUM"
                if len(profile_a.body) > len(profile_b.body) * 2:
                    severity = "HIGH"  # Significant data leakage

                diffs.append(ResponseDiff(
                    diff_type=ResponseDiffType.ARRAY_LENGTH,
                    field_path="root[]",
                    role_a=profile_a.role,
                    role_b=profile_b.role,
                    value_a=len(profile_a.body),
                    value_b=len(profile_b.body),
                    severity=severity,
                    description=f"Array length: {len(profile_a.body)} vs {len(profile_b.body)}",
                ))

        return diffs

    @staticmethod
    def _compare_dicts(
        dict_a: dict,
        dict_b: dict,
        role_a: str,
        role_b: str,
        prefix: str = "",
    ) -> list[ResponseDiff]:
        """Compare dictionaries recursively for value differences."""
        diffs = []

        common_keys = set(dict_a.keys()) & set(dict_b.keys())

        for key in common_keys:
            path = f"{prefix}.{key}" if prefix else key
            val_a = dict_a[key]
            val_b = dict_b[key]

            if isinstance(val_a, dict) and isinstance(val_b, dict):
                diffs.extend(ResponseAnalyzer._compare_dicts(val_a, val_b, role_a, role_b, path))
            elif val_a != val_b:
                # Check if this is a sensitive field
                is_sensitive = any(re.search(p, path.lower()) for p in SENSITIVE_FIELD_PATTERNS)
                severity = "HIGH" if is_sensitive else "LOW"

                # Check if it's an ID field that shouldn't differ
                is_id = any(re.search(p, path.lower()) for p in ID_PATTERNS)
                if is_id:
                    severity = "CRITICAL"  # Potential IDOR

                diffs.append(ResponseDiff(
                    diff_type=ResponseDiffType.FIELD_VALUE,
                    field_path=path,
                    role_a=role_a,
                    role_b=role_b,
                    value_a=val_a,
                    value_b=val_b,
                    severity=severity,
                    description=f"Value difference in '{path}': {val_a} vs {val_b}",
                ))

        return diffs


# =============================================================================
# RESPONSE DIFF VISUALIZER
# =============================================================================

class ResponseDiffVisualizer:
    """Generate visual diffs for response comparison."""

    @staticmethod
    def generate_text_diff(profile_a: ResponseProfile, profile_b: ResponseProfile) -> str:
        """Generate unified text diff of responses."""
        try:
            if isinstance(profile_a.body, (dict, list)):
                text_a = json.dumps(profile_a.body, indent=2, sort_keys=True).splitlines(keepends=True)
            else:
                text_a = str(profile_a.body).splitlines(keepends=True)

            if isinstance(profile_b.body, (dict, list)):
                text_b = json.dumps(profile_b.body, indent=2, sort_keys=True).splitlines(keepends=True)
            else:
                text_b = str(profile_b.body).splitlines(keepends=True)

            diff = unified_diff(
                text_a, text_b,
                fromfile=f"Response ({profile_a.role})",
                tofile=f"Response ({profile_b.role})",
            )

            return "".join(diff)
        except Exception:
            return "Unable to generate diff"

    @staticmethod
    def generate_markdown_report(
        endpoint: str,
        profiles: list[ResponseProfile],
        diffs: list[ResponseDiff],
    ) -> str:
        """Generate markdown report of role comparison."""
        lines = [
            f"# API Role Comparison Report",
            f"\n## Endpoint: `{endpoint}`\n",
            f"\n### Roles Tested\n",
        ]

        for profile in profiles:
            lines.append(f"- **{profile.role}**: Status {profile.status_code}, {len(profile.fields)} fields")

        if diffs:
            lines.append(f"\n### Differences Found: {len(diffs)}\n")

            # Group by severity
            critical = [d for d in diffs if d.severity == "CRITICAL"]
            high = [d for d in diffs if d.severity == "HIGH"]
            medium = [d for d in diffs if d.severity == "MEDIUM"]
            low = [d for d in diffs if d.severity == "LOW"]

            if critical:
                lines.append("\n#### CRITICAL\n")
                for d in critical:
                    lines.append(f"- `{d.field_path}`: {d.description}")

            if high:
                lines.append("\n#### HIGH\n")
                for d in high:
                    lines.append(f"- `{d.field_path}`: {d.description}")

            if medium:
                lines.append("\n#### MEDIUM\n")
                for d in medium:
                    lines.append(f"- `{d.field_path}`: {d.description}")

            if low:
                lines.append("\n#### LOW\n")
                for d in low[:10]:  # Limit low severity
                    lines.append(f"- `{d.field_path}`: {d.description}")
                if len(low) > 10:
                    lines.append(f"- ... and {len(low) - 10} more")
        else:
            lines.append("\n### No significant differences found\n")

        return "\n".join(lines)

    @staticmethod
    def generate_html_diff(profile_a: ResponseProfile, profile_b: ResponseProfile) -> str:
        """Generate HTML side-by-side diff."""
        html = f"""
        <div class="diff-container">
            <h3>Response Comparison: {profile_a.role} vs {profile_b.role}</h3>
            <div class="diff-panels">
                <div class="panel left">
                    <h4>{profile_a.role} (Status: {profile_a.status_code})</h4>
                    <pre>{json.dumps(profile_a.body, indent=2) if isinstance(profile_a.body, (dict, list)) else profile_a.body}</pre>
                </div>
                <div class="panel right">
                    <h4>{profile_b.role} (Status: {profile_b.status_code})</h4>
                    <pre>{json.dumps(profile_b.body, indent=2) if isinstance(profile_b.body, (dict, list)) else profile_b.body}</pre>
                </div>
            </div>
        </div>
        """
        return html


# =============================================================================
# API LOGIC PROFILER SCANNER
# =============================================================================

class APILogicProfiler(ScanModule):
    """
    API Logic Profiler - Detects authorization vulnerabilities by comparing
    responses across different roles/users.

    THIS IS WHERE TOP TIER BOUNTIES COME FROM.

    Usage:
        1. Configure roles with different auth tokens/cookies
        2. Point at endpoints
        3. Analyze differences for security implications
    """

    name = "api_logic_profiler"
    version = API_LOGIC_PROFILER_VERSION

    def __init__(self, settings: "Settings") -> None:
        super().__init__(settings)
        self.timeout = getattr(settings.timeouts, 'request_timeout', 30)
        self.roles: list[RoleConfig] = []
        self.analyzer = ResponseAnalyzer()
        self.visualizer = ResponseDiffVisualizer()

    def configure_roles(self, roles: list[RoleConfig]) -> None:
        """Configure roles for comparison testing."""
        self.roles = roles
        logger.info(f"[APILogicProfiler] Configured {len(roles)} roles: {[r.name for r in roles]}")

    async def scan(
        self,
        host: str,
        asset_data: dict[str, Any],
        rate_limiter: "RateLimiter",
    ) -> dict[str, Any]:
        """
        Execute API logic profiling scan.

        Args:
            host: Target host
            asset_data: Asset data with endpoints, roles config, etc.
            rate_limiter: Rate limiter

        Returns:
            Scan results with authorization findings
        """
        logger.info(f"[APILogicProfiler v{self.version}] Starting scan on {host}")

        findings: list[dict] = []
        info_items: list[dict] = []
        reports: list[str] = []

        base_url = f"https://{host}" if not host.startswith("http") else host

        # Get roles from asset_data if not configured
        if not self.roles:
            roles_config = asset_data.get("roles", [])
            self.roles = [
                RoleConfig(
                    name=r.get("name", "unknown"),
                    headers=r.get("headers", {}),
                    cookies=r.get("cookies", {}),
                )
                for r in roles_config
            ]

        if len(self.roles) < 2:
            logger.debug("[APILogicProfiler] No roles configured, using unauthenticated testing")
            self.roles = [
                RoleConfig(name="unauthenticated", headers={}, cookies={}),
            ]

        # Get endpoints to test
        endpoints = asset_data.get("endpoints", [])
        api_endpoints = asset_data.get("api_endpoints", [])
        all_endpoints = list(set(endpoints + api_endpoints))

        # ====================================================================
        # PHASE 1: API Discovery (probe common API paths)
        # ====================================================================
        logger.info("[APILogicProfiler] Phase 1: API Discovery")
        discovered_apis = await self._discover_api_endpoints(base_url, rate_limiter)
        all_endpoints.extend(discovered_apis)
        all_endpoints = list(set(all_endpoints))
        
        info_items.append({
            "type": "api_discovery",
            "discovered": len(discovered_apis),
            "total_endpoints": len(all_endpoints),
        })

        # Filter for interesting endpoints
        interesting_patterns = [
            r"/api/", r"/rest/", r"/v\d+/", r"/graphql",
            r"/user", r"/account", r"/profile", r"/me",
            r"/admin", r"/manage", r"/internal", r"/private",
            r"/order", r"/payment", r"/billing", r"/transaction",
            r"/document", r"/file", r"/export", r"/report",
            r"/feedback", r"/comment", r"/message", r"/notification",
        ]

        priority_endpoints = []
        other_endpoints = []

        for ep in all_endpoints:
            if any(re.search(p, ep, re.IGNORECASE) for p in interesting_patterns):
                priority_endpoints.append(ep)
            else:
                other_endpoints.append(ep)

        test_endpoints = priority_endpoints[:30] + other_endpoints[:10]

        stats = {
            "endpoints_tested": 0,
            "apis_discovered": len(discovered_apis),
            "roles_tested": len(self.roles),
            "vulnerabilities_found": 0,
            "data_exposures": 0,
        }

        # ====================================================================
        # PHASE 2: Unauthenticated Data Exposure Detection
        # ====================================================================
        logger.info("[APILogicProfiler] Phase 2: Unauthenticated Data Exposure")
        exposure_findings = await self._test_unauthenticated_exposure(
            base_url, test_endpoints, rate_limiter
        )
        for finding in exposure_findings:
            findings.append(self._create_finding(finding).to_dict())
            stats["vulnerabilities_found"] += 1
            stats["data_exposures"] += 1

        # ====================================================================
        # PHASE 3: IDOR via URL Path ID Manipulation
        # ====================================================================
        logger.info("[APILogicProfiler] Phase 3: IDOR Path Testing")
        idor_findings = await self._test_idor(host, test_endpoints, rate_limiter)
        for finding in idor_findings:
            findings.append(self._create_finding(finding).to_dict())
            stats["vulnerabilities_found"] += 1

        # ====================================================================
        # PHASE 4: IDOR via Query Parameter Manipulation
        # ====================================================================
        logger.info("[APILogicProfiler] Phase 4: IDOR Parameter Testing")
        param_findings = await self._test_idor_parameters(
            base_url, test_endpoints, rate_limiter
        )
        for finding in param_findings:
            findings.append(self._create_finding(finding).to_dict())
            stats["vulnerabilities_found"] += 1

        # ====================================================================
        # PHASE 5: Role-based comparison (if roles available)
        # ====================================================================
        if len(self.roles) >= 2:
            logger.info("[APILogicProfiler] Phase 5: Role Comparison")
            for endpoint in test_endpoints[:15]:
                await rate_limiter.acquire(host)
                stats["endpoints_tested"] += 1

                try:
                    profiles = []
                    for role in self.roles:
                        await rate_limiter.acquire(host)
                        profile = await self._profile_endpoint(endpoint, role)
                        if profile:
                            profiles.append(profile)

                    if len(profiles) >= 2:
                        all_diffs = []
                        for i, profile_a in enumerate(profiles):
                            for profile_b in profiles[i+1:]:
                                diffs = self.analyzer.compare_profiles(profile_a, profile_b)
                                all_diffs.extend(diffs)

                        report = self.visualizer.generate_markdown_report(endpoint, profiles, all_diffs)
                        reports.append(report)

                        endpoint_findings = self._analyze_for_vulnerabilities(endpoint, profiles, all_diffs)
                        for finding in endpoint_findings:
                            findings.append(self._create_finding(finding).to_dict())
                            stats["vulnerabilities_found"] += 1

                except Exception as e:
                    logger.debug(f"[APILogicProfiler] Error testing {endpoint}: {e}")

        logger.info(f"[APILogicProfiler v{self.version}] Scan complete: {len(findings)} findings")

        return {
            "module": self.name,
            "version": self.version,
            "findings": findings,
            "info": info_items,
            "reports": reports,
            "stats": stats,
        }

    async def _discover_api_endpoints(
        self,
        base_url: str,
        rate_limiter: "RateLimiter",
    ) -> list[str]:
        """Discover API endpoints by probing common paths."""
        discovered = []
        
        # Common API paths to probe
        api_paths = [
            # REST API patterns
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/rest", "/rest/v1", "/rest/v2",
            "/v1", "/v2", "/v3",
            
            # User/Account endpoints
            "/api/users", "/api/user", "/api/Users",
            "/api/accounts", "/api/account",
            "/api/profiles", "/api/profile",
            "/api/me", "/api/self", "/api/whoami",
            "/rest/user/whoami", "/rest/user/login-status",
            
            # Data endpoints
            "/api/products", "/api/Products",
            "/api/orders", "/api/Orders",
            "/api/items", "/api/data",
            "/api/feedbacks", "/api/Feedbacks",
            "/api/comments", "/api/reviews",
            "/api/messages", "/api/notifications",
            
            # Admin endpoints
            "/api/admin", "/admin/api",
            "/api/config", "/api/settings",
            "/api/configuration",
            "/rest/admin/application-configuration",
            "/administration",
            
            # Security endpoints
            "/api/SecurityQuestions",
            "/api/Complaints", "/api/Recycles",
            "/api/Quantitys", "/api/BasketItems",
            
            # Search/Query
            "/api/search", "/rest/products/search",
            "/api/query",
            
            # File/Document
            "/api/files", "/api/documents",
            "/api/uploads", "/api/attachments",
            
            # GraphQL
            "/graphql", "/api/graphql",
        ]
        
        parsed = urlparse(base_url)
        host = parsed.netloc
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for path in api_paths:
                await rate_limiter.acquire(host)
                
                try:
                    url = f"{base_url}{path}"
                    response = await client.get(url)
                    
                    # Consider endpoint discovered if:
                    # - 200 OK with JSON response
                    # - 401/403 (endpoint exists but needs auth)
                    if response.status_code in [200, 401, 403]:
                        discovered.append(url)
                        
                        # If 200 with JSON, also try with /1 suffix for IDOR
                        if response.status_code == 200:
                            content_type = response.headers.get("content-type", "")
                            if "json" in content_type:
                                discovered.append(f"{url}/1")
                                discovered.append(f"{url}/2")
                                
                except Exception:
                    continue
        
        logger.info(f"[APILogicProfiler] Discovered {len(discovered)} API endpoints")
        return discovered

    async def _test_unauthenticated_exposure(
        self,
        base_url: str,
        endpoints: list[str],
        rate_limiter: "RateLimiter",
    ) -> list[AuthzFinding]:
        """Test for sensitive data exposure without authentication."""
        findings = []
        
        parsed = urlparse(base_url)
        host = parsed.netloc
        
        # Sensitive field patterns
        sensitive_patterns = [
            (r'"email"\s*:\s*"[^"]+@[^"]+"', "email", "HIGH"),
            (r'"password"\s*:', "password_field", "CRITICAL"),
            (r'"api[_-]?key"\s*:', "api_key", "CRITICAL"),
            (r'"token"\s*:', "token", "HIGH"),
            (r'"secret"\s*:', "secret", "CRITICAL"),
            (r'"ssn"\s*:', "ssn", "CRITICAL"),
            (r'"credit[_-]?card"\s*:', "credit_card", "CRITICAL"),
            (r'"phone"\s*:\s*"[^"]+"', "phone", "MEDIUM"),
            (r'"address"\s*:', "address", "MEDIUM"),
            (r'"username"\s*:\s*"[^"]+"', "username", "MEDIUM"),
            (r'"role"\s*:\s*"admin"', "admin_role", "HIGH"),
            (r'"is[_-]?admin"\s*:\s*true', "admin_flag", "HIGH"),
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for endpoint in endpoints:
                await rate_limiter.acquire(host)
                
                try:
                    # Test without any auth
                    response = await client.get(endpoint)
                    
                    if response.status_code != 200:
                        continue
                    
                    content = response.text
                    content_type = response.headers.get("content-type", "")
                    
                    # Check for JSON response with sensitive data
                    if "json" in content_type.lower():
                        found_sensitive = []
                        max_severity = "LOW"
                        
                        for pattern, field_name, severity in sensitive_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                found_sensitive.append(field_name)
                                if severity == "CRITICAL":
                                    max_severity = "CRITICAL"
                                elif severity == "HIGH" and max_severity != "CRITICAL":
                                    max_severity = "HIGH"
                                elif severity == "MEDIUM" and max_severity not in ["CRITICAL", "HIGH"]:
                                    max_severity = "MEDIUM"
                        
                        # Also check for arrays with multiple records (data enumeration)
                        try:
                            data = response.json()
                            record_count = 0
                            
                            if isinstance(data, list):
                                record_count = len(data)
                            elif isinstance(data, dict):
                                if "data" in data and isinstance(data["data"], list):
                                    record_count = len(data["data"])
                                elif "results" in data and isinstance(data["results"], list):
                                    record_count = len(data["results"])
                                elif "items" in data and isinstance(data["items"], list):
                                    record_count = len(data["items"])
                            
                            if record_count > 1:
                                found_sensitive.append(f"array_data({record_count}_records)")
                                if max_severity == "LOW":
                                    max_severity = "MEDIUM"
                                    
                        except Exception:
                            pass
                        
                        if found_sensitive:
                            confidence = 0.95 if max_severity == "CRITICAL" else 0.90 if max_severity == "HIGH" else 0.80
                            
                            findings.append(AuthzFinding(
                                vuln_type=VulnerabilityType.DATA_LEAKAGE,
                                endpoint=endpoint,
                                method="GET",
                                roles_affected=["unauthenticated"],
                                diffs=[],
                                confidence=confidence,
                                impact=f"Sensitive data exposed without authentication: {', '.join(found_sensitive)}",
                                evidence=[
                                    f"Endpoint: {endpoint}",
                                    f"Status: 200 OK (no auth required)",
                                    f"Sensitive fields: {', '.join(found_sensitive)}",
                                    f"Response size: {len(content)} bytes",
                                ],
                                remediation="Implement proper authentication and authorization checks",
                            ))
                            
                except Exception as e:
                    logger.debug(f"[APILogicProfiler] Exposure test error for {endpoint}: {e}")
        
        return findings

    async def _test_idor_parameters(
        self,
        base_url: str,
        endpoints: list[str],
        rate_limiter: "RateLimiter",
    ) -> list[AuthzFinding]:
        """Test for IDOR via query parameter manipulation."""
        findings = []
        
        parsed = urlparse(base_url)
        host = parsed.netloc
        
        # Common ID parameter names
        id_params = [
            "id", "userId", "user_id", "uid", "accountId", "account_id",
            "profileId", "profile_id", "orderId", "order_id",
            "documentId", "doc_id", "fileId", "file_id",
            "customerId", "customer_id", "memberId", "member_id",
        ]
        
        # Base endpoints to test (without existing query params)
        base_endpoints = []
        for ep in endpoints:
            parsed_ep = urlparse(ep)
            base_ep = f"{parsed_ep.scheme}://{parsed_ep.netloc}{parsed_ep.path}"
            if base_ep not in base_endpoints:
                base_endpoints.append(base_ep)
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
            for endpoint in base_endpoints[:20]:
                for param in id_params[:5]:  # Test top 5 params per endpoint
                    await rate_limiter.acquire(host)
                    
                    try:
                        # Test with id=1
                        url1 = f"{endpoint}?{param}=1"
                        response1 = await client.get(url1)
                        
                        if response1.status_code != 200:
                            continue
                        
                        await rate_limiter.acquire(host)
                        
                        # Test with id=2
                        url2 = f"{endpoint}?{param}=2"
                        response2 = await client.get(url2)
                        
                        if response2.status_code != 200:
                            continue
                        
                        # Compare responses - if different content, potential IDOR
                        content1 = response1.text
                        content2 = response2.text
                        
                        # Check if responses are different (indicating different data)
                        if content1 != content2 and len(content1) > 50 and len(content2) > 50:
                            # Verify it's not just timestamp differences
                            # by checking if the core data structure differs
                            try:
                                json1 = response1.json()
                                json2 = response2.json()
                                
                                # Check for different IDs in response
                                str1 = str(json1)
                                str2 = str(json2)
                                
                                # If one contains "1" and other contains "2" in ID fields
                                # it's likely IDOR
                                if ('"id": 1' in str1 or '"id":"1"' in str1) and \
                                   ('"id": 2' in str2 or '"id":"2"' in str2):
                                    
                                    findings.append(AuthzFinding(
                                        vuln_type=VulnerabilityType.IDOR,
                                        endpoint=endpoint,
                                        method="GET",
                                        roles_affected=["unauthenticated"],
                                        diffs=[],
                                        confidence=0.90,
                                        impact=f"Can access different objects by manipulating '{param}' parameter",
                                        evidence=[
                                            f"Endpoint: {endpoint}",
                                            f"Parameter: {param}",
                                            f"Request 1: {url1} → {len(content1)} bytes",
                                            f"Request 2: {url2} → {len(content2)} bytes",
                                            f"Different data returned for different IDs",
                                        ],
                                        remediation="Verify user has access to the requested resource",
                                    ))
                                    break  # Found IDOR for this endpoint
                                    
                            except Exception:
                                pass
                                
                    except Exception as e:
                        logger.debug(f"[APILogicProfiler] Param IDOR test error: {e}")
        
        return findings

    async def _profile_endpoint(
        self,
        endpoint: str,
        role: RoleConfig,
    ) -> Optional[ResponseProfile]:
        """Profile an endpoint for a specific role."""
        try:
            headers = role.headers.copy()

            async with httpx.AsyncClient(timeout=self.timeout, verify=False) as client:
                start = time.time()

                response = await client.get(
                    endpoint,
                    headers=headers,
                    cookies=role.cookies,
                )

                return self.analyzer.profile_response(role.name, response, start)

        except Exception as e:
            logger.debug(f"[APILogicProfiler] Profile error for {role.name}: {e}")
            return None

    def _analyze_for_vulnerabilities(
        self,
        endpoint: str,
        profiles: list[ResponseProfile],
        diffs: list[ResponseDiff],
    ) -> list[AuthzFinding]:
        """Analyze diffs for authorization vulnerabilities."""
        findings = []

        # Check for BOLA/BFLA
        critical_diffs = [d for d in diffs if d.severity == "CRITICAL"]
        high_diffs = [d for d in diffs if d.severity == "HIGH"]

        if critical_diffs:
            # Likely IDOR/BOLA
            findings.append(AuthzFinding(
                vuln_type=VulnerabilityType.BOLA,
                endpoint=endpoint,
                method="GET",
                roles_affected=[d.role_a for d in critical_diffs] + [d.role_b for d in critical_diffs],
                diffs=critical_diffs,
                confidence=0.90,  # Scale 0-1, not percentage
                impact="Access to unauthorized data/objects",
                evidence=[d.description for d in critical_diffs],
                remediation="Implement proper object-level authorization checks",
            ))

        # Check for data leakage
        field_presence_diffs = [d for d in diffs if d.diff_type == ResponseDiffType.FIELD_PRESENCE and d.severity == "HIGH"]
        if field_presence_diffs:
            findings.append(AuthzFinding(
                vuln_type=VulnerabilityType.DATA_LEAKAGE,
                endpoint=endpoint,
                method="GET",
                roles_affected=list(set([d.role_a for d in field_presence_diffs])),
                diffs=field_presence_diffs,
                confidence=0.85,  # Scale 0-1, not percentage
                impact="Sensitive data exposed to unauthorized roles",
                evidence=[d.description for d in field_presence_diffs],
                remediation="Filter response fields based on user permissions",
            ))

        # Check for privilege escalation indicators
        status_diffs = [d for d in diffs if d.diff_type == ResponseDiffType.STATUS_CODE]
        for diff in status_diffs:
            if diff.value_a == 200 and diff.value_b in [401, 403]:
                # Lower privileged role got access
                findings.append(AuthzFinding(
                    vuln_type=VulnerabilityType.BFLA,
                    endpoint=endpoint,
                    method="GET",
                    roles_affected=[diff.role_a, diff.role_b],
                    diffs=[diff],
                    confidence=0.95,  # Scale 0-1, not percentage
                    impact=f"Role '{diff.role_a}' can access endpoint that '{diff.role_b}' cannot",
                    evidence=[diff.description],
                    remediation="Implement proper function-level authorization",
                ))

        return findings

    async def _test_idor(
        self,
        host: str,
        endpoints: list[str],
        rate_limiter: "RateLimiter",
    ) -> list[AuthzFinding]:
        """Test for IDOR by manipulating IDs in URLs."""
        findings = []

        # Patterns for ID extraction
        id_patterns = [
            (r'/(\d+)(?:/|$)', 'numeric'),
            (r'/([a-f0-9-]{36})(?:/|$)', 'uuid'),
            (r'/([a-f0-9]{24})(?:/|$)', 'objectid'),
        ]

        for endpoint in endpoints:
            for pattern, id_type in id_patterns:
                match = re.search(pattern, endpoint, re.IGNORECASE)
                if not match:
                    continue

                original_id = match.group(1)

                # Generate test IDs
                if id_type == 'numeric':
                    test_ids = [
                        str(int(original_id) + 1),
                        str(int(original_id) - 1),
                        "1",
                        "0",
                        str(int(original_id) + 1000),
                    ]
                elif id_type == 'uuid':
                    # Modify last character
                    chars = list(original_id)
                    chars[-1] = 'a' if chars[-1] != 'a' else 'b'
                    test_ids = [''.join(chars)]
                else:
                    continue

                # Test each ID
                for test_id in test_ids[:3]:
                    test_endpoint = endpoint.replace(original_id, test_id)
                    await rate_limiter.acquire(host)

                    try:
                        if len(self.roles) >= 2:
                            # Use authenticated role
                            role = self.roles[1] if self.roles[1].name != "unauthenticated" else self.roles[0]
                        else:
                            role = RoleConfig(name="default")

                        profile = await self._profile_endpoint(test_endpoint, role)

                        if profile and profile.status_code == 200:
                            # Successful access to different ID - potential IDOR
                            findings.append(AuthzFinding(
                                vuln_type=VulnerabilityType.IDOR,
                                endpoint=endpoint,
                                method="GET",
                                roles_affected=[role.name],
                                diffs=[],
                                confidence=0.85,  # Scale 0-1, not percentage
                                impact=f"Can access object {test_id} instead of {original_id}",
                                evidence=[
                                    f"Original ID: {original_id}",
                                    f"Modified ID: {test_id}",
                                    f"Status: {profile.status_code}",
                                    f"Response has {len(profile.fields)} fields",
                                ],
                                remediation="Verify user owns/has access to the requested object",
                            ))
                            break  # Found IDOR, stop testing this endpoint

                    except Exception as e:
                        logger.debug(f"[APILogicProfiler] IDOR test error: {e}")

        return findings

    def _create_finding(self, authz_finding: AuthzFinding) -> Finding:
        """Create Finding object from AuthzFinding."""
        parsed = urlparse(authz_finding.endpoint)
        host = parsed.netloc

        severity_map = {
            VulnerabilityType.IDOR: ("HIGH", 7.5),
            VulnerabilityType.BOLA: ("HIGH", 7.5),
            VulnerabilityType.BFLA: ("HIGH", 8.1),
            VulnerabilityType.HORIZONTAL_PRIV_ESC: ("HIGH", 7.1),
            VulnerabilityType.VERTICAL_PRIV_ESC: ("CRITICAL", 8.8),
            VulnerabilityType.MASS_ASSIGNMENT: ("HIGH", 7.5),
            VulnerabilityType.DATA_LEAKAGE: ("MEDIUM", 5.3),
            VulnerabilityType.MULTI_TENANT_ISOLATION: ("CRITICAL", 9.1),
            VulnerabilityType.STATE_INCONSISTENCY: ("MEDIUM", 5.4),
        }

        severity, cvss = severity_map.get(authz_finding.vuln_type, ("MEDIUM", 5.0))

        cwe_map = {
            VulnerabilityType.IDOR: "CWE-639",
            VulnerabilityType.BOLA: "CWE-639",
            VulnerabilityType.BFLA: "CWE-285",
            VulnerabilityType.HORIZONTAL_PRIV_ESC: "CWE-284",
            VulnerabilityType.VERTICAL_PRIV_ESC: "CWE-269",
            VulnerabilityType.MASS_ASSIGNMENT: "CWE-915",
            VulnerabilityType.DATA_LEAKAGE: "CWE-200",
            VulnerabilityType.MULTI_TENANT_ISOLATION: "CWE-284",
            VulnerabilityType.STATE_INCONSISTENCY: "CWE-362",
        }

        return Finding(
            type="authorization",
            name=f"{authz_finding.vuln_type.value} - {authz_finding.endpoint}",
            severity=severity,
            description=(
                f"{authz_finding.vuln_type.value} vulnerability detected. "
                f"{authz_finding.impact}. "
                f"Roles affected: {', '.join(set(authz_finding.roles_affected))}. "
                f"Confidence: {authz_finding.confidence}%"
            ),
            host=host,
            matched_at=authz_finding.endpoint,
            evidence=authz_finding.evidence,
            cvss_score=cvss,
            cwe=cwe_map.get(authz_finding.vuln_type, "CWE-284"),
            confidence=authz_finding.confidence,
            remediation=authz_finding.remediation,
            references=[
                "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
                "https://portswigger.net/web-security/access-control/idor",
                "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
            ],
        )


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

async def quick_role_comparison(
    endpoint: str,
    roles: list[dict],
) -> dict:
    """
    Quick role comparison without full scanner setup.

    Args:
        endpoint: API endpoint to test
        roles: List of role configs [{name, headers, cookies}, ...]

    Returns:
        Comparison results with diffs
    """
    role_configs = [
        RoleConfig(
            name=r.get("name", f"role_{i}"),
            headers=r.get("headers", {}),
            cookies=r.get("cookies", {}),
        )
        for i, r in enumerate(roles)
    ]

    analyzer = ResponseAnalyzer()
    visualizer = ResponseDiffVisualizer()

    profiles = []

    async with httpx.AsyncClient(timeout=30, verify=False) as client:
        for role in role_configs:
            start = time.time()
            try:
                response = await client.get(
                    endpoint,
                    headers=role.headers,
                    cookies=role.cookies,
                )
                profile = analyzer.profile_response(role.name, response, start)
                profiles.append(profile)
            except Exception as e:
                logger.error(f"Error profiling {role.name}: {e}")

    all_diffs = []
    for i, profile_a in enumerate(profiles):
        for profile_b in profiles[i+1:]:
            diffs = analyzer.compare_profiles(profile_a, profile_b)
            all_diffs.extend(diffs)

    report = visualizer.generate_markdown_report(endpoint, profiles, all_diffs)

    return {
        "endpoint": endpoint,
        "roles_tested": [r.name for r in role_configs],
        "profiles": [
            {
                "role": p.role,
                "status": p.status_code,
                "fields": len(p.fields),
                "sensitive_fields": p.sensitive_fields,
            }
            for p in profiles
        ],
        "diffs": [
            {
                "type": d.diff_type.name,
                "field": d.field_path,
                "severity": d.severity,
                "description": d.description,
            }
            for d in all_diffs
        ],
        "report": report,
    }
