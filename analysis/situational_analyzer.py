"""
Situational Analyzer
=====================

AI-driven situational analysis that understands the CONTEXT of each target
and makes intelligent decisions based on:

1. Target Profile - What kind of target is this?
2. Security Posture - How hardened is it?
3. Attack Surface - What's exposed?
4. Risk Assessment - What's worth pursuing?
5. Strategy Selection - Best approach for THIS situation

This is like having an expert pentester's intuition in code.

Author: canigetrichpls
"""

import asyncio
import re
import json
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs
import structlog

logger = structlog.get_logger(__name__)


# =============================================================================
# TARGET PROFILE MODELS
# =============================================================================

class TargetType(Enum):
    """What kind of target are we dealing with?"""
    API_SERVICE = auto()          # REST/GraphQL API
    WEB_APPLICATION = auto()      # Traditional web app
    SPA_APPLICATION = auto()      # Single Page Application
    MOBILE_BACKEND = auto()       # Mobile app backend
    AUTHENTICATION = auto()       # Auth/login system
    FILE_STORAGE = auto()         # File upload/download
    E_COMMERCE = auto()           # Shopping/payments
    ADMIN_PANEL = auto()          # Administrative interface
    DOCUMENTATION = auto()        # Docs/help pages
    UNKNOWN = auto()


class SecurityLevel(Enum):
    """How hardened is the target?"""
    HARDENED = auto()     # WAF, rate limiting, strong CSP
    MODERATE = auto()     # Some protections
    WEAK = auto()         # Minimal protections
    UNKNOWN = auto()


class AttackStrategy(Enum):
    """What approach should we take?"""
    AGGRESSIVE = auto()        # Fast, many payloads
    SURGICAL = auto()          # Targeted, specific
    STEALTHY = auto()          # Slow, avoid detection
    EXPLORATORY = auto()       # Discovery-focused
    CHAIN_BASED = auto()       # Combine low-severity findings


@dataclass
class TargetProfile:
    """Complete profile of a target."""
    url: str
    type: TargetType = TargetType.UNKNOWN
    security_level: SecurityLevel = SecurityLevel.UNKNOWN
    recommended_strategy: AttackStrategy = AttackStrategy.EXPLORATORY
    
    # Technical details
    tech_stack: str = ""
    framework: str = ""
    hosting: str = ""
    cdn_waf: str = ""
    
    # Features detected
    has_auth: bool = False
    has_file_upload: bool = False
    has_api: bool = False
    has_user_input: bool = False
    has_sensitive_data: bool = False
    
    # Security features
    has_csp: bool = False
    has_cors: bool = False
    has_rate_limit: bool = False
    has_waf: bool = False
    
    # Attack surface
    exposed_endpoints: List[str] = field(default_factory=list)
    input_parameters: List[str] = field(default_factory=list)
    interesting_headers: Dict[str, str] = field(default_factory=dict)
    
    # Risk assessment
    high_value_targets: List[str] = field(default_factory=list)
    vulnerability_indicators: List[str] = field(default_factory=list)


@dataclass
class SituationalAssessment:
    """Assessment of the current situation."""
    profile: TargetProfile
    threats: List[str] = field(default_factory=list)
    opportunities: List[str] = field(default_factory=list)
    recommended_actions: List[dict] = field(default_factory=list)
    priority_order: List[str] = field(default_factory=list)
    estimated_success_rate: float = 0.0


# =============================================================================
# INTELLIGENCE PATTERNS
# =============================================================================

# URL patterns that indicate target type
URL_PATTERNS = {
    TargetType.API_SERVICE: [
        r"/api/", r"/v\d+/", r"/graphql", r"/rest/",
        r"/swagger", r"/openapi", r"api\.", r"-api\.",
    ],
    TargetType.AUTHENTICATION: [
        r"/login", r"/auth", r"/oauth", r"/sso",
        r"/signin", r"/signup", r"/register", r"/token",
    ],
    TargetType.ADMIN_PANEL: [
        r"/admin", r"/dashboard", r"/manage", r"/cms",
        r"/control", r"/panel", r"/console",
    ],
    TargetType.FILE_STORAGE: [
        r"/upload", r"/files", r"/media", r"/assets",
        r"/download", r"/storage", r"/blob",
    ],
    TargetType.E_COMMERCE: [
        r"/cart", r"/checkout", r"/payment", r"/order",
        r"/product", r"/shop", r"/store",
    ],
    TargetType.DOCUMENTATION: [
        r"/docs", r"/help", r"/faq", r"/support",
        r"/guide", r"/manual",
    ],
}

# Headers that reveal information
REVEALING_HEADERS = {
    "server": "tech_stack",
    "x-powered-by": "tech_stack",
    "x-aspnet-version": "framework:aspnet",
    "x-aspnetmvc-version": "framework:aspnet_mvc",
    "x-drupal-cache": "framework:drupal",
    "x-generator": "framework",
    "x-shopify-stage": "platform:shopify",
    "cf-ray": "cdn:cloudflare",
    "x-amz-cf-id": "cdn:cloudfront",
    "x-akamai-transformed": "cdn:akamai",
    "x-cache": "cdn",
    "via": "proxy",
}

# Error patterns that indicate vulnerabilities
ERROR_PATTERNS = {
    # SQL Injection indicators
    r"mysql|mariadb": ("sqli", "mysql", 9),
    r"postgres": ("sqli", "postgresql", 9),
    r"sqlite": ("sqli", "sqlite", 8),
    r"ora-\d+|oracle": ("sqli", "oracle", 9),
    r"mssql|sql server": ("sqli", "mssql", 9),
    
    # NoSQL indicators
    r"mongodb|bson": ("nosqli", "mongodb", 8),
    r"redis": ("nosqli", "redis", 7),
    
    # Path traversal indicators
    r"no such file|cannot find|not found.*path": ("path_traversal", None, 7),
    r"failed to open stream": ("path_traversal", "php", 8),
    
    # Information disclosure
    r"stack trace|at line \d+": ("info_leak", None, 6),
    r"debug|traceback": ("info_leak", None, 5),
    r"exception|error occurred": ("info_leak", None, 4),
    
    # SSTI indicators
    r"\$\{|\{\{|\{%": ("ssti", None, 8),
}

# Parameter names that indicate vulnerability type
PARAM_VULNERABILITY_MAP = {
    # IDOR candidates
    "id": ("idor", 8),
    "user_id": ("idor", 9),
    "account": ("idor", 9),
    "uid": ("idor", 8),
    "profile": ("idor", 7),
    "order_id": ("idor", 8),
    
    # XSS candidates
    "search": ("xss", 9),
    "q": ("xss", 8),
    "query": ("xss", 8),
    "keyword": ("xss", 8),
    "name": ("xss", 7),
    "message": ("xss", 8),
    "comment": ("xss", 8),
    "title": ("xss", 7),
    
    # SQLi candidates
    "sort": ("sqli", 7),
    "order": ("sqli", 7),
    "filter": ("sqli", 7),
    "category": ("sqli", 6),
    
    # SSRF candidates
    "url": ("ssrf", 9),
    "link": ("ssrf", 8),
    "src": ("ssrf", 7),
    "dest": ("ssrf", 7),
    "uri": ("ssrf", 8),
    "path": ("ssrf", 7),
    "domain": ("ssrf", 8),
    "host": ("ssrf", 8),
    "site": ("ssrf", 7),
    "fetch": ("ssrf", 8),
    "callback": ("ssrf", 8),
    
    # Open redirect
    "redirect": ("open_redirect", 9),
    "return": ("open_redirect", 8),
    "next": ("open_redirect", 8),
    "target": ("open_redirect", 7),
    "redir": ("open_redirect", 8),
    "returnTo": ("open_redirect", 9),
    "continue": ("open_redirect", 7),
    
    # File inclusion
    "file": ("lfi", 9),
    "page": ("lfi", 8),
    "template": ("lfi", 8),
    "include": ("lfi", 9),
    "doc": ("lfi", 7),
    "document": ("lfi", 7),
}


# =============================================================================
# SITUATIONAL ANALYZER
# =============================================================================

class SituationalAnalyzer:
    """
    Analyzes the situation and makes intelligent strategic decisions.
    
    This is the "strategic mind" that:
    1. Profiles the target to understand what we're dealing with
    2. Assesses security posture to know our constraints
    3. Identifies opportunities based on the specific situation
    4. Recommends the best strategy for THIS target
    5. Prioritizes actions based on likelihood of success
    """
    
    def __init__(self, http_client=None, rate_limiter=None):
        self.http_client = http_client
        self.rate_limiter = rate_limiter
        self.profile = None
    
    async def analyze(
        self,
        target_url: str,
        initial_findings: List[dict] = None,
    ) -> SituationalAssessment:
        """
        Perform complete situational analysis.
        """
        logger.info(f"[Situational] Analyzing: {target_url}")
        
        # Create initial profile
        self.profile = TargetProfile(url=target_url)
        
        # Phase 1: URL Analysis
        self._analyze_url(target_url)
        
        # Phase 2: Active Reconnaissance
        if self.http_client:
            await self._active_recon()
        
        # Phase 3: Finding Analysis
        if initial_findings:
            self._analyze_findings(initial_findings)
        
        # Phase 4: Strategy Selection
        self._select_strategy()
        
        # Phase 5: Generate Assessment
        assessment = self._generate_assessment()
        
        logger.info(
            f"[Situational] Profile: {self.profile.type.name}, "
            f"Security: {self.profile.security_level.name}, "
            f"Strategy: {self.profile.recommended_strategy.name}"
        )
        
        return assessment
    
    # =========================================================================
    # PHASE 1: URL ANALYSIS
    # =========================================================================
    
    def _analyze_url(self, url: str):
        """Extract intelligence from URL structure."""
        parsed = urlparse(url)
        url_lower = url.lower()
        
        # Determine target type from URL patterns
        for target_type, patterns in URL_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, url_lower, re.I):
                    self.profile.type = target_type
                    logger.info(f"[Situational] Target type from URL: {target_type.name}")
                    break
            if self.profile.type != TargetType.UNKNOWN:
                break
        
        # Extract query parameters for analysis
        params = parse_qs(parsed.query)
        for param in params:
            self.profile.input_parameters.append(param)
            
            # Check if parameter suggests vulnerability
            param_lower = param.lower()
            for vuln_param, (vuln_type, priority) in PARAM_VULNERABILITY_MAP.items():
                if vuln_param in param_lower:
                    self.profile.vulnerability_indicators.append(
                        f"{vuln_type}:{param} (priority: {priority})"
                    )
        
        # Analyze path for sensitive endpoints
        path_parts = parsed.path.split("/")
        for part in path_parts:
            if any(s in part.lower() for s in ["admin", "internal", "private", "api"]):
                self.profile.high_value_targets.append(parsed.path)
                break
    
    # =========================================================================
    # PHASE 2: ACTIVE RECONNAISSANCE
    # =========================================================================
    
    async def _active_recon(self):
        """Perform active reconnaissance."""
        try:
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            
            response = await self.http_client.get(self.profile.url)
            
            # Analyze headers
            self._analyze_headers(dict(response.headers))
            
            # Analyze response body
            self._analyze_body(response.text)
            
            # Probe for additional information
            await self._probe_security_features()
            
        except Exception as e:
            logger.error(f"[Situational] Recon error: {e}")
    
    def _analyze_headers(self, headers: dict):
        """Extract intelligence from response headers."""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header, info_type in REVEALING_HEADERS.items():
            if header in headers_lower:
                value = headers_lower[header]
                self.profile.interesting_headers[header] = value
                
                if ":" in info_type:
                    key, val = info_type.split(":")
                    if key == "framework":
                        self.profile.framework = val
                    elif key == "cdn":
                        self.profile.cdn_waf = val
                elif info_type == "tech_stack":
                    self.profile.tech_stack = value
        
        # Security headers analysis
        self.profile.has_csp = "content-security-policy" in headers_lower
        
        # CORS analysis
        self.profile.has_cors = "access-control-allow-origin" in headers_lower
        
        # Check for security headers
        security_headers = [
            "x-frame-options",
            "x-content-type-options",
            "x-xss-protection",
            "strict-transport-security",
        ]
        
        present_headers = sum(1 for h in security_headers if h in headers_lower)
        
        if present_headers >= 4:
            self.profile.security_level = SecurityLevel.HARDENED
        elif present_headers >= 2:
            self.profile.security_level = SecurityLevel.MODERATE
        else:
            self.profile.security_level = SecurityLevel.WEAK
    
    def _analyze_body(self, body: str):
        """Extract intelligence from response body."""
        body_lower = body.lower()
        
        # Detect if SPA
        if any(s in body_lower for s in ["react", "angular", "vue", "webpack", "bundle.js"]):
            if self.profile.type == TargetType.UNKNOWN:
                self.profile.type = TargetType.SPA_APPLICATION
        
        # Detect authentication features
        if any(s in body_lower for s in ["login", "sign in", "password", "authenticate"]):
            self.profile.has_auth = True
        
        # Detect file upload
        if any(s in body_lower for s in ['type="file"', "upload", "multipart"]):
            self.profile.has_file_upload = True
        
        # Detect user input
        if any(s in body_lower for s in ["<input", "<textarea", "<form"]):
            self.profile.has_user_input = True
        
        # Check for sensitive data patterns
        sensitive_patterns = [
            r"api[_-]?key", r"token", r"secret", r"password",
            r"credit.?card", r"ssn", r"social.?security",
        ]
        for pattern in sensitive_patterns:
            if re.search(pattern, body_lower, re.I):
                self.profile.has_sensitive_data = True
                break
        
        # Look for error messages
        for pattern, (vuln_type, tech, priority) in ERROR_PATTERNS.items():
            if re.search(pattern, body_lower, re.I):
                self.profile.vulnerability_indicators.append(
                    f"{vuln_type}:{tech or 'detected'} (priority: {priority})"
                )
    
    async def _probe_security_features(self):
        """Probe for security features."""
        # Test for WAF
        try:
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            
            response = await self.http_client.get(
                f"{self.profile.url}?test=<script>alert(1)</script>"
            )
            
            if response.status_code in [403, 406, 429]:
                self.profile.has_waf = True
                self.profile.security_level = SecurityLevel.HARDENED
                
        except Exception:
            pass
        
        # Test for rate limiting
        try:
            for _ in range(5):
                if self.rate_limiter:
                    await self.rate_limiter.acquire()
                response = await self.http_client.get(self.profile.url)
                if response.status_code == 429:
                    self.profile.has_rate_limit = True
                    break
        except Exception:
            pass
    
    # =========================================================================
    # PHASE 3: FINDING ANALYSIS
    # =========================================================================
    
    def _analyze_findings(self, findings: List[dict]):
        """Analyze initial findings for opportunities."""
        for finding in findings:
            finding_type = finding.get("type", "").lower()
            finding_name = finding.get("name", "").lower()
            severity = finding.get("severity", "").lower()
            evidence = finding.get("evidence", [])
            
            # Extract intelligence from findings
            if "endpoint" in finding_type or "api" in finding_type:
                for item in evidence:
                    if isinstance(item, str) and "/" in item:
                        self.profile.exposed_endpoints.append(item)
            
            # Identify missing protections
            if "missing" in finding_type:
                if "csp" in finding_name:
                    self.profile.has_csp = False
                if "x-frame" in finding_name:
                    self.profile.vulnerability_indicators.append("clickjacking:possible (priority: 7)")
            
            # Identify opportunities from severity
            if severity in ["high", "critical"]:
                self.profile.high_value_targets.append(f"{finding_name}: {finding_type}")
    
    # =========================================================================
    # PHASE 4: STRATEGY SELECTION
    # =========================================================================
    
    def _select_strategy(self):
        """Select the best attack strategy for this situation."""
        p = self.profile
        
        # Decision tree for strategy selection
        
        # If hardened, go stealthy
        if p.security_level == SecurityLevel.HARDENED:
            if p.has_waf:
                self.profile.recommended_strategy = AttackStrategy.STEALTHY
            else:
                self.profile.recommended_strategy = AttackStrategy.SURGICAL
        
        # If many vulnerabilities indicated, be aggressive
        elif len(p.vulnerability_indicators) > 3:
            self.profile.recommended_strategy = AttackStrategy.AGGRESSIVE
        
        # If only low-severity findings, try chaining
        elif p.vulnerability_indicators and all("priority: 5" in v or "priority: 4" in v 
                                                 for v in p.vulnerability_indicators):
            self.profile.recommended_strategy = AttackStrategy.CHAIN_BASED
        
        # If API, be surgical
        elif p.type == TargetType.API_SERVICE:
            self.profile.recommended_strategy = AttackStrategy.SURGICAL
        
        # If auth system, be surgical
        elif p.type == TargetType.AUTHENTICATION:
            self.profile.recommended_strategy = AttackStrategy.SURGICAL
        
        # Default to exploratory
        else:
            self.profile.recommended_strategy = AttackStrategy.EXPLORATORY
        
        logger.info(f"[Situational] Strategy selected: {p.recommended_strategy.name}")
    
    # =========================================================================
    # PHASE 5: ASSESSMENT GENERATION
    # =========================================================================
    
    def _generate_assessment(self) -> SituationalAssessment:
        """Generate complete situational assessment."""
        assessment = SituationalAssessment(profile=self.profile)
        
        # Identify threats (what could block us)
        assessment.threats = self._identify_threats()
        
        # Identify opportunities (what we can exploit)
        assessment.opportunities = self._identify_opportunities()
        
        # Generate recommended actions
        assessment.recommended_actions = self._generate_recommendations()
        
        # Prioritize actions
        assessment.priority_order = self._prioritize_actions(assessment.recommended_actions)
        
        # Estimate success rate
        assessment.estimated_success_rate = self._estimate_success_rate()
        
        return assessment
    
    def _identify_threats(self) -> List[str]:
        """Identify what could block our attacks."""
        threats = []
        
        if self.profile.has_waf:
            threats.append("WAF detected - payloads may be blocked")
        
        if self.profile.has_rate_limit:
            threats.append("Rate limiting - need to slow down")
        
        if self.profile.has_csp:
            threats.append("CSP present - XSS execution may be limited")
        
        if self.profile.security_level == SecurityLevel.HARDENED:
            threats.append("Hardened target - expect sophisticated protections")
        
        return threats
    
    def _identify_opportunities(self) -> List[str]:
        """Identify exploitation opportunities."""
        opportunities = []
        
        if not self.profile.has_csp:
            opportunities.append("No CSP - XSS payloads will execute without browser blocking")
        
        if self.profile.security_level == SecurityLevel.WEAK:
            opportunities.append("Weak security posture - multiple attack vectors likely viable")
        
        if self.profile.has_auth:
            opportunities.append("Authentication system - test for auth bypass, IDOR")
        
        if self.profile.has_file_upload:
            opportunities.append("File upload - test for unrestricted upload, path traversal")
        
        if self.profile.has_user_input:
            opportunities.append("User input - test for injection vulnerabilities")
        
        if self.profile.type == TargetType.API_SERVICE:
            opportunities.append("API service - test for BOLA, mass assignment, rate limiting bypass")
        
        for indicator in self.profile.vulnerability_indicators:
            if "priority: 9" in indicator or "priority: 8" in indicator:
                opportunities.append(f"High-priority indicator: {indicator}")
        
        return opportunities
    
    def _generate_recommendations(self) -> List[dict]:
        """Generate specific recommended actions."""
        actions = []
        
        # Based on target type
        if self.profile.type == TargetType.API_SERVICE:
            actions.extend([
                {
                    "action": "api_auth_test",
                    "description": "Test API authentication and authorization",
                    "priority": 9,
                    "techniques": ["JWT manipulation", "BOLA", "rate limit bypass"],
                },
                {
                    "action": "api_injection",
                    "description": "Test for injection in API parameters",
                    "priority": 8,
                    "techniques": ["SQLi", "NoSQLi", "Command injection"],
                },
            ])
        
        if self.profile.type == TargetType.AUTHENTICATION:
            actions.extend([
                {
                    "action": "auth_bypass",
                    "description": "Test authentication bypass techniques",
                    "priority": 10,
                    "techniques": ["Response manipulation", "Default creds", "SQL bypass"],
                },
                {
                    "action": "password_policy",
                    "description": "Test password policy and brute force protection",
                    "priority": 7,
                    "techniques": ["Rate limiting", "Account lockout", "Complexity"],
                },
            ])
        
        # Based on vulnerability indicators
        for indicator in self.profile.vulnerability_indicators:
            parts = indicator.split(":")
            if len(parts) >= 2:
                vuln_type = parts[0]
                
                if vuln_type == "xss" and not any(a["action"] == "xss_test" for a in actions):
                    actions.append({
                        "action": "xss_test",
                        "description": "Test for XSS vulnerabilities",
                        "priority": 9,
                        "techniques": ["Reflected XSS", "DOM XSS", "Stored XSS"],
                    })
                
                if vuln_type == "sqli" and not any(a["action"] == "sqli_test" for a in actions):
                    actions.append({
                        "action": "sqli_test",
                        "description": "Test for SQL injection",
                        "priority": 10,
                        "techniques": ["Error-based", "Time-based", "Union-based"],
                    })
                
                if vuln_type == "idor" and not any(a["action"] == "idor_test" for a in actions):
                    actions.append({
                        "action": "idor_test",
                        "description": "Test for IDOR vulnerabilities",
                        "priority": 9,
                        "techniques": ["ID manipulation", "UUID prediction", "Horizontal privesc"],
                    })
                
                if vuln_type == "ssrf" and not any(a["action"] == "ssrf_test" for a in actions):
                    actions.append({
                        "action": "ssrf_test",
                        "description": "Test for SSRF vulnerabilities",
                        "priority": 10,
                        "techniques": ["Internal port scan", "Cloud metadata", "File read"],
                    })
        
        # Based on missing protections
        if not self.profile.has_csp:
            if not any(a["action"] == "xss_test" for a in actions):
                actions.append({
                    "action": "xss_test",
                    "description": "No CSP - XSS exploitation easier",
                    "priority": 8,
                    "techniques": ["Script injection", "Event handlers"],
                })
        
        return actions
    
    def _prioritize_actions(self, actions: List[dict]) -> List[str]:
        """Return actions in priority order."""
        sorted_actions = sorted(actions, key=lambda x: x.get("priority", 0), reverse=True)
        return [a["action"] for a in sorted_actions]
    
    def _estimate_success_rate(self) -> float:
        """Estimate likelihood of finding exploitable vulnerabilities."""
        score = 50.0  # Base score
        
        # Security level impact
        if self.profile.security_level == SecurityLevel.WEAK:
            score += 30
        elif self.profile.security_level == SecurityLevel.MODERATE:
            score += 10
        elif self.profile.security_level == SecurityLevel.HARDENED:
            score -= 20
        
        # Vulnerability indicators
        score += min(len(self.profile.vulnerability_indicators) * 5, 25)
        
        # High value targets
        score += min(len(self.profile.high_value_targets) * 3, 15)
        
        # Threats
        if self.profile.has_waf:
            score -= 15
        if self.profile.has_rate_limit:
            score -= 5
        
        return min(max(score, 0), 100)
    
    # =========================================================================
    # REPORT GENERATION
    # =========================================================================
    
    def generate_report(self, assessment: SituationalAssessment) -> str:
        """Generate situational analysis report."""
        p = assessment.profile
        
        report = f"""# Situational Analysis Report

## Target Profile

**URL:** {p.url}
**Type:** {p.type.name}
**Security Level:** {p.security_level.name}
**Recommended Strategy:** {p.recommended_strategy.name}

## Technical Details

| Attribute | Value |
|-----------|-------|
| Tech Stack | {p.tech_stack or 'Unknown'} |
| Framework | {p.framework or 'Unknown'} |
| CDN/WAF | {p.cdn_waf or 'None detected'} |
| Has Auth | {'✅' if p.has_auth else '❌'} |
| Has File Upload | {'✅' if p.has_file_upload else '❌'} |
| Has API | {'✅' if p.has_api else '❌'} |
| Has CSP | {'✅' if p.has_csp else '❌'} |
| Has WAF | {'✅' if p.has_waf else '❌'} |
| Has Rate Limiting | {'✅' if p.has_rate_limit else '❌'} |

## Attack Surface

**Exposed Endpoints:** {len(p.exposed_endpoints)}
**Input Parameters:** {', '.join(p.input_parameters) or 'None discovered'}
**Vulnerability Indicators:** {len(p.vulnerability_indicators)}

### Vulnerability Indicators
"""
        
        for indicator in p.vulnerability_indicators[:10]:
            report += f"- {indicator}\n"
        
        report += f"""
## Threats

These factors may impede exploitation:

"""
        for threat in assessment.threats:
            report += f"- ⚠️ {threat}\n"
        
        report += f"""
## Opportunities

These factors increase success probability:

"""
        for opp in assessment.opportunities:
            report += f"- ✅ {opp}\n"
        
        report += f"""
## Recommended Actions

Prioritized attack plan:

"""
        for i, action in enumerate(assessment.recommended_actions[:10], 1):
            report += f"""### {i}. {action['action']}

**Priority:** {action.get('priority', 'N/A')}/10
**Description:** {action['description']}
**Techniques:** {', '.join(action.get('techniques', []))}

"""
        
        report += f"""
## Success Estimation

**Estimated Success Rate:** {assessment.estimated_success_rate:.1f}%

This estimate is based on:
- Security posture analysis
- Vulnerability indicators found
- Attack surface complexity
- Protection mechanisms detected
"""
        
        return report


# =============================================================================
# CONVENIENCE FUNCTION
# =============================================================================

async def analyze_situation(
    target_url: str,
    initial_findings: List[dict] = None,
    http_client=None,
    rate_limiter=None,
) -> Tuple[SituationalAssessment, str]:
    """
    Perform situational analysis on a target.
    
    Returns:
        Tuple of (assessment, report)
    """
    analyzer = SituationalAnalyzer(http_client, rate_limiter)
    assessment = await analyzer.analyze(target_url, initial_findings or [])
    report = analyzer.generate_report(assessment)
    
    return assessment, report
