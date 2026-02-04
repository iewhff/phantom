"""
Master Intelligence System
===========================

The ultimate AI-driven attack coordination system.

Combines:
1. Situational Awareness - Understand the context
2. Adaptive Brain - Think and adapt in real-time
3. Vulnerability Chaining - Combine findings for impact
4. Intelligent Attacker - Execute smart attacks

This is the "master mind" that orchestrates everything.

Author: canigetrichpls
"""

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse
import structlog

# Import our intelligence modules
from analysis.situational_analyzer import (
    SituationalAnalyzer,
    SituationalAssessment,
    TargetProfile,
    TargetType,
    SecurityLevel,
    AttackStrategy,
)
from analysis.adaptive_brain import (
    AdaptiveAttackBrain,
    ExploitResult,
    Confidence,
)
from analysis.vuln_chain_engine import (
    VulnChainEngine,
    AttackChain,
    chain_vulnerabilities,
)
from analysis.intelligent_attacker import (
    IntelligentAttacker,
    IntelligentFinding,
)

logger = structlog.get_logger(__name__)


# =============================================================================
# DATA MODELS
# =============================================================================

@dataclass
class MasterFinding:
    """A finding produced by the master intelligence system."""
    name: str
    type: str
    severity: str
    confidence: str
    exploitable: bool
    
    # Evidence
    url: str = ""
    payload: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    poc_html: str = ""
    
    # Context
    attack_path: str = ""
    business_impact: str = ""
    reproduction_steps: List[str] = field(default_factory=list)
    
    # Source
    source_system: str = ""  # Which system found this
    chain_id: str = ""       # If part of a chain


@dataclass
class MasterReport:
    """Complete report from the master intelligence system."""
    target_url: str
    scan_time: str
    
    # Analysis results
    target_profile: TargetProfile = None
    assessment: SituationalAssessment = None
    
    # Findings
    critical_findings: List[MasterFinding] = field(default_factory=list)
    high_findings: List[MasterFinding] = field(default_factory=list)
    medium_findings: List[MasterFinding] = field(default_factory=list)
    low_findings: List[MasterFinding] = field(default_factory=list)
    
    # Chains
    exploit_chains: List[AttackChain] = field(default_factory=list)
    
    # Statistics
    total_attacks_attempted: int = 0
    successful_exploits: int = 0
    chains_identified: int = 0
    estimated_bounty_value: str = "$0"


# =============================================================================
# MASTER INTELLIGENCE SYSTEM
# =============================================================================

class MasterIntelligence:
    """
    The Master Intelligence System coordinates all attack modules.
    
    Think of this as the "General" who:
    1. Assesses the battlefield (Situational Analyzer)
    2. Plans the campaign (Strategy Selection)
    3. Executes tactics (Adaptive Brain)
    4. Exploits opportunities (Intelligent Attacker)
    5. Chains victories (Vulnerability Chaining)
    6. Reports to command (Report Generation)
    """
    
    def __init__(self, http_client=None, rate_limiter=None):
        self.http_client = http_client
        self.rate_limiter = rate_limiter
        
        # Initialize all intelligence modules
        self.situational = SituationalAnalyzer(http_client, rate_limiter)
        self.brain = AdaptiveAttackBrain(http_client, rate_limiter)
        self.chainer = VulnChainEngine()
        self.attacker = IntelligentAttacker(http_client, rate_limiter)
        
        # State
        self.target_url = ""
        self.findings: List[MasterFinding] = []
        self.exploit_results: List[ExploitResult] = []
        self.chains: List[AttackChain] = []
    
    async def execute_campaign(
        self,
        target_url: str,
        initial_findings: List[dict] = None,
        max_iterations: int = 15,
    ) -> MasterReport:
        """
        Execute complete intelligence campaign.
        
        This is the main entry point that orchestrates everything.
        """
        self.target_url = target_url
        initial_findings = initial_findings or []
        start_time = datetime.now()
        
        logger.info(f"[Master] Starting campaign against: {target_url}")
        
        # =================================================================
        # PHASE 1: SITUATIONAL AWARENESS
        # =================================================================
        
        logger.info("[Master] Phase 1: Situational Analysis")
        assessment = await self.situational.analyze(target_url, initial_findings)
        
        logger.info(
            f"[Master] Target: {assessment.profile.type.name}, "
            f"Security: {assessment.profile.security_level.name}, "
            f"Success Rate: {assessment.estimated_success_rate:.1f}%"
        )
        
        # =================================================================
        # PHASE 2: STRATEGY ADAPTATION
        # =================================================================
        
        logger.info("[Master] Phase 2: Adapting Strategy")
        strategy = self._adapt_strategy(assessment)
        
        logger.info(f"[Master] Using strategy: {strategy.name}")
        
        # =================================================================
        # PHASE 3: INTELLIGENT ATTACKS
        # =================================================================
        
        logger.info("[Master] Phase 3: Executing Intelligent Attacks")
        
        # Adjust iterations based on strategy
        if strategy == AttackStrategy.AGGRESSIVE:
            iterations = max_iterations
        elif strategy == AttackStrategy.STEALTHY:
            iterations = max_iterations // 2
        else:
            iterations = max_iterations
        
        # Run the intelligent attacker with enhanced heuristics for criticals
        from analysis.intelligent_attacker import intelligent_attack
        # Heuristics: fuzz endpoints/params with critical keywords
        critical_keywords = [
            "admin", "reset", "forgot", "token", "password", "auth", "session", "privilege", "elevate", "impersonate", "bypass", "root", "debug", "internal", "config", "secret", "key", "oauth", "callback", "redirect", "sensitive", "upload", "file", "exec", "shell", "cmd", "api_key", "jwt", "bearer", "csrf", "sso", "2fa", "mfa"
        ]
        # If initial_findings has endpoints/params, prioritize those
        prioritized_findings = []
        for f in (initial_findings or []):
            url = f.get("url") or f.get("endpoint") or ""
            param = f.get("param", "")
            if any(kw in url.lower() or kw in param.lower() for kw in critical_keywords):
                prioritized_findings.append(f)
        # Merge prioritized with rest (no duplicates)
        findings_for_attack = prioritized_findings + [f for f in (initial_findings or []) if f not in prioritized_findings]
        # Run intelligent attack with max_depth=8 for more chaining
        intelligent_findings, _ = await intelligent_attack(
            target_url,
            findings_for_attack,
            self.http_client,
            self.rate_limiter,
            max_depth=8,
        )
        # Convert intelligent findings to master findings
        for finding in intelligent_findings:
            self.findings.append(self._convert_intelligent_finding(finding))
        logger.info(f"[Master] Intelligent attacker found: {len(intelligent_findings)} potential vulnerabilities (critical heuristics applied)")
        
        # =================================================================
        # PHASE 4: ADAPTIVE BRAIN ATTACKS
        # =================================================================
        
        logger.info("[Master] Phase 4: Running Adaptive Brain")
        
        # The brain does targeted exploitation attempts
        self.exploit_results = await self.brain.analyze_and_exploit(
            target_url,
            initial_findings,
            iterations,
        )
        
        # Convert successful exploits to master findings
        for result in self.exploit_results:
            if result.success:
                self.findings.append(self._convert_exploit_result(result))
        
        successful = len([r for r in self.exploit_results if r.success])
        logger.info(f"[Master] Brain attacks: {len(self.exploit_results)} attempts, {successful} successful")
        
        # =================================================================
        # PHASE 5: VULNERABILITY CHAINING
        # =================================================================
        
        logger.info("[Master] Phase 5: Finding Vulnerability Chains")
        
        # Combine all findings for chaining
        all_findings = initial_findings + self._findings_to_dict()
        
        # Use chain_vulnerabilities for the chaining
        self.chains, chain_report = await chain_vulnerabilities(
            findings=all_findings,
            target_url=target_url,
            http_client=self.http_client,
            rate_limiter=self.rate_limiter,
        )
        
        # Count successful chains
        successful_chains = [c for c in self.chains if c.status.value == "success"]
        
        logger.info(f"[Master] Found {len(self.chains)} potential chains, {len(successful_chains)} exploited")
        
        # =================================================================
        # PHASE 6: REPORT GENERATION
        # =================================================================
        
        logger.info("[Master] Phase 6: Generating Report")
        
        report = self._generate_report(assessment, start_time)
        
        logger.info(
            f"[Master] Campaign complete! "
            f"Critical: {len(report.critical_findings)}, "
            f"High: {len(report.high_findings)}, "
            f"Medium: {len(report.medium_findings)}, "
            f"Low: {len(report.low_findings)}"
        )
        
        return report
    
    # =========================================================================
    # STRATEGY ADAPTATION
    # =========================================================================
    
    def _adapt_strategy(self, assessment: SituationalAssessment) -> AttackStrategy:
        """Adapt strategy based on situational assessment."""
        profile = assessment.profile
        
        # If WAF detected, be very careful
        if profile.has_waf:
            logger.info("[Master] WAF detected - switching to stealthy mode")
            return AttackStrategy.STEALTHY
        
        # If many vulnerability indicators, be aggressive
        if len(profile.vulnerability_indicators) > 5:
            logger.info("[Master] Many indicators - switching to aggressive mode")
            return AttackStrategy.AGGRESSIVE
        
        # If API, be surgical
        if profile.type == TargetType.API_SERVICE:
            logger.info("[Master] API target - using surgical precision")
            return AttackStrategy.SURGICAL
        
        # If auth system, focus on that
        if profile.type == TargetType.AUTHENTICATION:
            logger.info("[Master] Auth system - using surgical precision")
            return AttackStrategy.SURGICAL
        
        # If weak security, be aggressive
        if profile.security_level == SecurityLevel.WEAK:
            logger.info("[Master] Weak security - going aggressive")
            return AttackStrategy.AGGRESSIVE
        
        # Default to the recommended strategy
        return profile.recommended_strategy
    
    # =========================================================================
    # FINDING CONVERSION
    # =========================================================================
    
    def _convert_intelligent_finding(self, finding: IntelligentFinding) -> MasterFinding:
        """Convert IntelligentFinding to MasterFinding."""
        return MasterFinding(
            name=finding.name,
            type=finding.type,
            severity=finding.severity,
            confidence=finding.confidence,
            exploitable=finding.exploitable,
            url=finding.url,
            payload=finding.payload,
            evidence=finding.evidence,
            poc_html=finding.poc,
            attack_path=finding.attack_vector,
            business_impact=self._assess_impact(finding.type, finding.severity),
            reproduction_steps=self._generate_repro_steps(finding),
            source_system="intelligent_attacker",
        )
    
    def _convert_exploit_result(self, result: ExploitResult) -> MasterFinding:
        """Convert ExploitResult to MasterFinding."""
        severity = self._determine_severity(result)
        
        return MasterFinding(
            name=result.attack.name,
            type=result.attack.type,
            severity=severity,
            confidence=result.confidence.name,
            exploitable=result.success,
            url=result.attack.target,
            payload=result.attack.payload,
            evidence=result.evidence,
            poc_html=result.poc,
            attack_path=result.attack.reasoning,
            business_impact=self._assess_impact(result.attack.type, severity),
            reproduction_steps=self._generate_repro_from_attack(result.attack),
            source_system="adaptive_brain",
        )
    
    def _determine_severity(self, result: ExploitResult) -> str:
        """Determine severity based on exploit result."""
        attack_type = result.attack.type.lower()
        
        # Critical severity
        if any(t in attack_type for t in ["sqli", "rce", "auth_bypass", "ssrf"]):
            return "critical"
        
        # High severity
        if any(t in attack_type for t in ["xss", "idor", "nosqli"]):
            return "high"
        
        # Medium severity
        if any(t in attack_type for t in ["cors", "redirect", "clickjacking"]):
            if result.confidence.value >= 80:
                return "high"
            return "medium"
        
        # Low severity
        return "low"
    
    def _assess_impact(self, vuln_type: str, severity: str) -> str:
        """Assess business impact of vulnerability."""
        impact_map = {
            "sqli": "Complete database compromise - data theft, modification, or deletion",
            "xss": "Account takeover via session hijacking, phishing attacks",
            "rce": "Complete server compromise - full system access",
            "auth_bypass": "Unauthorized access to protected resources and user accounts",
            "idor": "Access to other users' data - privacy breach",
            "ssrf": "Internal network access - cloud metadata theft, internal port scan",
            "cors": "Cross-origin data theft - authenticated user data exfiltration",
            "clickjacking": "UI redressing attacks - tricking users into unintended actions",
            "open_redirect": "Phishing attacks - redirecting users to malicious sites",
        }
        
        for key, impact in impact_map.items():
            if key in vuln_type.lower():
                return impact
        
        if severity == "critical":
            return "Severe impact - immediate remediation required"
        elif severity == "high":
            return "Significant impact - prioritize remediation"
        elif severity == "medium":
            return "Moderate impact - plan remediation"
        else:
            return "Limited impact - consider remediation"
    
    def _generate_repro_steps(self, finding: IntelligentFinding) -> List[str]:
        """Generate reproduction steps from intelligent finding."""
        steps = [
            f"1. Navigate to: {finding.url}",
        ]
        
        if finding.payload:
            steps.append(f"2. Inject payload: {finding.payload}")
        
        if finding.evidence:
            steps.append(f"3. Observe the response for evidence of vulnerability")
        
        steps.append(f"4. Confirm exploitation using the provided PoC")
        
        return steps
    
    def _generate_repro_from_attack(self, attack) -> List[str]:
        """Generate reproduction steps from attack."""
        steps = [
            f"1. Send request to: {attack.target}",
            f"2. Method: {attack.method}",
        ]
        
        if attack.payload:
            steps.append(f"3. Payload: {attack.payload}")
        
        if attack.headers:
            steps.append(f"4. Custom headers: {json.dumps(attack.headers)}")
        
        steps.append(f"5. Expected: {attack.expected_response}")
        
        return steps
    
    def _findings_to_dict(self) -> List[dict]:
        """Convert MasterFindings to dict format for chaining."""
        return [
            {
                "name": f.name,
                "type": f.type,
                "severity": f.severity,
                "evidence": f.evidence,
            }
            for f in self.findings
        ]
    
    # =========================================================================
    # REPORT GENERATION
    # =========================================================================
    
    def _generate_report(
        self,
        assessment: SituationalAssessment,
        start_time: datetime,
    ) -> MasterReport:
        """Generate comprehensive master report."""
        elapsed = datetime.now() - start_time
        
        report = MasterReport(
            target_url=self.target_url,
            scan_time=f"{elapsed.total_seconds():.1f}s",
            target_profile=assessment.profile,
            assessment=assessment,
            total_attacks_attempted=len(self.exploit_results),
            successful_exploits=len([r for r in self.exploit_results if r.success]),
            chains_identified=len(self.chains),
        )
        
        # Categorize findings by severity
        for finding in self.findings:
            if finding.exploitable:
                if finding.severity == "critical":
                    report.critical_findings.append(finding)
                elif finding.severity == "high":
                    report.high_findings.append(finding)
                elif finding.severity == "medium":
                    report.medium_findings.append(finding)
                else:
                    report.low_findings.append(finding)
        
        # Add chains
        report.exploit_chains = self.chains
        
        # Estimate bounty value
        report.estimated_bounty_value = self._estimate_bounty(report)
        
        return report
    
    def _estimate_bounty(self, report: MasterReport) -> str:
        """Estimate potential bounty value."""
        total = 0
        
        # Typical bug bounty ranges
        total += len(report.critical_findings) * 5000
        total += len(report.high_findings) * 1500
        total += len(report.medium_findings) * 500
        total += len(report.low_findings) * 100
        
        # Chains add value
        total += len([c for c in report.exploit_chains if c.target_severity == "critical"]) * 3000
        total += len([c for c in report.exploit_chains if c.target_severity == "high"]) * 1000
        
        return f"${total:,}"
    
    def generate_markdown_report(self, report: MasterReport) -> str:
        """Generate Markdown report for HackerOne."""
        md = f"""# 🎯 Master Intelligence Security Assessment

## Executive Summary

**Target:** {report.target_url}
**Scan Duration:** {report.scan_time}
**Strategy Used:** {report.target_profile.recommended_strategy.name}

### Results Overview

| Severity | Count |
|----------|-------|
| 🔴 Critical | {len(report.critical_findings)} |
| 🟠 High | {len(report.high_findings)} |
| 🟡 Medium | {len(report.medium_findings)} |
| 🟢 Low | {len(report.low_findings)} |

**Vulnerability Chains Found:** {report.chains_identified}
**Estimated Value:** {report.estimated_bounty_value}

---

## Target Intelligence

**Type:** {report.target_profile.type.name}
**Security Level:** {report.target_profile.security_level.name}
**Tech Stack:** {report.target_profile.tech_stack or 'Unknown'}
**WAF Detected:** {'Yes' if report.target_profile.has_waf else 'No'}

### Attack Surface

- **Exposed Endpoints:** {len(report.target_profile.exposed_endpoints)}
- **Input Parameters:** {len(report.target_profile.input_parameters)}
- **Vulnerability Indicators:** {len(report.target_profile.vulnerability_indicators)}

---

"""
        
        # Critical Findings
        if report.critical_findings:
            md += "## 🔴 Critical Vulnerabilities\n\n"
            for i, finding in enumerate(report.critical_findings, 1):
                md += self._format_finding(i, finding)
        
        # High Findings
        if report.high_findings:
            md += "## 🟠 High Severity Vulnerabilities\n\n"
            for i, finding in enumerate(report.high_findings, 1):
                md += self._format_finding(i, finding)
        
        # Medium Findings
        if report.medium_findings:
            md += "## 🟡 Medium Severity Vulnerabilities\n\n"
            for i, finding in enumerate(report.medium_findings, 1):
                md += self._format_finding(i, finding)
        
        # Low Findings (summarized)
        if report.low_findings:
            md += f"## 🟢 Low Severity ({len(report.low_findings)} findings)\n\n"
            for finding in report.low_findings[:5]:
                md += f"- **{finding.name}**: {finding.url[:80]}...\n"
            if len(report.low_findings) > 5:
                md += f"\n*...and {len(report.low_findings) - 5} more*\n"
            md += "\n"
        
        # Vulnerability Chains
        if report.exploit_chains:
            md += "## 🔗 Vulnerability Chains\n\n"
            for i, chain in enumerate(report.exploit_chains, 1):
                md += f"""### Chain {i}: {chain.name}

**Target Severity:** {chain.target_severity.upper()}
**Status:** {chain.status.value}

**Chain Path:**
"""
                for j, step in enumerate(chain.steps, 1):
                    status_icon = "✅" if step.status.value == "success" else "❌" if step.status.value == "failed" else "⏳"
                    md += f"{j}. {status_icon} {step.name}: {step.description}\n"
                
                if chain.poc:
                    md += f"""
**Proof of Concept:**
```html
{chain.poc[:1500]}
```
"""
                md += "\n---\n\n"
        
        # No findings case
        if not any([
            report.critical_findings,
            report.high_findings,
            report.medium_findings,
            report.low_findings,
        ]):
            md += """## Results

No exploitable vulnerabilities were found.

The target demonstrates robust security controls:
- Effective WAF/filtering
- Strong security headers
- Proper input validation

Continue monitoring for new attack vectors.
"""
        
        return md
    
    def _format_finding(self, num: int, finding: MasterFinding) -> str:
        """Format a single finding for the report."""
        return f"""### {num}. {finding.name}

**Type:** {finding.type}
**Confidence:** {finding.confidence}
**Source:** {finding.source_system}

**Target URL:**
```
{finding.url}
```

**Payload:**
```
{finding.payload or 'N/A'}
```

**Business Impact:**
{finding.business_impact}

**Reproduction Steps:**
{chr(10).join(finding.reproduction_steps)}

**Evidence:**
```json
{json.dumps(finding.evidence, indent=2, default=str)[:1000]}
```

**Proof of Concept:**
```html
{finding.poc_html[:2000] if finding.poc_html else 'See reproduction steps'}
```

---

"""


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

async def run_master_intelligence(
    target_url: str,
    initial_findings: List[dict] = None,
    http_client=None,
    rate_limiter=None,
    max_iterations: int = 15,
) -> Tuple[MasterReport, str]:
    """
    Run the complete Master Intelligence campaign.
    
    Args:
        target_url: Target URL to analyze
        initial_findings: Initial scan findings
        http_client: HTTP client for requests
        rate_limiter: Rate limiter instance
        max_iterations: Maximum attack iterations
    
    Returns:
        Tuple of (MasterReport, markdown_report)
    """
    master = MasterIntelligence(http_client, rate_limiter)
    report = await master.execute_campaign(
        target_url,
        initial_findings or [],
        max_iterations,
    )
    markdown = master.generate_markdown_report(report)
    
    return report, markdown
