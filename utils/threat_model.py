"""
Threat Modeling Engine v1.0 - Business Impact Analysis

Transforms technical findings into business-relevant threat scenarios.
Essential for professional pentest reports that stakeholders understand.

Author: PetNTester AI
Version: 1.0.0
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class BusinessImpactLevel(Enum):
    """Business impact severity levels."""
    CRITICAL = "critical"      # Business-ending, massive financial/legal exposure
    HIGH = "high"              # Significant financial loss, regulatory issues
    MEDIUM = "medium"          # Moderate business disruption
    LOW = "low"                # Minor inconvenience
    INFORMATIONAL = "info"     # No direct business impact


class ThreatCategory(Enum):
    """STRIDE threat categories."""
    SPOOFING = "spoofing"                  # Identity impersonation
    TAMPERING = "tampering"                # Data modification
    REPUDIATION = "repudiation"            # Denying actions
    INFORMATION_DISCLOSURE = "info_disclosure"  # Data leakage
    DENIAL_OF_SERVICE = "dos"              # Service disruption
    ELEVATION_OF_PRIVILEGE = "elevation"   # Unauthorized access


@dataclass
class ThreatScenario:
    """A realistic attack scenario with business context."""
    title: str
    description: str
    attack_steps: list[str]
    threat_actor: str
    likelihood: str  # Low, Medium, High
    business_impact: BusinessImpactLevel
    affected_assets: list[str]
    regulatory_implications: list[str]
    financial_impact: str
    remediation_priority: int  # 1-5, 1 being highest


@dataclass
class ThreatModel:
    """Complete threat model for a finding."""
    finding_type: str
    finding_severity: str
    stride_categories: list[ThreatCategory]
    attack_scenarios: list[ThreatScenario]
    business_summary: str
    executive_summary: str
    risk_score: float  # 0-10
    recommendations: list[str]


# Mapping of vulnerability types to threat models
# NOTE: Business impact is CONDITIONAL - describes what COULD happen if vulnerabilities exist
THREAT_MAPPINGS: dict[str, dict[str, Any]] = {
    # Header vulnerabilities
    "missing_header": {
        "stride": [ThreatCategory.INFORMATION_DISCLOSURE, ThreatCategory.TAMPERING],
        "scenarios": [
            {
                "title": "Defense-in-Depth Gaps (Browser Hardening)",
                "threat_actor": "External Attacker",
                "description": "Missing browser security headers reduce defense layers against client-side attacks",
                "attack_steps": [
                    "Security headers provide defense-in-depth (not primary controls)",
                    "Missing CSP: XSS payloads execute without restriction if XSS exists",
                    "Missing X-Frame-Options: Site can be framed for clickjacking",
                    "Missing HSTS: First-connection vulnerable to MITM on public networks",
                ],
                "likelihood": "Conditional (multiplier for other vulnerabilities)",
                "affected_assets": ["Browser security posture", "User sessions (if exploited)"],
                "regulatory": ["GDPR Article 32 (security measures)", "PCI-DSS Requirement 6.5"],
                "financial": "€10K-100K per incident (if exploited in combination)",
            },
        ],
        "business_summary": "Defense-in-depth gaps in browser hardening. These headers are secondary controls that limit damage if primary vulnerabilities exist.",
        "executive_summary": "Application lacks browser hardening headers. These are defense-in-depth measures that limit impact of other vulnerabilities.",
    },

    # CORS vulnerabilities
    "cors": {
        "stride": [ThreatCategory.INFORMATION_DISCLOSURE, ThreatCategory.SPOOFING],
        "scenarios": [
            {
                "title": "Cross-Origin Access Control Weakness",
                "threat_actor": "Malicious Website Operator",
                "description": "CORS policy allows cross-origin requests that may expose sensitive data",
                "attack_steps": [
                    "CORS headers analyzed for permissive configurations",
                    "If credentials allowed + origin reflected: cross-origin data access possible",
                    "Exploitation requires victim to visit attacker's site while authenticated",
                    "Risk severity depends on data sensitivity of affected endpoints",
                ],
                "likelihood": "Conditional (depends on credentials + origin reflection + data sensitivity)",
                "affected_assets": ["API endpoints", "Authenticated user data (if exposed)"],
                "regulatory": ["GDPR Articles 5, 32 (if data exposed)"],
                "financial": "€100K-1M+ (if data breach occurs)",
            },
        ],
        "business_summary": "CORS configuration may allow cross-origin access. Actual exploitability depends on credential handling and data sensitivity.",
        "executive_summary": "Cross-origin access control requires review. Risk level depends on what data is accessible and whether credentials are included.",
    },

    # XSS vulnerabilities (CONFIRMED - these are real findings)
    "xss": {
        "stride": [ThreatCategory.INFORMATION_DISCLOSURE, ThreatCategory.ELEVATION_OF_PRIVILEGE, ThreatCategory.TAMPERING],
        "scenarios": [
            {
                "title": "Account Takeover via Session Hijacking",
                "threat_actor": "Cybercriminal",
                "description": "CONFIRMED XSS allows attacker to steal sessions and take control",
                "attack_steps": [
                    "Attacker exploits CONFIRMED XSS vulnerability",
                    "Crafts malicious link and sends to admin via phishing",
                    "Admin clicks link, XSS payload executes",
                    "Session token sent to attacker's server",
                    "Attacker logs in as admin with stolen session",
                ],
                "likelihood": "High (XSS confirmed)",
                "affected_assets": ["Admin accounts", "All user data", "System configuration"],
                "regulatory": ["GDPR Article 33 (breach notification)", "All compliance frameworks"],
                "financial": "€500K-5M+ for full admin compromise",
            },
        ],
        "business_summary": "CONFIRMED XSS allows attackers to execute code in users' browsers, enabling account takeover and data theft.",
        "executive_summary": "CONFIRMED: Attackers can hijack your users' sessions and steal their data. This is a direct path to a data breach.",
    },

    "dom_xss": {
        "stride": [ThreatCategory.INFORMATION_DISCLOSURE, ThreatCategory.ELEVATION_OF_PRIVILEGE],
        "scenarios": [
            {
                "title": "Client-Side Account Takeover",
                "threat_actor": "Phishing Attacker",
                "description": "Attacker crafts malicious URL that steals credentials client-side",
                "attack_steps": [
                    "Attacker identifies DOM XSS in URL hash/parameters",
                    "Crafts URL with payload in fragment",
                    "Payload not visible in server logs (hash-based)",
                    "Victim clicks link, credentials stolen",
                ],
                "likelihood": "High",
                "affected_assets": ["User credentials", "Session tokens", "Personal data"],
                "regulatory": ["GDPR", "PCI-DSS"],
                "financial": "€50K-500K per incident",
            },
        ],
        "business_summary": "DOM XSS allows client-side attacks that bypass server-side security controls entirely.",
        "executive_summary": "A JavaScript vulnerability allows attackers to steal user credentials through specially crafted links. These attacks leave no server-side evidence.",
    },

    # SQL Injection
    "sqli": {
        "stride": [ThreatCategory.INFORMATION_DISCLOSURE, ThreatCategory.TAMPERING, ThreatCategory.ELEVATION_OF_PRIVILEGE],
        "scenarios": [
            {
                "title": "Complete Database Exfiltration",
                "threat_actor": "Nation-State / APT",
                "description": "Attacker extracts entire database including credentials",
                "attack_steps": [
                    "Attacker discovers SQL injection point",
                    "Enumerates database structure",
                    "Extracts all tables including users, payments",
                    "Obtains admin credentials",
                    "Sells data on dark web or uses for further attacks",
                ],
                "likelihood": "Critical",
                "affected_assets": ["All database records", "Credentials", "PII", "Financial data"],
                "regulatory": ["GDPR (€20M max fine)", "PCI-DSS (loss of certification)", "HIPAA ($1.5M/violation)"],
                "financial": "€1M-50M+ (breach costs, fines, lawsuits, reputation)",
            },
        ],
        "business_summary": "SQL Injection provides direct database access, enabling complete data breach.",
        "executive_summary": "CRITICAL: Attackers can read, modify, and delete your entire database. This is the most severe web vulnerability and will result in a major data breach if exploited.",
    },

    # SSL/TLS vulnerabilities
    "ssl": {
        "stride": [ThreatCategory.INFORMATION_DISCLOSURE, ThreatCategory.TAMPERING],
        "scenarios": [
            {
                "title": "Man-in-the-Middle Data Interception",
                "threat_actor": "Network Attacker (Coffee Shop, Hotel)",
                "description": "Attacker on same network intercepts unencrypted traffic",
                "attack_steps": [
                    "Victim connects to public WiFi",
                    "Attacker performs ARP spoofing",
                    "Intercepts traffic due to weak TLS",
                    "Captures credentials, session tokens, personal data",
                ],
                "likelihood": "Medium",
                "affected_assets": ["Credentials", "Session data", "Personal information"],
                "regulatory": ["PCI-DSS Requirement 4"],
                "financial": "€10K-100K per incident",
            },
        ],
        "business_summary": "Weak TLS configuration allows traffic interception on untrusted networks.",
        "executive_summary": "Users on public WiFi (coffee shops, airports) are at risk of having their data stolen by nearby attackers.",
    },

    # Aggregated browser hardening (enterprise style)
    "missing_browser_hardening": {
        "stride": [ThreatCategory.INFORMATION_DISCLOSURE, ThreatCategory.TAMPERING],
        "scenarios": [
            {
                "title": "Browser-based Attack Surface Expansion",
                "threat_actor": "External Attacker",
                "description": "Missing security headers expand the potential attack surface for browser-based attacks",
                "attack_steps": [
                    "Multiple security headers are missing from server responses",
                    "This expands attack surface IF other vulnerabilities exist",
                    "Missing CSP: XSS payloads execute without restriction",
                    "Missing HSTS: MITM possible on first connection",
                    "Missing X-Frame-Options: Clickjacking possible",
                ],
                "likelihood": "Conditional (amplifies other vulnerabilities)",
                "affected_assets": ["User sessions", "Browser security posture"],
                "regulatory": ["GDPR Article 32", "PCI-DSS Requirement 6.5"],
                "financial": "€10K-100K per incident (if exploited with other vulns)",
            },
        ],
        "business_summary": "Multiple browser hardening headers are missing. These are defense-in-depth controls that reduce impact of other vulnerabilities.",
        "executive_summary": "Application lacks browser security headers. This increases risk if other vulnerabilities exist but is not directly exploitable alone.",
    },

    # Insecure header configuration (dangerous values)
    "insecure_header": {
        "stride": [ThreatCategory.INFORMATION_DISCLOSURE, ThreatCategory.TAMPERING],
        "scenarios": [
            {
                "title": "Permissive Security Header Configuration",
                "threat_actor": "Malicious Third Party",
                "description": "Security headers are present but configured too permissively",
                "attack_steps": [
                    "Security header detected with dangerous configuration",
                    "CSP unsafe-inline/unsafe-eval: XSS protection reduced",
                    "CORS wildcard: Cross-origin access unrestricted",
                    "Risk depends on what data is exposed via these endpoints",
                ],
                "likelihood": "Conditional (depends on endpoint data sensitivity)",
                "affected_assets": ["API responses", "User data (if sensitive)"],
                "regulatory": ["GDPR Articles 5, 32 (if data exposed)"],
                "financial": "€10K-500K depending on data sensitivity",
            },
        ],
        "business_summary": "Security headers are present but configured too permissively, reducing their protective value.",
        "executive_summary": "Security controls are in place but misconfigured. Review configuration to ensure adequate protection.",
    },

    # CORS wildcard (specific finding type)
    "cors_wildcard": {
        "stride": [ThreatCategory.INFORMATION_DISCLOSURE, ThreatCategory.SPOOFING],
        "scenarios": [
            {
                "title": "Unrestricted Cross-Origin Access",
                "threat_actor": "Malicious Website Operator",
                "description": "CORS wildcard (*) allows any website to read responses",
                "attack_steps": [
                    "Server responds with Access-Control-Allow-Origin: *",
                    "Any website can make cross-origin requests and read responses",
                    "If endpoint returns sensitive data, it can be stolen",
                    "Note: Credentials cannot be included with wildcard CORS",
                ],
                "likelihood": "Conditional (depends on data sensitivity of endpoints)",
                "affected_assets": ["API endpoints", "Data returned by affected endpoints"],
                "regulatory": ["GDPR Articles 5, 32 (if PII exposed)"],
                "financial": "€10K-100K (lower risk without credentials)",
            },
        ],
        "business_summary": "CORS wildcard allows any website to access responses. Risk depends on endpoint data sensitivity.",
        "executive_summary": "Cross-origin access is unrestricted. Review what data is exposed and whether restriction is needed.",
    },
}


class ThreatModelEngine:
    """
    Generates threat models and business impact analysis for findings.

    Transforms technical vulnerability data into business-relevant
    risk assessments that executives and stakeholders understand.
    """

    VERSION = "1.0.0"

    def __init__(self) -> None:
        self.mappings = THREAT_MAPPINGS

    def analyze_finding(self, finding: dict[str, Any]) -> ThreatModel:
        """
        Generate threat model for a single finding.

        Args:
            finding: Vulnerability finding dict

        Returns:
            ThreatModel with business context
        """
        finding_type = finding.get("type", "unknown")
        severity = finding.get("severity", "MEDIUM")

        # Get base mapping or use generic
        base_mapping = self._get_mapping(finding_type)

        # Build scenarios
        scenarios = []
        for scenario_data in base_mapping.get("scenarios", []):
            scenario = ThreatScenario(
                title=scenario_data["title"],
                description=scenario_data["description"],
                attack_steps=scenario_data["attack_steps"],
                threat_actor=scenario_data["threat_actor"],
                likelihood=scenario_data["likelihood"],
                business_impact=self._severity_to_impact(severity),
                affected_assets=scenario_data.get("affected_assets", []),
                regulatory_implications=scenario_data.get("regulatory", []),
                financial_impact=scenario_data.get("financial", "Unknown"),
                remediation_priority=self._severity_to_priority(severity),
            )
            scenarios.append(scenario)

        # Calculate risk score
        risk_score = self._calculate_risk_score(severity, scenarios)

        return ThreatModel(
            finding_type=finding_type,
            finding_severity=severity,
            stride_categories=base_mapping.get("stride", []),
            attack_scenarios=scenarios,
            business_summary=base_mapping.get("business_summary", ""),
            executive_summary=base_mapping.get("executive_summary", ""),
            risk_score=risk_score,
            recommendations=self._generate_recommendations(finding),
        )

    def generate_executive_report(self, findings: list[dict]) -> dict[str, Any]:
        """
        Generate executive summary report for all findings.

        IMPORTANT: Consolidates findings by type to avoid repetition.
        1 finding type = 1 threat model (not 1 per individual finding).

        Returns:
            Executive-friendly report with business impact
        """
        # CONSOLIDATE: Group findings by type first
        findings_by_type: dict[str, list[dict]] = {}
        for finding in findings:
            finding_type = self._normalize_finding_type(finding.get("type", "unknown"))
            if finding_type not in findings_by_type:
                findings_by_type[finding_type] = []
            findings_by_type[finding_type].append(finding)

        # Generate ONE threat model per finding TYPE (not per finding)
        threat_models = []
        for finding_type, grouped_findings in findings_by_type.items():
            # Use highest severity finding as representative
            representative = max(grouped_findings, key=lambda f: self._severity_to_score(f.get("severity", "LOW")))
            tm = self.analyze_finding(representative)
            # Add count of consolidated findings
            tm.consolidated_count = len(grouped_findings)
            threat_models.append(tm)

        # Aggregate by business impact
        critical_risks = [tm for tm in threat_models if tm.risk_score >= 8.0]
        high_risks = [tm for tm in threat_models if 6.0 <= tm.risk_score < 8.0]
        medium_risks = [tm for tm in threat_models if 4.0 <= tm.risk_score < 6.0]

        # Aggregate regulatory implications
        all_regulations = set()
        for tm in threat_models:
            for scenario in tm.attack_scenarios:
                all_regulations.update(scenario.regulatory_implications)

        # Calculate overall risk
        if critical_risks:
            overall_risk = "CRITICAL"
            overall_message = "Immediate action required. High probability of data breach."
        elif high_risks:
            overall_risk = "HIGH"
            overall_message = "Significant vulnerabilities require prompt remediation."
        elif medium_risks:
            overall_risk = "MEDIUM"
            overall_message = "Vulnerabilities should be addressed in next sprint."
        else:
            overall_risk = "LOW"
            overall_message = "Minor issues identified. Address in regular maintenance."

        return {
            "executive_summary": {
                "overall_risk_level": overall_risk,
                "risk_message": overall_message,
                "total_findings": len(findings),
                "unique_finding_types": len(threat_models),
                "critical_count": len(critical_risks),
                "high_count": len(high_risks),
                "medium_count": len(medium_risks),
            },
            "business_impact": {
                "regulatory_exposure": list(all_regulations),
                "potential_breach_types": self._get_breach_types(threat_models),
                "estimated_financial_exposure": self._estimate_financial_exposure(threat_models),
            },
            "top_risks": [
                {
                    "title": tm.attack_scenarios[0].title if tm.attack_scenarios else "Unknown",
                    "risk_score": tm.risk_score,
                    "business_summary": tm.business_summary,
                    "findings_count": getattr(tm, 'consolidated_count', 1),
                    "remediation_priority": tm.attack_scenarios[0].remediation_priority if tm.attack_scenarios else 5,
                }
                for tm in sorted(threat_models, key=lambda x: x.risk_score, reverse=True)[:5]
            ],
            "recommended_actions": self._prioritize_recommendations(threat_models),
            "threat_models": [self._serialize_threat_model(tm) for tm in threat_models],
        }

    def _normalize_finding_type(self, finding_type: str) -> str:
        """Normalize finding type to consolidate similar findings."""
        finding_lower = finding_type.lower()

        # Preserve specific types that have their own threat models
        if finding_type == "missing_browser_hardening":
            return "missing_browser_hardening"  # Keep as-is (aggregated headers)
        if finding_type == "insecure_header":
            return "insecure_header"  # Keep as-is (dangerous config)
        if finding_type == "cors_wildcard":
            return "cors_wildcard"  # Keep as-is (specific CORS issue)

        # Group generic missing headers (non-aggregated) together
        if "missing_header" in finding_type:
            return "missing_header"

        # Group CORS variants (except cors_wildcard which has its own)
        if "cors" in finding_lower and finding_type != "cors_wildcard":
            return "cors"

        # Group XSS variants
        if "xss" in finding_lower or "dom_xss" in finding_lower:
            return "xss"

        # Group SQL injection variants
        if "sql" in finding_lower:
            return "sqli"

        # Group SSL/TLS variants
        if "ssl" in finding_lower or "tls" in finding_lower:
            return "ssl"

        return finding_type

    def _severity_to_score(self, severity: str) -> int:
        """Convert severity to numeric score for comparison."""
        scores = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        return scores.get(severity.upper(), 0)

    def _get_mapping(self, finding_type: str) -> dict:
        """Get mapping for finding type, with fallback."""
        # Direct match
        if finding_type in self.mappings:
            return self.mappings[finding_type]

        # Partial match
        for key, mapping in self.mappings.items():
            if key in finding_type or finding_type in key:
                return mapping

        # Generic fallback
        return {
            "stride": [ThreatCategory.INFORMATION_DISCLOSURE],
            "scenarios": [{
                "title": "Security Vulnerability Exploitation",
                "threat_actor": "External Attacker",
                "description": "Attacker exploits vulnerability to compromise system",
                "attack_steps": ["Discover vulnerability", "Develop exploit", "Execute attack"],
                "likelihood": "Medium",
                "affected_assets": ["Application", "Data"],
                "regulatory": ["General security compliance"],
                "financial": "Varies by impact",
            }],
            "business_summary": "Security vulnerability that could be exploited by attackers.",
            "executive_summary": "A security issue was identified that requires remediation.",
        }

    def _severity_to_impact(self, severity: str) -> BusinessImpactLevel:
        """Convert severity to business impact."""
        mapping = {
            "CRITICAL": BusinessImpactLevel.CRITICAL,
            "HIGH": BusinessImpactLevel.HIGH,
            "MEDIUM": BusinessImpactLevel.MEDIUM,
            "LOW": BusinessImpactLevel.LOW,
            "INFO": BusinessImpactLevel.INFORMATIONAL,
        }
        return mapping.get(severity.upper(), BusinessImpactLevel.MEDIUM)

    def _severity_to_priority(self, severity: str) -> int:
        """Convert severity to remediation priority (1-5)."""
        mapping = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4, "INFO": 5}
        return mapping.get(severity.upper(), 3)

    def _calculate_risk_score(self, severity: str, scenarios: list[ThreatScenario]) -> float:
        """Calculate risk score 0-10."""
        base_scores = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 5.0, "LOW": 3.0, "INFO": 1.0}
        base = base_scores.get(severity.upper(), 5.0)

        # Adjust based on likelihood
        for scenario in scenarios:
            if scenario.likelihood == "High":
                base += 0.5
            elif scenario.likelihood == "Critical":
                base += 1.0

        return min(10.0, base)

    def _generate_recommendations(self, finding: dict) -> list[str]:
        """Generate prioritized recommendations."""
        remediation = finding.get("remediation", "")
        recs = []

        if remediation:
            # Split multi-line remediation into separate items
            lines = remediation.split("\n")
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#"):
                    recs.append(line)

        if not recs:
            recs = ["Review and remediate this vulnerability", "Implement security testing in CI/CD"]

        return recs[:5]  # Limit to top 5

    def _get_breach_types(self, models: list[ThreatModel]) -> list[str]:
        """Get potential breach types from threat models."""
        breach_types = set()
        for model in models:
            for cat in model.stride_categories:
                if cat == ThreatCategory.INFORMATION_DISCLOSURE:
                    breach_types.add("Data Breach")
                elif cat == ThreatCategory.ELEVATION_OF_PRIVILEGE:
                    breach_types.add("Account Takeover")
                elif cat == ThreatCategory.TAMPERING:
                    breach_types.add("Data Manipulation")
        return list(breach_types)

    def _estimate_financial_exposure(self, models: list[ThreatModel]) -> str:
        """Estimate total financial exposure."""
        max_risk = max((m.risk_score for m in models), default=0)

        if max_risk >= 9.0:
            return "€1M - €50M+ (Critical data breach potential)"
        elif max_risk >= 7.0:
            return "€100K - €1M (Significant incident potential)"
        elif max_risk >= 5.0:
            return "€10K - €100K (Moderate incident potential)"
        else:
            return "€1K - €10K (Minor incident potential)"

    def _prioritize_recommendations(self, models: list[ThreatModel]) -> list[dict]:
        """Prioritize recommendations across all models."""
        all_recs = []
        for model in models:
            priority = min((s.remediation_priority for s in model.attack_scenarios), default=5)
            for rec in model.recommendations:
                all_recs.append({"recommendation": rec, "priority": priority})

        # Sort by priority and deduplicate
        seen = set()
        unique_recs = []
        for rec in sorted(all_recs, key=lambda x: x["priority"]):
            if rec["recommendation"] not in seen:
                seen.add(rec["recommendation"])
                unique_recs.append(rec)

        return unique_recs[:10]

    def _serialize_threat_model(self, model: ThreatModel) -> dict:
        """Serialize threat model to dict."""
        return {
            "finding_type": model.finding_type,
            "finding_severity": model.finding_severity,
            "stride_categories": [cat.value for cat in model.stride_categories],
            "risk_score": model.risk_score,
            "business_summary": model.business_summary,
            "executive_summary": model.executive_summary,
            "scenarios": [
                {
                    "title": s.title,
                    "description": s.description,
                    "threat_actor": s.threat_actor,
                    "likelihood": s.likelihood,
                    "business_impact": s.business_impact.value,
                    "attack_steps": s.attack_steps,
                    "affected_assets": s.affected_assets,
                    "regulatory_implications": s.regulatory_implications,
                    "financial_impact": s.financial_impact,
                    "remediation_priority": s.remediation_priority,
                }
                for s in model.attack_scenarios
            ],
            "recommendations": model.recommendations,
        }


# Convenience function
def generate_threat_report(findings: list[dict]) -> dict[str, Any]:
    """Generate complete threat model report for findings."""
    engine = ThreatModelEngine()
    return engine.generate_executive_report(findings)
