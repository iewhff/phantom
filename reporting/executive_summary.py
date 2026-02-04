"""
Executive Summary Generator.
Generates business-focused reports with risk and financial impact.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from utils.logger import get_logger

if TYPE_CHECKING:
    from compliance.compliance_mapper import ComplianceMapper
    from retest.retest_engine import RetestEngine

logger = get_logger(__name__)


@dataclass
class FinancialImpact:
    """Financial impact estimation."""
    breach_cost_low: float
    breach_cost_high: float
    regulatory_fines: float
    remediation_cost: float
    reputation_damage: float
    business_disruption: float
    
    @property
    def total_risk_exposure(self) -> float:
        """Calculate total risk exposure."""
        avg_breach = (self.breach_cost_low + self.breach_cost_high) / 2
        return avg_breach + self.regulatory_fines + self.reputation_damage + self.business_disruption


@dataclass
class ExecutiveFinding:
    """Business-friendly finding representation."""
    title: str
    business_impact: str
    risk_level: str  # Critical Business Risk, High, Moderate, Low
    affected_assets: list[str]
    potential_scenarios: list[str]
    recommended_action: str
    estimated_fix_time: str
    estimated_fix_cost: str


@dataclass
class ExecutiveSummary:
    """Complete executive summary."""
    generated_at: datetime
    target: str
    overall_risk_rating: str
    risk_score: int  # 0-100
    financial_impact: FinancialImpact
    key_findings: list[ExecutiveFinding]
    compliance_status: dict[str, Any]
    trend: dict[str, Any]
    immediate_actions: list[str]
    strategic_recommendations: list[str]


class ExecutiveSummaryGenerator:
    """
    Generates executive-level security assessment summaries.
    
    Features:
    - Business risk translation
    - Financial impact estimation
    - Compliance status overview
    - Trend analysis
    - Prioritized recommendations
    - Board-ready formatting
    """
    
    # Industry average breach costs (2024 data)
    BREACH_COSTS = {
        "healthcare": {"per_record": 10.93, "average": 10_930_000},
        "financial": {"per_record": 5.90, "average": 5_970_000},
        "technology": {"per_record": 5.03, "average": 4_970_000},
        "retail": {"per_record": 3.28, "average": 3_280_000},
        "default": {"per_record": 4.45, "average": 4_450_000},
    }
    
    # Regulatory fine estimates by framework
    REGULATORY_FINES = {
        "GDPR": {"max": 20_000_000, "percentage": 0.04},  # €20M or 4% revenue
        "PCI DSS": {"per_month": 100_000, "max": 500_000},
        "HIPAA": {"per_violation": 50_000, "max": 1_500_000},
        "SOX": {"per_violation": 5_000_000, "max": 25_000_000},
    }
    
    def __init__(
        self,
        settings: Any,
        industry: str = "default",
        annual_revenue: float = 0,
        compliance_mapper: ComplianceMapper | None = None,
        retest_engine: RetestEngine | None = None,
    ):
        self.settings = settings
        self.industry = industry
        self.annual_revenue = annual_revenue
        self.compliance_mapper = compliance_mapper
        self.retest_engine = retest_engine
    
    def generate_summary(
        self,
        findings: list[dict[str, Any]],
        target: str,
        scan_metadata: dict[str, Any] | None = None,
    ) -> ExecutiveSummary:
        """Generate comprehensive executive summary."""
        
        # Calculate overall risk
        risk_score = self._calculate_risk_score(findings)
        risk_rating = self._get_risk_rating(risk_score)
        
        # Estimate financial impact
        financial_impact = self._estimate_financial_impact(findings)
        
        # Translate findings to business language
        key_findings = self._translate_findings(findings)
        
        # Get compliance status
        compliance_status = self._get_compliance_status(findings)
        
        # Analyze trends
        trend = self._analyze_trend()
        
        # Generate recommendations
        immediate_actions = self._generate_immediate_actions(findings)
        strategic_recommendations = self._generate_strategic_recommendations(
            findings, compliance_status
        )
        
        return ExecutiveSummary(
            generated_at=datetime.now(),
            target=target,
            overall_risk_rating=risk_rating,
            risk_score=risk_score,
            financial_impact=financial_impact,
            key_findings=key_findings,
            compliance_status=compliance_status,
            trend=trend,
            immediate_actions=immediate_actions,
            strategic_recommendations=strategic_recommendations,
        )
    
    def _calculate_risk_score(self, findings: list[dict[str, Any]]) -> int:
        """Calculate overall risk score (0-100)."""
        if not findings:
            return 0
        
        severity_weights = {
            "CRITICAL": 25,
            "HIGH": 15,
            "MEDIUM": 8,
            "LOW": 3,
            "INFO": 0,
        }
        
        # Base score from findings
        raw_score = sum(
            severity_weights.get(f.get("severity", "MEDIUM"), 8)
            for f in findings
        )
        
        # Cap at 100
        score = min(raw_score, 100)
        
        # Adjust for exploitability
        exploitable = sum(
            1 for f in findings
            if f.get("evidence") and len(f.get("evidence", [])) > 0
        )
        
        if exploitable > 0:
            score = min(score + 10, 100)
        
        return score
    
    def _get_risk_rating(self, score: int) -> str:
        """Convert score to business risk rating."""
        if score >= 80:
            return "CRITICAL - Immediate Executive Attention Required"
        elif score >= 60:
            return "HIGH - Significant Business Risk"
        elif score >= 40:
            return "MODERATE - Requires Planned Remediation"
        elif score >= 20:
            return "LOW - Minor Security Improvements Needed"
        else:
            return "MINIMAL - Security Posture Acceptable"
    
    def _estimate_financial_impact(
        self,
        findings: list[dict[str, Any]],
    ) -> FinancialImpact:
        """Estimate potential financial impact of vulnerabilities."""
        
        costs = self.BREACH_COSTS.get(self.industry, self.BREACH_COSTS["default"])
        
        # Estimate based on severity
        critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
        
        # Breach probability multiplier
        prob_multiplier = 0.1 + (critical_count * 0.15) + (high_count * 0.08)
        prob_multiplier = min(prob_multiplier, 0.8)  # Cap at 80%
        
        # Estimate breach costs
        breach_low = costs["average"] * 0.5 * prob_multiplier
        breach_high = costs["average"] * 1.5 * prob_multiplier
        
        # Regulatory fines (if applicable)
        regulatory = 0
        if self.annual_revenue > 0:
            # GDPR-style calculation
            regulatory = min(
                self.annual_revenue * 0.04 * prob_multiplier,
                20_000_000
            )
        
        # Remediation costs (industry averages)
        remediation = (critical_count * 50_000) + (high_count * 25_000)
        
        # Reputation damage (10-30% of breach cost)
        reputation = costs["average"] * 0.2 * prob_multiplier
        
        # Business disruption (5-15% of annual revenue)
        disruption = self.annual_revenue * 0.1 * prob_multiplier if self.annual_revenue > 0 else 0
        
        return FinancialImpact(
            breach_cost_low=round(breach_low, 2),
            breach_cost_high=round(breach_high, 2),
            regulatory_fines=round(regulatory, 2),
            remediation_cost=round(remediation, 2),
            reputation_damage=round(reputation, 2),
            business_disruption=round(disruption, 2),
        )
    
    def _translate_findings(
        self,
        findings: list[dict[str, Any]],
    ) -> list[ExecutiveFinding]:
        """Translate technical findings to business language."""
        
        # Business impact translations
        business_impacts = {
            "SQL Injection": {
                "impact": "Attackers can access, modify, or delete all database information including customer data, financial records, and business secrets",
                "scenarios": [
                    "Complete customer database theft",
                    "Financial record manipulation",
                    "Ransomware deployment via database access",
                ],
            },
            "Cross-Site Scripting": {
                "impact": "Attackers can impersonate any user, steal login credentials, and redirect customers to malicious websites",
                "scenarios": [
                    "Customer credential theft at scale",
                    "Defacement of public-facing applications",
                    "Phishing attacks through trusted domain",
                ],
            },
            "Authentication Bypass": {
                "impact": "Unauthorized access to protected systems and data without valid credentials",
                "scenarios": [
                    "Administrative account takeover",
                    "Access to confidential business data",
                    "System-wide privilege escalation",
                ],
            },
            "SSRF": {
                "impact": "Attackers can access internal systems and cloud infrastructure, potentially reaching sensitive backend services",
                "scenarios": [
                    "Cloud metadata theft (AWS keys, etc.)",
                    "Internal network reconnaissance",
                    "Access to private services and databases",
                ],
            },
            "Broken Access Control": {
                "impact": "Users can access data and functions beyond their authorization, leading to data leakage and privilege abuse",
                "scenarios": [
                    "Access to other customers' data",
                    "Unauthorized administrative actions",
                    "Financial transaction manipulation",
                ],
            },
        }
        
        executive_findings = []
        
        # Group similar findings
        grouped: dict[str, list] = {}
        for finding in findings:
            key = finding.get("type", finding.get("name", "Other"))
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(finding)
        
        # Translate each group
        for vuln_type, group in grouped.items():
            if not group:
                continue
            
            # Get first finding as representative
            rep = group[0]
            severity = rep.get("severity", "MEDIUM")
            
            # Get business translation or generate generic
            translation = None
            for key, trans in business_impacts.items():
                if key.lower() in vuln_type.lower():
                    translation = trans
                    break
            
            if not translation:
                translation = {
                    "impact": f"Security vulnerability that could lead to unauthorized access or data exposure",
                    "scenarios": ["Data breach", "Service disruption", "Compliance violation"],
                }
            
            # Map severity to business risk level
            risk_levels = {
                "CRITICAL": "Critical Business Risk",
                "HIGH": "High Business Risk",
                "MEDIUM": "Moderate Business Risk",
                "LOW": "Low Business Risk",
            }
            
            # Estimate fix time and cost
            fix_estimates = {
                "CRITICAL": ("1-2 weeks", "$25,000-$75,000"),
                "HIGH": ("2-4 weeks", "$10,000-$30,000"),
                "MEDIUM": ("1-2 months", "$5,000-$15,000"),
                "LOW": ("Next release cycle", "$1,000-$5,000"),
            }
            fix_time, fix_cost = fix_estimates.get(severity, ("TBD", "TBD"))
            
            executive_findings.append(ExecutiveFinding(
                title=f"{vuln_type} ({len(group)} instances)",
                business_impact=translation["impact"],
                risk_level=risk_levels.get(severity, "Moderate Business Risk"),
                affected_assets=[f.get("matched_at", "Unknown") for f in group[:5]],
                potential_scenarios=translation["scenarios"],
                recommended_action=rep.get("remediation", "Engage security team for remediation"),
                estimated_fix_time=fix_time,
                estimated_fix_cost=fix_cost,
            ))
        
        # Sort by risk
        risk_order = {"Critical Business Risk": 0, "High Business Risk": 1, "Moderate Business Risk": 2, "Low Business Risk": 3}
        executive_findings.sort(key=lambda x: risk_order.get(x.risk_level, 4))
        
        return executive_findings[:10]  # Top 10 for executive attention
    
    def _get_compliance_status(
        self,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Get compliance status across frameworks."""
        
        if self.compliance_mapper:
            try:
                return self.compliance_mapper.generate_compliance_report(findings)
            except Exception as e:
                logger.warning(f"Compliance mapper error: {e}")
        
        # Fallback basic compliance assessment
        critical_high = sum(
            1 for f in findings
            if f.get("severity") in ["CRITICAL", "HIGH"]
        )
        
        return {
            "OWASP ASVS 4.0": {
                "status": "Non-Compliant" if critical_high > 0 else "Partially Compliant",
                "score": max(0, 100 - (critical_high * 15)),
            },
            "PCI DSS 4.0": {
                "status": "Non-Compliant" if critical_high > 0 else "Requires Review",
                "score": max(0, 100 - (critical_high * 20)),
            },
            "ISO 27001": {
                "status": "Controls Review Needed",
                "score": max(0, 100 - (critical_high * 10)),
            },
            "GDPR": {
                "status": "Risk Assessment Required" if critical_high > 0 else "Acceptable",
                "score": max(0, 100 - (critical_high * 12)),
            },
        }
    
    def _analyze_trend(self) -> dict[str, Any]:
        """Analyze security trend over time."""
        
        if self.retest_engine:
            try:
                progress = self.retest_engine.get_remediation_progress()
                delta = self.retest_engine._calculate_risk_delta()
                
                return {
                    "remediation_rate": progress.get("remediation_rate", 0),
                    "risk_trend": delta.get("direction", "unknown"),
                    "score_change": delta.get("score_change", 0),
                    "comparison_available": True,
                }
            except Exception as e:
                logger.warning(f"Retest engine error: {e}")
        
        return {
            "remediation_rate": 0,
            "risk_trend": "first_scan",
            "score_change": 0,
            "comparison_available": False,
        }
    
    def _generate_immediate_actions(
        self,
        findings: list[dict[str, Any]],
    ) -> list[str]:
        """Generate immediate action items."""
        
        actions = []
        
        # Critical findings
        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        if critical:
            actions.append(
                f"🚨 IMMEDIATE: {len(critical)} critical vulnerabilities require emergency patching within 24-48 hours"
            )
        
        # High findings
        high = [f for f in findings if f.get("severity") == "HIGH"]
        if high:
            actions.append(
                f"⚠️ URGENT: {len(high)} high-severity issues need remediation within 1-2 weeks"
            )
        
        # Check for specific high-impact vulns
        for finding in findings:
            name = finding.get("name", "").lower()
            
            if "sql injection" in name and finding.get("severity") == "CRITICAL":
                actions.append(
                    "🗃️ DATABASE: Implement parameterized queries and review database access immediately"
                )
                break
        
        for finding in findings:
            name = finding.get("name", "").lower()
            
            if "authentication" in name or "session" in name:
                if finding.get("severity") in ["CRITICAL", "HIGH"]:
                    actions.append(
                        "🔐 AUTHENTICATION: Review and strengthen authentication mechanisms"
                    )
                    break
        
        # General recommendations based on volume
        if len(findings) > 20:
            actions.append(
                "📊 ASSESSMENT: Consider engaging external security consultants for comprehensive review"
            )
        
        return actions[:7]  # Top 7 immediate actions
    
    def _generate_strategic_recommendations(
        self,
        findings: list[dict[str, Any]],
        compliance_status: dict[str, Any],
    ) -> list[str]:
        """Generate strategic security recommendations."""
        
        recommendations = []
        
        # Based on finding patterns
        finding_types = {f.get("type", f.get("name", "")) for f in findings}
        
        if any("injection" in t.lower() for t in finding_types):
            recommendations.append(
                "🛡️ Implement secure coding training focused on input validation and parameterized queries"
            )
        
        if any("auth" in t.lower() or "session" in t.lower() for t in finding_types):
            recommendations.append(
                "🔑 Review and modernize authentication infrastructure - consider MFA enforcement"
            )
        
        if any("access" in t.lower() or "authorization" in t.lower() for t in finding_types):
            recommendations.append(
                "📋 Implement comprehensive access control review and RBAC audit"
            )
        
        # Based on compliance status
        for framework, status in compliance_status.items():
            if isinstance(status, dict) and status.get("score", 100) < 70:
                recommendations.append(
                    f"📜 {framework}: Initiate compliance remediation program"
                )
        
        # General strategic recommendations
        recommendations.extend([
            "🔄 Establish continuous security scanning in CI/CD pipeline",
            "📝 Implement security champions program across development teams",
            "🎯 Conduct quarterly penetration testing assessments",
        ])
        
        return recommendations[:8]  # Top 8 strategic recommendations
    
    def render_report(
        self,
        summary: ExecutiveSummary,
        format: str = "markdown",
    ) -> str:
        """Render executive summary in specified format."""
        
        if format == "markdown":
            return self._render_markdown(summary)
        elif format == "json":
            return self._render_json(summary)
        elif format == "html":
            return self._render_html(summary)
        else:
            return self._render_markdown(summary)
    
    def _render_markdown(self, summary: ExecutiveSummary) -> str:
        """Render as Markdown."""
        
        lines = [
            "# 🔒 Executive Security Assessment Summary",
            "",
            f"**Target:** {summary.target}",
            f"**Date:** {summary.generated_at.strftime('%B %d, %Y')}",
            "",
            "---",
            "",
            "## Overall Risk Assessment",
            "",
            f"### Risk Rating: {summary.overall_risk_rating}",
            f"**Risk Score:** {summary.risk_score}/100",
            "",
        ]
        
        # Risk meter
        filled = int(summary.risk_score / 10)
        meter = "█" * filled + "░" * (10 - filled)
        lines.append(f"Risk Meter: [{meter}] {summary.risk_score}%")
        lines.append("")
        
        # Financial impact
        fi = summary.financial_impact
        lines.extend([
            "## 💰 Estimated Financial Impact",
            "",
            "| Category | Estimated Cost |",
            "|----------|---------------|",
            f"| Potential Breach Cost | ${fi.breach_cost_low:,.0f} - ${fi.breach_cost_high:,.0f} |",
            f"| Regulatory Fines Risk | ${fi.regulatory_fines:,.0f} |",
            f"| Remediation Investment | ${fi.remediation_cost:,.0f} |",
            f"| Reputation Impact | ${fi.reputation_damage:,.0f} |",
            f"| Business Disruption | ${fi.business_disruption:,.0f} |",
            f"| **Total Risk Exposure** | **${fi.total_risk_exposure:,.0f}** |",
            "",
        ])
        
        # Key findings
        lines.extend([
            "## 🎯 Key Findings",
            "",
        ])
        
        for i, finding in enumerate(summary.key_findings, 1):
            lines.extend([
                f"### {i}. {finding.title}",
                f"**Risk Level:** {finding.risk_level}",
                f"**Business Impact:** {finding.business_impact}",
                "",
                "**Potential Scenarios:**",
            ])
            for scenario in finding.potential_scenarios:
                lines.append(f"- {scenario}")
            lines.extend([
                "",
                f"**Recommended Action:** {finding.recommended_action}",
                f"**Estimated Effort:** {finding.estimated_fix_time} | {finding.estimated_fix_cost}",
                "",
            ])
        
        # Compliance status
        lines.extend([
            "## 📜 Compliance Status",
            "",
            "| Framework | Status | Score |",
            "|-----------|--------|-------|",
        ])
        
        for framework, status in summary.compliance_status.items():
            if isinstance(status, dict):
                lines.append(f"| {framework} | {status.get('status', 'N/A')} | {status.get('score', 'N/A')}% |")
        
        lines.append("")
        
        # Immediate actions
        lines.extend([
            "## ⚡ Immediate Actions Required",
            "",
        ])
        for action in summary.immediate_actions:
            lines.append(f"- {action}")
        lines.append("")
        
        # Strategic recommendations
        lines.extend([
            "## 📈 Strategic Recommendations",
            "",
        ])
        for rec in summary.strategic_recommendations:
            lines.append(f"- {rec}")
        lines.append("")
        
        # Trend
        if summary.trend.get("comparison_available"):
            lines.extend([
                "## 📊 Security Trend",
                "",
                f"- Remediation Rate: {summary.trend.get('remediation_rate', 0)}%",
                f"- Risk Trend: {summary.trend.get('risk_trend', 'N/A')}",
                f"- Score Change: {summary.trend.get('score_change', 0)}",
                "",
            ])
        
        lines.extend([
            "---",
            f"*Report generated on {summary.generated_at.strftime('%Y-%m-%d %H:%M:%S')}*",
        ])
        
        return "\n".join(lines)
    
    def _render_json(self, summary: ExecutiveSummary) -> str:
        """Render as JSON."""
        
        data = {
            "generated_at": summary.generated_at.isoformat(),
            "target": summary.target,
            "overall_risk_rating": summary.overall_risk_rating,
            "risk_score": summary.risk_score,
            "financial_impact": {
                "breach_cost_low": summary.financial_impact.breach_cost_low,
                "breach_cost_high": summary.financial_impact.breach_cost_high,
                "regulatory_fines": summary.financial_impact.regulatory_fines,
                "remediation_cost": summary.financial_impact.remediation_cost,
                "reputation_damage": summary.financial_impact.reputation_damage,
                "business_disruption": summary.financial_impact.business_disruption,
                "total_risk_exposure": summary.financial_impact.total_risk_exposure,
            },
            "key_findings": [
                {
                    "title": f.title,
                    "business_impact": f.business_impact,
                    "risk_level": f.risk_level,
                    "affected_assets": f.affected_assets,
                    "potential_scenarios": f.potential_scenarios,
                    "recommended_action": f.recommended_action,
                    "estimated_fix_time": f.estimated_fix_time,
                    "estimated_fix_cost": f.estimated_fix_cost,
                }
                for f in summary.key_findings
            ],
            "compliance_status": summary.compliance_status,
            "trend": summary.trend,
            "immediate_actions": summary.immediate_actions,
            "strategic_recommendations": summary.strategic_recommendations,
        }
        
        return json.dumps(data, indent=2)
    
    def _render_html(self, summary: ExecutiveSummary) -> str:
        """Render as HTML."""
        
        # Convert markdown to basic HTML
        md = self._render_markdown(summary)
        
        html_lines = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            "<title>Executive Security Assessment</title>",
            "<style>",
            "body { font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }",
            "h1 { color: #1a1a2e; border-bottom: 2px solid #4a4e69; }",
            "h2 { color: #22223b; margin-top: 30px; }",
            "h3 { color: #4a4e69; }",
            "table { border-collapse: collapse; width: 100%; margin: 15px 0; }",
            "th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }",
            "th { background-color: #4a4e69; color: white; }",
            ".risk-critical { color: #dc3545; font-weight: bold; }",
            ".risk-high { color: #fd7e14; font-weight: bold; }",
            ".risk-moderate { color: #ffc107; }",
            ".risk-low { color: #28a745; }",
            "</style>",
            "</head>",
            "<body>",
        ]
        
        # Simple markdown to HTML conversion
        in_table = False
        for line in md.split("\n"):
            if line.startswith("# "):
                html_lines.append(f"<h1>{line[2:]}</h1>")
            elif line.startswith("## "):
                html_lines.append(f"<h2>{line[3:]}</h2>")
            elif line.startswith("### "):
                html_lines.append(f"<h3>{line[4:]}</h3>")
            elif line.startswith("| ") and "---" not in line:
                if not in_table:
                    html_lines.append("<table>")
                    in_table = True
                    cells = line.split("|")[1:-1]
                    html_lines.append("<tr>" + "".join(f"<th>{c.strip()}</th>" for c in cells) + "</tr>")
                else:
                    cells = line.split("|")[1:-1]
                    html_lines.append("<tr>" + "".join(f"<td>{c.strip()}</td>" for c in cells) + "</tr>")
            elif line.startswith("- "):
                html_lines.append(f"<li>{line[2:]}</li>")
            elif line.startswith("**") and line.endswith("**"):
                html_lines.append(f"<p><strong>{line[2:-2]}</strong></p>")
            elif line == "---":
                if in_table:
                    html_lines.append("</table>")
                    in_table = False
                html_lines.append("<hr>")
            elif line.strip():
                html_lines.append(f"<p>{line}</p>")
        
        if in_table:
            html_lines.append("</table>")
        
        html_lines.extend([
            "</body>",
            "</html>",
        ])
        
        return "\n".join(html_lines)
