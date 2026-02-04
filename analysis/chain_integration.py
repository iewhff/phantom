"""
Attack Chain Integration - Integrates attack chain analysis with the main scanning workflow.
Provides seamless chain detection after vulnerability scanning.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from analysis.attack_chain_engine import AttackChainEngine, AttackChain
from analysis.chain_visualizer import ChainVisualizer
from analysis.chain_dashboard import AttackChainDashboard
from utils.logger import get_logger

logger = get_logger(__name__)


class AttackChainIntegration:
    """
    Integrates attack chain analysis with the pentesting workflow.
    
    Features:
    - Automatic chain detection from scan results
    - Multiple output formats (ASCII, HTML, JSON, Dashboard)
    - Integration with reporting system
    - Real-time chain detection during scanning
    """
    
    def __init__(self, output_dir: str | Path = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.engine = AttackChainEngine()
        self.visualizer = ChainVisualizer()
        self.dashboard = AttackChainDashboard()
        
        self.chains: list[AttackChain] = []
        self.findings: list[dict[str, Any]] = []
    
    async def analyze_from_scan_results(
        self,
        findings: list[dict[str, Any]],
        target: str = "Unknown",
    ) -> list[AttackChain]:
        """
        Analyze findings from scan results and detect attack chains.
        
        Args:
            findings: List of vulnerability findings from scanners
            target: Target name/URL for reporting
            
        Returns:
            List of detected attack chains
        """
        logger.info(f"Starting attack chain analysis for {target}")
        logger.info(f"Processing {len(findings)} findings")
        
        self.findings = findings
        
        # Run analysis
        self.chains = await self.engine.analyze_findings(findings)
        
        logger.info(f"Detected {len(self.chains)} attack chains")
        
        return self.chains
    
    def get_executive_summary(self) -> str:
        """Get executive summary of attack chains."""
        return self.engine.get_executive_summary(self.chains)
    
    def generate_ascii_report(self) -> str:
        """Generate ASCII report of all chains."""
        lines = [
            "=" * 80,
            "              🔗 ATTACK CHAIN ANALYSIS REPORT",
            "=" * 80,
            "",
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Total Chains: {len(self.chains)}",
            f"  Critical: {len([c for c in self.chains if c.max_severity == 'CRITICAL'])}",
            f"  High: {len([c for c in self.chains if c.max_severity == 'HIGH'])}",
            "",
            "-" * 80,
        ]
        
        for i, chain in enumerate(self.chains, 1):
            lines.append(f"\n[Chain {i}/{len(self.chains)}]")
            lines.append(self.visualizer.generate_ascii(chain))
            lines.append("\n" + "-" * 80)
        
        # Executive summary
        lines.append("\n" + "=" * 80)
        lines.append("                    📋 EXECUTIVE SUMMARY")
        lines.append("=" * 80)
        lines.append(self.get_executive_summary())
        
        return "\n".join(lines)
    
    def generate_html_report(self, target: str = "Unknown") -> str:
        """Generate detailed HTML report."""
        return self.visualizer.generate_html_report(self.chains, target)
    
    def generate_dashboard(self, target: str = "Unknown") -> str:
        """Generate interactive dashboard."""
        self.dashboard.set_data(self.chains, self.findings)
        return self.dashboard.generate_dashboard(target)
    
    def generate_mermaid_diagrams(self) -> list[str]:
        """Generate Mermaid diagrams for all chains."""
        return [self.visualizer.generate_mermaid(chain) for chain in self.chains]
    
    def export_json(self) -> str:
        """Export chains as JSON."""
        return self.visualizer.generate_json(self.chains)
    
    async def save_all_reports(
        self,
        target: str = "Unknown",
        prefix: str = "attack_chains",
    ) -> dict[str, Path]:
        """
        Save all report formats to files.
        
        Returns:
            Dictionary mapping format names to file paths
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{prefix}_{timestamp}"
        
        saved_files: dict[str, Path] = {}
        
        # ASCII Report
        ascii_path = self.output_dir / f"{base_name}.txt"
        ascii_path.write_text(self.generate_ascii_report(), encoding="utf-8")
        saved_files["ascii"] = ascii_path
        logger.info(f"Saved ASCII report: {ascii_path}")
        
        # HTML Report
        html_path = self.output_dir / f"{base_name}_report.html"
        html_path.write_text(self.generate_html_report(target), encoding="utf-8")
        saved_files["html"] = html_path
        logger.info(f"Saved HTML report: {html_path}")
        
        # Dashboard
        dashboard_path = self.output_dir / f"{base_name}_dashboard.html"
        dashboard_path.write_text(self.generate_dashboard(target), encoding="utf-8")
        saved_files["dashboard"] = dashboard_path
        logger.info(f"Saved dashboard: {dashboard_path}")
        
        # JSON Export
        json_path = self.output_dir / f"{base_name}.json"
        json_path.write_text(self.export_json(), encoding="utf-8")
        saved_files["json"] = json_path
        logger.info(f"Saved JSON export: {json_path}")
        
        # Mermaid Diagrams (single file with all)
        mermaid_path = self.output_dir / f"{base_name}_diagrams.md"
        mermaid_content = f"# Attack Chain Diagrams\n\nGenerated: {timestamp}\n\n"
        for i, diagram in enumerate(self.generate_mermaid_diagrams(), 1):
            mermaid_content += f"## Chain {i}: {self.chains[i-1].name}\n\n{diagram}\n\n"
        mermaid_path.write_text(mermaid_content, encoding="utf-8")
        saved_files["mermaid"] = mermaid_path
        logger.info(f"Saved Mermaid diagrams: {mermaid_path}")
        
        return saved_files
    
    def get_remediation_roadmap(self) -> list[dict[str, Any]]:
        """
        Generate prioritized remediation roadmap based on attack chains.
        
        Returns:
            List of remediation items sorted by priority
        """
        roadmap = []
        vulnerability_priority: dict[str, dict] = {}
        
        for chain in self.chains:
            chain_priority = chain.remediation_priority
            
            for node in chain.nodes:
                node_key = f"{node.name}:{node.endpoint}"
                
                if node_key not in vulnerability_priority:
                    vulnerability_priority[node_key] = {
                        "vulnerability": node.name,
                        "endpoint": node.endpoint,
                        "cwe": node.cwe,
                        "owasp": node.owasp,
                        "cvss": node.cvss,
                        "severity": node.severity,
                        "chain_count": 0,
                        "max_chain_priority": 0,
                        "chains": [],
                    }
                
                vulnerability_priority[node_key]["chain_count"] += 1
                vulnerability_priority[node_key]["chains"].append(chain.name)
                vulnerability_priority[node_key]["max_chain_priority"] = max(
                    vulnerability_priority[node_key]["max_chain_priority"],
                    chain_priority
                )
        
        # Calculate final priority score
        for key, vuln in vulnerability_priority.items():
            # Higher score = more urgent
            score = (
                vuln["max_chain_priority"] * 2 +
                vuln["chain_count"] * 1.5 +
                vuln["cvss"]
            )
            vuln["priority_score"] = round(score, 1)
        
        # Sort by priority score (descending)
        roadmap = sorted(
            vulnerability_priority.values(),
            key=lambda x: x["priority_score"],
            reverse=True
        )
        
        return roadmap
    
    def print_remediation_roadmap(self) -> None:
        """Print remediation roadmap to console."""
        roadmap = self.get_remediation_roadmap()
        
        print("\n" + "=" * 80)
        print("              🗺️ REMEDIATION ROADMAP")
        print("=" * 80)
        print(f"\n  Total items: {len(roadmap)}")
        print("-" * 80)
        
        for i, item in enumerate(roadmap[:20], 1):  # Top 20
            print(f"\n  #{i} [Score: {item['priority_score']}] {item['vulnerability']}")
            print(f"      Endpoint: {item['endpoint'][:50]}")
            print(f"      CVSS: {item['cvss']} | {item['cwe']} | {item['owasp']}")
            print(f"      Appears in {item['chain_count']} chain(s): {', '.join(item['chains'][:3])}")
        
        if len(roadmap) > 20:
            print(f"\n  ... and {len(roadmap) - 20} more items")


# Example usage and CLI
async def main():
    """Example usage of Attack Chain Integration."""
    
    # Sample findings (simulating scan results)
    sample_findings = [
        {
            "name": "Subdomain Takeover",
            "severity": "HIGH",
            "cvss": 7.5,
            "cwe": "CWE-284",
            "owasp": "A05:2021",
            "endpoint": "https://dev.example.com",
            "evidence": "Dangling DNS pointing to unclaimed S3 bucket",
        },
        {
            "name": "JWT None Algorithm",
            "severity": "CRITICAL",
            "cvss": 9.1,
            "cwe": "CWE-327",
            "owasp": "A02:2021",
            "endpoint": "https://api.example.com/auth",
            "evidence": "Server accepts 'none' algorithm in JWT header",
        },
        {
            "name": "IDOR in User Profile",
            "severity": "HIGH",
            "cvss": 7.5,
            "cwe": "CWE-639",
            "owasp": "A01:2021",
            "endpoint": "https://api.example.com/users/{id}",
            "evidence": "Can access other users' profiles by changing ID",
        },
        {
            "name": "SQL Injection",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "cwe": "CWE-89",
            "owasp": "A03:2021",
            "endpoint": "https://api.example.com/search",
            "evidence": "Parameter 'q' is vulnerable to SQL injection",
        },
        {
            "name": "Exposed Debug Endpoint",
            "severity": "MEDIUM",
            "cvss": 5.3,
            "cwe": "CWE-489",
            "owasp": "A05:2021",
            "endpoint": "https://api.example.com/debug",
            "evidence": "Debug endpoint exposes internal information",
        },
        {
            "name": "Missing Rate Limiting",
            "severity": "MEDIUM",
            "cvss": 5.0,
            "cwe": "CWE-770",
            "owasp": "A04:2021",
            "endpoint": "https://api.example.com/login",
            "evidence": "No rate limiting on authentication endpoint",
        },
    ]
    
    # Initialize integration
    integration = AttackChainIntegration(output_dir="reports/attack_chains")
    
    # Analyze findings
    chains = await integration.analyze_from_scan_results(
        findings=sample_findings,
        target="example.com"
    )
    
    # Print ASCII report
    print(integration.generate_ascii_report())
    
    # Print executive summary
    print("\n" + "=" * 80)
    print("              📋 EXECUTIVE SUMMARY")
    print("=" * 80)
    print(integration.get_executive_summary())
    
    # Print remediation roadmap
    integration.print_remediation_roadmap()
    
    # Save all reports
    saved = await integration.save_all_reports(target="example.com")
    
    print("\n" + "=" * 80)
    print("              📁 SAVED REPORTS")
    print("=" * 80)
    for format_name, path in saved.items():
        print(f"  {format_name}: {path}")


if __name__ == "__main__":
    asyncio.run(main())
